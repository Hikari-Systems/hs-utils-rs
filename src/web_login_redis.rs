//! Redis [`WebSessionStore`] for cross-replica browser login, over **either a
//! Sentinel cluster or a single node**.
//!
//! Backs [`crate::web_login::WebLogin`]'s `state → URL` map and post-login
//! cookie session in a shared redis so the `gate` (flow start) and `callback`
//! (flow finish) can run on different replicas behind a load balancer without
//! the callback hitting "no stored state".
//!
//! Two connection modes, chosen by which constructor the caller uses:
//!
//! * [`RedisSessionStore::from_sentinel`] — the deployed shape. Mirrors the
//!   FalkorDB/graph-data-service Sentinel pattern: discover the current master
//!   through Redis Sentinel and re-resolve on failover. The same FalkorDB
//!   Sentinel cluster is reused (it is just redis) on a dedicated db index.
//! * [`RedisSessionStore::from_url`] — a single node from a `redis://` or
//!   `rediss://` URL. This exists so a local compose stack can run one
//!   `redis:7` container and still exercise **the same store, the same
//!   serialisation and the same key layout** as production, instead of running
//!   a different store locally and discovering the difference in deployment.
//!   Standing up a three-node Sentinel quorum to develop against is not a
//!   reasonable ask, and the alternative — Postgres locally, redis in prod —
//!   means the code path under test is not the code path that ships.
//!
//! Both are sync constructors that perform **no I/O**: `Client::open` only
//! parses the URL, and Sentinel resolution happens per call. That is deliberate
//! and load-bearing for the posture below — a store that failed construction
//! when redis was down would turn a degraded dependency into a service that
//! will not boot.
//!
//! Posture matches the rest of hs-utils' shared stores: a failure is logged here
//! **and returned**, and the caller decides what it costs — a caller whose next
//! step depends on the write landing (the session-id rotation in `callback`) can
//! now tell that it did not.
//!
//! **What that costs during an outage is worth knowing before you plan a
//! maintenance window.** The gate's *read* fails open, but the browser tier
//! writes immediately afterwards and that write is fatal, so a redis outage is a
//! 503 on every browser-gated page — not "everyone is asked to log in again".
//! Api-gated routes still 401, because they return before the write. See
//! `web_login::gate`, and the oracle both stores share,
//! `web_login::tests::a_store_outage_is_a_401_on_the_api_tier_and_a_503_on_the_browser_tier`.
//!
//! Note both modes obtain a connection per operation. For Sentinel that is
//! required (the master can move); for a single node it is merely consistent,
//! and is the honest trade for keeping the two paths behaviourally identical.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::sentinel::{SentinelClient, SentinelNodeConnectionInfo, SentinelServerType};
use redis::{AsyncCommands, RedisConnectionInfo, TlsMode};
use tokio::sync::Mutex;

use crate::web_login::{log_safe, Session, WebSessionStore};

/// Connection settings for the redis Sentinel cluster backing the session
/// store. Mirrors the `session.redis` config block / `session__redis__*` env
/// keys (`auth` is the password, matching the existing controllers).
#[derive(Debug, Clone, Default)]
pub struct RedisSentinelConfig {
    /// Sentinel addresses (`host:port`, with or without a `redis://` scheme).
    pub hosts: Vec<String>,
    /// Sentinel master group name.
    pub master_name: String,
    /// Redis logical db index.
    pub db: i64,
    /// Redis ACL username (optional).
    pub username: Option<String>,
    /// Redis password (the `auth` key).
    pub password: Option<String>,
    /// Use TLS to the redis node (insecure verification, in-VPC).
    pub tls: bool,
}

/// Replace the userinfo in a URL with `***`, so a connection string can be
/// named in an error without publishing the password it carries.
///
/// A URL with no `@` has no userinfo and comes back unchanged — the host and
/// port are not secret, and keeping them is what makes the error actionable.
/// Otherwise the userinfo goes, the scheme and everything from the last `@`
/// onwards stay: `redis://user:pw@host:6379/0` → `redis://***@host:6379/0`.
///
/// **When the authority cannot be identified unambiguously it redacts
/// WHOLESALE, to `***`.** That is the fix for HIK-243 and it is a deliberate
/// trade, so the reasoning is here rather than in a ticket:
///
/// The previous rule bounded the authority at the first `/` after `://` and then
/// looked for `@` inside it. A password containing an unencoded `/` truncates the
/// authority *before* the `@`, the search finds nothing, and the URL was returned
/// **whole** into a startup error — `redis://user:hun/ter2@:::bad` came back
/// verbatim, password and all. And the gap was selected by the very character
/// causing the failure: an unencoded `/` in a password is what makes the URL
/// unparseable, hence what produces the error this function is redacting for.
/// Most of the sweep below leaked under it, and **the two figures — how many
/// spellings there are and how many of them leaked — are deliberately not
/// written here.** They live in the `SWEEP_CASES` and `PRE_FIX_LEAKS` constants
/// and nowhere else; `the_sweep_owns_both_figures_and_can_detect_the_defect`
/// re-runs the pre-fix body over the same lists, asserts them, and prints the
/// derived value beside the expected one if either moves. Run it if you want the
/// numbers.
///
/// **That is a change of shape rather than of digits, and it was earned.** The
/// pair used to be quoted in prose as well as asserted, and committed history
/// records it going stale **twice, in different copies** — which is the whole
/// argument, so both are named rather than counted:
///
/// - At `089d603`, **this** sentence shipped `(2,940, 2,044)` while the sweep
///   lists committed in the same file produce 8×5×14×7 = 3,920, and that
///   commit's own message says `3,920 spellings` and `2,576 of 3,920`. Stale
///   on arrival, contradicting its own commit.
/// - At `d46977a`, when `unix://` joined the sweep's `SCHEMES`, **this**
///   sentence was updated to `(4,410, 2,842)` and **the sweep test's own doc
///   comment** — added at `09f7211` — was the one left at `(3,920, 2,576)`,
///   three lines above the assertions contradicting it.
///
/// Both are derivable from `git show <sha>:src/web_login_redis.rs` plus
/// arithmetic over the committed lists. Neither is a recollection.
///
/// **The lesson is in the pair, not in either one.** The offender was a
/// different copy each time, so no rule of the form "watch that comment" was
/// ever going to hold — the first failure was a comment stale against its own
/// commit, the second a comment stale against assertions three lines below it.
/// Warning harder was the repair after the first, and it did not survive the
/// second. That is why there is now one owner instead of a better warning.
///
/// The two obvious repairs are both refused. A second hand-written index rule
/// ("the last `@` before the first `/` that follows it") is one more guess at a
/// syntax someone else's parser owns. And parsing with the `url` crate is
/// **circular**: the string reaching this function is by definition one a URL
/// parser has already rejected — that rejection is what produced the error being
/// logged — so `Url::parse` errs on exactly the inputs in scope and would need a
/// fail-closed fallback regardless.
///
/// So: an authority cannot contain `/`. If the span between the scheme and the
/// last `@` does, then either the `@` is in a path or query (harmless) or the
/// password contains a `/` (a leak), and **we cannot tell which without the
/// parser we do not have**. It costs actionability in the harmless case —
/// `redis://host:6379/db@2` becomes `***` rather than keeping its host, which is
/// the one existing test this change turns over — and that is the right way to
/// be wrong. The same rule and the same trade are in `botsafely-controller`'s
/// `auth::redact_userinfo`, whose earlier version resolved the ambiguity the
/// other way and leaked.
///
/// **That cost is wider than the one example**, and reading `db@2` as the shape
/// of it under-states what an operator loses. *Any* `@` anywhere past the
/// authority collapses the whole string: `rediss://host:6379/0?opt=a@b` and
/// `redis://user:pw@host:6379/0#frag@x` both render `***` (measured; pinned by
/// `an_at_sign_after_a_slash_is_ambiguous_so_it_fails_closed`). The trade still
/// goes this way — an `@` in a query or fragment is rare, and a password
/// containing a `/` is exactly what produces the errors this guards — but the
/// blast radius is "a lost hostname on any URL with a stray `@`", not one
/// contrived path segment.
///
/// **Credentials are not only ever in the userinfo, and for two of the four
/// schemes they are never there.** `unix` and `redis+unix` take username and
/// password from the **query string** — `query.get("user")` / `query.get("pass")`
/// at `connection.rs:438-439` — and such a URL has no `@` at all, so the rule
/// above returned it verbatim at its first branch:
/// `unix:///run/redis.sock?pass=hunter2&db=notanumber` came back whole, out of a
/// config value `session_store.rs` hands straight to `from_url`. So
/// [`carries_query_credentials`] runs **first** and fails closed on a hit,
/// whatever the scheme: an operator who writes `?pass=` on a `redis://` URL has
/// still put a live password into a string about to be logged, and redis quietly
/// ignoring it there does not unpublish it. It fails closed rather than blanking
/// the value alone because a raw `&` inside a password splits it into what looks
/// like a second parameter, and blanking one value would print the tail.
///
/// **Residual, stated rather than left to be rediscovered.** A password that
/// itself begins with one of the four accepted schemes followed by `://`, in a
/// value carrying no scheme of its own, still has that literal prefix printed —
/// a password of `redis://…` renders as `redis://***@host`. It is bounded to one
/// of four fixed words, so it discloses nothing about the rest of the secret,
/// and it needs a config value that is not a URL at all. Closing it entirely is
/// impossible without a parser: the two readings of such a string are textually
/// identical.
///
/// **And a note on what the sweep can and cannot see, because the query-string
/// hole above was invisible to it and would have stayed so.** `sweep_cases` is
/// exhaustive over *its* four lists, and every case it builds is
/// `scheme + userinfo + "@" + tail` — so **every case carries an `@` and none
/// carries a query-carried credential**, and a leak in that family cannot appear
/// in it however large it grows. An exhaustive product is exhaustive over the
/// space it enumerates and silent about the rest, which is easy to misread as
/// coverage.
///
/// That sentence read "it has no unix-scheme row" until `unix://` was added to
/// the sweep's `SCHEMES` to give this function's fourth accepted scheme an
/// oracle. It does have one now, and the correction is worth making rather than
/// deleting: the sweep's blindness to the query family was never about which
/// schemes it lists, it is about the **shape** every case is built to, and a
/// reader who fixed the first reading by adding a scheme would have believed the
/// gap closed while it was untouched.
///
/// That family has its own coverage, and it is deliberately **not** a second
/// hand-written table — the first attempt was one, and it was green while
/// `?pa<TAB>ss=` handed redis a live password. A table contains the spellings
/// its author already thought of, and this bug class exists precisely because
/// nobody's list is complete. So
/// `no_spelling_the_crate_reads_as_a_credential_survives_redaction` asks
/// `redis::IntoConnectionInfo` what the crate actually reads out of each URL and
/// asserts a relation between the two answers, rather than asserting a verdict
/// anyone typed.
fn redact_url_userinfo(url: &str) -> String {
    // Before anything to do with `@`: for two of the four schemes the credential
    // is not in the userinfo and there is no `@` to find. See the doc comment.
    if carries_query_credentials(url) {
        return "***".to_string();
    }

    // No `@` anywhere: there are no credentials to hide.
    let Some(at) = url.rfind('@') else {
        return url.to_string();
    };

    // The LAST `@`, because a password may contain one; anchoring on the first
    // cuts inside the secret and prints the rest of it.
    //
    // Only the four schemes `redis::Client::open` actually accepts count as a
    // scheme here, and that is stronger than an RFC 3986 charset check on
    // purpose. The charset check alone — which is what the controller's copy of
    // this function does — still reads the head of a **schemeless** password as
    // a scheme whenever that head happens to be scheme-shaped, and prints it:
    // the sweep below caught `HeadC4nary://T4ilCanary@h0st` rendering as
    // `HeadC4nary://***@h0st`. The two readings of that string are textually
    // isomorphic, so no amount of syntax will separate them; what separates them
    // is that this function is only ever handed a **redis** connection URL, and
    // `Client::open` rejects every other scheme (`connection.rs:99`) — so a
    // scheme outside the list means the string is not the URL it claims to be,
    // and the fail-closed answer is right.
    // All four of those schemes are in the sweep's `SCHEMES` too, and that is
    // not duplication for its own sake: `unix://` was missing from the sweep for
    // one revision, and deleting `"unix"` from the list here then survived the
    // whole suite.
    const SCHEMES: [&str; 4] = ["redis", "rediss", "redis+unix", "unix"];
    // `filter(|&i| i < at)` is **inert**, and it is not — and cannot become — a
    // panic guard. An earlier note here said it was, on the grounds that a short
    // or empty entry in `SCHEMES` would make `url[after_scheme..at]` below a
    // reversed slice; that is false, and so is its own worked example. `a@b://c`
    // with `""` in the list gives `at = 1` and `i = 3`, but `url[..i]` is `"a@b"`
    // — not `""` — so `contains` is false and the arm is `None`.
    //
    // The real guarantee is the scheme match, and it holds for **any** scheme
    // list whose entries carry no `@` (no redis scheme can): if `url[..i]` equals
    // such an entry then `url[i..i + 3]` is `://`, so no `@` sits at any index
    // below `i + 3`, so the `at` already found is `>= after_scheme`
    // unconditionally. Brute-forced rather than argued — every string of length
    // ≤ 7 over `{a, b, @, :, /}`, 97,656 per list, against the four schemes above
    // plus `+ ""`, `["a"]`, `[""]` and `["a", "b", ""]`, with the filter removed:
    // **0 reversed slices in every list**. The same proof covers the third
    // mutation of this line, `i < at` → `i <= at`; both it and dropping the filter
    // outright differ on nothing (measured, 0 of 6,930 adversarial spellings).
    // The line is left alone because removing it is provably a no-op either way
    // and this round is prose — nothing rests on it.
    //
    // `find` → `rfind` is **not** in that class, and calling it equivalent was
    // wrong. `rfind` returns a later `i`; `url[..i]` then fails the scheme match
    // and the mutant falls to the `None` arm, so any tail carrying a `://` of its
    // own separates them — `redis://u:pw@h://z` is `redis://***@h://z` here and
    // `***` under the mutant, as are `…@h0st:6379/0?next=redis://other` and
    // `…@h0st:6379/0#see://docs` (measured, 640 of those 6,930 spellings differ).
    // Its accepted set is a strict subset of this one's, so the direction is
    // fail-closed and no differing case leaks: actionability, never a secret.
    // Recorded anyway, because a claim of equivalence is exactly what gets the
    // next reader to write off a real difference.
    let scheme = url.find("://").filter(|&i| i < at).and_then(|i| {
        let candidate = url[..i].to_ascii_lowercase();
        SCHEMES
            .contains(&candidate.as_str())
            .then_some(i + "://".len())
    });

    match scheme {
        // Ambiguous — see the doc comment. Fail closed.
        Some(after_scheme) if url[after_scheme..at].contains('/') => "***".to_string(),
        Some(after_scheme) => format!("{}***{}", &url[..after_scheme], &url[at..]),
        // There is an `@`, so there may well be credentials, but this does not
        // parse as scheme-plus-authority. Refusing to guess is the whole job.
        None => "***".to_string(),
    }
}

/// True if the string carries a `user=` or `pass=` query parameter — the place
/// `unix` / `redis+unix` URLs keep their credentials. See
/// [`redact_url_userinfo`], which fails closed on a hit.
///
/// The query starts at the first `?` and ends at the first `#`, which is what
/// the parser redis uses does; no `?` means no query and therefore no
/// query-carried credential for it to read.
///
/// **ASCII tab, LF and CR are removed from the whole input first, because that
/// is the step `Url::parse` performs before it decides anything.** Without it
/// `?pa<TAB>ss=hunter2` is `pass` to redis and an unrecognised name here, and
/// the URL — password and all — was returned verbatim: 126 of the 210
/// credential-bearing spellings in
/// `no_spelling_the_crate_reads_as_a_credential_survives_redaction`'s corpus.
/// `from_url`'s `trim()` does not help; it takes those bytes off the ends, not
/// out of the middle. Removing them from the **raw** input rather than from the
/// decoded name is what mirrors the parser's order: `?p%09ass=` is a
/// percent-encoded tab, decoded afterwards, so redis reads it as `p<TAB>ass` and
/// it is correctly *not* a credential.
///
/// **It mirrors the parser's stripping step and NOT its trimming step**, and the
/// gap is written down rather than left to read as completeness. `Url::parse`
/// also removes leading and trailing C0-controls-and-space from the whole input
/// before anything else, which is not reproduced here — and `from_url`'s
/// `str::trim` is no substitute, being Unicode-whitespace and so leaving
/// `\x00`–`\x08` and `\x0e`–`\x1f` in place.
///
/// It is inert — but **not for the structural reason this comment gave until it
/// was measured**, and the correction matters because the wrong reason is the
/// more reassuring one. It said the trim "touches only the two ends of the
/// string, so a byte it would have removed can never sit inside a parameter
/// name". It can. A trailing byte sits inside a name whenever the last
/// parameter has no `=`: measured, `unix:///s.sock?db=0&pass\x00` is read by the
/// crate as the name `pass` — the trim removed the `\x00` — while this function
/// reads `pass\x00` and answers **false**. The two genuinely disagree.
///
/// What makes it inert is the value, not the name: a name a trailing trim can
/// reach is by construction the final one *and* carries no `=`, so the crate
/// recovers an **empty** credential (`Some("")` on that URL) and there is no
/// secret in the string for the disagreement to publish. The leading end is
/// simply before the `?` and cannot reach a name at all. Both halves are pinned
/// by `the_trimming_gap_reaches_a_name_but_never_a_value`, so the argument is
/// now an assertion rather than a paragraph.
///
/// A sweep at review agreed with the conclusion — every byte `0x00`–`0x20` plus
/// `0x7f`, `U+0085`, `U+00A0`, `U+FEFF` and `U+2028`, injected at 33 positions
/// across the query and userinfo families with the crate supplying the verdict,
/// gave 554 crate-confirmed credential-bearing spellings and 0 published — but
/// **that was a point-in-time measurement and no test re-derives it**, so it is
/// cited, not relied on. Add a rule here that reads outside the query, or one
/// that gives a valueless parameter a meaning, and the gap stops being inert.
fn carries_query_credentials(url: &str) -> bool {
    let url: String = url.replace(['\t', '\n', '\r'], "");
    let Some(q) = url.find('?') else {
        return false;
    };
    let query = url[q + 1..].split('#').next().unwrap_or("");
    query.split('&').any(|param| {
        let name = param.split('=').next().unwrap_or("");
        matches!(
            percent_decode_name(name).to_ascii_lowercase().as_str(),
            "user" | "pass"
        )
    })
}

/// Percent-decode a query parameter *name* far enough to compare it with the
/// two that matter.
///
/// `Url::query_pairs` decodes the name as well as the value, so `?%70ass=` is
/// read by redis as `pass` and a plain textual match would walk straight past
/// it. Undecodable bytes are irrelevant: the only names being compared are
/// ASCII, so anything that does not decode to them cannot match either way.
///
/// **This is one of two transforms between the raw URL and the name redis
/// compares, and it is the second of them.** The first — removal of every ASCII
/// tab, LF and CR — happens in [`carries_query_credentials`] on the raw string,
/// because that is where `Url::parse` does it, and the order is load-bearing
/// rather than incidental: `?p%09ass=` is a percent-encoded tab that survives
/// the removal and decodes here to `p<TAB>ass`, which redis does **not** read as
/// `pass`. Do the removal after this decode and that spelling starts failing
/// closed for no reason. Both directions are pinned by the differential corpus.
///
/// One transform is deliberately absent: `+` is form-decoded to a space by that
/// same parser and is not handled here, because no spelling containing a space
/// decodes to `user` or `pass`. `?pa+ss=` is in the differential corpus and the
/// crate agrees it is not a credential.
fn percent_decode_name(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%' && i + 2 < bytes.len())
            .then(|| Some(hex_nibble(bytes[i + 1])? * 16 + hex_nibble(bytes[i + 2])?))
            .flatten();
        match decoded {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// How this store reaches redis. Not public: callers choose by constructor,
/// and every operation goes through [`RedisSessionStore::conn`], so the two
/// modes cannot diverge in serialisation, key layout or failure handling.
enum Backend {
    /// Resolve the current master through Sentinel on every operation.
    Sentinel(Arc<Mutex<SentinelClient>>),
    /// A single node. `Client` holds parsed connection info, not a socket.
    Direct(redis::Client),
}

/// Redis [`WebSessionStore`], over a Sentinel cluster or a single node.
pub struct RedisSessionStore {
    backend: Backend,
    ttl_secs: u64,
    prefix: String,
}

impl RedisSessionStore {
    /// Default key prefix for session entries.
    pub const DEFAULT_PREFIX: &'static str = "weblogin:sess:";

    /// Build from a single-node `redis://` / `rediss://` URL.
    ///
    /// The URL carries everything the Sentinel config spells out as fields —
    /// db index (`/0`), credentials (`redis://user:pass@host`) and TLS
    /// (`rediss://`) — so there is no second config shape to keep in step.
    ///
    /// Performs no I/O: an unreachable host is discovered on first use, as an
    /// `Err` from whichever operation reached for it — not here. Only the read
    /// sites named in the module header absorb that; the writes do not.
    pub fn from_url(url: &str, ttl: Duration) -> Result<Self> {
        let url = url.trim();
        anyhow::ensure!(!url.is_empty(), "redis url is empty");
        // REDACTED, not raw. A redis URL carries its password inline
        // (`redis://user:pass@host`), and this error surfaces at startup in the
        // container log — where a misconfiguration would have published the
        // credential to whatever ships those logs. The host is what a reader
        // needs to diagnose "which redis did it try?"; the password never is.
        let client = redis::Client::open(url)
            .with_context(|| format!("open redis client for {}", redact_url_userinfo(url)))?;
        Ok(Self {
            backend: Backend::Direct(client),
            ttl_secs: ttl.as_secs().max(1),
            prefix: Self::DEFAULT_PREFIX.to_string(),
        })
    }

    /// Build from Sentinel settings. `ttl` is the per-session expiry (refreshed
    /// on every write).
    pub fn from_sentinel(cfg: RedisSentinelConfig, ttl: Duration) -> Result<Self> {
        let hosts: Vec<String> = cfg
            .hosts
            .iter()
            .map(|h| {
                if h.starts_with("redis://") {
                    h.clone()
                } else {
                    format!("redis://{h}")
                }
            })
            .collect();
        anyhow::ensure!(!hosts.is_empty(), "redis sentinel hosts list is empty");

        let node_info = SentinelNodeConnectionInfo {
            tls_mode: cfg.tls.then_some(TlsMode::Insecure),
            redis_connection_info: Some(RedisConnectionInfo {
                db: cfg.db,
                username: cfg.username.clone(),
                password: cfg.password.clone(),
                protocol: redis::ProtocolVersion::RESP2,
            }),
        };

        let sentinel = SentinelClient::build(
            hosts,
            cfg.master_name.clone(),
            Some(node_info),
            SentinelServerType::Master,
        )
        .context("build redis sentinel client")?;

        Ok(Self {
            backend: Backend::Sentinel(Arc::new(Mutex::new(sentinel))),
            ttl_secs: ttl.as_secs().max(1),
            prefix: Self::DEFAULT_PREFIX.to_string(),
        })
    }

    fn key(&self, sid: &str) -> String {
        format!("{}{sid}", self.prefix)
    }

    /// Borrow a fresh connection. Sentinel re-resolves the master each call so
    /// a failover is picked up without restarting; the direct path opens to the
    /// one node it was given. Every read and write goes through here, which is
    /// what keeps the two modes indistinguishable above this line.
    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection> {
        match &self.backend {
            Backend::Sentinel(sentinel) => {
                let mut s = sentinel.lock().await;
                s.get_async_connection()
                    .await
                    .context("sentinel get_async_connection")
            }
            Backend::Direct(client) => client
                .get_multiplexed_async_connection()
                .await
                .context("redis get_multiplexed_async_connection"),
        }
    }
}

// **No error path below names the `sid` — nor the `key`, and the second half is
// the trap.** `hs_session` is an unsigned bearer credential (possession is
// authentication), and these are the *error* branches, so during a redis outage
// they fire for every in-flight authenticated request at once. Swapping `{sid}`
// for `{key}` reads like a redaction and is not one: `Self::key` is
// `DEFAULT_PREFIX + sid`, so it discloses the entire credential behind fourteen
// characters of fixed prefix. Nothing derived from the sid is acceptable either
// — a truncation is still a partial disclosure, a hash is a stable handle to a
// credential — so it is *dropped* rather than redacted. The invariant, so it
// survives a refactor of these same lines: the sid never enters a formatted
// string in this module, not a message, not an `anyhow::Context`, not an error.
//
// What a reader gets instead is `session.store` / `session.op` as fields, plus
// whatever spans enclose the call — the fmt layer renders the scope as a prefix.
// **How much that is depends on the consumer, so do not read it as a
// guarantee.** `auth.gate` is this crate's only span and it wraps `decide`
// alone, so it covers the gate's `load`/`store` and NOT `callback`'s; an
// `http.server` span exists only in a service that installs one
// (`otel::axum_trace_layer`), which botsafely-controller does and two of the
// three consumers of this store do not. Where neither applies the line stands on
// its own fields. That is accepted: correlation is a compensating control, and
// dropping the credential is right with or without it.
// `error.message` is a **bare `&str`, never `%e`**: redis' `Display` output is
// downstream-derived (it embeds the server's own error text), and `%` emits
// bytes raw, so a newline in it would forge a whole log line. `session.*` take
// `%` because they are compile-time literals.
//
// The `connection failed` sites carry no sid, so they were left interpolated
// for one release — and the reason that was wrong is worth keeping, because it is
// not the reason it looks like. The chain comes from `conn()`, whose context is a
// fixed string plus a `RedisError`; it never carries the URL, so `from_url`'s
// `redact_url_userinfo` — which guards `Client::open` at construction — has
// nothing to do with these lines, and no credential is disclosed by them. What
// `{e:#}` rendered raw is `RedisError`'s `Display`, which reproduces the server's
// own `-ERR` reply **verbatim**: the RESP line parser terminates on CRLF, so a
// bare LF in that reply is not a terminator and survives into the error text. A
// hostile or compromised redis could therefore append whole forged lines to this
// service's log stream — the same shape the paragraph above rejects, reached from
// downstream rather than from caller input. They now carry the same **three**
// fields as the five other `tracing::error!` sites in this impl —
// `session.store`, `session.op`, `error.message` — and `error.message` is a bare
// `&str` on all of them: that is what makes the fmt layer escape the newline
// instead of emitting it. `tests/session_store_error_message_is_escaped_redis.rs`
// drives the `load` and `store` ones, including the over-256-byte reply that
// exercises `log_safe`'s cap.
//
// **There are three of them, not two, since HIK-241.** `remove`'s connection
// failure was `let Ok(mut conn) = self.conn().await else { return; };` — no
// field, no message, no line at all, so a logout during a redis outage was
// invisible from both ends: nothing in the log, and nothing returned to the
// caller either. It is the third, and it is not driven by that test.
//
// **Three, not four, and this store is not symmetric with the Postgres one.**
// `web_login_postgres` has five sites carrying four fields, the extra being
// `session.table`; redis has no table, so there is nothing for it to carry. The
// two stores get flattened to one shape every time someone summarises them —
// botsafely-controller's `CLAUDE.md` records correcting exactly that once
// already — so the counts are spelt out per store rather than shared.
//
// **Every failure is now both logged here and returned to the caller**, and the
// two are not redundant. The `error!` is the cause, at the only place that has
// it in full; the `Err` is the *fact* of the failure, which is what the caller
// needs in order to stop — it used to be swallowed here, so `callback` deleted a
// live session on the strength of a write that never landed. The returned error
// carries a fixed context string and the backend's own error as its source;
// neither names the sid, per the invariant above.
#[async_trait]
impl WebSessionStore for RedisSessionStore {
    async fn load(&self, sid: &str) -> Result<Option<Session>> {
        let key = self.key(sid);
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"load",
                    error.message = log_safe(&format!("{e:#}")).as_str(),
                    "web_login redis load: connection failed"
                );
                return Err(e.context("web_login redis load: connection failed"));
            }
        };
        let raw: Option<String> = match conn.get(&key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"load",
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login redis load failed"
                );
                return Err(anyhow::Error::new(e).context("web_login redis load"));
            }
        };
        let Some(raw) = raw else {
            return Ok(None);
        };
        match serde_json::from_str::<Session>(&raw) {
            Ok(s) => Ok(Some(s)),
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"load",
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login redis load: malformed payload"
                );
                Err(anyhow::Error::new(e).context("web_login redis load: malformed payload"))
            }
        }
    }

    async fn store(&self, sid: &str, session: &Session) -> Result<()> {
        let key = self.key(sid);
        let json = match serde_json::to_string(session) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"store",
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login redis store: serialize failed"
                );
                return Err(
                    anyhow::Error::new(e).context("web_login redis store: serialize failed")
                );
            }
        };
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"store",
                    error.message = log_safe(&format!("{e:#}")).as_str(),
                    "web_login redis store: connection failed"
                );
                return Err(e.context("web_login redis store: connection failed"));
            }
        };
        let res: redis::RedisResult<()> = conn.set_ex(&key, json, self.ttl_secs).await;
        if let Err(e) = res {
            tracing::error!(
                session.store = %"redis",
                session.op = %"store",
                error.message = log_safe(&e.to_string()).as_str(),
                "web_login redis store failed"
            );
            return Err(anyhow::Error::new(e).context("web_login redis store"));
        }
        Ok(())
    }

    async fn remove(&self, sid: &str) -> Result<()> {
        let key = self.key(sid);
        // **This branch logged nothing at all**, so a logout during a redis
        // outage was entirely invisible: no line, and — before the trait was
        // fallible — no way for the caller to know either. It now carries the
        // same three fields as its six siblings.
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"remove",
                    error.message = log_safe(&format!("{e:#}")).as_str(),
                    "web_login redis remove: connection failed"
                );
                return Err(e.context("web_login redis remove: connection failed"));
            }
        };
        let res: redis::RedisResult<()> = conn.del(&key).await;
        if let Err(e) = res {
            tracing::error!(
                session.store = %"redis",
                session.op = %"remove",
                error.message = log_safe(&e.to_string()).as_str(),
                "web_login redis remove failed"
            );
            return Err(anyhow::Error::new(e).context("web_login redis remove"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(3600);

    /// Every form the URL is expected to carry, because the whole argument for
    /// the direct mode is that the URL replaces the Sentinel config's fields.
    /// If a form does not parse, the caller has no other way to express it.
    #[test]
    fn from_url_accepts_the_forms_that_replace_the_sentinel_fields() {
        for url in [
            "redis://session-redis:6379",    // plain
            "redis://session-redis:6379/3",  // db index
            "redis://user:pass@host:6379/1", // credentials
            "rediss://host:6379",            // TLS
        ] {
            assert!(
                RedisSessionStore::from_url(url, TTL).is_ok(),
                "should parse: {url}"
            );
        }
    }

    /// An empty URL is the shape a missing/blank config key takes. It must be a
    /// refusable error, not a store that silently never works — the caller has
    /// to be able to tell "not configured" from "configured and broken".
    #[test]
    fn from_url_rejects_blank_and_non_redis_urls() {
        assert!(RedisSessionStore::from_url("", TTL).is_err());
        assert!(RedisSessionStore::from_url("   ", TTL).is_err());
        assert!(RedisSessionStore::from_url("http://not-redis:6379", TTL).is_err());
    }

    #[test]
    fn from_url_trims_surrounding_whitespace() {
        assert!(RedisSessionStore::from_url("  redis://session-redis:6379  ", TTL).is_ok());
    }

    /// Pre-existing guard, pinned so the refactor to `Backend` did not drop it.
    #[test]
    fn from_sentinel_still_rejects_an_empty_host_list() {
        let cfg = RedisSentinelConfig {
            master_name: "mymaster".into(),
            ..Default::default()
        };
        assert!(RedisSessionStore::from_sentinel(cfg, TTL).is_err());
    }

    /// The property the `Backend` enum exists to guarantee: the connection
    /// source is the *only* difference. A session written by a Sentinel-backed
    /// replica must be readable by a URL-backed one, which requires the key to
    /// be byte-identical — so this is what makes "same store locally and in
    /// production" a true statement rather than a hopeful one.
    #[test]
    fn both_modes_produce_the_same_key_for_the_same_session() {
        let direct = RedisSessionStore::from_url("redis://session-redis:6379", TTL).unwrap();
        let sentinel = RedisSessionStore::from_sentinel(
            RedisSentinelConfig {
                hosts: vec!["sentinel-a:26379".into()],
                master_name: "mymaster".into(),
                ..Default::default()
            },
            TTL,
        )
        .unwrap();

        assert_eq!(direct.key("abc123"), sentinel.key("abc123"));
        assert_eq!(direct.key("abc123"), "weblogin:sess:abc123");
        assert_eq!(direct.ttl_secs, sentinel.ttl_secs);
        assert_eq!(direct.prefix, sentinel.prefix);
    }

    /// A sub-second TTL would otherwise floor to 0 and make redis treat the
    /// `SET ... EX 0` as an error, dropping every session write.
    #[test]
    fn a_sub_second_ttl_is_floored_to_one_second() {
        let s = RedisSessionStore::from_url("redis://h:6379", Duration::from_millis(10)).unwrap();
        assert_eq!(s.ttl_secs, 1);
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// The defect this exists for: a misconfigured redis URL put the password
    /// into a startup error, and startup errors go to the container log.
    #[test]
    fn a_password_never_survives_into_the_error_text() {
        // `.err()` rather than `unwrap_err()`: the latter needs the Ok type to
        // be Debug, and deriving Debug on a store holding a live client is not
        // worth doing to satisfy a test.
        let err =
            RedisSessionStore::from_url("redis://user:hunter2@:::bad", Duration::from_secs(60))
                .err()
                .expect("a malformed redis url should fail to parse");
        let text = format!("{err:#}");
        assert!(
            !text.contains("hunter2"),
            "password leaked into the error: {text}"
        );
        assert!(
            text.contains("***"),
            "should say a credential was elided: {text}"
        );
    }

    #[test]
    fn userinfo_is_replaced_and_the_host_survives() {
        assert_eq!(
            redact_url_userinfo("redis://user:pass@session-redis:6379/0"),
            "redis://***@session-redis:6379/0"
        );
        // Username-only is still userinfo.
        assert_eq!(
            redact_url_userinfo("rediss://alice@host:6379"),
            "rediss://***@host:6379"
        );
    }

    #[test]
    fn a_url_without_credentials_is_untouched() {
        let u = "redis://session-redis:6379/0";
        assert_eq!(redact_url_userinfo(u), u);
    }

    /// **This is the one existing assertion HIK-243 turns over, and the cost is
    /// deliberate.** An `@` after a `/` may be an innocent path segment (this
    /// URL) or the tail of a password containing an unencoded `/` (the leak this
    /// commit fixes). Nothing short of a URL parser can tell them apart, and a
    /// URL parser is unavailable by construction — the string reaching here is
    /// one a URL parser has already rejected. So the harmless case pays: it
    /// loses its host rather than the leaking case keeping its password.
    #[test]
    fn an_at_sign_after_a_slash_is_ambiguous_so_it_fails_closed() {
        assert_eq!(
            redact_url_userinfo("redis://session-redis:6379/db@2"),
            "***"
        );
        // The reason it cannot simply keep the host: this is the same shape.
        assert_eq!(redact_url_userinfo("redis://user:hun/ter2@:::bad"), "***");
        // And the cost is not confined to a contrived path segment — any `@`
        // past the authority does it. Pinned so the doc comment's account of the
        // blast radius cannot drift from the behaviour.
        assert_eq!(redact_url_userinfo("rediss://host:6379/0?opt=a@b"), "***");
        assert_eq!(
            redact_url_userinfo("redis://user:pw@host:6379/0#frag@x"),
            "***"
        );
    }

    /// **Two of the four accepted schemes never put the credential in the
    /// userinfo at all.** `unix` and `redis+unix` take it from the query string
    /// (`connection.rs:438-439`), and such a URL carries no `@`, so the userinfo
    /// rule returns it verbatim at its very first branch.
    #[test]
    fn credentials_in_the_query_string_fail_closed() {
        for url in [
            "unix:///run/redis.sock?pass=hunter2&db=notanumber",
            "redis+unix:///run/r.sock?user=alice&pass=hunter2&protocol=9",
        ] {
            let out = redact_url_userinfo(url);
            assert_eq!(
                out, "***",
                "query-carried credentials leaked: {url} -> {out}"
            );
        }
    }

    /// **The over-refusal axis the differential structurally cannot see.**
    /// `query.get("pass")` is case-sensitive, so redis does not read `?PASS=` —
    /// but an operator who wrote it has still put a live password into a string
    /// about to be logged, so `carries_query_credentials` folds the case and
    /// fails closed anyway. Nothing asserted that until this test: `Q_NAMES`
    /// carries `PASS` and `User` and its doc comment states the behaviour, but
    /// `no_spelling_the_crate_reads_as_a_credential_survives_redaction` filters
    /// to the spellings the crate *does* read, so those rows contribute nothing
    /// to it — **taking the oracle from the crate is right for under-refusal and
    /// blind to over-refusal.** Measured: delete the `.to_ascii_lowercase()` in
    /// `carries_query_credentials` and the entire suite stayed green while
    /// `?PASS=` printed the operator's password whole into the startup error.
    ///
    /// The premise — that the crate really does ignore these — is deliberately
    /// not restated here. It is exactly what `credential_cases == 180` counts,
    /// and that assertion goes red if the crate ever starts reading them. Either
    /// answer is safe here, because this direction fails closed on both.
    ///
    /// The last row is the decode/fold **order**: `%50ASS` percent-decodes to
    /// `PASS` and is folded afterwards. Fold the raw name first instead and it
    /// decodes to `Pass`, which matches neither name.
    #[test]
    fn a_credential_name_in_any_case_fails_closed() {
        for url in [
            "unix:///s.sock?PASS=S3cretC4nary",
            "redis+unix:///s.sock?User=S3cretC4nary",
            "redis://h0st:6379/0?PaSs=S3cretC4nary",
            "unix:///s.sock?%50ASS=S3cretC4nary",
        ] {
            let out = redact_url_userinfo(url);
            assert_eq!(
                out, "***",
                "a credential name must fail closed whatever its case: {url} -> {out}"
            );
        }
    }

    /// The other side of that rule, and without it the cheapest way to satisfy
    /// the one above is to fail closed on any `?` at all. The query parameters
    /// redis reads that are *not* credentials — `db`, `protocol` — must leave the
    /// URL actionable, which is the whole reason this is not simply `"***"`.
    ///
    /// **The last row is the second oracle on "the query ends at the first
    /// `#`".** That sentence in `carries_query_credentials`' doc comment had one
    /// — `Q_PLACEMENTS`' `{n}={v}#frag` row, which catches changing the split's
    /// `.next()` to `.last()` — but that row puts the credential *before* the
    /// `#`, so it only shows a fragment does not break detection. Nothing showed
    /// the fragment was **excluded**: drop the `.split('#')` entirely and the
    /// whole suite stayed green. The direction is over-refusal (a `pass=` parked
    /// in a fragment would start collapsing the URL to `***`), so it costs
    /// actionability rather than a secret, but it is the same shape as the rest
    /// of this round.
    ///
    /// **Residual — and the justification this row first carried does not hold.**
    /// Because the fragment is excluded, `…#x&pass=SECRET` *is* returned whole:
    /// measured on the shipped function, `unix:///s.sock?db=3#x&pass=…`,
    /// `redis://h0st:6379/0?db=3#x&pass=…` and `unix:///s.sock#pass=…` all come
    /// back verbatim with the value published, and the crate reads a credential
    /// out of none of them.
    ///
    /// The reason given was that the query "is a place credentials legitimately
    /// live for two of the four schemes and a fragment is a place they live for
    /// none". That does not separate the cases it is offered to separate. On a
    /// **tcp** scheme the query is a place credentials live for none either, and
    /// `redis://h0st:6379/0?pass=…` still fails closed — on the explicit ground
    /// stated at [`redact_url_userinfo`], that an operator who wrote it has put a
    /// live password into a string about to be logged and redis ignoring it there
    /// does not unpublish it. That ground applies verbatim to the fragment, so
    /// `redis://h0st:6379/0?db=3#x&pass=…` and `redis://h0st:6379/0?pass=…` — one
    /// published whole, one collapsed to `***` — are told apart by this function
    /// for a reason the distinction cannot supply.
    ///
    /// The honest statement is narrower: **the rule mirrors the parser, and the
    /// tcp-query over-refusal is the one deliberate exception to that.**
    /// Extending the same exception to the fragment is a behaviour change, so it
    /// is filed as **HIK-265** rather than folded into a commit about giving the
    /// stated rules oracles. Until it lands, the last row below pins the current
    /// verdict — so the widening will turn this test red, which is the intent.
    #[test]
    fn ordinary_query_parameters_do_not_fail_closed() {
        for url in [
            "redis://h0st:6379/0?protocol=3",
            "unix:///run/redis.sock?db=3&protocol=3",
            "rediss://h0st:6379/0?opt=1",
            "unix:///run/redis.sock?db=3#x&pass=notacredential",
        ] {
            assert_eq!(redact_url_userinfo(url), url, "needlessly redacted: {url}");
        }
    }

    /// The decoder is what stops `?%70ass=` walking past the check, so it is
    /// tested directly rather than only through the table below: a bug in it
    /// publishes a password.
    #[test]
    fn a_query_parameter_name_is_decoded_the_way_the_url_parser_decodes_it() {
        assert_eq!(percent_decode_name("pass"), "pass");
        assert_eq!(percent_decode_name("%70ass"), "pass");
        assert_eq!(percent_decode_name("%70%61%73%73"), "pass");
        // Not a valid escape, so it stays as written — which is also what
        // `Url::query_pairs` does with it.
        assert_eq!(percent_decode_name("pass%"), "pass%");
        assert_eq!(percent_decode_name("pass%zz"), "pass%zz");
        assert_eq!(percent_decode_name("%2"), "%2");
        assert_eq!(percent_decode_name(""), "");
        // The ordering claim, at the decoder's own level: `%09` is a tab, and
        // it is decoded *after* the caller has removed the raw tabs — so this
        // must come back containing one, not collapse to `pass`. If it ever
        // returns `pass`, the two transforms have been folded together and
        // `?p%09ass=` starts failing closed for a spelling redis does not read.
        assert_eq!(percent_decode_name("p%09ass"), "p\tass");
        // Undecodable bytes must not panic; they simply cannot match either name.
        assert_ne!(percent_decode_name("%ff%fe"), "pass");
        // `hex_nibble`'s A–F path, in both cases. **No credential verdict can
        // reach it** — every nibble of `pass`, `user` and their case variants is
        // `0`–`7` (`p`=0x70, `a`=0x61, `s`=0x73, `u`=0x75, `e`=0x65, `r`=0x72,
        // `P`=0x50, `A`=0x41, `S`=0x53, `U`=0x55, `E`=0x45, `R`=0x52) — so
        // `to_digit(16)` → `to_digit(10)` survived the whole suite, this test
        // included. That is a decoder documented as decoding percent-escapes
        // with half its input alphabet unexercised, and the honest fix is a row
        // rather than a footnote claiming it does not matter: the next name
        // anyone adds here may well have an A–F nibble, and it would arrive with
        // the decoder silently broken.
        assert_eq!(percent_decode_name("%7Aebra"), "zebra");
        assert_eq!(percent_decode_name("%7aebra"), "zebra");
        // The other half of the same rule: **only** `%` starts an escape. Drop
        // the `bytes[i] == b'%'` sentinel and every byte followed by two
        // hex-digit characters is eaten as one, which is a real change the whole
        // suite otherwise survives — no credential verdict can reach it either,
        // because mangling needs two *adjacent* hex digits and neither `pass`
        // (`a` alone) nor `user` (`e` alone) has a pair, in any case. Benign,
        // then, but it is a documented decoder rule with no oracle, which is the
        // shape this round exists to remove — so it costs one row rather than a
        // footnote saying it does not matter.
        assert_eq!(percent_decode_name("pa5ss"), "pa5ss");
    }

    // ─── The query-credential differential ─────────────────────────────────
    //
    // **The oracle here is the redis crate itself, not a list of spellings
    // someone thought of.** The first version of this family's coverage was a
    // hand-written `NAMES` table — `pass`, `user`, `%70ass`, `%75ser`, `PASS`,
    // `User` — and it was green while `?pa<TAB>ss=` handed redis a live
    // password and this function returned the URL verbatim. A table can only
    // ever contain the spellings its author already knew about, and the whole
    // reason this bug class keeps recurring is that nobody's list is complete.
    //
    // So instead of asserting what *we* think redis reads, every case asks
    // `redis::IntoConnectionInfo` — the same code path `Client::open` runs —
    // and the assertion is a **relation between the two answers**: if redis
    // recovered the canary as a username or a password, the redacted string
    // must not contain it. Adding a spelling to the corpus needs no matching
    // change to any expectation.

    /// The canary a query-carried credential is spelt with. Plain ASCII so no
    /// decoding step can alter it between the URL and either answer.
    const QUERY_CANARY: &str = "S3cretC4nary";

    /// Scheme plus the path that scheme needs to parse at all — a socket path
    /// for the unix family, a db index for tcp. The two tcp ones are here
    /// because redis does **not** read `?pass=` on them, so they are the
    /// corpus's own over-refusal material: this function fails closed on them
    /// anyway, deliberately.
    const Q_BASES: &[&str] = &[
        "unix:///s.sock",
        "redis+unix:///s.sock",
        "UNIX:///s.sock",
        "redis://h0st:6379/0",
        "rediss://h0st:6379/0",
    ];

    /// Parameter names. **The list is deliberately not grouped by expected
    /// verdict** — the crate supplies the verdict, and labelling a row here
    /// would be the typed-in expectation this whole test exists to replace.
    /// What the mix is for:
    ///
    /// * `pass` / `user` / `%70ass` / `%75ser` — the plain and percent-encoded
    ///   spellings the hand-written table already had.
    /// * `pa<TAB>ss`, `pass<TAB>`, `<TAB>pass`, `pa<LF>ss`, `pa<CR>ss`,
    ///   `us<TAB>er` — **the family that table missed.** `Url::parse` removes
    ///   those three bytes from the whole input before it splits a parameter,
    ///   so redis reads every one of them as `pass` / `user`.
    /// * `p%09ass` — their control, and the reason the removal has to happen on
    ///   the raw string. It is a percent-encoded tab, decoded *after* the
    ///   removal step, so redis reads it as `p<TAB>ass`. Fold the two
    ///   transforms together and this row and the ones above disagree with the
    ///   crate in opposite directions.
    /// * `PASS` / `User` — `query.get("pass")` is case-sensitive, so the crate
    ///   does not read these; this function fails closed on them anyway.
    /// * `pa+ss`, `%2570ass` — one decode step too few and one too many.
    /// * `passx`, `opt` — not credential-shaped at all, so the corpus holds
    ///   cases that must come back untouched.
    const Q_NAMES: &[&str] = &[
        "pass", "user", "%70ass", "%75ser", "pa\tss", "pass\t", "\tpass", "pa\nss", "pa\rss",
        "us\ter", "PASS", "User", "p%09ass", "pa+ss", "%2570ass", "passx", "opt",
    ];

    /// Where in the query the parameter sits, including past a `#`, past a
    /// second `?`, and duplicated.
    ///
    /// **`{n}={v}&x=a?b` is what gives "the query starts at the FIRST `?`" an
    /// oracle**, and it is here because that half of
    /// [`carries_query_credentials`]' doc comment was pinned by nothing: no
    /// other row in this list, and no literal in any hand-written test in this
    /// module, contained a second `?`. Change the `find('?')` there to
    /// `rfind('?')` and the whole suite stayed green while
    /// `unix:///s.sock?pass=<canary>&db=notanumber&x=a?b` came back out of
    /// `from_url` verbatim — the operator's password whole on the startup error
    /// line, the same sink as the `?PASS=` mutant the previous commit closed. A
    /// `?` is legal inside a query value and the parser does not re-split on
    /// it, so a last-`?` reading discards exactly the slice the credential is
    /// in. The `#` half of that sentence is pinned by the `{n}={v}#frag` row.
    const Q_PLACEMENTS: &[&str] = &[
        "{n}={v}",
        "db=0&{n}={v}",
        "{n}={v}&protocol=3",
        "{n}={v}#frag",
        "x=1&{n}={v}&y=2",
        "{n}={v}&{n}={v}",
        "{n}={v}&x=a?b",
    ];

    fn query_corpus() -> Vec<String> {
        let mut out = Vec::new();
        for base in Q_BASES {
            for name in Q_NAMES {
                for placement in Q_PLACEMENTS {
                    let query = placement.replace("{n}", name).replace("{v}", QUERY_CANARY);
                    out.push(format!("{base}?{query}"));
                }
            }
        }
        out
    }

    /// What the redis crate itself recovers from a URL: `true` if the canary
    /// comes back as the username or the password. A URL the crate refuses to
    /// parse has no answer and is reported as such by the caller.
    fn redis_reads_the_canary(url: &str) -> Option<bool> {
        use redis::IntoConnectionInfo;
        let info = url.into_connection_info().ok()?;
        Some(
            info.redis.username.as_deref() == Some(QUERY_CANARY)
                || info.redis.password.as_deref() == Some(QUERY_CANARY),
        )
    }

    /// `carries_query_credentials` as it stood before the tab/LF/CR removal was
    /// added, kept only so the differential below has a control. Do not call it
    /// from anything but that test.
    fn tab_blind_carries_query_credentials(url: &str) -> bool {
        let Some(q) = url.find('?') else {
            return false;
        };
        let query = url[q + 1..].split('#').next().unwrap_or("");
        query.split('&').any(|param| {
            let name = param.split('=').next().unwrap_or("");
            matches!(
                percent_decode_name(name).to_ascii_lowercase().as_str(),
                "user" | "pass"
            )
        })
    }

    /// Count the spellings on which a redactor publishes a credential the redis
    /// crate really reads. Parameterised over the credential-detector so the
    /// pre-fix body can be measured on the identical corpus.
    ///
    /// **This is a MODEL of `redact_url_userinfo`, not the function itself**, and
    /// the difference bounds what the property test can ever prove. It has to be
    /// one — the control's whole purpose is to swap the detector out, which the
    /// shipped function does not let you do — but it means the property asserts
    /// over a reimplementation of the control flow, so a defect in the *wiring*
    /// is invisible to it. Measured: move the `carries_query_credentials` call in
    /// `redact_url_userinfo` below the `rfind('@')` early return, so a
    /// query-carried credential on an `@`-less URL is never checked at all, and
    /// `no_spelling_the_crate_reads_as_a_credential_survives_redaction` stays
    /// **green**. What goes red is only the hand-written tests that call the
    /// shipped function directly, and the list is given rather than a count
    /// because it grows:
    ///
    /// * `credentials_in_the_query_string_fail_closed`
    /// * `a_credential_name_in_any_case_fails_closed`
    /// * `a_query_password_fails_closed_on_the_tcp_schemes_that_ignore_it`
    /// * `the_trimming_gap_reaches_a_name_but_never_a_value`
    /// * `a_query_string_password_never_survives_into_the_error_text` — above
    ///   all, because it is the one that drives the production path through
    ///   `from_url`
    ///
    /// So do not delete any of those on the grounds that the property subsumes
    /// them: it does not, and cannot.
    ///
    /// **A second, structural bound on the same coverage, and it is the one a
    /// reader is most likely to assume away.** `redis_reads_the_canary` answers
    /// `None` for any URL `Client::open` rejects, and the filter below keeps only
    /// `Some(true)` — so **every case this function scores is a URL that parses
    /// successfully**, and a URL that parses successfully never reaches
    /// `redact_url_userinfo` in production at all: `from_url` calls the redactor
    /// only inside `with_context` on the **error** path. This corpus therefore
    /// measures the detector against the crate on the parse-success side, which
    /// is where the oracle can exist, and says nothing directly about the inputs
    /// the shipped code actually sees.
    ///
    /// End-to-end coverage of this family — a URL that parses far enough for the
    /// crate to read the credential and *then* fails, so the error really is
    /// built and the credential really is inside it — is the three literal rows
    /// in `a_query_string_password_never_survives_into_the_error_text`, which get
    /// there with `db=notanumber`. Three literals is the whole of it; that is the
    /// gap, and it is stated rather than left to be inferred from a green tick.
    fn under_refusals(carries: fn(&str) -> bool) -> Vec<String> {
        let mut out = Vec::new();
        for url in query_corpus() {
            if redis_reads_the_canary(&url) != Some(true) {
                continue;
            }
            // Mirrors `redact_url_userinfo` with the detector swapped. It must
            // NOT call the real function on the else branch: that would consult
            // the shipped detector again and the substituted one could never be
            // seen to miss anything. No case in this corpus carries an `@`, so
            // with the detector answering "no" the rest of that function is a
            // pass-through — asserted rather than assumed, because a corpus that
            // later grew an `@` would silently model the wrong function.
            let out_str = if carries(&url) {
                "***".to_string()
            } else {
                assert!(!url.contains('@'), "corpus case carries an `@`: {url}");
                url.clone()
            };
            if out_str.contains(QUERY_CANARY) {
                out.push(format!("{url:?} -> {out_str:?}"));
            }
        }
        out
    }

    /// **The property, with the crate as the oracle.** If `redis` recovers the
    /// canary from a URL, the redaction of that URL must not contain it.
    ///
    /// `#[cfg(unix)]` because `url_to_unix_connection_info` is itself
    /// `#[cfg(unix)]` (`connection.rs:423`) — off unix the crate refuses every
    /// `unix://` URL, and redis reads no query credential on the tcp schemes, so
    /// there is nothing left for the corpus to measure. **Not because it would
    /// be vacuously green:** `credential_cases == 180` would fail loudly against
    /// 0, which is the control doing its job. The gate is here so a non-unix
    /// build reports "not run" rather than "broken", and this crate ships in
    /// Linux containers. Only gate a test that genuinely depends on that
    /// `cfg` — see the tcp one below, which does not.
    #[cfg(unix)]
    #[test]
    fn no_spelling_the_crate_reads_as_a_credential_survives_redaction() {
        let corpus = query_corpus();
        assert_eq!(
            corpus.len(),
            Q_BASES.len() * Q_NAMES.len() * Q_PLACEMENTS.len(),
            "the cartesian product is not the size its own lists imply"
        );

        // The control that stops "zero under-refusals" being satisfied by a
        // corpus redis reads no credential out of at all.
        let credential_cases = corpus
            .iter()
            .filter(|u| redis_reads_the_canary(u) == Some(true))
            .count();
        assert_eq!(
            credential_cases, 210,
            "the number of spellings the crate reads a credential from changed; \
             if a name was added or the crate's parsing moved, re-derive it"
        );

        let leaks = under_refusals(carries_query_credentials);
        assert!(
            leaks.is_empty(),
            "{} of {credential_cases} spellings the redis crate reads a credential \
             from published it; first 10:\n{}",
            leaks.len(),
            leaks
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// **The control, and it is what makes the green above mean something.**
    /// Every assertion in the test before this one is "nothing leaked", which a
    /// corpus incapable of leaking would satisfy just as well. Running the
    /// tab-blind body over the identical corpus is the measurement that the
    /// corpus can detect the defect it was built for: 126 of the 210
    /// credential-bearing spellings — exactly and only those whose name carries
    /// an ASCII tab, LF or CR — came back verbatim, password and all.
    #[cfg(unix)]
    #[test]
    fn the_differential_can_see_the_defect_it_was_built_for() {
        let missed = under_refusals(tab_blind_carries_query_credentials);
        assert_eq!(
            missed.len(),
            126,
            "the corpus changed size or shape; re-derive this figure and the one \
             in `carries_query_credentials`' doc comment. First 10:\n{}",
            missed
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(
            missed
                .iter()
                .all(|m| m.contains("\\t") || m.contains("\\n") || m.contains("\\r")),
            "the tab-blind body missed something outside the tab/LF/CR family, so \
             the doc comment's account of the gap is wrong: {missed:?}"
        );
    }

    /// **The trimming-step gap, asserted instead of argued.**
    /// `carries_query_credentials` mirrors `Url::parse`'s tab/LF/CR *stripping*
    /// and not its *trimming* of leading and trailing C0-controls-and-space. Its
    /// doc comment justified that as inert on the grounds that a trim "touches
    /// only the two ends of the string, so a byte it would have removed can
    /// never sit inside a parameter name" — which is **false**, and this test is
    /// the measurement that says so plus the reason the conclusion survives
    /// anyway.
    ///
    /// Row 1 is the disagreement: the crate trims the trailing `\0`, reads the
    /// name as `pass` and hands back a password; we read `pass\0` and answer
    /// `false`, so the URL is returned whole. Row 1 is also why that costs
    /// nothing — the credential the crate recovers is the **empty string**,
    /// because a name a trailing trim can reach is necessarily the last
    /// parameter *and* carries no `=`, so there is no value in the string to
    /// publish. Row 2 is its control: take the `\0` away and the very same URL
    /// is a credential to both. Row 3 puts the byte at the leading end, which is
    /// before the `?` and so cannot reach a name at all.
    ///
    /// If a future change gives a valueless parameter a meaning, or lets this
    /// function read outside the query, row 1's `""` stops being harmless and
    /// this test is where that shows up.
    #[cfg(unix)]
    #[test]
    fn the_trimming_gap_reaches_a_name_but_never_a_value() {
        use redis::IntoConnectionInfo;

        // Row 1 — the two really do disagree, and the crate's credential is empty.
        let leaky = "unix:///s.sock?db=0&pass\u{0}";
        let info = leaky
            .into_connection_info()
            .expect("the crate parses a trailing-NUL unix url");
        assert_eq!(
            info.redis.password.as_deref(),
            Some(""),
            "the premise is that a trim-reachable name has no value; if the crate \
             ever recovers a non-empty credential here the gap stops being inert"
        );
        assert!(
            !carries_query_credentials(leaky),
            "premise: we read the name as `pass\\0` and do not match it"
        );
        assert_eq!(
            redact_url_userinfo(leaky),
            leaky,
            "nothing is redacted, which is only acceptable because there is no \
             credential value in the string"
        );

        // Row 2 — the control. Without the trailing byte the name matches and
        // the whole string fails closed, so row 1 is a real disagreement rather
        // than a URL neither side reads.
        let same_without_the_byte = "unix:///s.sock?db=0&pass";
        assert!(carries_query_credentials(same_without_the_byte));
        assert_eq!(redact_url_userinfo(same_without_the_byte), "***");

        // Row 3 — the leading end is before the `?`, so it can never reach a
        // name, and a real credential behind it still fails closed.
        let leading = "\u{0}unix:///s.sock?pass=S3cretC4nary";
        assert_eq!(
            redis_reads_the_canary(leading),
            Some(true),
            "premise: the crate trims the leading NUL and reads the credential"
        );
        assert_eq!(redact_url_userinfo(leading), "***");
    }

    /// **The deliberate over-refusal, pinned against the crate rather than
    /// against belief.** On a tcp scheme redis reads no credential out of the
    /// query at all — so `?pass=` there is an operator's secret sitting in a
    /// string about to be logged, not a credential redis uses. Failing closed
    /// on it anyway is a choice, and this is the assertion that says so out
    /// loud, with the crate confirming the premise.
    ///
    /// **Deliberately NOT `#[cfg(unix)]`, unlike its two neighbours.** Every URL
    /// here is `redis://` or `rediss://`, which go through
    /// `url_to_tcp_connection_info` — no `cfg` on it (`connection.rs:333`) — so
    /// this passes on every target, and gating it would drop the only
    /// over-refusal assertion on the scheme axis from non-unix builds for no
    /// reason. It carried that gate for one revision by proximity.
    #[test]
    fn a_query_password_fails_closed_on_the_tcp_schemes_that_ignore_it() {
        for url in [
            "redis://h0st:6379/0?pass=S3cretC4nary",
            "rediss://h0st:6379/0?user=alice&pass=S3cretC4nary",
        ] {
            assert_eq!(
                redis_reads_the_canary(url),
                Some(false),
                "premise broken: the crate now reads a query credential on tcp: {url}"
            );
            assert_eq!(
                redact_url_userinfo(url),
                "***",
                "a query-carried password must fail closed whatever the scheme: {url}"
            );
        }
    }

    /// The end-to-end half, and the reason this family is not hypothetical:
    /// `session_store.rs` hands `session.redis.url[0]` straight to `from_url`,
    /// and for these two schemes `Client::open` *parses* the URL and fails
    /// afterwards — so the error is real and the credential is inside it.
    ///
    /// The tab spelling is here rather than only in the differential because
    /// this is the path that actually reaches a container log, and `from_url`'s
    /// `trim()` is the thing that looks as though it already handled it: it
    /// removes tabs from the **ends** of the config value and does nothing to an
    /// interior one.
    #[test]
    fn a_query_string_password_never_survives_into_the_error_text() {
        for url in [
            "unix:///run/redis.sock?pass=hunter2&db=notanumber",
            "unix:///run/redis.sock?pa\tss=hunter2&db=notanumber",
            "unix:///run/redis.sock?us\ter=alice&pa\nss=hunter2&db=notanumber",
        ] {
            let err = RedisSessionStore::from_url(url, Duration::from_secs(60))
                .err()
                .expect("an invalid db index should fail to open");
            let text = format!("{err:#}");
            assert!(
                !text.contains("hunter2"),
                "password leaked into the error for {url:?}: {text}"
            );
            assert!(
                text.contains("***"),
                "should say a credential was elided for {url:?}: {text}"
            );
        }
    }

    /// **Where the tab removal stops, and why it does not need to go further.**
    /// It is confined to `carries_query_credentials`; the userinfo scan below it
    /// still reads the raw string. That is not an oversight — a tab spliced into
    /// the scheme costs the `://` or the scheme match, and both of those arms
    /// already fail closed. Pinned so nobody "completes" the fix by stripping
    /// the tabs from the whole of `redact_url_userinfo`, which would start
    /// handing the *userinfo* path a string it never received.
    #[test]
    fn a_tab_in_the_scheme_still_fails_closed_by_the_existing_arms() {
        // `redis\t` is not one of the four accepted schemes.
        assert_eq!(redact_url_userinfo("redis\t://u:hunter2@h0st"), "***");
        // The `://` itself is broken, so there is no scheme at all.
        assert_eq!(redact_url_userinfo("redis:/\t/u:hunter2@h0st"), "***");
    }

    /// A password may legitimately contain `@`, so the split must be on the
    /// LAST one in the authority or part of the secret survives.
    #[test]
    fn a_password_containing_an_at_sign_is_fully_redacted() {
        let out = redact_url_userinfo("redis://user:p@ss@host:6379");
        assert_eq!(out, "redis://***@host:6379");
        assert!(!out.contains("p@ss"));
    }

    #[test]
    fn a_non_url_is_returned_whole() {
        assert_eq!(redact_url_userinfo("not-a-url"), "not-a-url");
        assert_eq!(redact_url_userinfo(""), "");
    }

    // ─── The sweep ─────────────────────────────────────────────────────────
    //
    // **This is EXHAUSTIVE over the enumerated spelling space, and that is the
    // design — not a sample, and deliberately not `proptest`.** hs-utils has no
    // CI, so a randomised failure lands on one laptop with no recorded seed and
    // nobody watching; a fixed cartesian product fails the same way for everyone
    // who runs `cargo test`. If you add a spelling, add it to one of the four
    // lists below and the whole product re-runs. **Do not "simplify" this into
    // three hand-picked cases.** The last time this estate hand-picked cases for
    // a redactor, a 400,000-case sweep of the same function in
    // `botsafely-controller` found 430 leaks the hand-picked ones missed.

    /// Canaries at **both ends** of the password, because every leak this shape
    /// produces retains the head: the bug is a truncation, so a tail-only marker
    /// measured 0 detections out of 360 in the controller's equivalent. A leak of
    /// the head is a leak.
    const CANARY_HEAD: &str = "HeadC4nary";
    const CANARY_TAIL: &str = "T4ilCanary";

    /// Scheme prefixes. Three of these are not schemes this function accepts —
    /// the empty one, one starting with a digit, and `http`, which is
    /// RFC-3986-shaped but is not a redis scheme — because "there is an `@` but
    /// no scheme I can identify" is a fail-closed arm, not an unchanged one.
    /// `REDIS://` is here for the case fold.
    ///
    /// **All four schemes `Client::open` accepts are present, and `unix://` was
    /// the one missing.** `connection.rs:99` matches
    /// `"redis" | "rediss" | "redis+unix" | "unix"`, so the list below carried
    /// three of the four plus a case variant — and
    /// `where_it_does_not_fail_closed_it_keeps_the_scheme_and_the_host` asserted
    /// "exactly the four schemes `Client::open` accepts", a set its own contents
    /// could not express. Measured: delete `"unix"` from the production `SCHEMES`
    /// at [`redact_url_userinfo`] and the suite stayed green at 119/119, while
    /// `unix://Us3rname:<canary>@/s.sock` went from `unix://***@/s.sock` to
    /// `***`. That direction is fail-closed — actionability lost, never a secret
    /// — which is why it was a gap rather than a defect, but it is the same
    /// documented-behaviour-with-no-oracle shape as the two case folds.
    const SCHEMES: &[&str] = &[
        "redis://",
        "rediss://",
        "REDIS://",
        "redis+unix://",
        "unix://",
        "http://",
        "",
        "1bad://",
        "not-a-scheme:",
    ];

    /// Usernames, including ones carrying the two delimiters the parse turns on.
    const USERNAMES: &[&str] = &["", "Us3rname", "Us3r/name", "Us3r@name", "Us3r:name"];

    /// What sits between the two canaries in the password. `/` is the defect this
    /// commit fixes; `://` is what let a password masquerade as a scheme.
    const PASSWORD_MIDDLES: &[&str] = &[
        "", "/", "//", "@", ":", "://", "?", "#", "\\", " ", "%2F", "/x/", "@/", "/@",
    ];

    /// Everything after the `@`: host, port, path, query. Two of them carry an
    /// `@` of their own, which is what makes `rfind` ambiguous.
    const TAILS: &[&str] = &[
        "h0st",
        "h0st:6379",
        "h0st:6379/0",
        "h0st:6379/db@2",
        "h0st:6379/0?opt=a@b",
        ":::bad",
        "[::1]:6379",
    ];

    /// Every URL in the space, as `(url, userinfo, scheme, tail)`.
    fn sweep_cases() -> Vec<(String, String, &'static str, &'static str)> {
        let mut out = Vec::new();
        for scheme in SCHEMES {
            for user in USERNAMES {
                for mid in PASSWORD_MIDDLES {
                    for tail in TAILS {
                        let password = format!("{CANARY_HEAD}{mid}{CANARY_TAIL}");
                        let sep = if user.is_empty() { "" } else { ":" };
                        let userinfo = format!("{user}{sep}{password}");
                        out.push((
                            format!("{scheme}{userinfo}@{tail}"),
                            userinfo,
                            *scheme,
                            *tail,
                        ));
                    }
                }
            }
        }
        out
    }

    /// Which spellings leak, under whichever redactor is handed in. Taking the
    /// function as an argument is what lets the pre-fix body be measured over
    /// the same lists — see `the_sweep_owns_both_figures_and_can_detect_the_defect`.
    fn leaking_spellings(redactor: fn(&str) -> String) -> Vec<String> {
        let mut leaks = Vec::new();
        for (url, userinfo, _, _) in &sweep_cases() {
            let out = redactor(url);
            let chars: Vec<char> = userinfo.chars().collect();
            for window in chars.windows(4) {
                let needle: String = window.iter().collect();
                if out.contains(&needle) {
                    leaks.push(format!("{url:?} -> {out:?} (leaked {needle:?})"));
                    break;
                }
            }
        }
        leaks
    }

    /// **The property.** No run of four or more characters of the userinfo may
    /// appear in the output. Four rather than the whole string because every
    /// realistic version of this bug leaks a *prefix* of the secret — asserting
    /// only that the full password is absent is green against a function that
    /// prints all but its last character.
    #[test]
    fn no_four_character_run_of_the_userinfo_survives_any_spelling() {
        let cases = sweep_cases();
        // A control on the sweep itself: an empty or accidentally-shrunk product
        // would make every assertion below vacuous.
        assert_eq!(
            cases.len(),
            SCHEMES.len() * USERNAMES.len() * PASSWORD_MIDDLES.len() * TAILS.len(),
            "the cartesian product is not the size its own lists imply"
        );
        assert!(
            cases.len() > 2000,
            "the sweep shrank: {} cases",
            cases.len()
        );

        let leaks = leaking_spellings(redact_url_userinfo);

        assert!(
            leaks.is_empty(),
            "{} of {} spellings leaked userinfo into the redacted output; first 10:\n{}",
            leaks.len(),
            cases.len(),
            leaks
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The redactor as it stood before HIK-243, kept only so the sweep can be
    /// measured against it. Do not call it from anything but the test below.
    fn pre_hik243_redact(url: &str) -> String {
        let Some(scheme_end) = url.find("://") else {
            return url.to_string();
        };
        let authority_start = scheme_end + 3;
        let authority_end = url[authority_start..]
            .find('/')
            .map(|i| authority_start + i)
            .unwrap_or(url.len());
        let Some(at) = url[authority_start..authority_end].rfind('@') else {
            return url.to_string();
        };
        format!(
            "{}***{}",
            &url[..authority_start],
            &url[authority_start + at..]
        )
    }

    /// How many spellings the sweep builds, and how many of them the pre-fix
    /// body leaked. **The only place either number exists.** Nothing else — prose
    /// included — may restate them; the test below says why.
    const SWEEP_CASES: usize = 4_410;
    const PRE_FIX_LEAKS: usize = 2_842;

    /// **Two things at once, and the second is why it is written this way.**
    ///
    /// It shows the sweep can *detect* the defect it was built for: every
    /// assertion above is "no leak", which a sweep of spellings none of which
    /// could ever leak would also satisfy. Running the pre-fix body over the same
    /// lists is the control that gives those greens their meaning.
    ///
    /// And it **owns** the two figures, as the two constants above. Two prose
    /// copies used to restate them — `redact_url_userinfo`'s doc comment and
    /// **this one** — and at `d46977a`, the commit that added `unix://` to the
    /// sweep's `SCHEMES`, `redact_url_userinfo`'s copy was updated to
    /// `(4,410, 2,842)` while **this doc comment** was left at
    /// `(3,920, 2,576)`, three lines above the assertions that contradicted it.
    ///
    /// **At `d46977a` the offender was this comment, not the other one** — and
    /// getting that the wrong way round was itself a review finding, since the
    /// first version of this paragraph blamed `redact_url_userinfo`'s copy,
    /// which `git show d46977a:src/web_login_redis.rs` disproves in one
    /// command.
    ///
    /// **Scope that to `d46977a`, though, because the other copy had its own
    /// turn first.** At `089d603` `redact_url_userinfo`'s comment shipped
    /// `(2,940, 2,044)` against lists producing 3,920 — stale against its own
    /// commit message. Blaming either comment in general is therefore wrong,
    /// and the second version of this paragraph did that too, in the opposite
    /// direction, which is how the pair got written down properly.
    ///
    /// That is the argument for one owner. The offender was a different copy
    /// each time, so no rule of the form "watch that comment" could have held;
    /// only removing the copies could.
    ///
    /// If either number moves, the messages below print the derived value beside
    /// the expected one: updating the constant is then the whole repair, and
    /// there is no prose left to chase.
    #[test]
    fn the_sweep_owns_both_figures_and_can_detect_the_defect() {
        let cases = sweep_cases().len();
        let leaks = leaking_spellings(pre_hik243_redact).len();
        assert_eq!(
            cases, SWEEP_CASES,
            "the sweep now builds {cases} spellings, not {SWEEP_CASES}; set \
             `SWEEP_CASES` to {cases} — it is the only place that number lives"
        );
        assert_eq!(
            leaks, PRE_FIX_LEAKS,
            "the pre-fix body now leaks {leaks} of {cases} spellings, not \
             {PRE_FIX_LEAKS}; set `PRE_FIX_LEAKS` to {leaks} — it is the only \
             place that number lives"
        );
    }

    /// The other half, and without it the property above is satisfied by a
    /// function that returns `"***"` for everything. Whenever the redactor does
    /// *not* fail closed, it must have removed exactly the userinfo and kept the
    /// scheme and the host — which is the entire reason this function is not
    /// simply `"***"`.
    ///
    /// **The verdict is asserted per scheme, not as a count**, and that is the
    /// same over-refusal hole as `a_credential_name_in_any_case_fails_closed`.
    /// A bare `kept > 0` is satisfied by the lowercase rows alone, so `REDIS://`
    /// — which `SCHEMES`' own comment says is "here for the case fold" —
    /// asserted nothing: delete the `.to_ascii_lowercase()` from the scheme
    /// match in `redact_url_userinfo` and every test in the crate stayed green
    /// while `REDIS://u:pw@h0st` collapsed to `***`. Only actionability is lost
    /// there, never a secret, but it is the identical documented-behaviour-with-
    /// no-oracle shape. Naming the set also pins the negative: `http://`, the
    /// empty scheme, `1bad://` and `not-a-scheme:` must never survive.
    #[test]
    fn where_it_does_not_fail_closed_it_keeps_the_scheme_and_the_host() {
        use std::collections::BTreeSet;

        let mut kept_schemes = BTreeSet::new();
        for (url, _, scheme, tail) in sweep_cases() {
            let out = redact_url_userinfo(&url);
            if out == "***" {
                continue;
            }
            kept_schemes.insert(scheme);
            assert_eq!(
                out,
                format!("{scheme}***@{tail}"),
                "an accepted redaction must be scheme + `***@` + the tail, and nothing else: {url:?}"
            );
        }
        assert_eq!(
            kept_schemes,
            BTreeSet::from([
                "redis://",
                "rediss://",
                "REDIS://",
                "redis+unix://",
                "unix://",
            ]),
            "exactly the four schemes `Client::open` accepts (`connection.rs:99`), \
             plus the one case variant that proves the fold, must keep their host; \
             every other spelling must fail closed"
        );
    }

    /// **The positive control.** A URL with no userinfo is passed through
    /// untouched. Without this, a redactor that answered `"***"` unconditionally
    /// would satisfy every other assertion in this module.
    #[test]
    fn a_url_with_no_userinfo_is_never_redacted() {
        for u in [
            "redis://session-redis:6379",
            "redis://session-redis:6379/0",
            "rediss://session-redis:6379/3",
            "redis://[::1]:6379/0",
            "redis://h0st:6379/0?opt=1",
            "not-a-url",
            "",
        ] {
            assert_eq!(
                redact_url_userinfo(u),
                u,
                "a URL with no credentials must survive intact, or the error it \
                 appears in stops being actionable"
            );
        }
    }
}
