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
//! Posture matches the rest of hs-utils' shared stores: **fail open** — a redis
//! outage degrades to "the user is asked to log in again", never a 500.
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
/// Operates on the authority only — everything between `://` and the first `/`
/// that follows — so an `@` in a path or query is left alone. A URL with no
/// userinfo comes back unchanged, and anything that does not parse as
/// scheme-plus-authority is returned whole, because a value that is not a URL
/// cannot be leaking URL credentials and hiding it would only make the error
/// less useful.
fn redact_url_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find('/')
        .map(|i| authority_start + i)
        .unwrap_or(url.len());
    let authority = &url[authority_start..authority_end];

    // Last `@`, not first: a password may itself contain one.
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };
    format!(
        "{}***{}",
        &url[..authority_start],
        &url[authority_start + at..]
    )
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
    /// Performs no I/O: an unreachable host is discovered on first use and
    /// handled by the fail-open path, not here.
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
// The two `connection failed` sites carry no sid, so they were left interpolated
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
// downstream rather than from caller input. They now take the same four fields as
// the eight sites below, and `error.message` is a bare `&str` on all ten: that is
// what makes the fmt layer escape the newline instead of emitting it.
// `tests/session_store_error_message_is_escaped_redis.rs` drives both of them.
#[async_trait]
impl WebSessionStore for RedisSessionStore {
    async fn load(&self, sid: &str) -> Option<Session> {
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
                return None; // fail open
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
                return None;
            }
        };
        let raw = raw?;
        match serde_json::from_str::<Session>(&raw) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(
                    session.store = %"redis",
                    session.op = %"load",
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login redis load: malformed payload"
                );
                None
            }
        }
    }

    async fn store(&self, sid: &str, session: &Session) {
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
                return;
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
                return;
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
        }
    }

    async fn remove(&self, sid: &str) {
        let key = self.key(sid);
        let Ok(mut conn) = self.conn().await else {
            return;
        };
        let res: redis::RedisResult<()> = conn.del(&key).await;
        if let Err(e) = res {
            tracing::error!(
                session.store = %"redis",
                session.op = %"remove",
                error.message = log_safe(&e.to_string()).as_str(),
                "web_login redis remove failed"
            );
        }
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
            "redis://session-redis:6379",       // plain
            "redis://session-redis:6379/3",     // db index
            "redis://user:pass@host:6379/1",    // credentials
            "rediss://host:6379",               // TLS
        ] {
            assert!(RedisSessionStore::from_url(url, TTL).is_ok(), "should parse: {url}");
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
        let cfg = RedisSentinelConfig { master_name: "mymaster".into(), ..Default::default() };
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
        let err = RedisSessionStore::from_url("redis://user:hunter2@:::bad", Duration::from_secs(60))
            .err()
            .expect("a malformed redis url should fail to parse");
        let text = format!("{err:#}");
        assert!(!text.contains("hunter2"), "password leaked into the error: {text}");
        assert!(text.contains("***"), "should say a credential was elided: {text}");
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

    /// `@` after the authority is not userinfo. Redacting on the first `@`
    /// anywhere would mangle the host out of a perfectly safe URL.
    #[test]
    fn an_at_sign_in_the_path_is_not_treated_as_credentials() {
        let u = "redis://session-redis:6379/db@2";
        assert_eq!(redact_url_userinfo(u), u);
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
}
