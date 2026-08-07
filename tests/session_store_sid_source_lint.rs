//! Every `tracing` and `anyhow` invocation in the two session stores may only
//! reference identifiers on an **allow-list**, and only in the **position** each
//! one was reviewed in.
//!
//! **This is subordinate to the two behavioural tests, not a substitute for
//! them.** It earns its place for three reasons: it covers the three `error!`
//! sites that cannot be reached offline (both `serialize failed` branches, and
//! postgres' `malformed payload`, which needs a real row); it catches the
//! obvious wrong fix on the redis side, where swapping `{sid}` for `{key}` looks
//! like a redaction and in fact discloses the whole credential behind fourteen
//! fixed characters (`RedisSessionStore::key` is `"weblogin:sess:" + sid`); and it is
//! a statement of the *invariant* — the sid never enters a formatted string in
//! these modules, not a message, not an `anyhow::Context`, not an error — which
//! is what has to survive the refactor HIK-241 will make to these same lines.
//!
//! # Why an allow-list of identifiers, and not a deny-list of names (HIK-246)
//!
//! This lint used to ban the two *names* `sid` and `key`. That is defeated by
//! `let id = sid;` — a rename, which is a thing a refactor does for reasons of
//! its own, with no leak intended and none noticed. Measured on the tree this
//! ticket started from, all four of these passed it:
//!
//! | mutation | behavioural arms | old lint |
//! |----------|------------------|----------|
//! | rename to `id`, log it whole | postgres arm caught it | passed |
//! | rename to `id`, log a **7**-character prefix | passed (8-char sweep) | passed |
//! | rename at postgres `malformed payload`, add `correlator = %id` | **unreachable offline** | passed |
//! | bare `error!(` after `use tracing::error;`, naming `sid` | redis arm caught it | passed |
//!
//! Row three is the one that decides the design: no behavioural arm can reach
//! that site, so the lint is the **only** oracle there, and it said nothing
//! about a complete credential disclosure.
//!
//! An allow-list inverts the burden. A leak has to *name something*, and any
//! name that is not already sanctioned fails — so the default for a binding
//! nobody has reviewed is "refused", not "permitted".
//!
//! **It is an allow-list of identifiers, not of field shapes.** The obvious
//! stricter rule — "only the four sanctioned fields plus a literal message, and
//! it interpolates nothing" — is red against this tree on the day it lands:
//! `web_login_redis.rs`'s two `connection failed` sites carry no fields at all
//! and interpolate `{e:#}`. Two carve-outs on day one is how an allow-list
//! becomes a list of exceptions and then gets deleted. The identifier rule needs
//! none — `{e:#}` resolves to the capture name `e`, which is sanctioned — and it
//! is also the rule that survives HIK-241, because it only fires when a **new
//! binding is named**, which is exactly the evasion above.
//!
//! # A name is ruled on in the POSITION it was reviewed in (HIK-246, round two)
//!
//! One flat list of bare identifiers was itself defeated, with **no list edit at
//! all**. `message` is on the list — as a component of the field name
//! `error.message` — and a flat list has no notion of position, so
//!
//! ```ignore
//! let message = format!("sid={sid} err={e}");
//! tracing::error!(…, error.message = message.as_str(), "…");
//! ```
//!
//! named `session`, `store`, `op`, `table`, `error`, `message`, `as_str` — every
//! one sanctioned — and put the whole session id in the log with the lint 9/9
//! green. Measured, and confirmed live by applying the same shape at the
//! reachable redis site, where the behavioural arm renders
//! `error.message="sid=a7f3c1d9-…"`.
//!
//! Eight of the sixteen names on that flat list were ordinary local-binding
//! names, so this was not a one-off: the review that approved each of them was
//! implicitly about **one** position, and the list then honoured it in both.
//!
//! So there are two lists. [`ALLOWED_FIELD_IDENTS`] is what may appear to the
//! left of an `=` — the components of a dotted `tracing` field name, which are
//! not bindings and cannot carry a value. [`ALLOWED_VALUE_IDENTS`] is what may
//! appear anywhere a value is computed: the right of an `=`, a positional
//! argument, and an inline format capture inside a message string. `message` is
//! in the first and **not** the second, so the shape above is now an offence.
//!
//! # What it cannot do
//!
//! **It does not follow data flow, so a name sanctioned in VALUE position can
//! still be rebound** — that is the residual, stated plainly rather than as a
//! cost in list edits, because it costs none. Write `let e = format!("{sid}");`
//! above one of these sites and the lint passes.
//!
//! **Every name in [`ALLOWED_VALUE_IDENTS`] is rebindable, not some readable
//! subset of them**, and an earlier revision of this paragraph said "five of the
//! eleven … are ordinary binding names", listing `e`, `url`, `hosts`, `name`,
//! `table` — a plausibility judgement about which names *look* like bindings,
//! published in the shape of an enumeration. It is wrong, and the reason it is
//! wrong is worth more than the corrected number: the shadowing `let` sits
//! **outside every scanned invocation**, so the lint never sees it, and what the
//! name is used for *at the site* has no bearing on whether it can be rebound
//! *above* it. Measured — `let format = std::format!("sid={sid} err={e}");` with
//! `error.message = format.as_str()` is green, and `format` was on the
//! supposedly-safe half of that split as a helper name. `log_safe`, `as_str`,
//! `to_string`, `is_empty` and `redact_url_userinfo` behave identically.
//!
//! What the position split bought is that the *field-name* components —
//! `session`, `store`, `op`, `error`, `message` — are no longer usable that way,
//! and `message` was the one an actual reviewer reached for first.
//!
//! Closing the rest needs data flow, i.e. a real Rust parser over these two
//! modules, which is a different tool and its own ticket. It is also why the
//! behavioural arms are not deleted: a source scanner can show the source looks
//! right, never that the **rendered output** is clean.
//!
//! Deliberately scoped to the two web-login stores. It is **not** extended to
//! `src/mcp_resource_server/db_session_store.rs`, which has the same shape but a
//! different trust claim and its own ticket: a test that is red for another
//! ticket's reason gets muted, and then it is red for nobody's.
//!
//! **`InMemorySessionStore` (`src/web_login.rs`) is also unscanned**, and unlike
//! the MCP store that is not a deferral. It implements the same
//! `WebSessionStore` trait and takes the same `sid`, but it has no I/O and so no
//! error path: nothing in it formats anything, at any level, so there is no log
//! line for a sid to reach. It is named here because silence about a third
//! implementation of the trait reads as an oversight, which is the failure this
//! whole section exists to avoid.

/// Source of a module, with the path it came from for the failure message.
struct SourceFile {
    path: &'static str,
    text: &'static str,
}

const STORES: &[SourceFile] = &[
    SourceFile {
        path: "src/web_login_postgres.rs",
        text: include_str!("../src/web_login_postgres.rs"),
    },
    SourceFile {
        path: "src/web_login_redis.rs",
        text: include_str!("../src/web_login_redis.rs"),
    },
];

/// Where an identifier appeared inside a scanned invocation. The two are
/// different grammars, and a name reviewed in one was never reviewed in the
/// other — see the module header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Position {
    /// Left of a top-level `=`: a component of a dotted `tracing` field name.
    /// Not a binding, and it cannot carry a value.
    Field,
    /// Right of a top-level `=`, a positional argument, or an inline format
    /// capture inside a message string. This is where a session id would have
    /// to appear, so it is the strict list.
    Value,
}

/// Every identifier allowed to the **left** of an `=`, i.e. every component of
/// a sanctioned dotted field name: `session.store`, `session.op`,
/// `session.table`, `error.message`. Four field names, six components.
///
/// These are field *names* in `tracing`'s macro grammar, not expressions: the
/// macro turns them into a static string. Nothing here can carry a value, which
/// is exactly why the list is separate from [`ALLOWED_VALUE_IDENTS`] — put them
/// in one list and `let message = format!("{sid}")` is sanctioned by the review
/// that approved the field `error.message`.
const ALLOWED_FIELD_IDENTS: &[&str] = &["error", "message", "op", "session", "store", "table"];

/// Every identifier a scanned invocation may name where a **value** is
/// computed: right of an `=`, a positional argument, or an inline format
/// capture. This is the list a leak has to get past.
///
/// **Adding a name here is the reviewable act.** Each one has been read against
/// the question "can this carry the session id?", so extend it deliberately and
/// never to make a red build green:
///
/// * `e` — the error being reported. Downstream-derived text, which is why every
///   site puts it through `log_safe`; it is not derived from the sid.
/// * `table` — reached only as `%self.table`, the configured table name. `self`
///   is a keyword and is exempt below, but the **field** it reaches for is ruled
///   on here, which is why `self.sql_load` would fail on `sql_load`.
/// * `log_safe`, `format`, `to_string`, `as_str`, `is_empty` — helper and method
///   names, in callee position.
/// * `url`, `hosts` — construction-time redis connection settings in
///   `from_url` / `from_sentinel`. Startup config, never a session id.
/// * `redact_url_userinfo` — the redaction helper `url` sits behind **on today's
///   tree**. That is an observation about the two sites that exist, not a rule
///   this lint enforces: it does not follow data flow, so a future
///   `bail!("cannot reach {url}")` names only `url`, passes green, and
///   republishes the redis password. If you add a site naming `url`, put it
///   through `redact_url_userinfo` — nothing here will remind you.
/// * `name` — the configured table name, in `validate_table_name`'s `bail!`,
///   **on today's tree**: config read once at construction, and the branch that
///   names it is the one where it failed to be a Postgres identifier, so no
///   request reaches it. Same caveat as `url`.
///
/// Six of these — `url`, `hosts`, `redact_url_userinfo`, `name`, `format`,
/// `is_empty` — exist only because the scan was widened to the `anyhow` surface.
/// They are startup-config and helper names, not request data, which is why they
/// were acceptable to add — that is the standard, not "the build was red".
///
/// **HIK-241 owes this list one line.** That ticket adds `anyhow` context
/// strings to these same sites, and any binding it names that is not here will
/// fail this test. That failure is the design working, not a defect in it: the
/// fix is to add the *reviewed* name, with a bullet above saying why it cannot
/// carry the sid — not to widen the list until the build is green, which is the
/// same defeat by a friendlier route.
const ALLOWED_VALUE_IDENTS: &[&str] = &[
    "as_str",
    "e",
    "format",
    "hosts",
    "is_empty",
    "log_safe",
    "name",
    "redact_url_userinfo",
    "table",
    "to_string",
    "url",
];

/// Rust keywords that can appear inside one of these invocations. Exempt because
/// a keyword cannot *name* anything — `self.table` is checked on `table`.
const KEYWORDS: &[&str] = &[
    "as", "async", "await", "else", "false", "for", "if", "in", "let", "match", "move", "mut",
    "ref", "return", "self", "true", "while",
];

/// The invocations scanned, by **name** — the delimiter and the spacing around
/// it are matched by [`invocations`], not spelled out here.
///
/// # The `tracing` surface
///
/// Matched on the **bare** name, so `use tracing::error;` followed by `error!(…)`
/// is caught as well as `tracing::error!(…)`. Only the qualified form was
/// matched before, and that alone let a leak through on redis in silence.
///
/// `event` is here because **it is the macro the other five expand to**, it is
/// fully public, and it was the hole a reviewer walked a complete credential
/// disclosure through: `tracing::event!(tracing::Level::ERROR, session.correlator
/// = %id, …)` at the postgres `malformed payload` site left this lint 9/9 green
/// and both behavioural arms green, because no arm can reach that site.
///
/// The span constructors (`span!`, and the five `*_span!` levels) and
/// `Span::record` are here for the same reason one step removed: a span
/// attribute is published exactly as an event field is, and `span.record(…)` /
/// `#[tracing::instrument(fields(…))]` are how one gets set after the fact.
/// Neither module opens a span today. That is the argument **for** listing them
/// rather than against it — the cost is one line each now, and the cost of
/// noticing later is a release.
///
/// # The `anyhow` surface
///
/// `anyhow!` / `format_err!` / `bail!` / `ensure!` / `.context(` /
/// `.with_context(` are here because they are the one path on which the sid
/// reaches `error.message` without any `tracing` body naming it — the error is
/// formatted here and rendered by a caller's `{e:#}`. HIK-241 adds context
/// strings to these exact sites, so the gap would otherwise open in the same
/// release that closes the others.
///
/// `format_err` is `pub use anyhow as format_err;` (`lib.rs:286` in the
/// `Cargo.lock`-resolved anyhow 1.0.102, and unchanged through 1.0.104)
/// — the same macro under a second name, so scanning one and not the other is an
/// alias away from green.
///
/// `context` / `with_context` are [`Kind::Call`], which matches the name before
/// any `(` regardless of what precedes it, so the UFCS spelling
/// `Context::context(x, …)` is caught as well as the method one. A needle
/// carrying a leading `.` matches only the method spelling; that was the
/// previous shape and it was one keystroke from being bypassed.
const INVOCATIONS: &[Needle] = &[
    // tracing events
    Needle::mac("error"),
    Needle::mac("warn"),
    Needle::mac("info"),
    Needle::mac("debug"),
    Needle::mac("trace"),
    Needle::mac("event"),
    // tracing spans, and the two ways a field is added to one after the fact
    Needle::mac("span"),
    Needle::mac("error_span"),
    Needle::mac("warn_span"),
    Needle::mac("info_span"),
    Needle::mac("debug_span"),
    Needle::mac("trace_span"),
    Needle::call("record"),
    Needle::call("instrument"),
    // anyhow
    Needle::mac("anyhow"),
    Needle::mac("format_err"),
    Needle::mac("bail"),
    Needle::mac("ensure"),
    Needle::call("context"),
    Needle::call("with_context"),
];

enum Kind {
    /// `name!(…)`, `name! { … }`, `name![…]`, path-qualified or not.
    Macro,
    /// `name(…)` — a free function, a method (`x.name(…)`) or UFCS
    /// (`Trait::name(x, …)`). Deliberately position-agnostic; see above.
    Call,
}

struct Needle {
    name: &'static str,
    kind: Kind,
}

impl Needle {
    const fn mac(name: &'static str) -> Self {
        Needle {
            name,
            kind: Kind::Macro,
        }
    }
    const fn call(name: &'static str) -> Self {
        Needle {
            name,
            kind: Kind::Call,
        }
    }
    /// How the site is spelled in a failure message.
    fn label(&self) -> String {
        match self.kind {
            Kind::Macro => format!("{}!", self.name),
            Kind::Call => format!("{}(", self.name),
        }
    }
}

/// A source file with its `//` comments blanked out, plus anything the stripper
/// refuses to guess at.
struct Stripped {
    /// The source with comments replaced by spaces. Length and newlines are
    /// preserved, so offsets and line numbers are unchanged.
    text: String,
    /// `(1-based line, construct)` for each place the stripper met something it
    /// deliberately does not handle. **Never silently skipped** — see below.
    unsupported: Vec<(usize, &'static str)>,
}

/// Blank out `//` comments, **line by line**, tracking string literals so a `//`
/// inside one is not mistaken for a comment.
///
/// Stripping is needed at all because the lint would otherwise read its own
/// documentation: both modules carry long comment blocks *about* this invariant,
/// and one mentioning `.with_context(|| … {sid} …)` as the thing not to do would
/// fail the test it is explaining.
///
/// # Why line-oriented, and why two constructs are refused rather than parsed
///
/// A stripper's characteristic failure is not a false positive, it is going
/// **blind**: any construct that scans forward for a terminator will, if that
/// terminator is missing or mis-identified, swallow the rest of the file — and a
/// real offence inside the swallowed span is then reported clean. That is not
/// hypothetical. A sibling review found exactly this: a stripper that was not
/// string-aware treated a `/*` inside an ordinary string literal as a comment
/// opener and silently ate a genuine credential leak two lines later.
///
/// `web_login_redis.rs` carries twenty `//`-inside-a-string-literal sites of its
/// own (every `redis://…` / `rediss://…`, e.g. lines 347–350 and 433–439),
/// which is the *other* half of the same hazard and the one this
/// repo demonstrates directly. **It does not, however, make the main lint fail
/// loudly** — measured: with string-awareness removed the main lint stays green
/// and only `a_comment_marker_inside_a_string_literal_cannot_blind_the_scanner`
/// goes red. That is precisely the point of having the scanner self-tests: a
/// lint cannot detect its own blindness, so the blindness has to be asserted
/// somewhere the main assertion is not.
///
/// **`web_login_redis.rs`'s three `redis://***@…` lines — its 434, 439 and 462,
/// not this file's — do each contain a literal `/*`**, from the `/` of `://`
/// meeting the first `*` of the redaction. HIK-246 asserted in a commit message
/// that there was no `/*`
/// anywhere in either store file; that was false, and it is corrected here
/// because the sentence above is the one a future reader will reason from. The
/// conclusion it was offered against is unchanged, for a reason worth stating
/// rather than restating the claim: a non-string-aware stripper reaches the
/// `//` branch *first* — it is tested before the `/*` refusal — and blanks to
/// end of line, so the `/*` refusal never fires and those three sites do not
/// make string-awareness load-bearing. The sibling-review citation therefore
/// stays, and so does the measurement, which is what actually carries the
/// argument.
///
/// It matters here more than it looks. The postgres `malformed payload` site
/// cannot be reached offline, so **this lint is the only oracle covering it**. A
/// scanner that can be blinded leaves that site with no coverage at all, while
/// still reporting green.
///
/// So the only span this scanner will cross a newline for is a genuine
/// multi-line string literal, which Rust really does have — `validate_table_name`
/// has one — and which cannot run away, because an unterminated string literal
/// does not compile and these files are compiled by this crate.
///
/// The three constructs that *could* run away are refused, loudly, instead of
/// being handled approximately:
///
/// * **`/* … */` block comments.** Scanning for `*/` is the unbounded-swallow
///   shape above, and Rust nests them, so the naive version stops early and the
///   careful version is a parser. Neither module has one.
/// * **A char literal holding a quote or a body delimiter** — `"`, or any of
///   `(` `)` `{` `}` `[` `]`. Handling it properly means telling `'` apart from
///   a lifetime (`'a`, `'static`), which is again a parser.
/// * **A raw string literal** — `r"…"`, `r#"…"#`, `br"…"`, `cr##"…"##`. Its
///   body obeys neither of the two rules the `in_string`/`escaped` pair
///   encodes, so the machine desynchronises against the *rest of the file*.
///   See the closing section for both of the ways that happens.
///
/// All three are reported through [`Stripped::unsupported`] and fail the test
/// with a message saying what to do. **Fail loud beats handle-approximately**:
/// if any of them ever arrives in these files, someone is told, rather than the
/// lint quietly covering less than it claims.
///
/// # Why the char-literal refusal covers brackets and not just the quote
///
/// The refusal is written here, in the stripper, but **it is the only thing
/// standing between a char literal and [`invocations`]** — and the two are
/// blinded by different characters, so a refusal scoped to the quote left the
/// larger half open. The quote is *this* function's hazard: it opens a phantom
/// string running to the next `"` anywhere in the file. The six brackets are the
/// **body matcher's** hazard: `invocations` counts them to find where a body
/// ends, and it is string-aware but not char-literal-aware, so one closer inside
/// a char literal ends the body early and everything after it is never read.
///
/// Not a theoretical widening. Measured at the postgres `malformed payload`
/// site — the one this lint is the *only* oracle for:
///
/// ```ignore
/// session.table = %')',        // <- closes the body, for the scanner
/// session.correlator = %sid,   // <- never scanned
/// ```
///
/// The scanned body ended at `session.table = %'`, every name in it sanctioned,
/// and the suite was 13/13 green with a complete session-id disclosure and
/// `unsupported` empty. It compiles, and `rustfmt --emit stdout` leaves it
/// byte-identical — the same standard [`invocations`]' delimiter argument
/// applies to `error!{ … }`. The redis twin renders
/// `session.table=) session.correlator=a7f3c1d9-…`.
///
/// The three *openers* are refused as well, though they over-run rather than
/// truncate — the safe direction, because the offence stays inside the body —
/// since an over-running body swallows unrelated source and then fails on names
/// that are not the offence. One diagnosis beats two, and a symmetric rule
/// spares the next reader working out which three are the dangerous ones.
///
/// This is exactly the failure this section's own standard names: a stripper's
/// characteristic failure is going blind, and a real offence inside the
/// swallowed span is then reported clean. The stripper honoured that; the body
/// matcher did not, and the refusal is what now covers both.
///
/// # Why a raw string is refused, and the TWO ways it desynchronises
///
/// This was carried for one round as a documented residual, and the account
/// given there named **one** of the two triggers — which is worse than naming
/// none, because an auditor reading it greps for the wrong thing and concludes
/// the file is clean.
///
/// **Trigger 1, the one that was documented: a `\` before the closing quote.**
/// In a raw string `\` is not an escape, so `escaped` is set by a character
/// that does not escape anything:
///
/// ```ignore
/// let a = r"C:\";
/// let b = "redis://x"; tracing::error!(leak = %sid, "m");
/// ```
///
/// The `"` closing `r"C:\"` is read as escaped, so the string never ends; the
/// next real `"` closes it instead, leaving `redis://x` as *code*, whose `//`
/// then blanks the rest of the line. The whole `error!` is replaced by spaces
/// and the lint reports clean.
///
/// **Trigger 2, which has no backslash in it at all: an odd number of inner
/// `"`.**
///
/// ```ignore
/// let d = r#"the " character is not legal in a key"#;
/// ```
///
/// Each inner quote toggles `in_string`, so an odd count leaves the machine one
/// state out of step with the source for the **rest of the file** — every real
/// string read as code and every gap read as string. Embedded double quotes are
/// the entire reason anyone reaches for the `r#"…"#` form, so this is the
/// likelier of the two in practice, and it is invisible to a `\`-shaped grep.
/// Both were measured at `16bd876` against a real leak inserted at redis'
/// `remove` — the one method this repo's `CLAUDE.md` standingly tells a bumper
/// to check — each compiling clean with the lint 14/14 green.
///
/// **Why it is refused rather than left latent.** "Neither module contains a
/// raw string today" was true, and it was a hand grep written into a doc
/// comment — the thing this repo's own standard says is not a regression test.
/// It would have had to be re-run by a human after every future edit to these
/// two files for the lint to keep meaning what it says.
///
/// The stronger argument is that **the enumeration closes here**. The places an
/// unbalanced delimiter can hide in Rust are a closed set — line comments
/// (handled), block comments (refused), string and byte-string literals
/// (handled), char and byte-char literals (refused), raw strings (refused now).
/// Everything else is a token tree and cannot be unbalanced. So this section
/// can stop saying "approximately" and say what it covers, which is the
/// completeness claim the rest of it is built on.
///
/// It costs nothing on plausible source. [`raw_string_starts_at`] requires the
/// full `r` `#`* `"` prefix, so a raw *identifier* (`r#type`) is not touched —
/// it cannot hide a delimiter, being `r#` plus an identifier and nothing else.
/// And the `r"` that a grep for the sequence actually turns up in these files
/// is the one inside `"mymaster".into()` (`web_login_redis.rs:374`), which sits
/// within a string literal and so never reaches this branch at all. Measured on
/// today's tree: 13 redis invocations and 6 postgres ones still scanned, 19 in
/// total, and the whole `(file, line, label, body)` dump is byte-identical to
/// `16bd876`'s.
fn strip_comments(text: &str) -> Stripped {
    let mut out = String::with_capacity(text.len());
    let mut unsupported = Vec::new();
    // The one piece of state carried across a newline; see the doc comment.
    let mut in_string = false;
    let mut escaped = false;

    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let lineno = idx + 1;
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            let c = chars[i];
            if in_string {
                out.push(c);
                i += 1;
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
            } else if c == '/' && chars.get(i + 1) == Some(&'/') {
                // Blank to end of line. Nothing after this on this line is code,
                // so no quote in it can open a string — which is the half a
                // whole-file scanner gets wrong in the other direction.
                while i < chars.len() {
                    out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            } else {
                if c == '/' && chars.get(i + 1) == Some(&'*') {
                    unsupported.push((lineno, "/* … */ block comment"));
                } else if raw_string_starts_at(&chars, i) {
                    unsupported.push((lineno, "raw string literal"));
                } else if c == '\'' && char_literal_hides_a_delimiter(&chars, i) {
                    unsupported.push((lineno, "char literal holding a quote or a delimiter"));
                } else if c == '"' {
                    in_string = true;
                    escaped = false;
                }
                out.push(c);
                i += 1;
            }
        }
    }
    Stripped {
        text: out,
        unsupported,
    }
}

/// Does a raw string literal start at `at`?
///
/// The prefix is `r`, any number of `#`, then `"`, optionally preceded by the
/// byte or C marker: `r"…"`, `r#"…"#`, `r##"…"##`, `br"…"`, `cr#"…"#`.
///
/// **The quote is required, which is what keeps a raw *identifier* out of it.**
/// `r#type` is legal Rust, cannot hide a delimiter — it is `r#` followed by an
/// identifier and nothing else — and refusing it would be a loud false red on
/// source that does nothing wrong. Stopping the scan at `r#`, which is the
/// shorter rule, would do exactly that.
///
/// **The token boundary is load-bearing for the byte and C prefixes, and not
/// for the reason you would guess.** The tempting justification is
/// `"mymaster".into()` at `web_login_redis.rs:374`, which really does contain
/// the two characters `r"` — but that sits inside a string literal, where
/// [`strip_comments`] never reaches this function at all, so it pins nothing.
/// What the boundary actually stops is a **double report**: in `br"…"` the `r`
/// is itself a candidate start, preceded by `b`, so without the check the one
/// literal is pushed to [`Stripped::unsupported`] twice. Measured — delete the
/// guard and B7's `br"` row fails with two entries where it expects one.
///
/// So both halves of the rule are pinned, by different rows: drop the boundary
/// and `br"` double-reports; stop the prefix scan at `r#` instead of requiring
/// the quote and the raw-identifier row is falsely refused.
fn raw_string_starts_at(chars: &[char], at: usize) -> bool {
    if at > 0 && is_word(chars[at - 1]) {
        return false;
    }
    let mut i = at;
    if matches!(chars.get(i), Some('b') | Some('c')) {
        i += 1;
    }
    if chars.get(i) != Some(&'r') {
        return false;
    }
    i += 1;
    while chars.get(i) == Some(&'#') {
        i += 1;
    }
    chars.get(i) == Some(&'"')
}

/// Every character that steers one of the scanners, and so must never reach one
/// wrapped in a char literal: the `"` that opens a string for all four of them,
/// and the six brackets [`invocations`] counts to find the end of a body.
///
/// `'` itself is deliberately absent — `'\''` steers nothing, and refusing it
/// would fail loudly on ordinary source.
const SCANNER_DELIMITERS: &[char] = &['"', '(', ')', '{', '}', '[', ']'];

/// Does the `'` at `at` open a char literal holding one of
/// [`SCANNER_DELIMITERS`]?
///
/// **Matching the three literal characters `'`, `"`, `'` is not enough, and that
/// was a demonstrated gap**: `'\"'` is the same character escaped, it compiles,
/// and it opened the very phantom string the refusal exists to prevent while
/// leaving the lint 9/9 green with nothing in `unsupported`. So the rule is
/// "a char literal whose body contains one of those characters", which covers
/// both spellings, the byte forms `b'"'` / `b'\"'` (the `b` sits before the `'`
/// and is ignored), and — because a `\u{…}` escape is refused wholesale rather
/// than decoded — `'\u{22}'` as well. Refusing every `\u{…}` char literal is the
/// deliberate over-approximation: decoding one is a parser, and neither module
/// has one.
///
/// **The quote and the six brackets are the same refusal but not the same
/// hazard**, and the bracket half was the one that mattered: see
/// [`strip_comments`]' second section for the `session.table = %')'` measurement
/// that closed a scanned body two lines before a `%sid`.
///
/// **Do not overstate the quote half: that was a demonstrated gap in the
/// refusal, not a demonstrated silent blind.** Nobody got a leak through it. The
/// phantom string it opens makes the *stripper* stop reading comments, but
/// `invocations` starts each body scan with fresh string state, so the bodies are
/// still read — and an attempt to weaponise it ran the body away over the rest of
/// the file and failed loudly on unrelated names. It was fixed because a refusal
/// that a one-character escape walks past is not a refusal, not because a leak
/// hid behind it. The bracket half is the opposite: a silent blind, weaponised,
/// green.
///
/// The lookahead is **bounded** (the longest char literal is `'\u{10FFFF}'`, and
/// a newline ends the search), so this cannot itself become the unbounded scan
/// it is guarding against. A lifetime — `'a`, `'static` — has no closing `'`
/// within the bound, or encloses no delimiter if a later lifetime supplies one.
///
/// **Finding the closing quote needs the escape state, not the previous
/// character.** `chars[j - 1] != '\\'` was the first spelling and it reads the
/// *closing* quote of `'\\'` — an ordinary backslash char literal — as escaped:
/// the scan then runs on to the next `'` within the bound, and the span it
/// lands on starts with `\`, so [`is_char_literal_body`] accepts it. Measured on
/// compiling Rust containing no delimiter char literal at all:
///
/// ```ignore
/// if c == '\\' { p('n'); }          // refused
/// fn f() { g('\\', x); h('a'); }    // refused
/// ```
///
/// Loud rather than silent, and it can suppress nothing later — [`strip_comments`]
/// visits every `'` independently — but it is the exact failure this function's
/// own existence is justified by, one construct along: a lint that fails on
/// ordinary source is one people cannot keep green, and then it gets deleted.
/// The two rows above are in B5.
fn char_literal_hides_a_delimiter(chars: &[char], at: usize) -> bool {
    let end = (at + 13).min(chars.len());
    let mut escaped = false;
    for j in (at + 1)..end {
        if chars[j] == '\n' {
            return false;
        }
        if escaped {
            escaped = false;
        } else if chars[j] == '\\' {
            escaped = true;
        } else if chars[j] == '\'' {
            let body: String = chars[at + 1..j].iter().collect();
            if !is_char_literal_body(&body) {
                // Two lifetimes, not a literal. Widening from the quote to the
                // brackets made this reachable and the negative rows in
                // `a_char_literal_holding_a_quote_is_reported_in_every_spelling`
                // caught it: in `fn f<'a, 'b>(x: &'a str, …)` the `'b` closes on
                // the `'a` seven characters later, and the span between them
                // holds a `(`. Refusing that fails loudly on ordinary generic
                // source, which is how a lint people cannot keep green gets
                // deleted. A `"` between two lifetimes is a real string quote
                // and the stripper already tracks it, so nothing is lost.
                return false;
            }
            // The source characters are the whole question: these scanners read
            // text, so a delimiter only steers one if it is *written*. That is
            // why no escape needs decoding, and why B5's separate `\u{…}`
            // refusal is now subsumed rather than dropped — `\u{` cannot be
            // spelled without a brace, which is itself a delimiter. By the same
            // token `'\x29'` needs no clause: it is a legal spelling of `')'`
            // but contains no bracket, so it steers nothing.
            return body.contains(SCANNER_DELIMITERS);
        }
    }
    false
}

/// Is `body` — what sits between the two `'` — a char-literal body at all,
/// rather than the gap between two lifetimes?
///
/// One character, or an escape. Deliberately does not validate *which* escape —
/// an invalid one does not compile, so these files cannot contain it, and the
/// caller rules on the escape's written characters rather than on what it
/// denotes.
fn is_char_literal_body(body: &str) -> bool {
    let mut cs = body.chars();
    match cs.next() {
        Some('\\') => true,
        Some(_) => cs.next().is_none(),
        None => false,
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn skip_ws(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    i
}

/// Every scanned invocation in `text`, as (1-based line, label, body).
///
/// # The delimiter and the spacing are matched, not assumed
///
/// The needle used to be a literal string ending in `(`, which required the
/// paren to be the character immediately after the `!`. All three of these
/// compile, are legal, and slipped past that in silence — and **`rustfmt`
/// normalises none of them**, verified with `--emit stdout`, so a fmt-clean tree
/// does not close the hole and the brace form in particular survives a hand edit
/// unremarked:
///
/// ```ignore
/// tracing::error!{ … };      // brace-delimited
/// tracing::error !( … );     // space between `!` and `(`
/// tracing::error!
///     ( … );                 // newline between `!` and `(`
/// ```
///
/// So a macro is matched as *name*, optional whitespace, `!`, optional
/// whitespace, then any of `(` / `{` / `[`, and the body runs to the matching
/// closer of whichever one it found. A call is *name*, optional whitespace, `(`.
///
/// Strings are skipped while matching the delimiter, so a `(` inside a message
/// cannot end the scan early, and nesting is counted, so a `format!(…)` argument
/// stays inside the body rather than truncating it.
///
/// **It is string-aware but NOT char-literal-aware, and that is delegated, not
/// overlooked.** A closer inside a char literal — `session.table = %')'` — would
/// end the body two lines before a `%sid`, which is a silent blind of exactly
/// the kind [`strip_comments`] refuses to have. The guard is `strip_comments`'
/// char-literal refusal, which runs first and covers all four scanners rather
/// than each of them re-deriving it; see its second section for the
/// measurement. Do not make this loop char-literal-aware and drop that refusal —
/// [`arg_ranges`], [`field_value_split`] and [`raw_identifiers`] count the same
/// brackets and would each still be blind.
fn invocations(text: &str) -> Vec<(usize, String, String)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();

    for needle in INVOCATIONS {
        let pat: Vec<char> = needle.name.chars().collect();
        let mut at = 0usize;
        while at + pat.len() <= chars.len() {
            if chars[at..at + pat.len()] != pat[..] {
                at += 1;
                continue;
            }
            // A whole word, not the tail or head of a longer identifier —
            // `my_error!` and `with_context(` must not match `error` / `context`.
            let is_boundary = at
                .checked_sub(1)
                .map(|i| !is_word(chars[i]))
                .unwrap_or(true)
                && chars
                    .get(at + pat.len())
                    .map(|c| !is_word(*c))
                    .unwrap_or(true);
            if !is_boundary {
                at += 1;
                continue;
            }

            let mut i = at + pat.len();
            match needle.kind {
                Kind::Macro => {
                    // A macro may be path-qualified (`tracing::error!`) but is
                    // never a method (`x.error!`).
                    let mut p = at;
                    while p > 0 && chars[p - 1].is_whitespace() {
                        p -= 1;
                    }
                    if p > 0 && chars[p - 1] == '.' {
                        at += 1;
                        continue;
                    }
                    i = skip_ws(&chars, i);
                    if chars.get(i) != Some(&'!') {
                        at += 1;
                        continue;
                    }
                    i = skip_ws(&chars, i + 1);
                }
                Kind::Call => {
                    i = skip_ws(&chars, i);
                }
            }

            let (open_c, close_c) = match chars.get(i) {
                Some('(') => ('(', ')'),
                Some('{') if matches!(needle.kind, Kind::Macro) => ('{', '}'),
                Some('[') if matches!(needle.kind, Kind::Macro) => ('[', ']'),
                _ => {
                    at += 1;
                    continue;
                }
            };

            let body_start = i + 1;
            let line = chars[..body_start].iter().filter(|c| **c == '\n').count() + 1;

            let mut depth = 1usize;
            let mut j = body_start;
            let mut in_str = false;
            let mut escaped = false;
            while j < chars.len() && depth > 0 {
                let c = chars[j];
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == open_c {
                    depth += 1;
                } else if c == close_c {
                    depth -= 1;
                }
                j += 1;
            }
            let body: String = chars[body_start..j.saturating_sub(1)].iter().collect();
            out.push((line, needle.label(), body));
            at = body_start;
        }
    }
    out.sort_by_key(|(line, _, _)| *line);
    out
}

/// Split a body into its top-level, comma-separated arguments, as char ranges.
///
/// Depth-aware and string-aware, so the `,` inside `format!(a, b)` or inside a
/// message does not split an argument in two.
fn arg_ranges(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &c) in chars.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '(' || c == '[' || c == '{' {
            depth += 1;
        } else if c == ')' || c == ']' || c == '}' {
            depth -= 1;
        } else if c == ',' && depth == 0 {
            out.push((start, i));
            start = i + 1;
        }
    }
    out.push((start, chars.len()));
    out
}

/// The index of the `=` that separates a `tracing` field name from its value,
/// if this argument has one.
///
/// Top level only (`|| format!("a={b}")` is one value expression, not a field),
/// and never a comparison or a fat arrow — `==`, `!=`, `<=`, `>=`, `=>`.
fn field_value_split(chars: &[char]) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for i in 0..chars.len() {
        let c = chars[i];
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '(' || c == '[' || c == '{' {
            depth += 1;
        } else if c == ')' || c == ']' || c == '}' {
            depth -= 1;
        } else if c == '=' && depth == 0 {
            let prev = i.checked_sub(1).map(|j| chars[j]);
            let next = chars.get(i + 1).copied();
            if matches!(prev, Some('=' | '!' | '<' | '>')) || matches!(next, Some('=' | '>')) {
                continue;
            }
            return Some(i);
        }
    }
    None
}

/// Every identifier an invocation body references, tagged with the [`Position`]
/// it appeared in, in source order.
///
/// Two lexical positions inside each span, and both matter. Outside a string
/// literal, ordinary code identifiers. Inside one, `tracing`'s **inline format
/// captures** — `{e:#}` names `e` just as surely as `%e` does, and a lint that
/// read only code positions would be blind to the one interpolation shape both
/// modules already use. An inline capture is always [`Position::Value`]: it
/// names a binding whose *value* is rendered.
///
/// An argument with no top-level `=` — a positional argument, or the message
/// itself — is all value. That is the strict reading and it is the right one:
/// `error!(sid)` is `tracing`'s field shorthand, where the name and the value
/// are the same binding.
fn identifiers(body: &str) -> Vec<(Position, String)> {
    let chars: Vec<char> = body.chars().collect();
    let mut out = Vec::new();
    for (s, e) in arg_ranges(&chars) {
        let arg = &chars[s..e];
        match field_value_split(arg) {
            Some(k) => {
                for n in raw_identifiers(&arg[..k]) {
                    out.push((Position::Field, n));
                }
                for n in raw_identifiers(&arg[k + 1..]) {
                    out.push((Position::Value, n));
                }
            }
            None => {
                for n in raw_identifiers(arg) {
                    out.push((Position::Value, n));
                }
            }
        }
    }
    out
}

/// The identifier lexer: code identifiers, plus inline format captures inside
/// string literals. Positional (`{}`, `{0}`) and escaped (`{{`) braces are not
/// names and are skipped, as are numeric literals and their suffixes.
fn raw_identifiers(chars: &[char]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut in_str = false;
    let mut escaped = false;

    while i < chars.len() {
        let c = chars[i];
        if in_str {
            if escaped {
                escaped = false;
                i += 1;
            } else if c == '\\' {
                escaped = true;
                i += 1;
            } else if c == '"' {
                in_str = false;
                i += 1;
            } else if c == '{' {
                if chars.get(i + 1) == Some(&'{') {
                    i += 2; // `{{` is a literal brace
                    continue;
                }
                // `{name}` / `{name:spec}` / `{}` / `{0}`
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != '}' && chars[j] != ':' {
                    j += 1;
                }
                let name: String = chars[start..j].iter().collect();
                let name = name.trim().to_string();
                if !name.is_empty()
                    && name.chars().all(is_word)
                    && !name.starts_with(|c: char| c.is_ascii_digit())
                {
                    out.push(name);
                }
                i = start;
            } else {
                i += 1;
            }
        } else if c == '"' {
            in_str = true;
            i += 1;
        } else if is_word(c) && !c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && is_word(chars[i]) {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if c.is_ascii_digit() {
            // A numeric literal (and any suffix) is not an identifier.
            while i < chars.len() && is_word(chars[i]) {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn no_tracing_or_anyhow_line_in_either_session_store_names_an_unsanctioned_binding() {
    let mut offences: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for file in STORES {
        let source = strip_comments(file.text);

        // A construct the stripper refuses to guess at. Loud, because the
        // alternative is a scanner that reads less of the file than it thinks.
        assert!(
            source.unsupported.is_empty(),
            "{} contains a construct the scanner deliberately does not handle, so it can no \
             longer claim to have read the whole file: {:?}\nEither rewrite it (a `//` comment \
             instead of `/* */`) or extend `strip_comments` — do not leave it, and do not delete \
             this assertion.",
            file.path,
            source.unsupported
        );

        let found = invocations(&source.text);

        // A **liveness** check on the scanner, and nothing more. If the paren
        // matching or a macro spelling ever stops finding anything at all, the
        // test would pass vacuously — the failure mode a source lint is most
        // prone to.
        //
        // **Per file, never summed.** A total across `STORES` cannot see one
        // file go dark: postgres alone contributes six invocations, so a redis
        // scan that silently found nothing would still leave a healthy-looking
        // total. That matters concretely, because postgres' `malformed payload`
        // site is one this lint is the *only* oracle for.
        //
        // Deliberately not a count, either. The assertion it replaced was
        // `>= 5`, which gave a confidently wrong diagnosis when it tripped: it
        // reported "the scanner is broken, not the source" for what is far more
        // often a site being legitimately removed, and it only had any bite on
        // postgres by the accident of that file having exactly five sites. A
        // number nobody owns doubles as an unowned tripwire for a spelling
        // change, and this test should not carry a control it cannot diagnose.
        assert!(
            !found.is_empty(),
            "no tracing or anyhow invocation matched in {} — the scanner is not seeing this file",
            file.path
        );
        scanned += found.len();

        for (line, label, body) in found {
            // One offence per distinct name per position per site:
            // `session.id = %id` names `id` twice and is one mistake, not two.
            let mut reported: Vec<(Position, String)> = Vec::new();
            for (pos, ident) in identifiers(&body) {
                let allowed = match pos {
                    Position::Field => ALLOWED_FIELD_IDENTS.contains(&ident.as_str()),
                    Position::Value => ALLOWED_VALUE_IDENTS.contains(&ident.as_str()),
                };
                if KEYWORDS.contains(&ident.as_str())
                    || allowed
                    || reported.contains(&(pos, ident.clone()))
                {
                    continue;
                }
                reported.push((pos, ident.clone()));
                let list = match pos {
                    Position::Field => "ALLOWED_FIELD_IDENTS",
                    Position::Value => "ALLOWED_VALUE_IDENTS",
                };
                offences.push(format!(
                    "{}:{line} `{label}` names `{ident}` in {pos:?} position, which is not in \
                     {list}: {}",
                    file.path,
                    body.trim().replace('\n', " ")
                ));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "the session id must never enter a formatted log line, and only sanctioned identifiers \
         may be named where one is built — {} offence(s) across {scanned} invocations:\n{}\n\n\
         If the name really cannot carry a session id, add it to the list named above *with the \
         reason*. Do not widen a list to make this green, and do NOT delete this test: it is the \
         ONLY oracle for 3 of the 10 sid-bearing sites in these two modules (both `serialize \
         failed` branches and postgres' `malformed payload`), none of which any behavioural test \
         can reach offline.",
        offences.len(),
        offences.join("\n")
    );
}

/// The scanner's own mechanism, tested directly.
///
/// **Not decoration.** This lint's entire value is in what it *rejects*, and its
/// characteristic failure is going blind — matching nothing and passing
/// vacuously. The liveness assertion above catches only the total blindness of a
/// whole file; these catch the partial kind, where one spelling stops being seen
/// while the rest still are. That is precisely how the deny-list it replaced let
/// a bare `error!(` through on redis for a release, and how the allow-list that
/// replaced *it* let `event!`, `error!{…}` and `format_err!` through for one.
mod scanner {
    use super::{identifiers, invocations, strip_comments, Position};

    fn bodies(src: &str) -> Vec<String> {
        let stripped = strip_comments(src);
        assert!(
            stripped.unsupported.is_empty(),
            "{:?}",
            stripped.unsupported
        );
        invocations(&stripped.text)
            .into_iter()
            .map(|(_, _, body)| body.trim().to_string())
            .collect()
    }

    /// `(position, name)` pairs, as short strings, for readable assertions.
    fn idents(body: &str) -> Vec<String> {
        identifiers(body)
            .into_iter()
            .map(|(p, n)| {
                format!(
                    "{}:{n}",
                    match p {
                        Position::Field => "field",
                        Position::Value => "value",
                    }
                )
            })
            .collect()
    }

    #[test]
    fn a_macro_is_matched_bare_and_qualified_but_not_as_a_method() {
        assert_eq!(bodies(r#"tracing::error!("a");"#), vec![r#""a""#]);
        // Evasion M4: `use tracing::error;` then the bare spelling.
        assert_eq!(bodies(r#"error!("b");"#), vec![r#""b""#]);
        // Not the tail of a longer name, and not a method call.
        assert!(bodies(r#"my_error!("c"); x.error!("d");"#).is_empty());
    }

    /// **B1.** `event!` is the macro the other five expand to, and it is public.
    /// Omitting it left a complete credential disclosure green at the one site
    /// this lint is the only oracle for. The span family is here for the same
    /// reason one step removed — a span attribute is published like a field.
    #[test]
    fn the_event_macro_and_the_span_family_are_matched() {
        assert_eq!(
            bodies(r#"tracing::event!(tracing::Level::ERROR, session.correlator = %id, "x");"#),
            vec![r#"tracing::Level::ERROR, session.correlator = %id, "x""#]
        );
        for m in [
            "span",
            "error_span",
            "warn_span",
            "info_span",
            "debug_span",
            "trace_span",
        ] {
            assert_eq!(
                bodies(&format!(r#"tracing::{m}!(sid = %sid);"#)),
                vec!["sid = %sid"],
                "{m}! is not matched"
            );
        }
        // The two ways a field reaches a span after it was opened.
        assert_eq!(
            bodies(r#"span.record("session.id", &sid);"#),
            vec![r#""session.id", &sid"#]
        );
        assert_eq!(
            bodies(r#"#[tracing::instrument(fields(session.id = %sid))]"#),
            vec!["fields(session.id = %sid)"]
        );
    }

    /// **B2.** The delimiter and the spacing around it are matched, not assumed.
    /// All three of these compile and `rustfmt` normalises none of them, so a
    /// needle ending in a literal `(` was one hand edit from being bypassed.
    #[test]
    fn a_macro_is_matched_whatever_delimiter_and_spacing_it_uses() {
        assert_eq!(bodies(r#"tracing::error!{ "a" };"#), vec![r#""a""#]);
        assert_eq!(bodies(r#"tracing::error![ "b" ];"#), vec![r#""b""#]);
        assert_eq!(bodies(r#"tracing::error !( "c" );"#), vec![r#""c""#]);
        assert_eq!(bodies("tracing::error!\n( \"d\" );"), vec![r#""d""#]);
        // A brace body counts braces, not parens: a `(` inside must not confuse
        // it, and a `}` inside a string must not close it early.
        assert_eq!(
            bodies(r#"error!{ error.message = f(a), "b } c" };"#),
            vec![r#"error.message = f(a), "b } c""#]
        );
        // `!` that is not a macro bang: `error != x` must not match.
        assert!(bodies(r#"if error != x { y(); }"#).is_empty());
    }

    /// **B4.** `format_err!` is `pub use anyhow as format_err;`, and the UFCS
    /// spelling of `.context(` carries no leading dot. Both compiled green
    /// against the previous needles.
    #[test]
    fn the_anyhow_surface_is_matched_and_with_context_is_not_double_counted() {
        assert_eq!(bodies(r#"anyhow::bail!("a");"#), vec![r#""a""#]);
        assert_eq!(bodies(r#"anyhow::ensure!(ok, "b");"#), vec![r#"ok, "b""#]);
        assert_eq!(bodies(r#"x.context("c")?;"#), vec![r#""c""#]);
        // `.with_context(` must match once, as itself — `context` does not match
        // inside it, because the char before it is `_`.
        assert_eq!(bodies(r#"x.with_context(|| "d")?;"#), vec![r#"|| "d""#]);
        // The alias, and the UFCS spelling.
        assert_eq!(bodies(r#"anyhow::format_err!("e");"#), vec![r#""e""#]);
        assert_eq!(bodies(r#"Context::context(x, "f")?;"#), vec![r#"x, "f""#]);
    }

    #[test]
    fn a_body_survives_nested_parens_and_a_paren_inside_a_message() {
        assert_eq!(
            bodies(r#"error!("a) b", f(g(h)));"#),
            vec![r#""a) b", f(g(h))"#]
        );
    }

    #[test]
    fn a_comment_is_not_scanned_but_line_numbers_survive_it() {
        let src = "// error!(\"{sid}\")\n//\nerror!(\"real\");\n";
        let stripped = strip_comments(src);
        assert!(stripped.unsupported.is_empty());
        let found = invocations(&stripped.text);
        assert_eq!(found.len(), 1, "found {found:?}");
        assert_eq!(found[0].0, 3, "the comment must not shift the line number");
    }

    /// The **blinding** cases: a stripper that scans forward for a terminator
    /// it has mis-identified swallows the rest of the file, and a real offence
    /// inside the swallowed span is then reported clean. That failure is silent,
    /// which is what makes it worse than a false positive.
    #[test]
    fn a_comment_marker_inside_a_string_literal_cannot_blind_the_scanner() {
        // The sibling-review case: an unbalanced `/*` inside an ordinary string
        // literal. It must not open a comment, so the leak below is still seen.
        let src = "let banner = \"/* not a comment\";\nerror!(\"{sid}\");\n";
        assert_eq!(bodies(src), vec![r#""{sid}""#]);

        // The mirror, and the one this scanner is line-oriented to survive: a
        // `//` inside a string literal must not blank the rest of the line.
        // `web_login_redis.rs` has twenty of these (`redis://…`).
        let src = "error!(\"dial redis://{sid}\");\n";
        assert_eq!(bodies(src), vec![r#""dial redis://{sid}""#]);
        assert_eq!(idents(r#""dial redis://{sid}""#), vec!["value:sid"]);

        // And a quote inside a `//` comment must not open a phantom string that
        // runs on and swallows the next line's invocation.
        let src = "// he said \"hello\nerror!(\"{sid}\");\n";
        assert_eq!(bodies(src), vec![r#""{sid}""#]);
    }

    /// A construct the stripper refuses is *reported*, never skipped. Fail loud
    /// beats handle-approximately: both of these could otherwise scan forward
    /// past their intended end and take a real offence with them.
    #[test]
    fn a_construct_the_stripper_will_not_guess_at_is_reported_rather_than_swallowed() {
        let block = strip_comments("let a = 1;\n/* error!(\"{sid}\")\n");
        assert_eq!(block.unsupported, vec![(2, "/* … */ block comment")]);

        // A multi-line string literal is the one span it *does* cross a newline
        // for, and it must not be mistaken for either refused construct.
        let multi = strip_comments("let s = \"a \\\n     b\";\nerror!(\"{sid}\");\n");
        assert!(multi.unsupported.is_empty());
        assert_eq!(
            invocations(&multi.text)
                .into_iter()
                .map(|(_, _, b)| b)
                .collect::<Vec<_>>(),
            vec![r#""{sid}""#]
        );
    }

    /// **B5.** The quote-char-literal refusal used to match three literal
    /// characters, so the escaped spelling `'\"'` walked straight past it and
    /// opened exactly the phantom string the refusal exists to prevent.
    #[test]
    fn a_char_literal_holding_a_quote_is_reported_in_every_spelling() {
        for src in [
            "let q = '\"';\n",
            "let q = '\\\"';\n",
            "let q = b'\"';\n",
            "let q = b'\\\"';\n",
            "let q = '\\u{22}';\n",
        ] {
            assert_eq!(
                strip_comments(src).unsupported,
                vec![(1, "char literal holding a quote or a delimiter")],
                "not reported: {src:?}"
            );
        }
        // Ordinary char literals and lifetimes are not refused, or every file
        // with a `&'static str` in it would fail loudly for no reason. The last
        // three are the only char literals on today's tree —
        // `web_login_redis.rs:82,88` and `web_login_postgres.rs:170` — so a
        // widening that caught them would be red on the real files, not here.
        for src in [
            "let c = 'a';\n",
            "let c = '\\'';\n",
            "let c = '\\\\';\n",
            "let c = '\\n';\n",
            "fn f<'a, 'b>(x: &'a str, y: &'b str) -> &'static str { \"z\" }\n",
            "let c = '/';\n",
            "let c = '@';\n",
            "let c = b'_';\n",
            // `'\\'` with something after it on the same line. The row above
            // passes for the wrong reason — nothing follows it, so the runaway
            // scan finds no second `'` inside the bound. Reading the *closing*
            // quote as escaped (`chars[j - 1] != '\\'`) ran on to the next `'`
            // in the line and refused ordinary source holding no delimiter char
            // literal at all. Loud, not silent, but a lint that fails on source
            // like this is one people cannot keep green.
            "if c == '\\\\' { p('n'); }\n",
            "fn f() { g('\\\\', x); h('a'); }\n",
        ] {
            assert!(
                strip_comments(src).unsupported.is_empty(),
                "falsely refused: {src:?}"
            );
        }
    }

    /// **B6.** The half B5 left open. B5 refused a char literal holding a
    /// **quote**, which is the hazard for `strip_comments`. A char literal
    /// holding one of the six **bracket** characters is the hazard for
    /// [`invocations`], which counts them to find the end of a body — and that
    /// half was neither refused nor handled.
    ///
    /// At the postgres `malformed payload` site, `session.table = %')'` ended
    /// the scanned body at `session.table = %'`, so a `session.correlator = %sid`
    /// two lines later was never read. Measured: 13/13 green, `unsupported`
    /// empty, and the same shape at the reachable redis site renders
    /// `session.table=) session.correlator=a7f3c1d9-4e62-4b8a-9d15-c0ffee5ed17e`
    /// — the whole seeded sid.
    ///
    /// **Which row evades depends on the invocation's own delimiter, and the
    /// table below is about the scanned BODY, not about the verdict.** Only a
    /// char literal holding the *matching* closer truncates: at the real,
    /// paren-delimited postgres site `')'` is green and `'}'` / `']'` are red,
    /// because a brace does not close a paren. `'}'` is a live evasion against
    /// the brace spelling `tracing::error! { … }`, which B2 established compiles
    /// and survives `rustfmt` — measured green at cfc0b33 in exactly that
    /// combination, and refused now. And `b')'` truncates identically but is
    /// caught incidentally, on the stray `b` the byte prefix leaves in Value
    /// position — red for a reason that names neither `correlator` nor `sid`,
    /// which is a diagnosis nobody should be asked to rely on. Refusing all
    /// seven removes the need to reason about any of this.
    ///
    /// Each row asserts twice, and the second assertion is the one that
    /// outlives this implementation. The first pins the mechanism actually
    /// chosen — a loud refusal. The second states the *property*: whatever the
    /// scanner does with such a source, the offending name must not fall
    /// outside the body it reads. A future scanner that lexes char literals
    /// properly instead of refusing them satisfies the second and is free to
    /// drop the first.
    ///
    /// **The property half discriminates on four of these seven rows, not on
    /// seven**, and the claim is narrowed to that rather than restructured,
    /// because for the other three it is genuinely satisfied without any
    /// refusal — which is a fact about the input and not a weakness in the
    /// test. Measured at `cfc0b33` with the refusal assertion removed: the
    /// three closers and `b')'` failed on "the leak fell outside the body"; the
    /// three **openers** passed, because over-running is the safe direction and
    /// the leak stays inside the (too large) body. Those three are here for the
    /// *diagnosis* argument two paragraphs up — one message instead of a
    /// cascade of unrelated names — and it is the refusal assertion that
    /// carries them. Read "the property half was checked alone" as a statement
    /// about the test, not about every row in it.
    #[test]
    fn a_char_literal_holding_a_delimiter_cannot_truncate_a_scanned_body() {
        for src in [
            // The three closers, one per body delimiter, each truncating.
            r#"error!(a = %')', leak = %sid, "m");"#,
            "error!{ a = %'}', leak = %sid, \"m\" }",
            r#"error![ a = %']', leak = %sid, "m" ];"#,
            // The byte spelling: the `b` sits before the `'` and is ignored.
            r#"error!(a = %b')', leak = %sid, "m");"#,
            // The three openers. These over-run rather than truncate, which is
            // the safe direction — but the body then swallows unrelated source
            // and fails on names that are not the offence, so they are refused
            // for the same reason and diagnosed by the same message.
            r#"error!(a = %'(', leak = %sid, "m");"#,
            r#"error!(a = %'{', leak = %sid, "m");"#,
            r#"error!(a = %'[', leak = %sid, "m");"#,
        ] {
            let stripped = strip_comments(src);
            assert_eq!(
                stripped.unsupported,
                vec![(1, "char literal holding a quote or a delimiter")],
                "not refused: {src:?}"
            );
            assert!(
                !stripped.unsupported.is_empty()
                    || invocations(&stripped.text)
                        .iter()
                        .any(|(_, _, body)| body.contains("leak")),
                "scanned past a char literal in silence, and the leak fell outside \
                 the body: {src:?}"
            );
        }
    }

    /// **B7.** The third literal form, and — see [`strip_comments`]' closing
    /// section — the last one there is.
    ///
    /// [`strip_comments`]' `in_string`/`escaped` pair is the state machine for
    /// an *ordinary* string literal, and a raw string obeys neither of its
    /// rules. **Two independent ways to desynchronise it, and there is a row
    /// for each**, because an auditor who knows only the first would grep for a
    /// trailing `\` and conclude the file was safe:
    ///
    /// * a `\` before the closing quote — `r"C:\"` — which the machine reads as
    ///   an escaped quote, so the string never ends;
    /// * an **odd number of inner `"`** — `r#"the " character"#` — which needs
    ///   no backslash at all, and inner quotes are the entire reason anyone
    ///   reaches for the `#` form.
    ///
    /// Both were measured green at `16bd876` against a real leak inserted at
    /// redis' `remove`, the one method this repo's `CLAUDE.md` standingly tells
    /// a bumper to check.
    ///
    /// The third row is the **control** for the second mechanism: an *even*
    /// number of inner quotes re-synchronises, and the leak is then caught. It
    /// is the measurement that shows the trigger is the parity, not the `#`.
    ///
    /// Each row asserts twice, as B6 does, and the second assertion here
    /// discriminates on **five of the six rows** — every one but the control,
    /// where the scanner happens to stay in step. Measured with the refusal
    /// assertion removed: five failed on "the leak fell outside the body", the
    /// control passed.
    #[test]
    fn a_raw_string_literal_is_reported_rather_than_desynchronising_the_scanner() {
        for src in [
            // Trigger 1: the trailing `\`. The `"` closing `r"C:\"` is read as
            // escaped, so the next real `"` closes the phantom string instead
            // and `redis://x` is left as *code* — whose `//` then blanks the
            // rest of the line, leak and all.
            r#"let a = r"C:\";
let b = "redis://x"; error!(leak = %sid, "m");
"#,
            // Trigger 2: an odd number of inner `"`, no backslash anywhere.
            r##"let d = r#"the " character is not legal in a key"#;
let b = "redis://x"; error!(leak = %sid, "m");
"##,
            // The control for trigger 2: two inner quotes put the machine back
            // in step, and the leak is seen. The trigger is the parity.
            r##"let d = r#"a " b " c"#;
let b = "redis://x"; error!(leak = %sid, "m");
"##,
            // The byte and C prefixes sit before the `r` and are ignored, the
            // same way `b'"'`'s prefix is in B5.
            r#"let a = br"C:\";
let b = "redis://x"; error!(leak = %sid, "m");
"#,
            r#"let a = cr"C:\";
let b = "redis://x"; error!(leak = %sid, "m");
"#,
            // Any number of hashes, which is what makes the prefix a scan for
            // `r` `#`* `"` rather than a match on two fixed spellings. Spelled
            // with the content that makes a second `#` necessary in the first
            // place — an embedded `"#` — which is also an odd inner quote, so
            // the row carries the property oracle and not only the mechanism
            // one. `r##"x"##` was the first spelling here and does not: its
            // quotes balance, so the scanner stays in step and the leak is
            // seen. Measured, which is how that was found rather than assumed.
            r###"let a = r##"contains a "# sequence"##;
let b = "redis://x"; error!(leak = %sid, "m");
"###,
        ] {
            let stripped = strip_comments(src);
            assert_eq!(
                stripped.unsupported,
                vec![(1, "raw string literal")],
                "not refused: {src:?}"
            );
            assert!(
                !stripped.unsupported.is_empty()
                    || invocations(&stripped.text)
                        .iter()
                        .any(|(_, _, body)| body.contains("leak")),
                "scanned past a raw string in silence, and the leak fell outside \
                 the body: {src:?}"
            );
        }

        // Ordinary source that merely *contains* the two-character sequence is
        // not refused, or the lint fails loudly on the tree it guards.
        for src in [
            // `r"` inside a string literal. This is a real line —
            // `web_login_redis.rs:374` — and it is why grepping the store files
            // for `r"` reports hits that are not raw strings.
            "let cfg = C { master_name: \"mymaster\".into() };\n",
            // A raw *identifier*. `r#` followed by an identifier character is
            // not a raw string, and it cannot hide a delimiter: `r#` + ident is
            // all it can ever be. Refusing it would be a false red on legal
            // source for no gain, which is why the prefix scan requires the
            // quote rather than stopping at `r#`.
            "let r#type = 1; f(r#match);\n",
            // A lifetime named `r`, and a char literal holding one.
            "fn g<'r>(x: &'r str) -> &'r str { x }\n",
            "let c = 'r';\n",
        ] {
            assert!(
                strip_comments(src).unsupported.is_empty(),
                "falsely refused: {src:?}"
            );
        }
    }

    #[test]
    fn an_inline_format_capture_is_an_identifier_and_a_positional_one_is_not() {
        assert_eq!(idents(r#""{e:#}""#), vec!["value:e"]);
        assert_eq!(idents(r#""{name:?}""#), vec!["value:name"]);
        assert!(idents(r#""{} {0} {{sid}}""#).is_empty());
        // The shape the whole ticket is about: a renamed binding, in either
        // position, is still a name the allow-list gets to rule on.
        assert_eq!(
            idents(r#"correlator = %id, "x""#),
            ["field:correlator", "value:id"]
        );
        assert_eq!(idents(r#""load failed for {id}""#), vec!["value:id"]);
    }

    /// **B3.** A name is ruled on in the position it was reviewed in. `message`
    /// is sanctioned as a component of the field `error.message` and is *not*
    /// sanctioned as a binding — which is the whole difference between the two
    /// lists, and the difference a flat list could not express.
    #[test]
    fn an_identifier_is_ruled_on_in_the_position_it_appears_in() {
        assert_eq!(
            idents(r#"error.message = message.as_str()"#),
            [
                "field:error",
                "field:message",
                "value:message",
                "value:as_str"
            ]
        );
        // A positional argument, and the message itself, are all value.
        assert_eq!(idents(r#"ok, "b {sid}""#), ["value:ok", "value:sid"]);
        // A top-level `=` splits; one inside a nested call or a closure does not.
        assert_eq!(
            idents(r#"|| format!("a={b}", c = d)"#),
            ["value:format", "value:b", "value:c", "value:d"]
        );
        // A comparison is not a field split.
        assert_eq!(idents(r#"a == b"#), ["value:a", "value:b"]);
        assert_eq!(idents(r#"a != b"#), ["value:a", "value:b"]);
        assert_eq!(idents(r#"|x| x => y"#), ["value:x", "value:x", "value:y"]);
    }

    #[test]
    fn a_dotted_field_name_is_checked_component_by_component() {
        // This is what makes `self` safe to exempt as a keyword: the field it
        // reaches for is still ruled on.
        assert_eq!(
            idents(r#"session.table = %self.sql_load"#),
            [
                "field:session",
                "field:table",
                "value:self",
                "value:sql_load"
            ]
        );
    }
}
