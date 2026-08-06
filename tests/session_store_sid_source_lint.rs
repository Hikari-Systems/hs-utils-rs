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
//! cost in list edits, because it costs none. Five of the eleven value-position
//! names are ordinary binding names: `e`, `url`, `hosts`, `name`, `table`. Write
//! `let e = format!("{sid}");` above one of these sites and the lint passes. What
//! the position split bought is that the *field-name* components — `session`,
//! `store`, `op`, `error`, `message` — are no longer usable that way, and
//! `message` was the one an actual reviewer reached for first.
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
/// The two constructs that *could* run away are refused, loudly, instead of
/// being handled approximately:
///
/// * **`/* … */` block comments.** Scanning for `*/` is the unbounded-swallow
///   shape above, and Rust nests them, so the naive version stops early and the
///   careful version is a parser. Neither module has one.
/// * **A char literal holding a quote.** It would open a phantom string running
///   to the next `"` anywhere in the file. Handling it properly means telling `'`
///   apart from a lifetime (`'a`, `'static`), which is again a parser.
///
/// Both are reported through [`Stripped::unsupported`] and fail the test with a
/// message saying what to do. **Fail loud beats handle-approximately**: if
/// either construct ever arrives in these files, someone is told, rather than
/// the lint quietly covering less than it claims.
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
                } else if c == '\'' && char_literal_hides_a_quote(&chars, i) {
                    unsupported.push((lineno, "char literal holding a quote"));
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

/// Does the `'` at `at` open a char literal that contains a `"`?
///
/// **Matching the three literal characters `'`, `"`, `'` is not enough, and that
/// was a demonstrated gap**: `'\"'` is the same character escaped, it compiles,
/// and it opened the very phantom string the refusal exists to prevent while
/// leaving the lint 9/9 green with nothing in `unsupported`. So the rule is
/// "a char literal whose body contains a quote", which covers both spellings,
/// the byte forms `b'"'` / `b'\"'` (the `b` sits before the `'` and is ignored),
/// and — because a `\u{…}` escape is refused wholesale rather than decoded —
/// `'\u{22}'` as well. Refusing every `\u{…}` char literal is the deliberate
/// over-approximation: decoding one is a parser, and neither module has one.
///
/// **Do not overstate it: this was a demonstrated gap in the refusal, not a
/// demonstrated silent blind.** Nobody got a leak through it. The phantom string
/// it opens makes the *stripper* stop reading comments, but `invocations` starts
/// each body scan with fresh string state, so the bodies are still read — and an
/// attempt to weaponise it ran the body away over the rest of the file and
/// failed loudly on unrelated names. It is fixed because a refusal that a one-
/// character escape walks past is not a refusal, not because a leak hid behind
/// it.
///
/// The lookahead is **bounded** (the longest char literal is `'\u{10FFFF}'`, and
/// a newline ends the search), so this cannot itself become the unbounded scan
/// it is guarding against. A lifetime — `'a`, `'static` — has no closing `'`
/// within the bound, or encloses no quote if a later lifetime supplies one.
fn char_literal_hides_a_quote(chars: &[char], at: usize) -> bool {
    let end = (at + 13).min(chars.len());
    for j in (at + 1)..end {
        if chars[j] == '\n' {
            return false;
        }
        if chars[j] == '\'' && chars[j - 1] != '\\' {
            let body: String = chars[at + 1..j].iter().collect();
            return body.contains('"') || body.contains("\\u{");
        }
    }
    false
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
                vec![(1, "char literal holding a quote")],
                "not reported: {src:?}"
            );
        }
        // Ordinary char literals and lifetimes are not refused, or every file
        // with a `&'static str` in it would fail loudly for no reason.
        for src in [
            "let c = 'a';\n",
            "let c = '\\'';\n",
            "let c = '\\\\';\n",
            "let c = '\\n';\n",
            "fn f<'a, 'b>(x: &'a str, y: &'b str) -> &'static str { \"z\" }\n",
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
