//! Every `tracing` and `anyhow` invocation in the web-login modules may only
//! reference identifiers on an **allow-list**, and only in the **position** each
//! one was reviewed in — and, since HIK-274, only in the **file** it was
//! reviewed in.
//!
//! # Which files, and why that is a property rather than a list (HIK-274)
//!
//! The scanned set is every web-login module under `src/`. It was the two stores
//! alone until HIK-274, and `src/web_login.rs` — which holds `gate`, `decide`
//! and `callback`, i.e. the code that *mints, rotates and destroys* the sid the
//! stores merely persist — was unscanned. Nothing leaked there; the defect was
//! that a leak would have been green everywhere.
//!
//! **Seven `warn!` sites arrived in that file while it was unscanned, and they
//! divide into two reasons rather than one.** Five are HIK-241's, in `callback`
//! and `decide`, and those genuinely do sit in functions where `sid`, `new_sid`
//! or `cookie_sid` are live bindings. **Two are HIK-272's, and the qualifier is
//! false for them**: both are in `safe_dest`, whose three parameters are the
//! destination, the site name and an optional user id, with no session id in
//! scope at all — as this file's own `reason` bullet says further down. What
//! those two carry is the raw caller-supplied redirect destination, which is a
//! real reason to scan the module and a *different* one. The earlier phrasing
//! put all seven under the sid qualifier and so contradicted that bullet.
//!
//! [`every_web_login_module_in_src_is_scanned`] asserts the set against a
//! recursive walk of `src/` at test time rather than against a list written
//! here, because the failure this lint exists to prevent is *silent
//! under-reporting* and a hand-maintained file list is exactly that failure with
//! a friendly face: add `src/web_login_mysql.rs` — or, the shape that actually
//! got past the first version of this, `src/web_login/gate.rs` — and every
//! assertion below stays green while covering less than it claims.
//!
//! **Two residuals in that walk, neither closed.** The match is
//! `starts_with`/`ends_with` on the path below `src/`, and it is
//! **case-sensitive**: a `Web_Login_Mysql.rs` created on a case-insensitive file
//! system (APFS, NTFS) is a legal module that this walk does not see. And the
//! walk roots at `env!("CARGO_MANIFEST_DIR")`, which is baked in at compile
//! time, so the test binary is **not relocatable** — `cargo nextest archive` and
//! run elsewhere would panic, or worse, read a different checkout's `src/` and
//! report on that. Both are invisible today because there is no CI running this
//! suite; they are recorded here so that whoever adds one does not have to
//! rediscover them.
//!
//! **`src/controller/` is a known frontier, and it is named because silence
//! about it reads as coverage.** `src/controller/graphql/context.rs` holds a
//! `pub session_id: Option<String>` — the raw unsigned credential — in a module
//! this glob does not reach and, until this paragraph, did not mention. Nothing
//! leaks there today. But `src/mcp_resource_server/db_session_store.rs` is named
//! below as a deliberate exclusion *with a reason*, and a reader who sees one
//! module called out by name will take the glob as complete coverage of
//! "everything that handles the sid". It is not: it is complete coverage of the
//! web-login modules, which is a smaller claim.
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
//! not bindings and cannot carry a value. The value list is what may appear
//! anywhere a value is computed: the right of an `=`, a positional argument, and
//! an inline format capture inside a message string. `message` is in the first
//! and **not** the second, so the shape above is now an offence.
//!
//! # The value list is PER FILE, and the field list is shared (HIK-274)
//!
//! The same argument, one axis over. A name reviewed as safe *in one file* was
//! never thereby reviewed in another: `dest` is sound in `src/web_login.rs`,
//! where it is a redirect destination, and would be an unreviewed binding in
//! `src/web_login_redis.rs`, where `sid` is a parameter name and `let dest =
//! sid;` is a one-line refactor. So the value list is a field on
//! [`SourceFile`], and adding `src/web_login.rs` sanctions its names **there**.
//!
//! **The size of the win is stated as a property and not as a number**, which is
//! this file's own standing rule about counts over sets that grow. A shared list
//! sanctions the union of every module's names in *every* module — so bringing
//! one file in scope silently widens the other two, and `src/web_login.rs` is by
//! far the longest list. The per-file split sanctions each name only in the file
//! whose review established it, and the difference grows with every module
//! added. (A numeral was drafted here. It was wrong by one, because a later edit
//! in this same ticket retired `is_some`, which is exactly how such a numeral
//! goes stale — and it would have needed re-deriving on every future list edit.)
//!
//! [`ALLOWED_FIELD_IDENTS`] stays shared, and that is a decision rather than an
//! omission: a component left of a top-level `=` is turned into a static string
//! by `tracing`'s macro grammar and cannot carry a value at all, so there is
//! nothing for a per-file review to be *about*.
//!
//! # A sanctioned name that is no longer named is DELETED, not left (HIK-274)
//!
//! [`no_web_login_module_carries_a_dead_value_list_entry`] asserts that every
//! name on a file's list is actually named by some scanned site in that file.
//! It exists because this file's own standing warning — "do not widen a list to
//! make a red build green" — was until then only prose, and prose does not fail.
//! With the assertion, pre-emptive widening is not discouraged, it is
//! **impossible**: a name added ahead of the site that would need it is a dead
//! entry and fails immediately.
//!
//! The cost is real and is accepted: delete a log line and you must delete its
//! list entry too. That is a loud failure with an accurate diagnosis, which is
//! the trade this file makes everywhere else.
//!
//! # What it cannot do
//!
//! **It does not follow data flow, so a name sanctioned in VALUE position can
//! still be rebound** — that is the residual, stated plainly rather than as a
//! cost in list edits, because it costs none. Write `let e = format!("{sid}");`
//! above one of these sites and the lint passes.
//!
//! **Every name on a value list is rebindable, not some readable
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
//! Closing the rest needs data flow, i.e. a real Rust parser over the scanned
//! modules, which is a different tool and its own ticket. It is also why the
//! behavioural arms are not deleted: a source scanner can show the source looks
//! right, never that the **rendered output** is clean.
//!
//! **Second residual, independent of the first and broader than it: the scan is
//! BY NAME, so a log statement reached through a macro or a helper that is not
//! on [`INVOCATIONS`] is not scanned at all.** A site spelled `my_log!(sid)` or
//! `report(sid)` matches no needle, so its body is never read and whatever the
//! callee does with the value is invisible — and only the `src/web_login*.rs`
//! files are `include_str!`d, so the callee's own `tracing::error!` is out of
//! scope even when it is in this crate. Unlike the rebinding residual, this is not
//! closable by a lexical rule at all: the name of the offending helper is not
//! knowable in advance, which is the whole difference between it and the
//! constructs [`strip_comments`] refuses.
//!
//! Not hypothetical in shape. `log_safe` is exactly such a helper — declared in
//! `src/web_login.rs`, named by sites in all three scanned files. It formats and
//! truncates and logs nothing, which is why it is sanctioned in every file's
//! value list.
//!
//! **HIK-274 narrowed this residual and did not close it, and the difference is
//! worth stating precisely** — the sentence replaced here said that `log_safe`
//! being safe "is a fact about `web_login.rs`, which this lint does not read",
//! and that clause became false the moment `web_login.rs` was added.
//!
//! What changed: `log_safe`'s *body* is now inside a scanned file, so a
//! `tracing` or `anyhow` site placed **inside** it is scanned, and its parameter
//! is on no list, so it is caught.
//!
//! What did not change, and is the whole of the residual now: `log_safe` could
//! stop **truncating** without this lint noticing a thing. Its body is a
//! `format!`, which is not on [`INVOCATIONS`], so nothing here reads it. And the
//! calls to it in the two stores are still *trusted* rather than checked —
//! `log_safe(x)` sanctions `x` by wrapping it, and no rule here verifies the
//! callee is that helper rather than a same-named local.
//!
//! **Do not close this by putting `format!` on [`INVOCATIONS`].** Measured: it
//! reds on `src/web_login.rs`'s `build_set_cookie`, whose cookie-assembly
//! `format!` legitimately and necessarily names the sid — that is the function's
//! entire job. A lint that fails on the one place the sid *must* be formatted is
//! one people cannot keep green, and then it gets deleted.
//!
//! # The standing tax a scanned `src/web_login.rs` levies (HIK-274)
//!
//! [`strip_comments`] refuses a raw string literal rather than lexing one, so
//! **any future `r"…"` / `r#"…"#` anywhere in `src/web_login.rs` re-reds this
//! lint** — including in its `#[cfg(test)]` module, which is the majority of
//! that file and where JSON fixtures are the natural thing to write. HIK-274
//! rewrote two such fixtures as escaped ordinary string literals to land.
//!
//! This is designed behaviour, not a defect: the refusal is loud and its message
//! says what to do, which is the whole reason it is a refusal rather than an
//! approximation. But it will recur, so it is written down rather than
//! rediscovered. The fix when it does is to escape the literal. Teaching the
//! stripper to lex raw strings is a **separate ticket with its own red test**,
//! and deliberately so: it adds surface to the one function whose characteristic
//! failure is silent blindness, and the obvious normalisation — blank the body —
//! would mint a new blind, because a raw string is a perfectly legal `tracing`
//! message.
//!
//! **What bounds it today is a grep, not an assertion.** Neither store defines
//! or pulls in a macro of its own — no `macro_rules!`, no `include!`, no
//! `#[macro_use]` — and the only macros either file invokes beyond the scanned
//! set are `format!`, `vec!` and, inside `#[cfg(test)]` modules, `assert!` /
//! `assert_eq!`. None of those reaches a log: `format!` builds a `String` that
//! some *scanned* invocation then has to name, and the `assert*!` ones publish
//! only a panic message, only from a test binary. Nothing re-runs that grep —
//! the same standing weakness the raw-string residual was closed to remove,
//! kept here because there is no lexical rule to replace it with.
//!
//! Deliberately scoped to the web-login modules. It is **not** extended to
//! `src/mcp_resource_server/db_session_store.rs`, which has the same shape but a
//! different trust claim and its own ticket: a test that is red for another
//! ticket's reason gets muted, and then it is red for nobody's. The walk **does**
//! descend into `src/mcp_resource_server/` and declines that file because its
//! path below `src/` does not begin `web_login` — one reason, and the only one.
//! An earlier revision offered non-recursion as a second, independent reason;
//! the walk recurses now, and that was never a reason so much as an accident of
//! how the set happened to be computed. Pinned by
//! [`the_module_walk_descends_into_submodules_and_still_excludes_by_name`],
//! which puts a deliberately `web_login`-named decoy in that directory.
//!
//! **`InMemorySessionStore` is now in scope**, having moved with the file it
//! lives in (`src/web_login.rs`). It contributes nothing: it implements the same
//! `WebSessionStore` trait and takes the same `sid`, but has no I/O and so no
//! error path, and nothing in it formats anything at any level. It is named here
//! because it was previously called out as a deliberate *exclusion*, and a
//! reader checking that claim would now find it false.

/// Source of a module, with the path it came from for the failure message and
/// the value-position names sanctioned **in that module**.
struct SourceFile {
    path: &'static str,
    text: &'static str,
    /// Every identifier this module may name where a value is computed. Per
    /// file since HIK-274 — see the module header for why a name reviewed in one
    /// file is not thereby reviewed in another, and
    /// [`no_web_login_module_carries_a_dead_value_list_entry`] for why an entry
    /// no site names any longer is deleted rather than left.
    allowed_value_idents: &'static [&'static str],
    /// Whether this module is **declared** to contain scanned invocations.
    ///
    /// The liveness check below is a guard against the scanner going dark on a
    /// file, which is the failure a source lint is most prone to. But once the
    /// file set became a property (HIK-274), a `src/web_login*.rs` with no
    /// logging in it became something a reader is *obliged* to add here — and an
    /// unconditional floor then reports "the scanner is not seeing this file"
    /// about a file in which there was nothing to see. That is a confidently
    /// wrong diagnosis, and it is the same defect this file already records
    /// against the `>= 5` floor the liveness check replaced. Measured: adding a
    /// two-line `src/web_login_types.rs` correctly reddens the file-set
    /// assertion, and complying by adding the row then reddens the main lint
    /// with a message blaming the scanner.
    ///
    /// So it is declared rather than inferred, and **checked in both
    /// directions**: a module declared silent that turns out to have sites fails
    /// too. Without that second arm this field would be a way to switch the lint
    /// off for a file by asserting something false about it.
    expects_logging_sites: bool,
}

/// Every module scanned, with its own value-position allow-list.
///
/// **The membership of this table is itself asserted**, against a recursive walk
/// of `src/` at test time — see [`every_web_login_module_in_src_is_scanned`].
/// Adding a web-login module and not adding it here is a failure, which is the
/// whole of HIK-274.
const SCANNED_MODULES: &[SourceFile] = &[
    SourceFile {
        path: "src/web_login.rs",
        text: include_str!("../src/web_login.rs"),
        allowed_value_idents: WEB_LOGIN_VALUE_IDENTS,
        expects_logging_sites: true,
    },
    SourceFile {
        path: "src/web_login_postgres.rs",
        text: include_str!("../src/web_login_postgres.rs"),
        allowed_value_idents: POSTGRES_VALUE_IDENTS,
        expects_logging_sites: true,
    },
    SourceFile {
        path: "src/web_login_redis.rs",
        text: include_str!("../src/web_login_redis.rs"),
        allowed_value_idents: REDIS_VALUE_IDENTS,
        expects_logging_sites: true,
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

/// Every identifier allowed to the **left** of an `=`: every component of a
/// sanctioned dotted `tracing` field name, plus `name`, which is
/// `#[tracing::instrument]`'s own attribute key.
///
/// These are field *names* in `tracing`'s macro grammar, not expressions: the
/// macro turns them into a static string. Nothing here can carry a value, which
/// is exactly why the list is separate from the per-file value lists — put them
/// in one list and `let message = format!("{sid}")` is sanctioned by the review
/// that approved the field `error.message`.
///
/// **Shared across every module, unlike the value lists, and that asymmetry is
/// deliberate** (HIK-274). A value name has to be reviewed per file because it
/// names a *binding*, and the binding behind one spelling differs between
/// files. A field component names nothing and can carry nothing, so there is no
/// per-file fact for a review to establish.
///
/// The `auth.*` / `user.*` / `session.*` families here arrived with
/// `src/web_login.rs`: `auth.gate.*`, `auth.login.*`, `auth.redirect.*`,
/// `user.id`, `session.op`, and `state`. They are the span and event field names
/// that the gate, the callback and the redirect guard publish.
const ALLOWED_FIELD_IDENTS: &[&str] = &[
    "auth",
    "dest",
    "error",
    "fail_fast",
    "gate",
    "id",
    "load_failed",
    "login",
    "message",
    "minted",
    "name",
    "op",
    "outcome",
    "present",
    "reason",
    "redirect",
    "refused",
    "session",
    "site",
    "state",
    "store",
    "table",
    "user",
];

/// The names common to every scanned module's value list.
///
/// Not a list in its own right — each module's const spells its own names out in
/// full, so that reading one tells you the whole of what that file may say. This
/// is documentation of the overlap, and the place the shared bullets live:
///
/// * `e` — the error being reported. Downstream-derived text, which is why every
///   site puts it through `log_safe`; it is not derived from the sid.
/// * `log_safe`, `to_string`, `as_str` — helper and method names, in callee
///   position.
///
/// `format` is deliberately **not** here, and its absence is the whole of the
/// correction described at the bottom of this comment: it is named at a scanned
/// site in `src/web_login.rs` and in `src/web_login_redis.rs`, and at none in
/// `src/web_login_postgres.rs`. Adding it to postgres' list to make the overlap
/// tidier would immediately fail
/// [`no_web_login_module_carries_a_dead_value_list_entry`], which is the right
/// outcome — the two assertions between them leave exactly one legal shape.
///
/// **The lists also keep the OAuth tokens off a log line — but incidentally,
/// by default-deny, and not by any rule stated anywhere.** `token`, `sess` and
/// `profile` are on no module's value list, so `%token.access_token`,
/// `%token.id_token` and `%sess.id_token` are all offences today. That is worth
/// writing down for one reason: it means a future ticket must not sanction
/// `token` or `sess` on the grounds that "this lint is about the session id".
/// The `id_token` in a `TokenResponse` is a bearer credential in its own right,
/// and it reaches a log line by exactly the route the sid would.
///
/// **The obligation on a new name is unchanged, and per-file scoping does not
/// soften it.** A site spelled `.context(format!("… {sid} …"))` names `sid` and
/// fails this test; so does any other new binding. When that happens the fix is
/// to add the *reviewed* name to *that file's* list, with a bullet saying why it
/// cannot carry the sid — not to widen a list until the build is green, which is
/// the same defeat by a friendlier route.
///
/// **HIK-241 was owed a line here and needed none** in the two stores. That
/// ticket made `WebSessionStore` fallible and put an `anyhow` context string on
/// every error branch in both — **thirteen** new `.context(` sites, five in
/// `web_login_postgres.rs` and eight in `web_login_redis.rs` — and added no
/// name, because every one of those strings is a compile-time literal with no
/// inline capture in it. Its five new `warn!` sites in `src/web_login.rs` are a
/// different matter and were unscanned until HIK-274; they are why that file's
/// list is the long one.
/// **This const is CHECKED, not decorative** — see
/// [`the_shared_value_idents_really_are_shared_by_every_module`]. It shipped
/// once as an `#[allow(dead_code)]` restatement and was **false on the day it
/// landed**: it listed `format`, which `POSTGRES_VALUE_IDENTS` does not contain
/// and never did, postgres' `format!` calls all sitting inside `sqlx::query(…)`
/// or plain `let` bindings, none of them on [`INVOCATIONS`]. Two reviewers found
/// that independently, forty lines after this file's own rule about
/// hand-maintained restatements of a derived set. The lesson is the one the
/// header already argues for the allow-lists themselves: prose does not fail,
/// assertions do.
const VALUE_IDENTS_SHARED_BY_EVERY_MODULE: &[&str] = &["as_str", "e", "log_safe", "to_string"];

/// `src/web_login.rs` — `gate`, `decide`, `callback`, `safe_dest`.
///
/// The long list, because this is where the protocol lives rather than the
/// persistence. **`sid`, `new_sid` and `cookie_sid` are the live session-id
/// bindings in this file and NONE of them is here** — that was checked name by
/// name when the file was brought in scope, and `cookie_sid` was the one that
/// failed: `span.record("auth.gate.session.present", cookie_sid.is_some())`
/// named it, so `decide` now binds the bool first and records
/// `session_present`. Sanctioning `cookie_sid` instead would have made a later
/// `%cookie_sid` green, which is not even the rebinding residual — it needs no
/// rebinding, only a sigil.
///
/// * `reason` — `origin_relative_dest`'s error, `&'static str`, one of exactly
///   five compile-time literals (`missing`, `control_character`, `unparseable`,
///   `not_origin_relative`, `escapes_root`). Named only in `safe_dest`, which
///   has no session id in scope at all: its three parameters are the
///   destination, the site name and an optional user id.
/// * `dest` — two distinct bindings, neither derived from a sid. In `safe_dest`
///   it is the raw caller-supplied destination (`Option<&str>`), the most
///   attacker-controlled value in the module, which is why it goes through
///   `log_safe` and is recorded as a bare `&str`. In `callback` it is
///   `safe_dest`'s **return**, i.e. the sanitised origin-relative path.
/// * `site` — `&'static str`, `"gate"` or `"callback"`, passed by the two call
///   sites so one refusal line can say which guard fired.
/// * `uid`, `user_id`, `resolved` — the Kratos identity. A stable handle to a
///   person, not a bearer credential: it authenticates nobody. `resolved` is
///   reached only as `resolved.user_id`, and sanctioning it does **not** sanction
///   the rest of the struct, because a dotted path is ruled on component by
///   component — `resolved.profile` fails on `profile`. (An earlier revision
///   illustrated that with `resolved.id_token`. `ResolvedUser` has exactly two
///   fields, `user_id` and `profile`, so that named a phantom; the mechanism it
///   was demonstrating is real and is pinned by
///   `a_dotted_field_name_is_checked_component_by_component`.)
/// * `err` — `q.error`, the OAuth error the provider sent back. Provider-
///   supplied and capped by `log_safe`.
/// * `state_key` — the OAuth `state`. A key **into** the session's `redirects`
///   map, and in `decide` a freshly minted uuid; it names a redirect entry, not
///   a session. Recorded as a bare `&str` deliberately — see its site.
/// * `g`, `fail_fast` — `GateState` and its `bool`. Startup configuration,
///   chosen per route when the middleware is installed.
/// * `minted` — a `bool` out of the `(sid, sess, minted)` destructure, saying
///   whether *this* request created a session id. A distinct binding from the
///   `sid` beside it, and a `bool` cannot carry one.
/// * `span` — the `Span` handle, named at `.instrument(span)`. **The load-bearing
///   half is that `.instrument()` formats nothing**: it attaches the span to a
///   future, so no value of any kind is rendered there. The attribute form that
///   *does* publish values is `fields( … )`, and [`identifiers`] recurses into
///   that, so its contents are ruled on individually rather than being waved
///   through as part of one opaque argument.
/// * `unwrap_or_default` — a method name in callee position.
/// * `tracing`, `field`, `Empty` — the path components of
///   `tracing::field::Empty`, a unit struct meaning "declared, not yet set".
/// * `skip_all` — a keyword in `#[tracing::instrument]`'s attribute grammar, not
///   an expression. It is the *opposite* of a disclosure: it is what stops the
///   macro recording every argument, `sid` among them.
/// * `session_present` — the `bool` bound in `decide` by HIK-274 so that the
///   `span.record` need not name `cookie_sid`. See above. Note that it replaced
///   **two** names rather than one: `cookie_sid.is_some()` also put `is_some` in
///   value position, and moving the call out of the argument retired that too.
///   [`no_web_login_module_carries_a_dead_value_list_entry`] is what noticed —
///   the draft list for this ticket had been derived before that edit and still
///   carried `is_some`, which is precisely the stale entry that assertion exists
///   to refuse.
const WEB_LOGIN_VALUE_IDENTS: &[&str] = &[
    "Empty",
    "as_str",
    "dest",
    "e",
    "err",
    "fail_fast",
    "field",
    "format",
    "g",
    "log_safe",
    "minted",
    "reason",
    "resolved",
    "session_present",
    "site",
    "skip_all",
    "span",
    "state_key",
    "to_string",
    "tracing",
    "uid",
    "unwrap_or_default",
    "user_id",
];

/// `src/web_login_postgres.rs`.
///
/// * `table` — reached only as `%self.table`, the configured table name. `self`
///   is a keyword and is exempt below, but the **field** it reaches for is ruled
///   on here, which is why `self.sql_load` would fail on `sql_load`.
/// * `name` — the configured table name, in `validate_table_name`'s `bail!`,
///   **on today's tree**: config read once at construction, and the branch that
///   names it is the one where it failed to be a Postgres identifier, so no
///   request reaches it. Same data-flow caveat as `url` on the redis list.
const POSTGRES_VALUE_IDENTS: &[&str] = &["as_str", "e", "log_safe", "name", "table", "to_string"];

/// `src/web_login_redis.rs`.
///
/// * `url`, `hosts` — construction-time redis connection settings in `from_url`
///   / `from_sentinel`. Startup config, never a session id.
/// * `redact_url_userinfo` — the redaction helper `url` sits behind **on today's
///   tree**. That is an observation about the two sites that exist, not a rule
///   this lint enforces: it does not follow data flow, so a future
///   `bail!("cannot reach {url}")` names only `url`, passes green, and
///   republishes the redis password. If you add a site naming `url`, put it
///   through `redact_url_userinfo` — nothing here will remind you.
/// * `is_empty` — a method name, in callee position.
///
/// `url`, `hosts`, `redact_url_userinfo` and `is_empty` exist only because the
/// scan was widened to the `anyhow` surface. They are startup-config and helper
/// names, not request data, which is why they were acceptable to add — that is
/// the standard, not "the build was red".
const REDIS_VALUE_IDENTS: &[&str] = &[
    "as_str",
    "e",
    "format",
    "hosts",
    "is_empty",
    "log_safe",
    "redact_url_userinfo",
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
///   careful version is a parser. Neither module has one. **A nested one reports
///   twice**: the refusal fires per `/*`, not per comment, and the scan does not
///   skip the body it refuses, so `/* outer /* inner */ still outer */` pushes
///   two entries against the same line. That is harmless for the main lint,
///   which only asserts [`Stripped::unsupported`] is *empty* — but B6 and B7
///   assert **exact** vectors, so a future nested-comment row has to expect two.
///   Measured rather than reasoned:
///   `[(319, "/* … */ block comment"), (319, "/* … */ block comment")]`.
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
/// **The precondition, which the two examples encode but the prose around them
/// did not state.** "A raw string blinds the lint" is broader than what was
/// demonstrated, and the gap matters because the next reader will reason from
/// it. Desynchronising on its own hides **nothing**: [`strip_comments`] only
/// ever replaces text on its `//` branch, so while the machine is out of step it
/// is still copying the source through verbatim, and [`invocations`] starts
/// every body scan with fresh string state. What hides the leak is the
/// **re-synchronisation** — a later real `"` closes the runaway string, the text
/// after it is read as code, and if that text carries a `//` *on the same line
/// as, and before, a scanned invocation*, that invocation is blanked. Which is
/// why both examples above put a `//`-bearing string literal on the `error!`
/// line, and why the line-oriented `//` branch is what turns a desync into a
/// blind.
///
/// Measured at `16bd876`, same site, same raw string, the two shapes differing
/// only in whether `let _u = "redis://h";` shares the line:
///
/// ```ignore
/// let _pat = r"weblogin:sess:\";          // raw string on its own line
/// …
/// tracing::error!(                        // and `error!` on its own lines
///     session.store = %"redis", session.correlator = %sid, …
/// );
/// ```
///
/// → **13 passed, 1 FAILED**, naming `correlator` and `sid`. The simpler
/// injection is **caught**.
///
/// ```ignore
/// let _pat = r"weblogin:sess:\";
/// …
/// let _u = "redis://h"; tracing::error!(… session.correlator = %sid, …);
/// ```
///
/// → **14 passed, 0 failed**, the same leak reported clean.
///
/// So the honest claim is narrower than "a raw string blinds the lint": a raw
/// string **plus a same-line re-synchronising comment** blinds it. The refusal
/// is still the right call, and for a reason the narrowing sharpens rather than
/// weakens — the raw string is the half an author adds without noticing, while
/// `web_login_redis.rs` already supplies the other half twenty times over in its
/// own `redis://…` literals, so in *this* file the second condition is close to
/// free.
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
/// **Macro expansion does not qualify that claim, and an earlier account of it
/// said otherwise.** HIK-246's commit message left a residual reading "the rule
/// is lexical and cannot see a raw string produced by a macro expansion". That
/// is not a hazard of this stripper at all: expansion happens in the compiler,
/// after lexing, and cannot put text into the file being scanned. What the
/// scanner reads is the bytes on disk, so the enumeration above is over the
/// bytes on disk and is complete over them. The real residual in that
/// neighbourhood is a different one — the scan is by *name*, so an invocation
/// reached through a macro or helper not on [`INVOCATIONS`] is unscanned — and
/// it belongs to the module header's "What it cannot do", where it now is. It is
/// recorded as a correction rather than dropped because a residual described
/// wrongly is worse than one described narrowly: it sends an auditor looking for
/// a lexical hole that does not exist, past a name-resolution one that does.
///
/// It costs nothing on plausible source. [`raw_string_starts_at`] requires the
/// full `r` `#`* `"` prefix, so a raw *identifier* (`r#type`) is not touched —
/// it cannot hide a delimiter, being `r#` plus an identifier and nothing else.
/// And every `r"` a grep for the sequence turns up in the scanned files is the
/// tail of a word inside a string literal (`"mymaster".into()`,
/// `query.get("user")`, `bad_request("login error")`), which never reaches this
/// branch at all.
///
/// **That is a property of the tree, not of the files, and HIK-274 had to pay
/// for it.** `src/web_login.rs` carried two `r#"…"#` JSON fixtures in its
/// `#[cfg(test)]` module, and bringing that file in scope meant rewriting them
/// as escaped ordinary literals — the refusal fired exactly as designed, before
/// any allow-list question was reached. Expect it to recur: that file is
/// majority test code and a raw string is the natural way to write JSON. See the
/// module header's standing-tax section for what to do about it, and why
/// teaching this function to lex raw strings is a separate ticket rather than a
/// tidy-up.
///
/// **No inventory count is quoted here, deliberately.** The sentence this
/// replaces gave one, and HIK-241 falsified it the moment it put a `.context(`
/// on every error branch in both stores: a numeral in an unowned comment goes
/// stale on the next ticket that adds a logging site, which is most tickets in
/// these files. What this paragraph needs is only that the raw-string branch
/// is not reached on this tree, which the observation above establishes without
/// counting anything — and the scanner's liveness is the *test's* job, asserted
/// per file rather than described here.
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
/// The lookahead cannot itself become the unbounded scan it is guarding
/// against — but **what bounds it is the caller, not either guard inside it**,
/// and the prose here used to imply the reverse. [`strip_comments`] splits the
/// file on `\n` and hands this function a single line, so the scan is bounded by
/// the line whatever this function does. The `at + 13` ceiling (the longest char
/// literal is `'\u{10FFFF}'`) and the `'\n'` arm are belt-and-braces against a
/// future caller passing a longer slice; neither carries the boundedness
/// argument today and neither is pinned. Measured, both mutants survive the
/// whole suite at 15/15 — `end = chars.len()`, and the `'\n'` arm deleted. Read
/// them as defence in depth, not as guards anything rests on; the line split is
/// the guard.
///
/// A lifetime — `'a`, `'static` — either finds no closing `'` on the line at
/// all, or lands on a span [`is_char_literal_body`] rejects as the gap between
/// two lifetimes rather than a literal body; see the comment at that branch.
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

/// One scanned invocation.
#[derive(Debug)]
struct Invocation {
    /// 1-based line of the body's opening delimiter.
    line: usize,
    /// How the site is spelled, for a failure message: `warn!`, `context(`.
    label: String,
    /// The text between the delimiters.
    body: String,
    /// Where `body` sits in the text [`invocations`] was given, as **char**
    /// indices — added by HIK-274 so a test can splice a canary into a real
    /// site rather than into a synthetic imitation of one.
    ///
    /// These are usable against the *unstripped* source too, because
    /// [`strip_comments`] replaces characters one for one and never changes the
    /// length. That is relied on and asserted at the one place it matters, in
    /// [`every_scanned_site_in_web_login_is_actually_checked`].
    body_range: (usize, usize),
}

/// Every scanned invocation in `text`.
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
fn invocations(text: &str) -> Vec<Invocation> {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<Invocation> = Vec::new();

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
            let body_end = j.saturating_sub(1);
            let body: String = chars[body_start..body_end].iter().collect();
            out.push(Invocation {
                line,
                label: needle.label(),
                body,
                body_range: (body_start, body_end),
            });
            at = body_start;
        }
    }
    out.sort_by_key(|inv| inv.line);
    out
}

/// One name a scanned site is not allowed to have used.
struct Offence {
    line: usize,
    label: String,
    body: String,
    position: Position,
    ident: String,
}

/// Every offence in an already-[`strip_comments`]ed module text, given that
/// module's value list.
///
/// Factored out of the main test so the mutation proof
/// ([`every_scanned_site_in_web_login_is_actually_checked`]) drives **this**
/// code rather than a second, quietly diverging copy of the same loop — which
/// is the shape that would let the proof pass while the lint itself was broken.
fn offences_in(stripped_text: &str, allowed_value_idents: &[&str]) -> Vec<Offence> {
    let mut out = Vec::new();
    for inv in invocations(stripped_text) {
        // One offence per distinct name per position per site:
        // `session.id = %id` names `id` twice and is one mistake, not two.
        let mut reported: Vec<(Position, String)> = Vec::new();
        for (position, ident) in identifiers(&inv.body) {
            let allowed = match position {
                Position::Field => ALLOWED_FIELD_IDENTS.contains(&ident.as_str()),
                Position::Value => allowed_value_idents.contains(&ident.as_str()),
            };
            if KEYWORDS.contains(&ident.as_str())
                || allowed
                || reported.contains(&(position, ident.clone()))
            {
                continue;
            }
            reported.push((position, ident.clone()));
            out.push(Offence {
                line: inv.line,
                label: inv.label.clone(),
                body: inv.body.clone(),
                position,
                ident,
            });
        }
    }
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
///
/// # `fields( … )` is recursed into, and it RECLASSIFIES (HIK-274)
///
/// `#[tracing::instrument(name = "…", skip_all, fields(a.b = %x))]` presents the
/// whole `fields( … )` group as **one argument with no top-level `=`**, so the
/// rule above read every name inside it — `a`, `b` *and* `x` — as
/// [`Position::Value`]. That is not a cosmetic mis-labelling. Sanctioning `a`
/// and `b` in Value position to make such a file scan clean would undo HIK-246's
/// whole result: `let id = sid; warn!(x = %id)` is the evasion the two-list
/// split exists to stop, and it stops it only because a field-name component is
/// *not* thereby legal as a binding. `src/web_login.rs` has such an attribute
/// and would have demanded exactly that trade.
///
/// So a `fields( … )` argument is split on its own commas and each item run
/// through [`field_value_split`] as if it were a top-level argument.
///
/// **What that does is RECLASSIFY, and an earlier revision of this paragraph
/// claimed otherwise.** It said the recursion "only ever *splits*" and that "no
/// name that was reported stops being reported". Both are false, and the
/// paragraph immediately below them enumerated the counter-examples — the file
/// contradicted itself two paragraphs apart. Measured: delete the recursion and
/// the main lint reports ten Value-position offences at `src/web_login.rs`'s
/// `#[tracing::instrument]` which the recursion suppresses. They are not
/// silenced; they are moved to [`Position::Field`] and checked against
/// [`ALLOWED_FIELD_IDENTS`] instead.
///
/// **Nothing is weakened by that, and the argument is the one this file already
/// makes for keeping the field list shared**: a name left of a top-level `=` is
/// turned into a static string by `tracing`'s macro grammar and cannot carry a
/// value, so moving a field-name component out of the strict list forfeits
/// nothing a leak could use. What the recursion buys is the converse and it is
/// the point of the change — those names no longer have to be sanctioned as
/// *bindings*, which is what would have undone HIK-246's B3.
///
/// **The names it moves are enumerated rather than counted**, because a count
/// over this set goes stale on the next logging change while an enumeration
/// merely goes visibly incomplete. Delete the recursion and the value position
/// of `src/web_login.rs` demands exactly `auth`, `id`, `login`, `op`, `outcome`,
/// `redirect`, `refused`, `session`, `user` — every one a component of a dotted
/// field name — **and `fields`**, which is the group keyword and is discussed
/// next. (A draft of this paragraph said "the ten that leave are all field-name
/// components". Nine of them are; `fields` is not, and it is the one whose
/// disposal needs an argument rather than an observation.)
///
/// **One name really is dropped rather than moved: `fields` itself.** It is the
/// group keyword in `tracing`'s attribute grammar, not an expression, exactly as
/// `skip_all` is — and a leak cannot hide behind it, because `fields(sid)` has
/// no top-level `=` and still reports `sid` in Value position. What is lost is
/// only the ability of an unrelated `fields(…)` *call* inside some other scanned
/// body to be reported by its own name; its arguments are still read.
fn identifiers(body: &str) -> Vec<(Position, String)> {
    let chars: Vec<char> = body.chars().collect();
    let mut out = Vec::new();
    for (s, e) in arg_ranges(&chars) {
        push_argument(&chars[s..e], &mut out);
    }
    out
}

/// One argument of a scanned body, classified and pushed. Split out of
/// [`identifiers`] so a `fields( … )` group can hand its items back to the same
/// rule rather than to a second, drifting copy of it.
fn push_argument(arg: &[char], out: &mut Vec<(Position, String)>) {
    if let Some(k) = field_value_split(arg) {
        for n in raw_identifiers(&arg[..k]) {
            out.push((Position::Field, n));
        }
        for n in raw_identifiers(&arg[k + 1..]) {
            out.push((Position::Value, n));
        }
        return;
    }
    if let Some(inner) = fields_group_body(arg) {
        for (s, e) in arg_ranges(inner) {
            push_argument(&inner[s..e], out);
        }
        return;
    }
    for n in raw_identifiers(arg) {
        out.push((Position::Value, n));
    }
}

/// If `arg` is exactly a `fields( … )` group, the chars between its parens.
///
/// Deliberately strict: the whole argument, once trimmed, must be the word
/// `fields`, optional whitespace, `(`, and a matching `)` at the very end. So
/// `x.fields(…)` does not match (it starts at `x`), `fieldsy(…)` does not match
/// (no word boundary), and `fields(a) + b` does not match (something follows the
/// closer) — each of which is an ordinary expression whose names must keep being
/// read in Value position.
fn fields_group_body(arg: &[char]) -> Option<&[char]> {
    let start = skip_ws(arg, 0);
    let mut end = arg.len();
    while end > start && arg[end - 1].is_whitespace() {
        end -= 1;
    }
    let arg = &arg[start..end];

    const KW: &[char] = &['f', 'i', 'e', 'l', 'd', 's'];
    if arg.len() <= KW.len() || arg[..KW.len()] != *KW {
        return None;
    }
    let open = skip_ws(arg, KW.len());
    if arg.get(open) != Some(&'(') {
        return None;
    }
    // The matching closer must be the last character, or this is not a group —
    // it is a call sitting inside a larger expression.
    if arg.last() != Some(&')') {
        return None;
    }
    let inner = &arg[open + 1..arg.len() - 1];
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for &c in inner {
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
            if depth < 0 {
                return None;
            }
        }
    }
    if depth != 0 {
        return None;
    }
    Some(inner)
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
fn no_tracing_or_anyhow_line_in_a_web_login_module_names_an_unsanctioned_binding() {
    let mut offences: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for file in SCANNED_MODULES {
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
        // **Per file, never summed.** A total across the table cannot see one
        // file go dark: postgres contributes invocations of its own, so a redis
        // scan that silently found nothing would still leave a healthy-looking
        // total. That matters concretely, because postgres' `malformed payload`
        // site is one this lint is the *only* oracle for. (No count here either
        // — see `strip_comments`' doc comment for why one does not survive.)
        //
        // Deliberately not a count, either. The assertion it replaced was
        // `>= 5`, which gave a confidently wrong diagnosis when it tripped: it
        // reported "the scanner is broken, not the source" for what is far more
        // often a site being legitimately removed, and it only had any bite on
        // postgres by the accident of that file having exactly five sites. A
        // number nobody owns doubles as an unowned tripwire for a spelling
        // change, and this test should not carry a control it cannot diagnose.
        //
        // **Gated on the module's own declaration, and checked both ways.**
        // An unconditional floor cannot tell "the scanner went dark" from "this
        // module legitimately does not log", and since HIK-274 made the file set
        // a property the second case is one a reader can be *obliged* to add.
        // Blaming the scanner for it would be exactly the confidently-wrong
        // diagnosis described three paragraphs up. See `expects_logging_sites`.
        if file.expects_logging_sites {
            assert!(
                !found.is_empty(),
                "no tracing or anyhow invocation matched in {} — either the scanner has stopped \
                 seeing this file, or the file genuinely no longer logs anything. If it is the \
                 second, set `expects_logging_sites: false` on its row and empty its value list; \
                 do not delete the row, because the file-set property requires it.",
                file.path
            );
        } else {
            assert!(
                found.is_empty(),
                "{} is declared `expects_logging_sites: false` but {} scanned invocation(s) were \
                 found in it. Review them and flip the flag — a module must not be able to opt \
                 out of this lint by asserting something false about itself.",
                file.path,
                found.len()
            );
        }
        scanned += found.len();

        for o in offences_in(&source.text, file.allowed_value_idents) {
            let list = match o.position {
                Position::Field => "ALLOWED_FIELD_IDENTS".to_string(),
                Position::Value => format!("{}'s value list", file.path),
            };
            offences.push(format!(
                "{}:{} `{}` names `{}` in {:?} position, which is not in {list}: {}",
                file.path,
                o.line,
                o.label,
                o.ident,
                o.position,
                o.body.trim().replace('\n', " ")
            ));
        }
    }

    assert!(
        offences.is_empty(),
        "the session id must never enter a formatted log line, and only sanctioned identifiers \
         may be named where one is built — {} offence(s) across {scanned} invocations:\n{}\n\n\
         If the name really cannot carry a session id, add it to the list named above *with the \
         reason*. Do not widen a list to make this green, and do NOT delete this test: for every \
         site it covers that no behavioural test can reach offline — both `serialize failed` \
         branches and postgres' `malformed payload` among them — this lint is the ONLY oracle \
         there is.",
        offences.len(),
        offences.join("\n")
    );
}

/// [`VALUE_IDENTS_SHARED_BY_EVERY_MODULE`] must actually be shared by every
/// module.
///
/// The mirror of [`no_web_login_module_carries_a_dead_value_list_entry`], and it
/// exists for the same reason: that const shipped once as an
/// `#[allow(dead_code)]` restatement of a derived set and was false on the day
/// it landed. A claim nothing checks is a claim that rots, and this file's
/// entire argument for two allow-lists over a paragraph of guidance is that
/// prose does not fail.
///
/// Note what the two assertions do *together*. This one forbids a name being on
/// the shared list but missing from a module; the dead-entry one forbids a name
/// being on a module's list without a site naming it. So the only way to put
/// `format` back on the shared list is for postgres to genuinely acquire a site
/// that names it — which is exactly the condition under which the claim would
/// become true.
/// **Scoped to modules that log**, which is not a loophole but the only coherent
/// reading. A module declared `expects_logging_sites: false` has an empty value
/// list by construction — [`no_web_login_module_carries_a_dead_value_list_entry`]
/// would reject any name on it — so requiring the shared names *of it* would
/// make the two assertions jointly unsatisfiable for a legitimately silent
/// module. Measured while driving exactly that case with a logging-free
/// `src/web_login_types.rs`: this assertion was the second thing to block it,
/// after the liveness floor.
#[test]
fn the_shared_value_idents_really_are_shared_by_every_module() {
    for file in SCANNED_MODULES.iter().filter(|f| f.expects_logging_sites) {
        for name in VALUE_IDENTS_SHARED_BY_EVERY_MODULE {
            assert!(
                file.allowed_value_idents.contains(name),
                "`{name}` is listed in VALUE_IDENTS_SHARED_BY_EVERY_MODULE but is not on {}'s \
                 value list. Either it is not in fact shared — remove it from the shared list, \
                 which is where this const went wrong before — or that module has acquired a \
                 site naming it and its own list needs the name adding, with a bullet.",
                file.path
            );
        }
    }
}

/// Every name on a module's value list must be **named by a site in that
/// module**. A sanctioned name no site uses is deleted, not left (HIK-274).
///
/// This turns the standing warning above the lists — "do not widen a list to
/// make this green" — from prose into an assertion. Prose does not fail. With
/// it, the pre-emptive half of that mistake is not discouraged but
/// *impossible*: a name added ahead of the site that would need it has nothing
/// naming it and is reported here immediately, before it can sanction anything.
///
/// It does not, and cannot, catch the other half — a name added *alongside* a
/// real site that genuinely names it. Nothing lexical can; that is what the
/// bullet arguing why the name cannot carry a sid is for, and why review is
/// still the control there.
///
/// **The shared [`ALLOWED_FIELD_IDENTS`] is deliberately not covered.** "Dead"
/// there would mean dead across every module at once, which is a different
/// assertion about a list whose entries cannot carry a value in the first place.
/// Stated rather than left silent: a stale *field* entry is caught by nothing.
#[test]
fn no_web_login_module_carries_a_dead_value_list_entry() {
    for file in SCANNED_MODULES {
        let source = strip_comments(file.text);
        assert!(
            source.unsupported.is_empty(),
            "{}: {:?}",
            file.path,
            source.unsupported
        );

        let mut named: Vec<String> = Vec::new();
        for inv in invocations(&source.text) {
            for (pos, ident) in identifiers(&inv.body) {
                if pos == Position::Value && !named.contains(&ident) {
                    named.push(ident);
                }
            }
        }

        let dead: Vec<&&str> = file
            .allowed_value_idents
            .iter()
            .filter(|n| !named.iter().any(|seen| seen == *n))
            .collect();

        assert!(
            dead.is_empty(),
            "{}: {dead:?} is sanctioned in value position but no longer named by any scanned \
             site in this file — delete the entry, and its bullet with it. A sanctioned name \
             with nothing behind it is either a list widened ahead of the code, which is the \
             exact defeat those bullets exist to prevent, or the residue of a log line someone \
             removed. Neither should survive.",
            file.path
        );
    }
}

/// The canary spliced into real source by the two mutation tests below. Chosen
/// so that it is on no list and could not plausibly be added to one.
const CANARY: &str = "hik274_canary_binding";

/// The char index at which the line containing `offset` begins.
fn line_start(chars: &[char], offset: usize) -> usize {
    chars[..offset]
        .iter()
        .rposition(|c| *c == '\n')
        .map(|i| i + 1)
        .unwrap_or(0)
}

/// **T3 — the mutation proof, driven over EVERY scanned site rather than a
/// hand-picked few.**
///
/// The trap this test is written around is HIK-274's own, and it is worth
/// stating before the mechanism: **a mutation test that hands
/// [`strip_comments`] / [`invocations`] / [`identifiers`] some text of its own
/// is GREEN against the tree this ticket started from.** The scanner already
/// worked on any string it was given; what was missing was the *file set*. So a
/// proof built on synthetic source proves nothing about this ticket at all.
///
/// This one therefore takes its text **from [`SCANNED_MODULES`] by path, and
/// panics if that path is absent** — which is what ties it to the thing that
/// actually changed. It then splices [`CANARY`] into each real site's body in
/// turn and asserts the full pipeline reports it, in [`Position::Value`], at
/// that site's own line.
///
/// **It names no line number and no site, so it cannot go stale.** It covers
/// HIK-241's five `warn!` sites and HIK-272's two without listing them, and it
/// will cover the next one the day it is written. The ticket's own suggestion —
/// "assert the three new `warn!` sites in turn" — was both wrong about the count
/// and a list that would need editing on every future logging change.
///
/// The mutant is only ever *scanned*, never compiled.
#[test]
fn every_scanned_site_in_web_login_is_actually_checked() {
    let file = SCANNED_MODULES
        .iter()
        .find(|f| f.path == "src/web_login.rs")
        .expect(
            "src/web_login.rs is absent from SCANNED_MODULES — that IS the HIK-274 defect, and \
             this proof is meaningless without it",
        );

    assert!(
        !file.allowed_value_idents.contains(&CANARY)
            && !ALLOWED_FIELD_IDENTS.contains(&CANARY)
            && !KEYWORDS.contains(&CANARY),
        "the canary is sanctioned somewhere, so this test cannot fail"
    );

    let original: Vec<char> = file.text.chars().collect();
    let stripped = strip_comments(file.text);
    assert!(
        stripped.unsupported.is_empty(),
        "{:?}",
        stripped.unsupported
    );

    // The splice uses offsets computed on the STRIPPED text against the
    // ORIGINAL. That is sound only because stripping replaces characters one
    // for one, so assert it rather than rely on it: if `strip_comments` ever
    // grew a branch that changed the length, every splice below would land at
    // the wrong place and the test would fail in a way nobody could read.
    assert_eq!(
        stripped.text.chars().count(),
        original.len(),
        "strip_comments is no longer length-preserving, so body_range offsets do not carry over \
         to the original text"
    );

    let sites = invocations(&stripped.text);
    assert!(!sites.is_empty(), "the scanner is not seeing {}", file.path);

    for site in &sites {
        let (body_start, _) = site.body_range;

        let mut mutated: String = original[..body_start].iter().collect();
        mutated.push_str(CANARY);
        mutated.push_str(", ");
        mutated.extend(original[body_start..].iter());

        let mutated = strip_comments(&mutated);
        assert!(
            mutated.unsupported.is_empty(),
            "the splice itself was refused at {}:{} — {:?}",
            file.path,
            site.line,
            mutated.unsupported
        );

        let offences = offences_in(&mutated.text, file.allowed_value_idents);
        assert!(
            offences
                .iter()
                .any(|o| o.ident == CANARY && o.position == Position::Value && o.line == site.line),
            "a canary spliced into the `{}` at {}:{} was NOT reported: this site is scanned by \
             `invocations` but something downstream — `identifiers`, a list, the position rule — \
             lets an arbitrary new binding through it.\nbody: {}",
            site.label,
            file.path,
            site.line,
            site.body.trim().replace('\n', " ")
        );
    }

    // A readable control on top of the sweep, for the sites this ticket was
    // actually filed about. **Located by their message literal, never by a line
    // number**: a line number drifts silently onto a neighbouring site as the
    // file grows and then asserts something nobody intended, whereas a message
    // that has been reworded or removed fails loudly and says which one.
    for message in [
        // HIK-272, `safe_dest` — the most attacker-controlled value in the
        // module travels on this line.
        "web_login: post-login redirect destination refused",
        // HIK-241, `callback` and `decide`.
        "web_login: session store unavailable, login refused",
        "web_login: rotated session stored, but the superseded row could not be removed",
        "web_login: provider returned error",
        "web_login: no stored state",
    ] {
        assert!(
            sites.iter().any(|s| s.body.contains(message)),
            "no scanned site in {} carries the message {message:?}. If that line was \
             deliberately reworded, update this list; if it was removed, check the sweep above \
             still covers whatever replaced it.",
            file.path
        );
    }
}

/// **T4 — what T3 cannot kill, driven rather than asserted.**
///
/// Both rows assert the lint stays **green** on source that really does move a
/// session id onto a log line. They are not decoration and they are not
/// tolerated failures: they are the module header's two residuals made
/// executable, so that the day someone closes either hole these go **red** and
/// the prose describing them has to be corrected rather than quietly outliving
/// the limitation it describes.
///
/// A residual that is only written down drifts. A residual that is asserted
/// cannot.
#[test]
fn the_residuals_this_lint_cannot_close_are_pinned_as_gaps() {
    let file = SCANNED_MODULES
        .iter()
        .find(|f| f.path == "src/web_login.rs")
        .expect("src/web_login.rs must be scanned");

    let original: Vec<char> = file.text.chars().collect();
    let stripped = strip_comments(file.text);
    let sites = invocations(&stripped.text);

    // --- Residual 1: the scan is BY NAME. -------------------------------
    // A log statement reached through a macro or helper that is not on
    // `INVOCATIONS` is not scanned at all, so the sid it carries is invisible.
    // Here the canary goes to `my_log!`, standing beside a real site, on its
    // own line. No needle matches `my_log`, so nothing about it is ever read.
    //
    // Closing this needs the *name* of the offending helper to be knowable in
    // advance, which it is not — see the module header. If this row ever goes
    // red, that residual has been closed and the header must say so.
    let victim = sites.first().expect("at least one scanned site");
    let at = line_start(&original, victim.body_range.0);
    let mut mutated: String = original[..at].iter().collect();
    mutated.push_str(&format!("    my_log!({CANARY});\n"));
    mutated.extend(original[at..].iter());
    let mutated = strip_comments(&mutated);
    assert!(mutated.unsupported.is_empty(), "{:?}", mutated.unsupported);
    assert!(
        !offences_in(&mutated.text, file.allowed_value_idents)
            .iter()
            .any(|o| o.ident == CANARY),
        "the by-name residual has been CLOSED: a `my_log!` beside a scanned site is now \
         reported. That is an improvement — update the module header's second residual, which \
         still says such a site 'matches no needle, so its body is never read'."
    );

    // --- Residual 2: no data flow. --------------------------------------
    // A name sanctioned in value position can be rebound above the site, and
    // the shadowing `let` sits outside every scanned invocation, so the lint
    // never sees it. Here `e` — sanctioned in every module, as the error being
    // reported — is rebound to the canary immediately above a real site whose
    // body names `e` through an inline capture.
    //
    // Closing this needs a real Rust parser over these modules, which is a
    // different tool and its own ticket.
    let victim = sites
        .iter()
        .find(|s| s.body.contains("{e:#}"))
        .expect("a site naming `e` through an inline capture");
    let at = line_start(&original, victim.body_range.0);
    let mut mutated: String = original[..at].iter().collect();
    mutated.push_str(&format!("    let e = {CANARY};\n"));
    mutated.extend(original[at..].iter());
    let mutated = strip_comments(&mutated);
    assert!(mutated.unsupported.is_empty(), "{:?}", mutated.unsupported);
    let offences = offences_in(&mutated.text, file.allowed_value_idents);
    assert!(
        !offences.iter().any(|o| o.ident == CANARY),
        "the data-flow residual has been CLOSED: a `let` above a site is now followed. Update \
         the module header's 'What it cannot do', which still says `let e = format!(\"{{sid}}\")` \
         above one of these sites passes."
    );
    // And the mutated file is still wholly clean, which is what makes the gap a
    // gap rather than an accident of where the canary landed: the rebinding is
    // invisible *and* nothing else about it is reported, so a real leak written
    // this way ships with the suite green.
    assert!(
        offences.is_empty(),
        "the rebinding row is no longer isolating the residual — the mutated file now has \
         unrelated offences, so its green result would not mean what it claims: {:?}",
        offences
            .iter()
            .map(|o| format!("{}:{} {}", file.path, o.line, o.ident))
            .collect::<Vec<_>>()
    );
}

/// Every web-login module under `src`, as a `/`-separated path relative to
/// `relative_to`, sorted.
///
/// # The rule is on the PATH below `src/`, not on the file name
///
/// A `.rs` file counts if its path relative to `src` starts with `web_login`.
/// That is one rule, and it covers all three shapes the crate can take:
/// `src/web_login.rs`, a sibling like `src/web_login_redis.rs`, and **anything
/// inside a `src/web_login/` directory whatever it is called** —
/// `src/web_login/gate.rs`, `src/web_login/mod.rs`.
///
/// **The last of those is the whole point, and a file-name rule does not get
/// it.** The defect this replaces was a non-recursive [`std::fs::read_dir`],
/// and the obvious repair — recurse, still matching the file name
/// `web_login*.rs` — is not a repair at all: the leak that exposed the bug was
/// `src/web_login/leaky.rs`, whose *name* matches nothing. Recursion alone
/// finds `src/web_login/web_login_gate.rs` and walks straight past
/// `src/web_login/gate.rs`, which is what anyone splitting a 3,000-line module
/// would actually write. Both halves are pinned by
/// [`the_module_walk_descends_into_submodules_and_still_excludes_by_name`].
///
/// `src/mcp_resource_server/db_session_store.rs` stays excluded because its
/// path does not begin `web_login`, which is now the *only* reason — the walk
/// really does descend into that directory and decline the file. See the module
/// header for why that module is out of scope.
///
/// A symlinked directory is skipped rather than followed:
/// [`std::fs::DirEntry::file_type`] does not traverse symlinks, so such an entry
/// is neither `is_dir()` nor `is_file()` and falls through both arms. That is
/// what keeps the walk from cycling, and it is a property of `file_type` rather
/// than of anything written here — so do not "simplify" it to `path.is_dir()`,
/// which *does* traverse.
fn web_login_modules_under(src: &std::path::Path, relative_to: &std::path::Path) -> Vec<String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => panic!("{} is not readable: {e}", dir.display()),
        };
        for entry in entries {
            let entry = entry.expect("a readable directory entry");
            let file_type = entry.file_type().expect("a readable file type");
            let path = entry.path();
            if file_type.is_dir() {
                walk(&path, out);
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    walk(src, &mut files);

    let mut out: Vec<String> = files
        .into_iter()
        .filter_map(|path| {
            let below_src = path
                .strip_prefix(src)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            if !below_src.starts_with("web_login") || !below_src.ends_with(".rs") {
                return None;
            }
            Some(
                path.strip_prefix(relative_to)
                    .expect("under the root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            )
        })
        .collect();
    out.sort();
    out
}

/// The walk itself, driven against a temporary tree.
///
/// This exists because [`every_web_login_module_in_src_is_scanned`] cannot
/// discriminate on the property that matters here: the real `src/` has no
/// `web_login/` submodule today, so a revert to the non-recursive
/// [`std::fs::read_dir`] leaves that test **green**. The bug was silent exactly
/// because the tree does not currently exercise it, and asserting against the
/// tree cannot fix that.
///
/// It builds the tree under the OS temp directory rather than in `src/`, because
/// a fixture file left in `src/` would be compiled into the crate — and a
/// `web_login_fixture.rs` sitting there would then be a *real* member of the set
/// this lint asserts over, which is a worse problem than the one it tests.
#[test]
fn the_module_walk_descends_into_submodules_and_still_excludes_by_name() {
    let root = std::env::temp_dir().join(format!(
        "hik274-walk-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);

    for (dir, file) in [
        ("src", "web_login.rs"),
        ("src", "web_login_redis.rs"),
        // **The case that exposed the bug.** A submodule of the very file this
        // ticket is about, whose own name matches nothing. A file-name rule
        // walks past it however deeply it recurses.
        ("src/web_login", "leaky.rs"),
        ("src/web_login", "mod.rs"),
        ("src/web_login", "web_login_gate.rs"),
        // Deeper still, to show the recursion is not one level deep, and with
        // one name matching and one not.
        ("src/web_login/inner", "helper.rs"),
        ("src/web_login/inner", "web_login_deep.rs"),
        // Must stay excluded — and now on its PATH alone, the walk having
        // genuinely descended into this directory.
        ("src/mcp_resource_server", "db_session_store.rs"),
        ("src/mcp_resource_server", "web_login_lookalike.rs"),
        // Must not match.
        ("src", "config.rs"),
        ("src", "session_store.rs"),
        // A near-miss on each half of the rule.
        ("src", "web_logins.rs.bak"),
        ("src", "not_web_login.rs"),
    ] {
        std::fs::create_dir_all(root.join(dir)).expect("create fixture dir");
        std::fs::write(root.join(dir).join(file), "// fixture\n").expect("write fixture");
    }

    let found = web_login_modules_under(&root.join("src"), &root);
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        found,
        vec![
            "src/web_login.rs".to_string(),
            "src/web_login/inner/helper.rs".to_string(),
            "src/web_login/inner/web_login_deep.rs".to_string(),
            "src/web_login/leaky.rs".to_string(),
            "src/web_login/mod.rs".to_string(),
            "src/web_login/web_login_gate.rs".to_string(),
            "src/web_login_redis.rs".to_string(),
        ],
        "the walk must take EVERY `.rs` under `src/web_login/` whatever it is called, not just \
         the ones whose file name happens to start with `web_login`. `src/web_login/leaky.rs` is \
         the shape that exposed this: a sid-handling submodule of the file this lint exists to \
         cover, invisible to a file-name rule however deeply it recurses."
    );
    // Spelled out separately because it is the reason the exclusion still holds
    // once the recursion fix removed the other one. The walk DID descend into
    // `src/mcp_resource_server/`; both files there are declined on their path,
    // including one deliberately named to match a file-name rule.
    assert!(
        !found.iter().any(|p| p.contains("mcp_resource_server")),
        "the deliberate exclusion of the MCP session store has stopped holding"
    );
}

/// **T1 — the file set is a property, not a hand-maintained list.**
///
/// This is the assertion HIK-274 exists to add, and it is the only one in this
/// file that is red on the tree that ticket started from. Everything else here
/// scans whatever text it is handed, so a mutation proof over synthetic source
/// is green whether or not `src/web_login.rs` is in [`SCANNED_MODULES`] — the
/// scanner was never the gap, the **file set** was. So this test takes the set
/// from the filesystem at test time and compares it to the table.
///
/// It is red twice over, which is the point of writing it as a property:
///
/// * against the pre-HIK-274 tree, where `src/web_login.rs` exists on disk and
///   is absent from the table — the ticket's own defect; and
/// * the day someone adds `src/web_login_mysql.rs` — or `src/web_login/gate.rs`
///   — and does not review it, which is the *class*, and which no hand-listed
///   set of paths can catch.
///
/// **The walk RECURSES and matches on the PATH, and both halves were defects
/// for one review round.** The first version used a bare [`std::fs::read_dir`]
/// matching a file name, so `src/web_login/leaky.rs` — one `mod leaky;` away,
/// and a submodule of the very file this ticket exists to cover — was invisible
/// and this test stayed green. Recursion alone does not fix that, because
/// `leaky.rs` matches no file-name pattern; see [`web_login_modules_under`] for
/// why the rule is the path below `src/` instead, and for the measurement
/// showing a name rule fails in *both* directions.
///
/// That is not a hypothetical refactor: `src/web_login.rs` is well over three
/// thousand lines, and HIK-274 has just made its test module hostile to raw
/// strings, so splitting it into `src/web_login/{gate,callback,store}.rs` is the
/// natural next move. It failed **closed** the other way — renaming
/// `web_login.rs` to `web_login/mod.rs` reddened even the original — so only the
/// additive submodule was silent, which is the worse direction.
///
/// **`src/mcp_resource_server/db_session_store.rs` stays out of scope because
/// its path does not begin `web_login`**, and that is the whole of the reason
/// now. An earlier revision gave two — the name, and `read_dir` not recursing —
/// and offered them as independent belt and braces. The second is gone with the
/// recursion fix, and it was never a *reason* so much as an accident of the
/// implementation. See the module header for why that module is excluded; if it
/// is ever brought in scope it gets its own review and its own row, not a
/// widened glob.
#[test]
fn every_web_login_module_in_src_is_scanned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let on_disk = web_login_modules_under(&root.join("src"), root);

    let mut scanned: Vec<String> = SCANNED_MODULES.iter().map(|f| f.path.to_string()).collect();
    scanned.sort();

    assert_eq!(
        scanned, on_disk,
        "the set of web-login modules on disk and the set this lint scans have \
         diverged. Every module implementing or gating a web-login session handles the `sid`, \
         which IS the unsigned `hs_session` bearer credential, so an unscanned one is a leak \
         that would be green everywhere. Add the file to the table and review its logging \
         sites — do not narrow this test."
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
            .map(|inv| inv.body.trim().to_string())
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
        assert_eq!(
            found[0].line, 3,
            "the comment must not shift the line number"
        );
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
                .map(|inv| inv.body)
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
                        .any(|inv| inv.body.contains("leak")),
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
                        .any(|inv| inv.body.contains("leak")),
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

    /// **T5.** `fields( … )` is recursed into (HIK-274).
    ///
    /// Without this, `#[tracing::instrument(…, fields(session.op = %x))]`
    /// presents the whole group as one argument with no top-level `=`, so every
    /// name in it — the field components included — lands in
    /// [`Position::Value`]. Making `src/web_login.rs` scan clean would then have
    /// required sanctioning `session`, `op`, `user` and `id` as *bindings*,
    /// which is precisely what B3 exists to prevent: it would make
    /// `let id = sid; warn!(x = %id)` legal.
    #[test]
    fn a_fields_group_is_recursed_into_rather_than_read_as_one_value() {
        // The real shape from `src/web_login.rs`'s `#[tracing::instrument]`.
        assert_eq!(
            idents("fields(session.op = tracing::field::Empty)"),
            [
                "field:session",
                "field:op",
                "value:tracing",
                "value:field",
                "value:Empty"
            ]
        );

        // **The tightening must not lose a leak.** A value inside the group is
        // still Value, so the allow-list still gets to rule on it — this is the
        // row that stops the recursion becoming a blanket exemption for
        // everything written inside `fields(…)`.
        assert_eq!(idents("fields(x = %sid)"), ["field:x", "value:sid"]);
        // No `=` inside the group at all: `tracing`'s field shorthand, where the
        // name and the value are the same binding. Still Value.
        assert_eq!(idents("fields(sid)"), ["value:sid"]);

        // Several items, and the group as one argument among others.
        assert_eq!(
            idents(r#"name = "auth.login", skip_all, fields(a.b = %sid, c = %d)"#),
            [
                "field:name",
                "value:skip_all",
                "field:a",
                "field:b",
                "value:sid",
                "field:c",
                "value:d"
            ]
        );

        // The negatives. An ordinary call argument is NOT recursed into: `a` in
        // `f(a = b)` stays in Value position, because outside `tracing`'s field
        // grammar there is nothing turning it into a static string.
        assert_eq!(idents("f(a = b)"), ["value:f", "value:a", "value:b"]);
        // Nor does a `fields(…)` that is not the whole argument qualify — in
        // both of these it is an expression, not the attribute keyword.
        assert_eq!(
            idents("fields(a = b) + c"),
            ["value:fields", "value:a", "value:b", "value:c"]
        );
        assert_eq!(
            idents("x.fields(a = b)"),
            ["value:x", "value:fields", "value:a", "value:b"]
        );
        // And the bare word is just a name.
        assert_eq!(idents("fields"), ["value:fields"]);
    }
}
