//! Every `tracing` and `anyhow` invocation in the two session stores may only
//! reference identifiers on an **allow-list**.
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
//! # What it cannot do
//!
//! It does not follow data flow. `let msg = format!("{sid}");` on the line above
//! and `error.message = msg.as_str()` inside the body names only `msg`, and
//! adding `msg` to the list would pass. That is the residual, and it is why the
//! behavioural arms are not deleted: a source scanner can show the source looks
//! right, never that the **rendered output** is clean.
//!
//! Deliberately scoped to the two web-login stores. It is **not** extended to
//! `src/mcp_resource_server/db_session_store.rs`, which has the same shape but a
//! different trust claim and its own ticket: a test that is red for another
//! ticket's reason gets muted, and then it is red for nobody's.

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

/// Every identifier a scanned invocation in these two modules is allowed to
/// name. Anything else fails the test.
///
/// **Adding a name here is the reviewable act.** Each one has been read against
/// the question "can this carry the session id?", so extend it deliberately and
/// never to make a red build green:
///
/// * `session`, `store`, `op`, `table`, `error`, `message` — components of the
///   four sanctioned dotted **field names** (`session.store`, `session.op`,
///   `session.table`, `error.message`), not bindings.
/// * `e` — the error being reported. Downstream-derived text, which is why every
///   site puts it through `log_safe`; it is not derived from the sid.
/// * `self` is a keyword and is exempt below, but the **field** it reaches for is
///   checked here: only `table` and `prefix` are reachable, and `self.sql_load`
///   would fail on `sql_load`.
/// * `log_safe`, `format`, `to_string`, `as_str`, `is_empty` — helpers.
/// * `url`, `hosts` — construction-time redis connection settings in
///   `from_url` / `from_sentinel`. `url` reaches a log only through
///   `redact_url_userinfo`; both are startup config, never a session id.
/// * `redact_url_userinfo` — the redaction helper that guard sits behind.
/// * `name` — the configured table name, in `validate_table_name`'s `bail!`.
///   Config read once at construction, and the branch that names it is the one
///   where it failed to be a Postgres identifier; no request ever reaches it.
///
/// The last four exist only because the scan was widened to the `anyhow`
/// surface. They are startup-config names, not request data, which is why they
/// were acceptable to add — that is the standard, not "the build was red".
///
/// **HIK-241 owes this list one line.** That ticket adds `anyhow` context
/// strings to these same sites, and any binding it names that is not here will
/// fail this test. That failure is the design working, not a defect in it: the
/// fix is to add the *reviewed* name, with a bullet above saying why it cannot
/// carry the sid — not to widen the list until the build is green, which is the
/// same defeat by a friendlier route.
const ALLOWED_IDENTS: &[&str] = &[
    "as_str",
    "e",
    "error",
    "format",
    "hosts",
    "is_empty",
    "log_safe",
    "message",
    "name",
    "op",
    "redact_url_userinfo",
    "session",
    "store",
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

/// The invocations scanned. Each entry is a needle and whether a `.` may precede
/// it (i.e. whether it is a method rather than a macro).
///
/// The tracing macros are matched on the **bare** spelling so that
/// `use tracing::error;` followed by `error!(…)` is caught as well as
/// `tracing::error!(…)`. Only the qualified form was matched before, and that
/// alone let a leak through on redis in silence.
///
/// `anyhow!` / `bail!` / `ensure!` / `.context(` / `.with_context(` are here
/// because they are the one path on which the sid reaches `error.message`
/// without any `tracing` body naming it — the error is formatted here and
/// rendered by a caller's `{e:#}`. HIK-241 adds context strings to these exact
/// sites, so the gap would otherwise open in the same release that closes the
/// others.
const INVOCATIONS: &[Needle] = &[
    Needle::macro_call("error!("),
    Needle::macro_call("warn!("),
    Needle::macro_call("info!("),
    Needle::macro_call("debug!("),
    Needle::macro_call("trace!("),
    Needle::macro_call("anyhow!("),
    Needle::macro_call("bail!("),
    Needle::macro_call("ensure!("),
    Needle::method_call(".context("),
    Needle::method_call(".with_context("),
];

struct Needle {
    text: &'static str,
    /// A macro may be path-qualified (`tracing::error!`) but must not be a
    /// method (`.error!`); a method needle carries its own leading `.`.
    is_method: bool,
}

impl Needle {
    const fn macro_call(text: &'static str) -> Self {
        Needle {
            text,
            is_method: false,
        }
    }
    const fn method_call(text: &'static str) -> Self {
        Needle {
            text,
            is_method: true,
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
/// * **A `'"'` char literal.** It would open a phantom string running to the next
///   `"` anywhere in the file. Handling it properly means telling `'` apart from
///   a lifetime (`'a`, `'static`), which is again a parser.
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
                } else if c == '\''
                    && chars.get(i + 1) == Some(&'"')
                    && chars.get(i + 2) == Some(&'\'')
                {
                    unsupported.push((lineno, "'\"' char literal"));
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

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Every scanned invocation in `text`, as (1-based line, needle, body).
///
/// Matches the paren-delimited argument list, skipping over string literals so a
/// `(` inside a message cannot end the scan early. Nesting is counted, so a
/// `format!(…)` argument stays inside the body rather than truncating it.
fn invocations(text: &str) -> Vec<(usize, &'static str, String)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();

    for needle in INVOCATIONS {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(needle.text) {
            let at = from + rel;
            let open = at + needle.text.len(); // just past the `(`
            from = open;

            // A macro may be path-qualified but must not be a method call, and
            // must not be the tail of a longer identifier.
            if !needle.is_method {
                if let Some(prev) = text[..at].chars().next_back() {
                    if is_word(prev) || prev == '.' {
                        continue;
                    }
                }
            }

            let open_chars = text[..open].chars().count();
            let line = text[..open].lines().count();

            let mut depth = 1usize;
            let mut i = open_chars;
            let mut in_str = false;
            let mut escaped = false;
            while i < chars.len() && depth > 0 {
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
                } else if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                }
                i += 1;
            }
            let body: String = chars[open_chars..i.saturating_sub(1)].iter().collect();
            out.push((line, needle.text, body));
        }
    }
    out.sort_by_key(|(line, _, _)| *line);
    out
}

/// Every identifier an invocation body references, in source order.
///
/// Two positions, and both matter. Outside a string literal, ordinary code
/// identifiers. Inside one, `tracing`'s **inline format captures** — `{e:#}`
/// names `e` just as surely as `%e` does, and a lint that read only code
/// positions would be blind to the one interpolation shape both modules already
/// use.
fn identifiers(body: &str) -> Vec<String> {
    let chars: Vec<char> = body.chars().collect();
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

        for (line, needle, body) in found {
            // One offence per distinct name per site: `session.id = %id` names
            // `id` twice and is one mistake, not two.
            let mut reported: Vec<String> = Vec::new();
            for ident in identifiers(&body) {
                if KEYWORDS.contains(&ident.as_str())
                    || ALLOWED_IDENTS.contains(&ident.as_str())
                    || reported.contains(&ident)
                {
                    continue;
                }
                reported.push(ident.clone());
                offences.push(format!(
                    "{}:{line} `{needle}` names `{ident}`, which is not in ALLOWED_IDENTS: {}",
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
         If the name really cannot carry a session id, add it to ALLOWED_IDENTS *with the reason*. \
         Do not widen the list to make this green.",
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
/// a bare `error!(` through on redis for a release.
mod scanner {
    use super::{identifiers, invocations, strip_comments};

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

    #[test]
    fn a_macro_is_matched_bare_and_qualified_but_not_as_a_method() {
        assert_eq!(bodies(r#"tracing::error!("a");"#), vec![r#""a""#]);
        // Evasion M4: `use tracing::error;` then the bare spelling.
        assert_eq!(bodies(r#"error!("b");"#), vec![r#""b""#]);
        // Not the tail of a longer name, and not a method call.
        assert!(bodies(r#"my_error!("c"); x.error!("d");"#).is_empty());
    }

    #[test]
    fn the_anyhow_surface_is_matched_and_with_context_is_not_double_counted() {
        assert_eq!(bodies(r#"anyhow::bail!("a");"#), vec![r#""a""#]);
        assert_eq!(bodies(r#"anyhow::ensure!(ok, "b");"#), vec![r#"ok, "b""#]);
        assert_eq!(bodies(r#"x.context("c")?;"#), vec![r#""c""#]);
        // `.with_context(` must match once, as itself — `.context(` does not
        // match inside it, because the char before `context(` is `_`.
        assert_eq!(bodies(r#"x.with_context(|| "d")?;"#), vec![r#"|| "d""#]);
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
        let src = "error!(\"dial redis://{sid}\");\n";
        assert_eq!(bodies(src), vec![r#""dial redis://{sid}""#]);
        assert_eq!(super::identifiers(r#""dial redis://{sid}""#), vec!["sid"]);

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

        let quote = strip_comments("let q = '\"';\n");
        assert_eq!(quote.unsupported, vec![(1, "'\"' char literal")]);

        // A multi-line string literal is the one span it *does* cross a newline
        // for, and it must not be mistaken for either of the above.
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

    #[test]
    fn an_inline_format_capture_is_an_identifier_and_a_positional_one_is_not() {
        assert_eq!(identifiers(r#""{e:#}""#), vec!["e"]);
        assert_eq!(identifiers(r#""{name:?}""#), vec!["name"]);
        assert!(identifiers(r#""{} {0} {{sid}}""#).is_empty());
        // The shape the whole ticket is about: a renamed binding, in either
        // position, is still a name the allow-list gets to rule on.
        assert_eq!(
            identifiers(r#"correlator = %id, "x""#),
            ["correlator", "id"]
        );
        assert_eq!(identifiers(r#""load failed for {id}""#), vec!["id"]);
    }

    #[test]
    fn a_dotted_field_name_is_checked_component_by_component() {
        // This is what makes `self` safe to exempt as a keyword: the field it
        // reaches for is still ruled on.
        assert_eq!(
            identifiers(r#"session.table = %self.sql_load"#),
            ["session", "table", "self", "sql_load"]
        );
    }
}
