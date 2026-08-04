//! No `tracing` invocation in either session store may mention `sid` or `key`.
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
//! **Its weakness, stated rather than discovered later: it matches on the
//! binding's name.** Rename `sid` to `id` at the top of the function and this
//! test stops noticing, while the leak is exactly as bad. It catches the
//! *realistic* regression — `git revert` restores `{sid}` literally, and a
//! well-meaning "add a correlator back" reaches for the binding that is in
//! scope — not a creative one. The behavioural tests are what catch a leak by
//! any other name.
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

/// Every `tracing::<level>!(…)` invocation in `text`, as (1-based line, body).
///
/// Matches the paren-delimited argument list, skipping over string literals so a
/// `(` inside a message cannot end the scan early. Nesting is counted, so a
/// `format!(…)` argument stays inside the body rather than truncating it.
fn tracing_invocations(text: &str) -> Vec<(usize, String)> {
    const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];
    let bytes: Vec<char> = text.chars().collect();
    let mut out = Vec::new();

    for level in LEVELS {
        let macro_call = format!("tracing::{level}!(");
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(&macro_call) {
            let open = from + rel + macro_call.len(); // just past the `(`
            let open_chars = text[..open].chars().count();
            let line = text[..open].lines().count();

            let mut depth = 1usize;
            let mut i = open_chars;
            let mut in_str = false;
            let mut escaped = false;
            while i < bytes.len() && depth > 0 {
                let c = bytes[i];
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
            let body: String = bytes[open_chars..i.saturating_sub(1)].iter().collect();
            out.push((line, body));
            from = open;
        }
    }
    out.sort_by_key(|(line, _)| *line);
    out
}

/// Whether `needle` occurs in `hay` as a whole Rust identifier, so `sid` does
/// not match inside `considered` and `key` does not match inside `keyword`.
fn mentions_identifier(hay: &str, needle: &str) -> bool {
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let at = from + rel;
        let before_ok = hay[..at].chars().next_back().is_none_or(|c| !is_word(c));
        let after_ok = hay[at + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_word(c));
        if before_ok && after_ok {
            return true;
        }
        from = at + needle.len();
    }
    false
}

#[test]
fn no_tracing_line_in_either_session_store_names_the_sid() {
    let mut offences: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for file in STORES {
        let invocations = tracing_invocations(file.text);
        // A control on the scanner itself. If the paren matching or the macro
        // spelling ever stops finding anything, this test would pass vacuously —
        // which is the exact failure mode a source lint is prone to.
        assert!(
            invocations.len() >= 5,
            "found only {} tracing invocations in {} — the scanner is broken, not the source",
            invocations.len(),
            file.path
        );
        scanned += invocations.len();

        for (line, body) in invocations {
            for needle in ["sid", "key"] {
                if mentions_identifier(&body, needle) {
                    offences.push(format!(
                        "{}:{line} names `{needle}` in a tracing invocation: {}",
                        file.path,
                        body.trim().replace('\n', " ")
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "the session id must never enter a formatted log line — {} offence(s) across {scanned} \
         tracing invocations:\n{}",
        offences.len(),
        offences.join("\n")
    );
}
