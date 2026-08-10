//! A refused post-login destination has to be *audible*, exactly once, with the
//! reason on the line — and an accepted one has to be silent.
//!
//! **Its own binary, for the reason `tests/gate_span.rs` sets out at length:**
//! `tracing`'s callsite interest cache is process-global while
//! `tracing::subscriber::set_default` is thread-local, and the `web_login` unit
//! tests drive the gate on several threads with no subscriber installed. That
//! caches `Interest::never` for the callsites inside `decide`, so a log
//! assertion written as a unit test beside the module measures a different
//! system. Read that file's header before changing this one.
//!
//! The subscriber is pinned at **`WARN`**, and that is deliberate rather than
//! tidiness: the fleet runs at `debug`, so a demotion of this line to `debug!`
//! would pass a `DEBUG`-pinned test while changing nothing an operator sees.
//! At `WARN` the demotion goes red.
//!
//! **`WARN` is not the shape the fleet runs, and that is this file's biggest
//! limit.** Under this filter the refusal renders with no `auth.gate{…}` field
//! prefix, so the event's own fields are the whole line. Under the shipped
//! `log.level: debug` the prefix is there, carrying the two `auth.redirect.*`
//! span fields, and `auth.redirect.reason` consequently appears on the line
//! **twice**. Nothing here can see that; `tests/redirect_refusal_log_debug.rs`
//! is the sibling that drives the production filter shape and pins the real
//! line. Keep both — this one is what a `debug!` demotion goes red against, and
//! that one is what a claim about production output has to be measured on.
//!
//! For the same reason the oracle below counts **lines carrying the message**
//! and not occurrences of a field name. A field-name count is a property of the
//! filter, not of the code: it reads 1 here and 2 under the shipped filter, so
//! written that way this test would pin the harness.
//!
//! **What else it cannot kill.** It drives the gate only, and since `safe_dest`
//! branches into two `warn!` callsites (the callback's carries `user.id`, the
//! gate's cannot), this reaches exactly one of them — the `None` arm. A
//! demotion or a field change confined to the `Some` arm would leave both this
//! file and its `debug` sibling green. Nothing in the tree reads the callback's
//! line; that site's *behaviour* is pinned by
//! `no_stored_destination_can_send_the_browser_off_origin_after_login` on the
//! response rather than on the log. It also drives one hostile spelling, not
//! the table: `MUST_REFUSE` lives in the crate's `#[cfg(test)]` module and an
//! integration binary cannot see it. What is under test here is the shape of
//! the line, not the coverage of the rule.
#![cfg(feature = "web-login")]

use std::sync::{Arc, Mutex};

use axum::{body::Body, http::Request, routing::get, Router};
use hs_utils::mcp_resource_server::kratos_resolver::KratosUserResolver;
use hs_utils::web_login::{gate, InMemorySessionStore, WebLogin, WebLoginConfig};
use tower::ServiceExt as _;
use tracing_subscriber::prelude::*;

/// The one spelling driven here. `not_origin_relative` is its measured reason
/// on `url` 2.5.8; the rest of the table is
/// `a_hostile_destination_is_never_persisted_in_the_session`'s business.
const HOSTILE: &str = "//evil.example.com/x";
const HARMLESS: &str = "/dash?tab=runs";

/// The refusal's message. Counting lines that carry *this* is filter-shape
/// independent, which counting a field name is not.
const MESSAGE: &str = "web_login: post-login redirect destination refused";

/// `Arc<Mutex<Vec<u8>>>` is not itself a `MakeWriter`, hence the wrapper — the
/// same shape the session-store log binaries use.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn rendered(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The browser tier of the gate, over an in-memory store. `fail_fast: false`
/// is what reaches the branch that records a destination at all.
fn gated_app() -> Router {
    let resolver = Arc::new(KratosUserResolver::new(
        "http://kratos:4434",
        "https://hikari-systems.com/",
        true,
    ));
    let wl = WebLogin::with_store(
        WebLoginConfig::new(
            "client-abc",
            "secret-xyz",
            "https://auth.example.com/oauth2/auth",
            "https://auth.example.com/oauth2/token",
            "https://auth.example.com/userinfo",
            "openid profile email",
        ),
        resolver,
        Arc::new(InMemorySessionStore::default()),
    );
    Router::new().route("/dash", get(|| async { "ok" })).layer(
        axum::middleware::from_fn_with_state(wl.gate_state(false), gate),
    )
}

async fn drive(target: &str) {
    gated_app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(target)
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-host", "app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_refused_destination_is_audible_exactly_once_and_names_its_reason() {
    let capture = Capture::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(capture.clone())
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        )
        .try_init()
        .expect("this binary installs exactly one subscriber");

    // The accepted request goes FIRST, so its silence is asserted against a
    // buffer that is still empty for a reason rather than one the refusal has
    // already filled.
    drive(HARMLESS).await;
    assert_eq!(
        capture.rendered(),
        "",
        "an accepted destination is a successful same-origin forward and writes nothing"
    );

    drive(HOSTILE).await;
    let rendered = capture.rendered();

    // Lines carrying the MESSAGE, not occurrences of a field name — see the
    // header. One refusal is one line, whatever the filter does to the fields.
    assert_eq!(
        rendered.lines().filter(|l| l.contains(MESSAGE)).count(),
        1,
        "one refusal is one line, no more and no fewer:\n{rendered}"
    );
    assert!(
        rendered.contains("auth.redirect.reason=not_origin_relative"),
        "`refused` alone cannot tell a UI typo from someone probing:\n{rendered}"
    );
    assert!(
        rendered.contains("auth.redirect.outcome=refused"),
        "the verdict belongs on the line beside its reason:\n{rendered}"
    );
    assert!(
        rendered.contains("auth.redirect.site=gate"),
        "two call sites share this line, so it has to say which one:\n{rendered}"
    );

    // The destination is the most attacker-controlled value on the line, and
    // the assertion is on the QUOTES rather than on the value alone because the
    // quoting is the load-bearing half a reader would otherwise skim past.
    //
    // Getting the attribution right matters more than it looks: the **bare
    // `&str`** is what makes the fmt layer escape *and* quote — escaping stops a
    // CRLF forging a whole line, quoting stops a space or an `=` forging a
    // `key=value` pair inside one — while `log_safe` contributes **only the
    // 256-byte cap**, being truncation and nothing else. Believe the reverse and
    // you would switch to `%`, keep the `log_safe(..)` call, and think both
    // holes were still shut. `tests/session_store_error_message_is_escaped_redis
    // .rs` makes the same point about the same helper.
    assert!(
        rendered.contains(&format!("auth.redirect.dest=\"{HOSTILE}\"")),
        "the refused destination must be recorded as a quoted, bounded &str:\n{rendered}"
    );
}
