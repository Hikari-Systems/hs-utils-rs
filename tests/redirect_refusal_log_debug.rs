//! What the fleet actually sees when a post-login destination is refused.
//!
//! The sibling `tests/redirect_refusal_log.rs` pins the refusal at `WARN`,
//! which is the right filter for the hazard *it* guards (a demotion of the line
//! to `debug!` goes red there). But `WARN` is not what any deployment runs, and
//! the difference is not cosmetic: under that file's filter the refusal renders
//! with no `auth.gate{…}` prefix, and under this one it renders with it. Every
//! claim about the shape of the production line has to be measured here.
//!
//! The filter is the shipped one — `EnvFilter::new("debug")`, matching
//! `config.json`'s `log.level: debug` on the consumers — and it sits at the
//! **registry**, which is where `hs_utils::otel::init` puts it. That placement
//! is fidelity to the deployed construction, nothing more.
//!
//! **Why a separate file rather than a second layer beside the `WARN` one.** A
//! subscriber is installed once per process, so a file wanting a different
//! global filter shape needs its own process. Keeping them apart means each
//! file's subscriber *is* the deployment it is named for, and neither has to
//! explain which of two filters produced the line it asserts on. That is a
//! clarity choice, not a mechanism `tracing-subscriber` forces — an earlier
//! revision of this header asserted the latter, on a claim about span creation
//! that measurement did not support, and it is deleted rather than reworded.
//!
//! What that buys, and it is the correction this file was added for: the two
//! `auth.redirect.*` span fields are **not** export-only. `fmt::Layer::on_record`
//! appends each recorded field to the span's `FormattedFields`, and
//! `Format<Full>` writes every in-scope span's fields in braces ahead of each
//! event inside it — so with no OTLP exporter configured at all, those fields
//! render, and `auth.redirect.reason` appears on the line twice.
//!
//! **Its own binary, like every log-reading test here**, because `tracing`'s
//! callsite interest cache is process-global and a subscriber can be installed
//! once. See `tests/gate_span.rs`' header.
//!
//! **What it cannot kill.** It drives the gate site only, so the callback's
//! `user.id` field is not covered by it — nothing in the tree reads that line,
//! and the callback's *behaviour* is pinned on the response instead, by
//! `no_stored_destination_can_send_the_browser_off_origin_after_login`. It also
//! asserts the two-occurrence duplication as a fact about today's
//! `tracing-subscriber`; a future version that stops writing span fields ahead
//! of events would redden this file, which is intended — the claim in
//! `safe_dest`'s doc comment would have gone stale at the same moment.
#![cfg(feature = "web-login")]

use std::sync::{Arc, Mutex};

use axum::{body::Body, http::Request, routing::get, Router};
use hs_utils::mcp_resource_server::kratos_resolver::KratosUserResolver;
use hs_utils::web_login::{gate, InMemorySessionStore, WebLogin, WebLoginConfig};
use tower::ServiceExt as _;
use tracing_subscriber::prelude::*;

const HOSTILE: &str = "//evil.example.com/x";
const MESSAGE: &str = "web_login: post-login redirect destination refused";

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

#[tokio::test]
async fn the_shipped_filter_renders_the_refusal_reason_on_the_span_and_on_the_event() {
    let capture = Capture::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(capture.clone()),
        )
        // At the REGISTRY, which is where `otel::init` puts it. Fidelity to the
        // shipped construction; see the header.
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .try_init()
        .expect("this binary installs exactly one subscriber");

    gated_app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(HOSTILE)
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-host", "app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let rendered = capture.rendered();
    let line = rendered
        .lines()
        .find(|l| l.contains(MESSAGE))
        .unwrap_or_else(|| panic!("the refusal was never logged:\n{rendered}"));

    // Still exactly one line, at `debug` as at `warn`.
    assert_eq!(
        rendered.lines().filter(|l| l.contains(MESSAGE)).count(),
        1,
        "one refusal is one line:\n{rendered}"
    );

    // The level, asserted here too. This binary would otherwise be green
    // against the `debug!` demotion the WARN sibling exists to catch, and a
    // reader landing here first should not have to infer that from the filter.
    assert!(
        line.contains("WARN"),
        "a refusal is a WARN, not a DEBUG the fleet would never filter for:\n{line}"
    );

    // The span prefix. THIS is the correction: these two fields are not
    // export-only — they render with no exporter configured at all.
    assert!(
        line.contains("auth.gate{"),
        "the refusal renders inside the auth.gate span at the shipped filter:\n{line}"
    );
    let braces = line
        .split_once("auth.gate{")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(inside, _)| inside)
        .unwrap_or_else(|| panic!("no auth.gate{{…}} field prefix:\n{line}"));
    assert!(
        braces.contains("auth.redirect.refused=true"),
        "the span carries the verdict:\n{braces}"
    );
    assert!(
        braces.contains(r#"auth.redirect.reason="not_origin_relative""#),
        "the span carries the reason, quoted because `Span::record` took a &str:\n{braces}"
    );

    // …and the event's own fields, after the message.
    let (_, after_message) = line.split_once(MESSAGE).expect("message present");
    assert!(
        after_message.contains("auth.redirect.outcome=refused")
            && after_message.contains("auth.redirect.reason=not_origin_relative")
            && after_message.contains("auth.redirect.site=gate")
            && after_message.contains(&format!(r#"auth.redirect.dest="{HOSTILE}""#)),
        "the event's own fields follow the message:\n{after_message}"
    );

    // The consequence, stated as an assertion rather than as prose: the reason
    // appears TWICE on the production line, once in the braces and once among
    // the event fields. `safe_dest`'s doc comment says so; this is what makes
    // that sentence checkable.
    assert_eq!(
        line.matches("auth.redirect.reason=").count(),
        2,
        "once on the span, once on the event:\n{line}"
    );

    // The gate has no authenticated user, so the line must not carry one. The
    // callback's does; nothing here drives that site.
    assert!(
        !line.contains("user.id"),
        "the gate refuses before anyone is authenticated:\n{line}"
    );
}
