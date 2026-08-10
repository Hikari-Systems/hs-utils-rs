//! The `auth.gate` span must cover the gate's decision and close *before* the
//! request goes downstream.
//!
//! This lives in `tests/` rather than beside the module, and the reason is the
//! whole point of the test. `tracing`'s callsite interest cache is
//! **process-global**, while `tracing::subscriber::set_default` is
//! thread-local. The unit tests in `web_login` drive `gate` on several threads
//! with no subscriber installed, which caches `Interest::never` for the
//! `auth.gate` callsite for the whole process; `rebuild_interest_cache()` does
//! not rescue it, because it re-registers against the global dispatcher, which
//! is still `NoSubscriber`. A disabled span makes `.instrument()` a no-op, so
//! the current span inside the handler stays the caller's — which is exactly
//! what a passing assertion looks like.
//!
//! Measured against the faithful mutation — this file's shipped `info_span!`
//! callsite held open with `next.run(req).instrument(span)` — under a full
//! `cargo test --all-features` at default parallelism: as a unit test beside the
//! module, **19 of 30 runs passed against the broken code**; relocated here,
//! **30 of 30 fail**. The mutation has to reproduce the shipped *callsite*, not
//! merely the shipped misbehaviour: reverting to the `#[tracing::instrument]`
//! attribute form moves the callsite, changes what the interest cache does, and
//! measures a different system.
//!
//! An integration test gets its own binary, so nothing else can touch the
//! callsite, and the subscriber here is installed **globally** rather than
//! per-thread — so callsite registration sees a real subscriber and the
//! interest cache is built correctly rather than being worked around.
//!
//! Belt and braces on top of the isolation: the span the handler observes is
//! asserted positively (it must be the caller's), *and* a capturing layer
//! asserts `auth.gate` was genuinely recorded. A disabled span therefore fails
//! on the second assertion instead of passing the first.
#![cfg(feature = "web-login")]

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use hs_utils::mcp_resource_server::kratos_resolver::KratosUserResolver;
use hs_utils::web_login::{
    gate, InMemorySessionStore, Session, WebLogin, WebLoginConfig, WebSessionStore,
};
use tower::ServiceExt as _;
use tracing::Instrument as _;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

/// The seeded session id. A uuid rather than a short label so the leak check
/// below can test a six-character prefix and mean it: a short canary makes
/// truncation undetectable, because every prefix long enough to matter is the
/// whole string.
const SID: &str = "0f9c2b7a-4e51-4a3d-9c6e-1b8d5f2a7c34";

/// Records every span created and the fields set on it, so the test can prove
/// `auth.gate` was actually enabled rather than silently compiled out of the
/// run, and can pin the attribute contract.
///
/// Fields need both hooks: the span opens with most of its fields `Empty` and
/// fills them in later via `Span::record`, which arrives at `on_record`.
#[derive(Clone, Default)]
struct Captured {
    names: Arc<Mutex<Vec<&'static str>>>,
    fields: Arc<Mutex<Vec<(String, String)>>>,
}

/// Flattens a field value to a string. `record_debug` is the catch-all that
/// picks up the bools.
struct Collect<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for Collect<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }
}

impl<S: tracing::Subscriber> Layer<S> for Captured {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        self.names.lock().unwrap().push(attrs.metadata().name());
        attrs.record(&mut Collect(&mut self.fields.lock().unwrap()));
    }

    fn on_record(&self, _: &tracing::Id, values: &tracing::span::Record<'_>, _: Context<'_, S>) {
        values.record(&mut Collect(&mut self.fields.lock().unwrap()));
    }
}

#[tokio::test]
async fn the_gate_span_does_not_wrap_the_downstream_handler() {
    let captured = Captured::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(captured.clone()))
        .expect("this binary installs exactly one subscriber");

    // Seeded through the public `Deserialize` impl: `Session`'s fields are
    // private, and an authenticated one is what makes the handler reachable.
    let store = Arc::new(InMemorySessionStore::default());
    let sess: Session = serde_json::from_value(serde_json::json!({
        "user_id": "kratos-identity-1"
    }))
    .expect("session from json");
    store
        .store(SID, &sess)
        .await
        .expect("the in-memory store cannot fail");

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
        store,
    );

    // What span was current when the handler ran?
    let seen: Arc<Mutex<Option<&'static str>>> = Arc::new(Mutex::new(None));
    let probe = seen.clone();
    let app = Router::new()
        .route(
            "/api/graphql",
            axum::routing::post(move || {
                let probe = probe.clone();
                async move {
                    *probe.lock().unwrap() = tracing::Span::current().metadata().map(|m| m.name());
                    "ok"
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            wl.gate_state(true),
            gate,
        ));

    let resp = async {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/graphql")
                .header(header::COOKIE, format!("hs_session={SID}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }
    .instrument(tracing::info_span!("test.caller"))
    .await;

    assert_eq!(resp.status(), StatusCode::OK);

    // Without this the test is satisfied by a span that never existed, which is
    // precisely the false green that put it in its own binary.
    assert!(
        captured.names.lock().unwrap().contains(&"auth.gate"),
        "auth.gate was never recorded, so this run proves nothing about its extent"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        Some("test.caller"),
        "the handler must run under the caller's span — auth.gate has to close on \
         the gate's decision, not stay open across next.run"
    );

    // The attribute contract. Nothing pinned this before, which is how the
    // deprecated `enduser.id` spelling survived to review.
    let fields = captured.fields.lock().unwrap().clone();
    // `Span::record` is last-write-wins, and this list is not span-scoped, so
    // the LAST match is the faithful read. Today every field is recorded once
    // on one span in a single-request binary, so first and last agree — but a
    // field recorded twice, or a second request, would make `find` silently pin
    // the superseded value.
    let named = |k: &str| -> Option<String> {
        fields
            .iter()
            .rfind(|(n, _)| n == k)
            .map(|(_, v)| v.trim_matches('"').to_string())
    };

    assert_eq!(
        named("user.id").as_deref(),
        Some("kratos-identity-1"),
        "the authenticated branch must carry the end user's id"
    );
    assert!(
        named("enduser.id").is_none(),
        "enduser.* is deprecated in the OTel semantic conventions; user.id replaced it"
    );
    assert_eq!(named("auth.gate.outcome").as_deref(), Some("authenticated"));
    assert_eq!(named("auth.gate.session.present").as_deref(), Some("true"));
    assert_eq!(named("auth.gate.session.minted").as_deref(), Some("false"));
    // Set at span construction rather than by a later `record`, so this is the
    // only assertion exercising the `on_new_span` half of the capture. Without
    // it that hook can be deleted and every other assertion still passes.
    assert_eq!(
        named("auth.gate.fail_fast").as_deref(),
        Some("true"),
        "fail_fast is set at span construction, so a miss here means the \
         on_new_span half of the capture stopped working"
    );

    // The security-critical half, and it was unpinned too: the `hs_session`
    // value is the bearer credential, so it must never reach an attribute.
    // Spans leave the building.
    //
    // Checking the six-character prefix closes TRUNCATION, which is the
    // realistic leak — a `&sid[..8]` on an attribute would sail past a
    // whole-value comparison, and the old canary (`sid-live`) was itself only
    // eight characters, so every prefix long enough to matter was the whole
    // string. Testing the shortest prefix is sufficient for all longer ones:
    // any value containing a prefix of length >= 6 contains the 6-char one too.
    //
    // It cannot detect a HASH, and does not claim to: a digest shares no
    // substring with its input, so no substring test can catch one. That is a
    // real gap in this assertion, stated rather than papered over.
    let canary = &SID[..6];
    for (name, value) in &fields {
        assert!(
            !value.contains(canary),
            "the session id leaked into span attribute {name}"
        );
    }
}
