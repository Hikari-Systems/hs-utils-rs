//! The `auth.login` span must not publish the credentials `callback` is handed.
//!
//! `#[tracing::instrument]` records every argument it is not told to skip, by
//! `Debug`. `callback` takes `HeaderMap` — which carries `cookie:
//! hs_session=<the bearer session id>` — and `Query<CallbackQuery>`, which
//! carries the one-time authorization `code` and the `state`. One keyword,
//! `skip_all`, is the whole of what stands between that span and a token dump.
//!
//! **`skip(wl)` compiles.** `WebLogin` derives `Clone` and not `Debug`, so the
//! obvious "skip the state, keep the rest" spelling type-checks — and it
//! type-checks *because* the other two arguments are `Debug` and are being
//! recorded. Nothing else in the tree catches that: the source lint
//! (`session_store_sid_source_lint.rs`) `include_str!`s only the two store
//! files, and `gate_span.rs` covers `auth.gate`, which wraps `decide` and never
//! sees this handler. Verified by applying that mutation to the shipped
//! attribute: the whole suite stays green, and this file goes red on the sid,
//! the code and the state at once.
//!
//! It lives in `tests/` for the reason `gate_span.rs`'s header sets out at
//! length: `tracing`'s callsite interest cache is process-global while
//! `set_default` is thread-local, so a unit test sharing a binary with tests
//! that drive `callback` without a subscriber can cache `Interest::never` for
//! this callsite and then pass vacuously. Its own binary, one global subscriber.
#![cfg(feature = "web-login")]

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use hs_utils::mcp_resource_server::kratos_resolver::KratosUserResolver;
use hs_utils::web_login::{
    InMemorySessionStore, Session, WebLogin, WebLoginConfig, WebSessionStore,
};
use tower::ServiceExt as _;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

/// The three secrets this handler holds, as uuids so a prefix test means
/// something: a short canary makes truncation undetectable, because every prefix
/// long enough to matter is the whole string.
const SID: &str = "0f9c2b7a-4e51-4a3d-9c6e-1b8d5f2a7c34";
const CODE: &str = "6d3a1e88-2c47-4b90-8f15-a7e0c9d4b621";
const STATE: &str = "b81f5c02-9a6d-47e3-8c14-5f39d2a70e6b";

/// Records every span created and every field set on one, so the assertions can
/// read what would have been exported.
#[derive(Clone, Default)]
struct Captured {
    names: Arc<Mutex<Vec<&'static str>>>,
    fields: Arc<Mutex<Vec<(String, String)>>>,
}

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

/// The two endpoints `callback` calls: the token endpoint and userinfo. stdlib
/// sockets, no new dependency. A copy of the unit tests' stub rather than a
/// shared fixture, because this binary cannot reach into the crate's private
/// test module.
fn oauth_provider_stub() -> String {
    use std::io::{BufRead, BufReader, Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            if len > 0 {
                let mut body = vec![0u8; len];
                let _ = reader.read_exact(&mut body);
            }

            let json = if path.starts_with("/token") {
                r#"{"access_token":"at-1","token_type":"bearer","expires_in":3600,"id_token":"idt-1"}"#
            } else {
                r#"{"sub":"kratos-identity-9"}"#
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            let _ = stream.flush();
        }
    });
    base
}

#[tokio::test]
async fn the_login_span_carries_the_verdict_and_none_of_the_credentials() {
    let captured = Captured::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(captured.clone()))
        .expect("this binary installs exactly one subscriber");

    let base = oauth_provider_stub();
    let cfg = WebLoginConfig::new(
        "client-abc",
        "secret-xyz",
        "https://auth.example.com/oauth2/auth",
        format!("{base}/token"),
        format!("{base}/userinfo"),
        "openid profile email",
    );

    // Seeded through the public `Deserialize` impl: `Session`'s fields are
    // private, and a pending `state` is what makes the success branch reachable.
    let store = Arc::new(InMemorySessionStore::default());
    let sess: Session = serde_json::from_value(serde_json::json!({
        "redirects": { STATE: "/dash?tab=runs" }
    }))
    .expect("session from json");
    store
        .store(SID, &sess)
        .await
        .expect("the in-memory store cannot fail");

    // `fallback: false` keeps the resolver off the network: with no fallback it
    // never fetches, so the unroutable admin URL is never dialled.
    let resolver = Arc::new(KratosUserResolver::new(
        "http://kratos.invalid:4434",
        "https://hikari-systems.com/",
        false,
    ));
    let resp = WebLogin::with_store(cfg, resolver, store)
        .callback_router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/oauth2/callback?code={CODE}&state={STATE}"))
                .header(header::COOKIE, format!("hs_session={SID}"))
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-host", "app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // A login that failed would exercise a different branch and record a
    // different outcome, so this is a precondition of everything below rather
    // than a claim about redirects.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Without this the leak sweep is satisfied by a span that never existed,
    // which is precisely the false green that put this in its own binary.
    assert!(
        captured.names.lock().unwrap().contains(&"auth.login"),
        "auth.login was never recorded, so this run proves nothing about it"
    );

    let fields = captured.fields.lock().unwrap().clone();
    // `Span::record` is last-write-wins, so the LAST match is the faithful read.
    let named = |k: &str| -> Option<String> {
        fields
            .iter()
            .rfind(|(n, _)| n == k)
            .map(|(_, v)| v.trim_matches('"').to_string())
    };

    assert_eq!(
        named("auth.login.outcome").as_deref(),
        Some("success"),
        "the span's whole purpose is the verdict"
    );
    assert_eq!(
        named("user.id").as_deref(),
        Some("kratos-identity-9"),
        "the high-cardinality handle that finds one login out of a million"
    );
    assert!(
        named("session.op").is_none(),
        "session.op belongs to the store-outage outcome and must not be \
         present on a clean login — a field that is present-and-empty on every \
         success defeats the filter an operator reaches for"
    );

    // The security half. Prefixes rather than whole values, because truncation
    // is the realistic leak: `&sid[..8]` on an attribute would sail past a
    // whole-value comparison. Testing the shortest prefix covers every longer
    // one. It cannot detect a HASH — a digest shares no substring with its
    // input — and does not claim to.
    for (canary, what) in [
        (&SID[..6], "the session id (the bearer credential)"),
        (&CODE[..6], "the authorization code (a one-time credential)"),
        (&STATE[..6], "the state (attacker-chosen)"),
    ] {
        for (name, value) in &fields {
            assert!(
                !value.contains(canary),
                "{what} leaked into span attribute {name} = {value}"
            );
        }
    }
}
