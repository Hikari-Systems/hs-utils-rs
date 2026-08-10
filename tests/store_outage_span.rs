//! The two span fields a store outage is diagnosed from: `session.op` and
//! `auth.gate.session.load_failed`.
//!
//! Both were added by HIK-241 and neither was asserted anywhere. Delete every
//! `span.record("session.op", …)` in `web_login.rs` **and** the
//! `auth.gate.session.load_failed` record, and the rest of the suite stays
//! green — `login_span.rs` only asserts `session.op` is *absent* on a clean
//! login, which a field nothing ever sets satisfies perfectly. That is the
//! present-and-empty trap inverted: absent-and-never-present.
//!
//! What they are for is telling two identical-looking incidents apart. The
//! gate's read fails open, so on the api tier an outage refuses with
//! `outcome=refused_401 session.present=true` — byte-identical to an expired
//! session, a different incident with a different owner. And
//! `outcome=store_unavailable` alone cannot say whether the store could not be
//! *read* or could not be *written*, which are different failures of a store
//! and, at `callback`, different amounts of lost work.
//!
//! Its own binary, and the reason is `gate_span.rs`'s at length: `tracing`'s
//! callsite interest cache is process-global while `set_default` is
//! thread-local, so a unit test sharing a binary with the many tests that drive
//! `gate` and `callback` with no subscriber can cache `Interest::never` for
//! these callsites and then pass vacuously.
//!
//! **One test function, not five.** The subscriber is global, so parallel
//! `#[tokio::test]`s would interleave their fields into one capture; the drives
//! are sequential and the capture is cleared between them, so a `rfind` cannot
//! read the previous drive's value.
#![cfg(feature = "web-login")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::get,
    Router,
};
use hs_utils::mcp_resource_server::kratos_resolver::KratosUserResolver;
use hs_utils::web_login::{
    gate, InMemorySessionStore, Session, WebLogin, WebLoginConfig, WebSessionStore,
};
use tower::ServiceExt as _;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

const SID: &str = "0f9c2b7a-4e51-4a3d-9c6e-1b8d5f2a7c34";
const STATE: &str = "b81f5c02-9a6d-47e3-8c14-5f39d2a70e6b";

/// One recorded field: the span's **name**, the field's name, the value. The
/// span name is what makes a single capture serve two spans — `auth.gate` and
/// `auth.login` both carry a `session.op`, and reading the wrong one would be a
/// false green.
type Recorded = (&'static str, String, String);

/// Every field set on every span.
#[derive(Clone, Default)]
struct Captured {
    fields: Arc<Mutex<Vec<Recorded>>>,
}

impl Captured {
    /// The last value recorded for `key` on a span named `span`. Last, not
    /// first: `Span::record` is last-write-wins.
    fn field(&self, span: &str, key: &str) -> Option<String> {
        self.fields
            .lock()
            .unwrap()
            .iter()
            .rfind(|(s, k, _)| *s == span && k == key)
            .map(|(_, _, v)| v.trim_matches('"').to_string())
    }
    fn clear(&self) {
        self.fields.lock().unwrap().clear();
    }
}

struct Collect<'a>(&'static str, &'a mut Vec<Recorded>);

impl tracing::field::Visit for Collect<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.1
            .push((self.0, field.name().to_string(), value.to_string()));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.1
            .push((self.0, field.name().to_string(), format!("{value:?}")));
    }
}

impl<S> Layer<S> for Captured
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        let name = attrs.metadata().name();
        attrs.record(&mut Collect(name, &mut self.fields.lock().unwrap()));
    }

    /// The interesting half: every field here is `Empty` at construction and
    /// filled in by `Span::record`, so the name has to be recovered from the
    /// registry rather than from the event.
    fn on_record(&self, id: &tracing::Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let name = span.name();
        values.record(&mut Collect(name, &mut self.fields.lock().unwrap()));
    }
}

/// A store that misbehaves on a chosen `load` call and, optionally, on every
/// `store`. A copy rather than a shared fixture: this binary cannot reach the
/// crate's private test module, which is the same reason `login_span.rs` copies
/// the provider stub.
///
/// `fail_load_nth` is a **1-based call index** because `callback` loads twice
/// and the second read — the re-read that carries a concurrent tab's `state`
/// across the rotation — is a separate branch with its own `session.op`.
struct Misbehaving {
    inner: InMemorySessionStore,
    fail_load_nth: usize,
    fail_store: bool,
    loads: AtomicUsize,
}

impl Misbehaving {
    fn new(fail_load_nth: usize, fail_store: bool) -> Self {
        Self {
            inner: InMemorySessionStore::default(),
            fail_load_nth,
            fail_store,
            loads: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl WebSessionStore for Misbehaving {
    async fn load(&self, sid: &str) -> anyhow::Result<Option<Session>> {
        let nth = self.loads.fetch_add(1, Ordering::SeqCst) + 1;
        if nth == self.fail_load_nth {
            anyhow::bail!("session store load failed (test)");
        }
        self.inner.load(sid).await
    }
    async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()> {
        if self.fail_store {
            anyhow::bail!("session store write failed (test)");
        }
        self.inner.store(sid, session).await
    }
    async fn remove(&self, sid: &str) -> anyhow::Result<()> {
        self.inner.remove(sid).await
    }
}

/// The two endpoints `callback` calls. A copy, for the reason above.
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
                r#"{"access_token":"at-1","refresh_token":"rt-1","token_type":"bearer","expires_in":3600,"id_token":"idt-1"}"#
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

fn login(base: &str) -> WebLoginConfig {
    WebLoginConfig::new(
        "client-abc",
        "secret-xyz",
        "https://auth.example.com/oauth2/auth",
        format!("{base}/token"),
        format!("{base}/userinfo"),
        "openid profile email",
    )
}

/// `fallback: false` keeps the resolver off the network: with no fallback it
/// never fetches, so the unroutable admin URL is never dialled.
fn resolver() -> Arc<KratosUserResolver> {
    Arc::new(KratosUserResolver::new(
        "http://kratos.invalid:4434",
        "https://hikari-systems.com/",
        false,
    ))
}

/// A session holding a pending `state`, which is what makes `callback` reach
/// the token exchange. Seeded through the public `Deserialize` impl, because
/// `Session`'s fields are private.
async fn seeded(store: &Misbehaving) {
    let sess: Session = serde_json::from_value(serde_json::json!({
        "redirects": { STATE: "/dash?tab=runs" }
    }))
    .expect("session from json");
    store
        .inner
        .store(SID, &sess)
        .await
        .expect("the in-memory store cannot fail");
}

fn callback_request() -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/oauth2/callback?code=auth-code&state={STATE}"))
        .header(header::COOKIE, format!("hs_session={SID}"))
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "app.example.com")
        .body(Body::empty())
        .unwrap()
}

fn gated_request() -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/dash")
        // A cookie, or the gate never asks the store anything.
        .header(header::COOKIE, format!("hs_session={SID}"))
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "app.example.com")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn a_store_outage_names_the_operation_that_failed_on_the_span() {
    let captured = Captured::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(captured.clone()))
        .expect("this binary installs exactly one subscriber");

    let base = oauth_provider_stub();

    // ── 1. The gate's fail-open read, api tier ──────────────────────────────
    //
    // The 401 here is indistinguishable from an expired session in every other
    // field the span carries, which is the whole reason `load_failed` exists.
    let store = Arc::new(Misbehaving::new(1, false));
    let wl = WebLogin::with_store(login(&base), resolver(), store);
    let resp = Router::new()
        .route("/dash", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            wl.gate_state(true),
            gate,
        ))
        .oneshot(gated_request())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Without this the assertions below are satisfied by a span that never
    // existed — the false green that put this in its own binary.
    assert_eq!(
        captured.field("auth.gate", "auth.gate.outcome").as_deref(),
        Some("refused_401"),
        "auth.gate was never recorded, so this drive proves nothing about it"
    );
    assert_eq!(
        captured
            .field("auth.gate", "auth.gate.session.load_failed")
            .as_deref(),
        Some("true"),
        "an outage and an expired session both refuse with \
         session.present=true; this field is the only thing that tells them apart"
    );

    // ── 2. The gate's write, browser tier ───────────────────────────────────
    captured.clear();
    let store = Arc::new(Misbehaving::new(0, true));
    let wl = WebLogin::with_store(login(&base), resolver(), store);
    let resp = Router::new()
        .route("/dash", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            wl.gate_state(false),
            gate,
        ))
        .oneshot(gated_request())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        captured.field("auth.gate", "auth.gate.outcome").as_deref(),
        Some("store_unavailable")
    );
    assert_eq!(
        captured.field("auth.gate", "session.op").as_deref(),
        Some("store"),
        "the gate's only fatal store call is the write, and the span must say so"
    );
    assert!(
        captured
            .field("auth.gate", "auth.gate.session.load_failed")
            .is_none(),
        "this store's reads all succeeded — a load_failed here would mean the \
         field is recorded unconditionally"
    );

    // ── 3. `callback`'s first load ──────────────────────────────────────────
    captured.clear();
    let store = Arc::new(Misbehaving::new(1, false));
    seeded(&store).await;
    let resp = WebLogin::with_store(login(&base), resolver(), store)
        .callback_router()
        .oneshot(callback_request())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        captured
            .field("auth.login", "auth.login.outcome")
            .as_deref(),
        Some("store_unavailable"),
        "auth.login was never recorded, so this drive proves nothing about it"
    );
    assert_eq!(
        captured.field("auth.login", "session.op").as_deref(),
        Some("load"),
        "a read outage before the token exchange costs the caller nothing but a \
         retry; the write one below has spent the code"
    );

    // ── 4. `callback`'s RE-READ, the restored second load ───────────────────
    //
    // Same two field values as drive 3, and that is the point: the branch is
    // reached only after the token exchange, so nothing but the call index
    // distinguishes the fixture. Delete the `span.record` in that arm alone and
    // this is the only assertion in the tree that notices.
    captured.clear();
    let store = Arc::new(Misbehaving::new(2, false));
    seeded(&store).await;
    let resp = WebLogin::with_store(login(&base), resolver(), store)
        .callback_router()
        .oneshot(callback_request())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        captured
            .field("auth.login", "auth.login.outcome")
            .as_deref(),
        Some("store_unavailable")
    );
    assert_eq!(
        captured.field("auth.login", "session.op").as_deref(),
        Some("load"),
        "the re-read is a load, not the store below it"
    );
    assert_eq!(
        captured.field("auth.login", "user.id").as_deref(),
        Some("kratos-identity-9"),
        "and past the identity the refusal is attributable, unlike drive 3's"
    );

    // ── 5. `callback`'s rotation write ──────────────────────────────────────
    captured.clear();
    let store = Arc::new(Misbehaving::new(0, true));
    seeded(&store).await;
    let resp = WebLogin::with_store(login(&base), resolver(), store)
        .callback_router()
        .oneshot(callback_request())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        captured
            .field("auth.login", "auth.login.outcome")
            .as_deref(),
        Some("store_unavailable")
    );
    assert_eq!(
        captured.field("auth.login", "session.op").as_deref(),
        Some("store"),
        "this is the expensive one: the code is spent and the user is resolved, \
         so `load` here would send a reader looking at the wrong end of the store"
    );
}
