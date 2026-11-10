//! The one way this crate sends an outbound HTTP request, so every call gets
//! the same client span: `{METHOD} {host}`, the status, a redacted `url.full`
//! and, with the `otel` feature, a `traceparent` header — so the service on
//! the other end continues this trace instead of starting its own.
//!
//! Services on reqwest 0.12 can use it too (it is re-exported as
//! `hs_utils::otel::send`):
//!
//! ```rust,ignore
//! use hs_utils::http_client::SendTraced as _;
//! let resp = state.http.get(&url).header("X-Api-Key", &key).send_traced().await?;
//! // or, as a function:
//! let resp = hs_utils::http_client::send(
//!     state.http.get(format!("{}/api/items/{id}", cfg.data_url)).header("X-Api-Key", &key),
//! ).await?;
//! ```

use reqwest::{RequestBuilder, Response};
use tracing::{Instrument, Level};

use crate::telemetry::{http_client_span, record_error, record_http_client_status, Outbound, UrlRecord};

/// Send `request` inside a client span. Behaves exactly like
/// `RequestBuilder::send` otherwise: same result, same errors.
///
/// The span records the URL's path (query values redacted). When the path is
/// itself a credential — a Slack or Discord webhook, a user-supplied "post to
/// this URL" target, an MCP server URL with a key in it — use [`send_opaque`].
pub async fn send(request: RequestBuilder) -> reqwest::Result<Response> {
    send_with(request, TraceOptions::new()).await
}

/// As [`send`], but the span records only the origin (`scheme://host:port`):
/// for a URL whose path or query is, or may be, a credential. Still carries
/// `traceparent` — that is a header, and says nothing about the URL.
pub async fn send_opaque(request: RequestBuilder) -> reqwest::Result<Response> {
    send_with(request, TraceOptions::new().opaque()).await
}

/// As [`send`], with the client span at `level`. `Level::DEBUG` keeps a hot
/// polling loop's calls out of an `otel.level=info` export while
/// `http.client.request.duration` still counts them; `WARN` and `ERROR` are
/// treated as `INFO`.
pub async fn send_at(request: RequestBuilder, level: Level) -> reqwest::Result<Response> {
    send_with(request, TraceOptions::new().level(level)).await
}

/// [`send_opaque`] at `level`; see [`send_at`].
pub async fn send_opaque_at(request: RequestBuilder, level: Level) -> reqwest::Result<Response> {
    send_with(request, TraceOptions::new().opaque().level(level)).await
}

/// What the client span of one call records, for the cases [`send`] does not
/// cover: its level, and how much of the URL goes on `url.full`.
///
/// ```rust,ignore
/// use hs_utils::http_client::{SendTraced as _, TraceOptions};
/// // A path segment that is a credential: record the route, not the id.
/// http.get(format!("{base}/api/session/{id}"))
///     .send_traced_with(TraceOptions::new().path("/api/session/{id}"))
///     .await?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceOptions {
    level: Level,
    url: UrlChoice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UrlChoice {
    Full,
    Origin,
    Path(String),
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceOptions {
    /// What [`send`] records: an `INFO` span with the path and the query's
    /// parameter names.
    pub fn new() -> Self {
        Self { level: Level::INFO, url: UrlChoice::Full }
    }

    /// The span's level (`DEBUG` for a hot polling loop). `WARN` and `ERROR`
    /// are treated as `INFO`.
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Record only `scheme://host:port`, as [`send_opaque`] does.
    pub fn opaque(mut self) -> Self {
        self.url = UrlChoice::Origin;
        self
    }

    /// Record `path` in place of the request's own — a route template such as
    /// `/api/session/{id}`, when a path segment is a credential. The query's
    /// parameter names are still recorded (never their values). Pass a
    /// constant: it is what the trace store sees.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.url = UrlChoice::Path(path.into());
        self
    }
}

/// Send `request` with the client span `opts` describes; see [`TraceOptions`].
pub async fn send_with(request: RequestBuilder, opts: TraceOptions) -> reqwest::Result<Response> {
    let (client, built) = request.build_split();
    // `mut` is only needed when `otel` injects the trace header.
    #[allow(unused_mut)]
    let mut built = built?;
    let url = built.url();
    let span = http_client_span(Outbound {
        method: built.method().as_str(),
        scheme: url.scheme(),
        host: url.host_str().unwrap_or_default(),
        port: url.port(),
        path: url.path(),
        query: url.query(),
        record: match &opts.url {
            UrlChoice::Full => UrlRecord::Full,
            UrlChoice::Origin => UrlRecord::Origin,
            UrlChoice::Path(p) => UrlRecord::Path(p),
        },
        level: opts.level,
    });
    #[cfg(feature = "otel")]
    crate::otel::inject_outbound_context(&span, built.headers_mut());

    let result = client.execute(built).instrument(span.clone()).await;
    match &result {
        Ok(resp) => record_http_client_status(&span, resp.status().as_u16()),
        Err(e) => record_error(&span, &kind(e)),
    }
    result
}

/// `.send_traced()` on a `RequestBuilder`: [`send`] as a method, so a chained
/// builder needs one word changed rather than re-nesting.
///
/// ```rust,ignore
/// use hs_utils::http_client::SendTraced as _;
/// let resp = http.get(&url).bearer_auth(token).send_traced().await?;
/// let resp = http.get(&poll_url).send_traced_at(tracing::Level::DEBUG).await?;
/// ```
pub trait SendTraced {
    /// See [`send`].
    fn send_traced(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send;
    /// See [`send_opaque`]: for a URL that is its own credential.
    fn send_traced_opaque(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send;

    /// See [`send_at`]: the client span at `level` (`DEBUG` for a hot loop).
    ///
    /// The default (for an implementation outside this crate) ignores
    /// `level`; `RequestBuilder`'s honours it.
    fn send_traced_at(self, level: Level) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send
    where
        Self: Sized,
    {
        let _ = level;
        self.send_traced()
    }

    /// See [`send_opaque_at`].
    ///
    /// The default ignores `level`; `RequestBuilder`'s honours it.
    fn send_traced_opaque_at(self, level: Level) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send
    where
        Self: Sized,
    {
        let _ = level;
        self.send_traced_opaque()
    }

    /// See [`send_with`]. The default records the origin only unless the
    /// options ask for the full URL — it cannot honour a path override, so it
    /// errs towards recording less.
    fn send_traced_with(self, opts: TraceOptions) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send
    where
        Self: Sized + Send,
    {
        let full = opts.url == UrlChoice::Full;
        async move {
            if full {
                self.send_traced().await
            } else {
                self.send_traced_opaque().await
            }
        }
    }
}

impl SendTraced for RequestBuilder {
    fn send_traced(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send(self)
    }
    fn send_traced_opaque(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send_opaque(self)
    }
    fn send_traced_at(self, level: Level) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send_at(self, level)
    }
    fn send_traced_opaque_at(self, level: Level) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send_opaque_at(self, level)
    }
    fn send_traced_with(self, opts: TraceOptions) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send_with(self, opts)
    }
}

/// What kind of failure, without `reqwest::Error`'s `Display` — that includes
/// the full URL, query string and all, which is exactly what `url.full`
/// redacts.
fn kind(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_redirect() {
        "redirect"
    } else if e.is_body() {
        "body"
    } else if e.is_decode() {
        "decode"
    } else if e.is_request() {
        "request"
    } else {
        "error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::test_capture::{capture, install};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-shot HTTP server that answers 503 and hands back what it was sent.
    async fn server() -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn records_the_status_and_redacts_the_query() {
        let cap = capture();
        let _g = install(&cap);
        let (base, srv) = server().await;

        let resp = send(reqwest::Client::new().get(format!("{base}/admin/x?token=SECRET"))).await.unwrap();
        assert_eq!(resp.status(), 503, "send must not change the response");
        let _ = srv.await;

        let rec = cap.lock().unwrap().clone();
        let get = |k: &str| rec.iter().rev().find(|(f, _)| f == k).map(|(_, v)| v.clone());
        assert_eq!(get("http.response.status_code").as_deref(), Some("503"));
        assert_eq!(get("otel.status_code").as_deref(), Some("ERROR"), "a 5xx from the far end is an error");
        let all = rec.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" | ");
        assert!(!all.contains("SECRET"), "query value reached the span: {all}");
    }

    #[tokio::test]
    async fn a_connect_failure_is_recorded_without_the_url() {
        let cap = capture();
        let _g = install(&cap);
        // Port 9 (discard) on loopback: nothing listens, so the connect fails.
        let err = send(reqwest::Client::new().get("http://127.0.0.1:9/x?token=SECRET")).await;
        assert!(err.is_err());
        let rec = cap.lock().unwrap().clone();
        assert!(rec.iter().any(|(k, v)| k == "otel.status_code" && v == "ERROR"));
        assert!(rec.iter().any(|(k, v)| k == "error" && v == "connect"), "{rec:?}");
        assert!(!rec.iter().any(|(_, v)| v.contains("SECRET")), "{rec:?}");
    }

    /// A one-shot server answering 204 that hands back the request head.
    async fn hop() -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n").await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_lowercase()
        });
        (format!("http://{addr}"), handle)
    }

    /// `send_traced_at(DEBUG)` is below an INFO filter; `send_traced()` is not.
    #[tokio::test]
    async fn send_traced_at_debug_is_a_debug_span() {
        use tracing_subscriber::{layer::SubscriberExt, Layer as _};
        let cap = capture();
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(
                crate::telemetry::test_capture::Capture(cap.clone())
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            ),
        );
        let client = reqwest::Client::new();
        let (base, srv) = hop().await;
        let resp = client.get(format!("{base}/poll")).send_traced_at(Level::DEBUG).await.unwrap();
        assert_eq!(resp.status(), 204, "the level must not change the call");
        let _ = srv.await;
        assert!(!cap.lock().unwrap().iter().any(|(k, _)| k == "url.full"), "a DEBUG span passed an INFO filter");

        let (base, srv) = hop().await;
        let _ = client.get(format!("{base}/poll")).send_traced_opaque_at(Level::INFO).await.unwrap();
        let _ = srv.await;
        let rec = cap.lock().unwrap().clone();
        let url = rec.iter().find(|(k, _)| k == "url.full").map(|(_, v)| v.as_str());
        assert_eq!(url, Some(base.as_str()), "opaque at INFO: the origin only");
    }

    /// `send_traced_with(path)` records the template, never the id.
    #[tokio::test]
    async fn send_traced_with_a_path_records_the_template() {
        let cap = capture();
        let _g = install(&cap);
        let (base, srv) = hop().await;
        let _ = reqwest::Client::new()
            .delete(format!("{base}/api/session/SESSION_SECRET"))
            .send_traced_with(TraceOptions::new().path("/api/session/{id}"))
            .await
            .unwrap();
        assert!(srv.await.unwrap().starts_with("delete /api/session/session_secret "), "the request itself is untouched");
        let rec = cap.lock().unwrap().clone();
        assert!(!rec.iter().any(|(_, v)| v.contains("SESSION_SECRET")), "{rec:?}");
        assert_eq!(
            rec.iter().find(|(k, _)| k == "url.full").map(|(_, v)| v.clone()),
            Some(format!("{base}/api/session/{{id}}"))
        );
    }

    /// Through the real export layer at `info`: a DEBUG client span is not
    /// exported, and the `traceparent` it sends is its caller's, so the far
    /// end still continues the caller's trace.
    #[cfg(feature = "otel")]
    #[tokio::test]
    async fn a_debug_call_is_not_exported_but_still_continues_the_trace() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::{layer::SubscriberExt, Layer as _};

        opentelemetry::global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(
                tracing_opentelemetry::layer()
                    .with_tracer(provider.tracer("test"))
                    .with_filter(tracing_subscriber::EnvFilter::new("info")),
            ),
        );

        let (base, srv) = hop().await;
        async { reqwest::Client::new().get(format!("{base}/poll")).send_traced_at(Level::DEBUG).await.unwrap() }
            .instrument(tracing::info_span!("poll.loop"))
            .await;
        let req = srv.await.unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let names: Vec<&str> = spans.iter().map(|s| s.name.as_ref()).collect();
        assert_eq!(names, ["poll.loop"], "the DEBUG client span must not be exported at info");
        let caller = &spans[0].span_context;
        let want = format!("traceparent: 00-{}-{}-01", caller.trace_id(), caller.span_id());
        assert!(req.contains(&want), "want {want} in {req}");
    }
}
