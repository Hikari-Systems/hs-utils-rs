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
use tracing::Instrument;

use crate::telemetry::{http_client_span, record_error, record_http_client_status, Outbound};

/// Send `request` inside a client span. Behaves exactly like
/// `RequestBuilder::send` otherwise: same result, same errors.
///
/// The span records the URL's path (query values redacted). When the path is
/// itself a credential — a Slack or Discord webhook, a user-supplied "post to
/// this URL" target, an MCP server URL with a key in it — use [`send_opaque`].
pub async fn send(request: RequestBuilder) -> reqwest::Result<Response> {
    send_inner(request, false).await
}

/// As [`send`], but the span records only the origin (`scheme://host:port`):
/// for a URL whose path or query is, or may be, a credential. Still carries
/// `traceparent` — that is a header, and says nothing about the URL.
pub async fn send_opaque(request: RequestBuilder) -> reqwest::Result<Response> {
    send_inner(request, true).await
}

async fn send_inner(request: RequestBuilder, opaque: bool) -> reqwest::Result<Response> {
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
        opaque,
    });
    #[cfg(feature = "otel")]
    crate::otel::inject_span_context(&span, built.headers_mut());

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
/// ```
pub trait SendTraced {
    /// See [`send`].
    fn send_traced(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send;
    /// See [`send_opaque`]: for a URL that is its own credential.
    fn send_traced_opaque(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send;
}

impl SendTraced for RequestBuilder {
    fn send_traced(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send(self)
    }
    fn send_traced_opaque(self) -> impl std::future::Future<Output = reqwest::Result<Response>> + Send {
        send_opaque(self)
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
}
