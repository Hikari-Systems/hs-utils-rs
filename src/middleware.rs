//! Actix-web middleware shared across hs services.
//!
//! # Request timing
//!
//! ```rust,ignore
//! App::new()
//!     .wrap(hs_utils::middleware::timing())
//!     // ...
//! ```
//!
//! # API key guard
//!
//! ```rust,ignore
//! let api_key = cfg.server.api_key.clone().unwrap_or_default();
//! App::new()
//!     .wrap(hs_utils::middleware::ApiKey(api_key))
//!     // ...
//! ```

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    HttpResponse,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::rc::Rc;

// ── Timing ───────────────────────────────────────────────────────────────────

/// Returns a pre-configured `actix_web::middleware::Logger` that logs each
/// request as `METHOD /path → STATUS (Xms)`.
///
/// Bridges to `tracing` via the `tracing-log` compatibility layer that
/// `tracing_subscriber` installs — no extra setup needed.
pub fn timing() -> actix_web::middleware::Logger {
    actix_web::middleware::Logger::new("%r → %s (%D ms)")
}

// ── forwardedFor ─────────────────────────────────────────────────────────────

/// Extracted protocol, host, and URLs from `X-Forwarded-*` headers (or the
/// request itself when running without a reverse proxy).
///
/// Mirrors the `forwardedFor` helper in the TypeScript `hs.utils` package.
#[derive(Debug, Clone)]
pub struct ForwardedInfo {
    /// e.g. `https://api.example.com`
    pub base_url: String,
    /// `base_url` + the original request path + query string
    pub full_url: String,
}

/// Extract forwarded connection info from a request.
///
/// Reads `X-Forwarded-Proto`, `X-Forwarded-Port`, and `X-Forwarded-Host`
/// (with an optional `x_prefix` prepended to each header name, e.g.
/// `"my-"` → `X-My-Forwarded-Proto`).  Falls back to the request's own
/// protocol/host when the headers are absent.
pub fn forwarded_for(req: &ServiceRequest, x_prefix: &str) -> ForwardedInfo {
    let headers = req.headers();

    let proto_key = format!("x-{x_prefix}forwarded-proto");
    let port_key = format!("x-{x_prefix}forwarded-port");
    let host_key = format!("x-{x_prefix}forwarded-host");

    let conn = req.connection_info().clone();
    let protocol = headers
        .get(&proto_key)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| conn.scheme())
        .to_owned();

    let default_port = if protocol == "https" { "443" } else { "80" };
    let port = headers
        .get(&port_key)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(default_port)
        .to_owned();

    let host = headers
        .get(&host_key)
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("")
        .to_owned();

    let is_standard = (protocol == "https" && port == "443")
        || (protocol == "http" && port == "80");
    let port_suffix = if is_standard {
        String::new()
    } else {
        format!(":{port}")
    };

    let base_url = format!("{protocol}://{host}{port_suffix}");
    let full_url = format!("{base_url}{}", req.uri());

    ForwardedInfo { base_url, full_url }
}

// ── API key ───────────────────────────────────────────────────────────────────

/// Actix-web middleware that validates the `X-Api-Key` request header.
///
/// - If the key is an empty string, the middleware allows all requests and
///   logs a warning (matches the TS behaviour for unconfigured deployments).
/// - Otherwise, requests without a matching `X-Api-Key` header receive
///   `401 Unauthorized`.
///
/// # Usage
///
/// ```rust,ignore
/// App::new()
///     .wrap(hs_utils::middleware::ApiKey("my-secret-key".into()))
/// ```
pub struct ApiKey(pub String);

pub struct ApiKeyMiddleware<S> {
    service: Rc<S>,
    key: String,
}

impl<S, B> Transform<S, ServiceRequest> for ApiKey
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = ApiKeyMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ApiKeyMiddleware {
            service: Rc::new(service),
            key: self.0.clone(),
        }))
    }
}

impl<S, B> Service<ServiceRequest> for ApiKeyMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let key = self.key.clone();
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            if key.is_empty() {
                tracing::warn!("server.apiKey not configured — all requests permitted");
                return service.call(req).await.map(|r| r.map_into_left_body());
            }

            let provided = req
                .headers()
                .get("X-Api-Key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if provided == key {
                service.call(req).await.map(|r| r.map_into_left_body())
            } else {
                let (req, _) = req.into_parts();
                let resp = HttpResponse::Unauthorized().body("Unauthorized: invalid API key");
                Ok(ServiceResponse::new(req, resp).map_into_right_body())
            }
        })
    }
}
