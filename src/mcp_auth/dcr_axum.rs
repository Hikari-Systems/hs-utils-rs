//! Axum adapter for the RFC 7591 DCR proxy.
//!
//! # Wiring
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use hs_utils::mcp_auth::{HydraDcrProxyConfig, dcr_axum};
//!
//! let dcr_cfg = Arc::new(HydraDcrProxyConfig::new(
//!     "https://sso.hikari-systems.com",
//!     vec!["https://mcp.example.com".to_string()],
//! ));
//!
//! let app = axum::Router::new()
//!     .route("/register", axum::routing::post(dcr_axum::proxy))
//!     .with_state(dcr_cfg);
//! ```

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderValue, StatusCode},
    response::Response,
};

use super::config::HydraDcrProxyConfig;
use super::dcr_core::forward_register;

/// Axum handler for `POST /register`.
///
/// Mount with `Router::new().route("/register", post(proxy)).with_state(cfg)`,
/// where `cfg` is `Arc<HydraDcrProxyConfig>`.
pub async fn proxy(
    State(cfg): State<Arc<HydraDcrProxyConfig>>,
    body: Bytes,
) -> Response {
    let resp = forward_register(&cfg, &body).await;
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    if let Some(ct) = resp.content_type {
        if let Ok(value) = HeaderValue::from_str(&ct) {
            builder = builder.header("content-type", value);
        }
    }
    builder
        .body(Body::from(resp.body))
        .unwrap_or_else(|e| {
            tracing::error!("DCR proxy axum response build failed: {e}");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .expect("empty response always builds")
        })
}
