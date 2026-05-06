//! Actix-web adapter for the RFC 7591 DCR proxy.
//!
//! # Wiring
//!
//! ```rust,ignore
//! use hs_utils::mcp_auth::hydra_dcr_proxy::{HydraDcrProxyConfig, proxy};
//!
//! let dcr_cfg = HydraDcrProxyConfig::new(
//!     "https://sso.hikari-systems.com",
//!     vec!["https://mcp.example.com".to_string()],
//! );
//!
//! App::new()
//!     .app_data(web::Data::new(dcr_cfg))
//!     .route("/dcr/register", web::post().to(proxy));
//! ```

use actix_web::{http::StatusCode, web, HttpResponse};

use super::config::HydraDcrProxyConfig;
use super::dcr_core::forward_register;

/// Actix-web handler for `POST /dcr/register`.
///
/// Register on the `App` using `web::post().to(proxy)` and supply the config
/// via `app_data(web::Data::new(HydraDcrProxyConfig::new(...)))`.
pub async fn proxy(cfg: web::Data<HydraDcrProxyConfig>, body: web::Bytes) -> HttpResponse {
    let resp = forward_register(cfg.get_ref(), &body).await;
    let mut builder = HttpResponse::build(
        StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );
    if let Some(ct) = resp.content_type {
        builder.insert_header(("content-type", ct));
    }
    builder.body(resp.body)
}
