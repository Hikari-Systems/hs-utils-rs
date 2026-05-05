//! RFC 7591 Dynamic Client Registration proxy in front of Ory Hydra.
//!
//! Forwards POST `/dcr/register` requests to Hydra's `/oauth2/register` but
//! injects `audience: <allowed_audiences>` into the registered client so MCP
//! clients (e.g. claude.ai) can request audience-scoped tokens via the Ory
//! `audience` parameter at `/oauth2/auth`. Hydra v2 ignores RFC 8707's
//! `resource` parameter; the Ory `audience` parameter is the actual mechanism
//! that flows through to the access token's `aud` claim.
//!
//! Mirrors the TypeScript reference at
//! `hs.utils/lib/mcp-auth/hydraDcrProxy.ts`.
//!
//! # Wiring (actix-web)
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
use serde_json::{json, Value};

/// Config for the DCR proxy. Construct with `HydraDcrProxyConfig::new` and
/// register as `web::Data` on the actix `App`.
#[derive(Clone)]
pub struct HydraDcrProxyConfig {
    upstream: String,
    allowed_audiences: Vec<String>,
    client: reqwest::Client,
}

impl HydraDcrProxyConfig {
    /// Build a new DCR proxy config.
    ///
    /// Panics if `allowed_audiences` is empty — matches the TS contract
    /// (`createHydraDcrProxyHandler` throws synchronously on construction).
    /// Set `mcp:auth:allowedAudiences` to a comma-separated list of MCP
    /// resource URLs the proxy is allowed to register clients for.
    pub fn new(authorization_server_url: impl Into<String>, allowed_audiences: Vec<String>) -> Self {
        if allowed_audiences.is_empty() {
            panic!(
                "HydraDcrProxyConfig::new: allowed_audiences must be non-empty. \
                 Set mcp:auth:allowedAudiences to a comma-separated list of MCP \
                 resource URLs the proxy is allowed to register clients for."
            );
        }
        let url = authorization_server_url.into();
        let upstream = format!("{}/oauth2/register", url.trim_end_matches('/'));
        Self {
            upstream,
            allowed_audiences,
            client: reqwest::Client::new(),
        }
    }

    /// Build with a caller-supplied `reqwest::Client` (e.g. when sharing a
    /// connection pool with other components).
    pub fn with_client(
        authorization_server_url: impl Into<String>,
        allowed_audiences: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        let mut cfg = Self::new(authorization_server_url, allowed_audiences);
        cfg.client = client;
        cfg
    }
}

/// Actix-web handler for `POST /dcr/register`.
///
/// Register on the `App` using `web::post().to(proxy)` and supply the config
/// via `app_data(web::Data::new(HydraDcrProxyConfig::new(...)))`.
pub async fn proxy(cfg: web::Data<HydraDcrProxyConfig>, body: web::Bytes) -> HttpResponse {
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_resp(
                400,
                "invalid_client_metadata",
                Some("Request body must be a JSON object."),
            );
        }
    };

    let mut obj = match parsed {
        Value::Object(m) => m,
        _ => {
            return error_resp(
                400,
                "invalid_client_metadata",
                Some("Request body must be a JSON object."),
            );
        }
    };

    let incoming_audience: Vec<String> = obj
        .remove("audience")
        .and_then(|v| match v {
            Value::Array(arr) => Some(arr),
            _ => None,
        })
        .map(|arr| {
            arr.into_iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let mut audience: Vec<String> = Vec::with_capacity(
        incoming_audience.len() + cfg.allowed_audiences.len(),
    );
    for a in incoming_audience.into_iter().chain(cfg.allowed_audiences.iter().cloned()) {
        if !audience.contains(&a) {
            audience.push(a);
        }
    }

    obj.insert(
        "audience".to_string(),
        Value::Array(audience.into_iter().map(Value::String).collect()),
    );

    let merged_body = match serde_json::to_vec(&Value::Object(obj)) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("DCR proxy serialise merged body failed: {e}");
            return error_resp(500, "internal_error", None);
        }
    };

    let upstream_resp = match cfg
        .client
        .post(&cfg.upstream)
        .header("content-type", "application/json")
        .body(merged_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                "DCR proxy upstream fetch to {} failed: {e}",
                cfg.upstream
            );
            return error_resp(
                502,
                "upstream_unavailable",
                Some("Failed to reach upstream authorization server."),
            );
        }
    };

    let status = upstream_resp.status().as_u16();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("DCR proxy reading upstream body failed: {e}");
            return error_resp(
                502,
                "upstream_unavailable",
                Some("Failed to read upstream response."),
            );
        }
    };

    let mut resp = HttpResponse::build(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );
    if let Some(ct) = content_type {
        resp.insert_header(("content-type", ct));
    }
    resp.body(bytes)
}

fn error_resp(status: u16, error: &str, description: Option<&str>) -> HttpResponse {
    let body = match description {
        Some(d) => json!({ "error": error, "error_description": d }),
        None => json!({ "error": error }),
    };
    HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .content_type("application/json")
        .body(body.to_string())
}
