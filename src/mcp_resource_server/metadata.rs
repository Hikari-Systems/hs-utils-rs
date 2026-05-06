//! Axum router for RFC 9728 / OAuth discovery endpoints:
//!
//! - `GET /.well-known/oauth-protected-resource[/mcp]` — Protected Resource
//!   Metadata, advertises the resource URL, supported scopes, and the AS the
//!   client should hit for tokens.
//! - `GET /.well-known/oauth-authorization-server` — proxied + cached
//!   forward of the upstream issuer's AS metadata.
//! - `GET /.well-known/client-metadata/{client_id}` — best-effort echo of
//!   the registered client metadata (kept for parity with the TS surface;
//!   in this crate it returns 404 unless an external store is wired up).

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::config::McpAuthConfig;

const AS_METADATA_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct MetadataState {
    pub auth_cfg: Arc<McpAuthConfig>,
    as_cache: Arc<Mutex<Option<(Instant, Value)>>>,
    http: reqwest::Client,
}

impl MetadataState {
    pub fn new(auth_cfg: Arc<McpAuthConfig>) -> Self {
        Self::with_client(auth_cfg, reqwest::Client::new())
    }

    pub fn with_client(auth_cfg: Arc<McpAuthConfig>, http: reqwest::Client) -> Self {
        Self {
            auth_cfg,
            as_cache: Arc::new(Mutex::new(None)),
            http,
        }
    }
}

pub fn router(state: MetadataState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(prm_handler),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(prm_handler),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(as_metadata_handler),
        )
        .route(
            "/.well-known/client-metadata/{client_id}",
            get(client_metadata_handler),
        )
        .with_state(state)
}

async fn prm_handler(State(state): State<MetadataState>) -> Response {
    let cfg = &state.auth_cfg;
    let authorization_servers: Vec<String> = cfg
        .authorization_server_url
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| vec![s.clone()])
        .unwrap_or_default();
    let body = json!({
        "resource": cfg.resource_server_url,
        "authorization_servers": authorization_servers,
        "scopes_supported": cfg.supported_scopes,
        "bearer_methods_supported": ["header"],
        "resource_documentation": cfg.resource_server_url,
    });
    json_with_cors(body)
}

async fn as_metadata_handler(State(state): State<MetadataState>) -> Response {
    {
        let guard = state.as_cache.lock().await;
        if let Some((ts, body)) = guard.as_ref() {
            if ts.elapsed() < AS_METADATA_TTL {
                return json_with_cors(body.clone());
            }
        }
    }

    let as_url = match state
        .auth_cfg
        .authorization_server_url
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => return upstream_error(),
    };
    let url = format!("{as_url}/.well-known/oauth-authorization-server");

    let fetched: Value = match state.http.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(err) => {
                tracing::error!("AS metadata parse failed for {url}: {err:#}");
                return upstream_error();
            }
        },
        Ok(resp) => {
            tracing::error!("AS metadata fetch from {url} returned {}", resp.status());
            return upstream_error();
        }
        Err(err) => {
            tracing::error!("AS metadata fetch failed for {url}: {err:#}");
            return upstream_error();
        }
    };

    {
        let mut guard = state.as_cache.lock().await;
        *guard = Some((Instant::now(), fetched.clone()));
    }
    json_with_cors(fetched)
}

async fn client_metadata_handler(
    State(_state): State<MetadataState>,
    Path(_client_id): Path<String>,
) -> Response {
    // Without a DCR registration store wired up locally, we can't return
    // per-client metadata. Returning 404 is the documented fallback.
    (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown_client" }))).into_response()
}

fn json_with_cors(body: Value) -> Response {
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

fn upstream_error() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": "upstream_unavailable",
            "error_description": "Failed to reach upstream authorization server."
        })),
    )
        .into_response()
}
