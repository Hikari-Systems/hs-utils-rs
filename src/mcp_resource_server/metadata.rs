//! Axum router for RFC 9728 / OAuth discovery endpoints, mirroring TS
//! `lib/mcp-auth/discovery.ts` + `cimd.ts`:
//!
//! - `GET /.well-known/oauth-protected-resource[/mcp]` — PRM.
//! - `GET /.well-known/oauth-authorization-server` — upstream AS metadata,
//!   field-allowlisted (`sanitizeAsm`), cached via the [`AsmCache`] store
//!   (5-min TTL), `502` on upstream failure, S256 warning.
//! - `GET /.well-known/client-metadata/{client_id}` — CIMD, read through
//!   the [`ClientStore`].
//!
//! Deviation from TS: the PRM `resource` is the configured
//! `resource_server_url` (the Rust crate has no forwarded-host helper);
//! TS derives it from the inbound forwarded host. Functionally equivalent
//! behind a stable public URL.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Map, Value};

use super::config::McpAuthConfig;
use super::stores::{AsmCache, ClientStore};

const ASM_CACHE_TTL_MS: u64 = 5 * 60 * 1000;

const ASM_FIELD_ALLOWLIST: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "service_documentation",
    "ui_locales_supported",
    "op_policy_uri",
    "op_tos_uri",
    "revocation_endpoint",
    "revocation_endpoint_auth_methods_supported",
    "introspection_endpoint",
    "introspection_endpoint_auth_methods_supported",
    "code_challenge_methods_supported",
];

#[derive(Clone)]
pub struct MetadataState {
    pub auth_cfg: Arc<McpAuthConfig>,
    pub asm_cache: Arc<dyn AsmCache>,
    pub clients: Arc<dyn ClientStore>,
    http: reqwest::Client,
}

impl MetadataState {
    pub fn new(
        auth_cfg: Arc<McpAuthConfig>,
        asm_cache: Arc<dyn AsmCache>,
        clients: Arc<dyn ClientStore>,
    ) -> Self {
        Self {
            auth_cfg,
            asm_cache,
            clients,
            http: reqwest::Client::new(),
        }
    }
}

pub fn router(state: MetadataState) -> Router {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(prm_handler))
        .route("/.well-known/oauth-protected-resource/mcp", get(prm_handler))
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
        .map(|s| vec![s.trim_end_matches('/').to_string()])
        .unwrap_or_default();
    json_with_cors(json!({
        "resource": cfg.resource_server_url,
        "authorization_servers": authorization_servers,
        "scopes_supported": cfg.supported_scopes,
        "bearer_methods_supported": ["header"],
    }))
}

fn sanitize_asm(raw: &Value) -> Value {
    let mut out = Map::new();
    if let Some(obj) = raw.as_object() {
        for (k, v) in obj {
            if ASM_FIELD_ALLOWLIST.contains(&k.as_str()) {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(out)
}

async fn as_metadata_handler(State(state): State<MetadataState>) -> Response {
    let as_url = match state
        .auth_cfg
        .authorization_server_url
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => return upstream_error(),
    };
    let upstream = format!("{as_url}/.well-known/oauth-authorization-server");

    if let Some(cached) = state
        .asm_cache
        .get(&upstream, ASM_CACHE_TTL_MS)
        .await
    {
        return json_with_cors(cached);
    }

    let fetched: Value = match state
        .http
        .get(&upstream)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("ASM proxy: parse failed for {upstream}: {err}");
                return upstream_error();
            }
        },
        Ok(resp) => {
            tracing::warn!(
                "ASM proxy: upstream {upstream} returned {}",
                resp.status()
            );
            return upstream_error();
        }
        Err(err) => {
            tracing::warn!("ASM proxy: upstream fetch failed for {upstream}: {err}");
            return upstream_error();
        }
    };

    let sanitized = sanitize_asm(&fetched);
    let s256 = sanitized
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|v| v.as_str() == Some("S256")))
        .unwrap_or(false);
    if !s256 {
        tracing::warn!(
            "ASM proxy: upstream does not advertise PKCE S256; OAuth 2.1 requires it"
        );
    }

    state.asm_cache.set(&upstream, sanitized.clone()).await;
    json_with_cors(sanitized)
}

async fn client_metadata_handler(
    State(state): State<MetadataState>,
    Path(client_id): Path<String>,
) -> Response {
    match state.clients.get(&client_id).await {
        Some(reg) => (StatusCode::OK, Json(serde_json::to_value(reg).unwrap()))
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "error_description": "No client registered with that ID"
            })),
        )
            .into_response(),
    }
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
            "error_description":
                "Could not fetch authorization server metadata from upstream."
        })),
    )
        .into_response()
}
