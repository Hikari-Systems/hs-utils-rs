//! Axum middleware that turns a Bearer access token into an `AuthExtension`
//! attached to the request, or rejects with 401 + RFC 9728 `WWW-Authenticate`
//! pointing at the resource's PRM URL.
//!
//! Mirrors the behaviour of `applyMcpAuth` in `@hikari-systems/hs.utils`,
//! plus the `userResolver` step.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use uuid::Uuid;

use super::claims::OauthProfile;
use super::config::McpAuthConfig;
use super::jwt::JwtVerifier;
use super::user_resolver::ClaimsUserResolver;

/// Per-request auth context attached to the axum request extensions.
#[derive(Debug, Clone)]
pub struct AuthExtension {
    pub user_id: Option<Uuid>,
    pub profile: Option<OauthProfile>,
    pub sub: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}

/// Shared state passed into the auth middleware. Construct once at startup
/// and clone (cheap — it's all `Arc`s).
#[derive(Clone)]
pub struct AuthState {
    pub verifier: Arc<JwtVerifier>,
    pub resolver: Arc<ClaimsUserResolver>,
    pub auth_cfg: Arc<McpAuthConfig>,
}

/// Axum middleware fn. Wire with
/// `axum::middleware::from_fn_with_state(state, auth_middleware)`.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let token = match extract_bearer(&request) {
        Some(t) => t,
        None => return unauthorized(&state.auth_cfg, "missing Bearer token"),
    };

    let claims = match state.verifier.verify(&token).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!("JWT verification failed: {err:#}");
            return unauthorized(&state.auth_cfg, "invalid_token");
        }
    };

    let resolved = state.resolver.resolve(&claims.raw).await;

    let scopes = claims.scopes();
    let extension = AuthExtension {
        user_id: resolved.as_ref().map(|r| r.user_id),
        profile: resolved.as_ref().map(|r| r.profile.clone()),
        sub: Some(claims.sub.clone()),
        client_id: claims.client_id.clone(),
        scopes: scopes.clone(),
    };

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    tracing::debug!(
        target: "auth",
        "{method} {path} userId={user} email={email} name={name} sub={sub} client={client} scopes={scopes}",
        user = extension.user_id.map(|u| u.to_string()).unwrap_or_else(|| "-".to_string()),
        email = extension.profile.as_ref().and_then(|p| p.email.clone()).unwrap_or_else(|| "-".to_string()),
        name = extension.profile.as_ref().and_then(|p| p.name.clone()).unwrap_or_else(|| "-".to_string()),
        sub = extension.sub.as_deref().unwrap_or("-"),
        client = extension.client_id.as_deref().unwrap_or("-"),
        scopes = scopes.join(","),
    );

    request.extensions_mut().insert(extension);
    next.run(request).await
}

fn extract_bearer(req: &Request<Body>) -> Option<String> {
    let header = req.headers().get(header::AUTHORIZATION)?;
    let raw = header.to_str().ok()?.trim();
    let prefix = "Bearer ";
    if raw.len() <= prefix.len() {
        return None;
    }
    if !raw[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let token = raw[prefix.len()..].trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn unauthorized(cfg: &McpAuthConfig, error_code: &str) -> Response {
    let prm_url = format!(
        "{}/.well-known/oauth-protected-resource",
        cfg.resource_server_url.trim_end_matches('/')
    );
    let www_authenticate = format!(
        "Bearer realm=\"{}\", error=\"{}\", resource_metadata=\"{}\"",
        cfg.resource_server_url, error_code, prm_url
    );

    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": error_code })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&www_authenticate) {
        resp.headers_mut().insert("www-authenticate", value);
    }
    resp
}
