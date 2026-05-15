//! RFC 7591 Dynamic Client Registration handler.
//!
//! Mirrors the TS `@hikari-systems/hs.utils` `lib/mcp-auth/dcr.ts`
//! `createDcrHandler`: per-IP sliding-window rate limit (5 / 60s),
//! redirect-uri validation (https, or http://localhost|127.0.0.1), a
//! random `client_id`, persisted via the `ClientStore`, returned 201.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};

use super::stores::{ClientRegistration, ClientStore, DcrRateLimitStore};

const RATE_LIMIT_WINDOW_MS: u64 = 60 * 1000;
const RATE_LIMIT_MAX: usize = 5;

#[derive(Clone)]
pub struct DcrState {
    pub clients: Arc<dyn ClientStore>,
    pub rate_limit: Arc<dyn DcrRateLimitStore>,
}

/// Router exposing `POST /register` (mount at the host root, like the TS
/// `app.post('/register', …)`).
pub fn dcr_router(state: DcrState) -> Router {
    Router::new()
        .route("/register", post(handler))
        .with_state(state)
}

fn json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_acceptable_redirect_uri(uri: &str) -> bool {
    match url_parts(uri) {
        Some((scheme, host)) => {
            scheme == "https"
                || (scheme == "http" && (host == "localhost" || host == "127.0.0.1"))
        }
        None => false,
    }
}

// Minimal scheme+host split (no url crate dep). Returns lowercased scheme
// and host. Good enough for the https / http-localhost check.
fn url_parts(uri: &str) -> Option<(String, String)> {
    let (scheme, rest) = uri.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // strip userinfo@ and :port
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

async fn handler(
    State(state): State<DcrState>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    let ip = client_ip(&headers);
    let allowed = state
        .rate_limit
        .record_and_check(&ip, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX)
        .await;
    if !allowed {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "DCR rate limit exceeded; try again shortly.",
        );
    }

    let Some(Json(body)) = body else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Request body must be JSON.",
        );
    };

    let redirect_uris: Vec<String> = match body.get("redirect_uris") {
        Some(Value::Array(arr))
            if !arr.is_empty() && arr.iter().all(|v| v.is_string()) =>
        {
            arr.iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        }
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "redirect_uris must be a non-empty array of strings.",
            )
        }
    };

    if let Some(bad) = redirect_uris
        .iter()
        .find(|u| !is_acceptable_redirect_uri(u))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!(
                "Redirect URI not permitted: {bad}. Use https:// or http://localhost."
            ),
        );
    }

    let client_id = uuid::Uuid::new_v4().to_string();
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let registration = ClientRegistration {
        client_id: client_id.clone(),
        client_id_issued_at: issued_at,
        redirect_uris,
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
    };
    state.clients.set(&client_id, registration.clone()).await;

    (StatusCode::CREATED, Json(registration)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_resource_server::stores::{
        InMemoryClientStore, InMemoryDcrRateLimitStore,
    };

    fn state() -> DcrState {
        DcrState {
            clients: Arc::new(InMemoryClientStore::default()),
            rate_limit: Arc::new(InMemoryDcrRateLimitStore::default()),
        }
    }

    #[test]
    fn redirect_uri_rules() {
        assert!(is_acceptable_redirect_uri("https://app.example/cb"));
        assert!(is_acceptable_redirect_uri("http://localhost:3000/cb"));
        assert!(is_acceptable_redirect_uri("http://127.0.0.1/cb"));
        assert!(!is_acceptable_redirect_uri("http://evil.example/cb"));
        assert!(!is_acceptable_redirect_uri("ftp://x/cb"));
        assert!(!is_acceptable_redirect_uri("not-a-url"));
    }

    #[tokio::test]
    async fn registers_and_persists_client() {
        let st = state();
        let resp = handler(
            State(st.clone()),
            HeaderMap::new(),
            Some(Json(json!({ "redirect_uris": ["https://a/cb"] }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn rejects_bad_redirect() {
        let resp = handler(
            State(state()),
            HeaderMap::new(),
            Some(Json(json!({ "redirect_uris": ["http://evil/cb"] }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rate_limit_blocks_after_max() {
        let st = state();
        for _ in 0..RATE_LIMIT_MAX {
            let r = handler(
                State(st.clone()),
                HeaderMap::new(),
                Some(Json(json!({ "redirect_uris": ["https://a/cb"] }))),
            )
            .await;
            assert_eq!(r.status(), StatusCode::CREATED);
        }
        let blocked = handler(
            State(st.clone()),
            HeaderMap::new(),
            Some(Json(json!({ "redirect_uris": ["https://a/cb"] }))),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
