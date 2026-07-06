//! mcp-data-service-backed [`rmcp` `SessionStore`] for cross-replica
//! streamable-HTTP session recovery.
//!
//! Set on `StreamableHttpServerConfig::session_store` (keeping
//! `stateful_mode = true`): when a request hits a replica that doesn't hold the
//! live session, rmcp calls `load` and restores the session locally from the
//! stored `initialize` params instead of returning "Session not found".
//!
//! Routes (mcp-data-service):
//!   - `GET    /api/mcpSession/{id}`  → 200 `{ "initializeParams": {…} }` | 204/404
//!   - `PUT    /api/mcpSession/{id}`  body `{ "initializeParams": {…}, "ttlMs": <n> }`
//!   - `DELETE /api/mcpSession/{id}`
//!
//! Matches the db_stores.rs posture: fail-open (reads → `Ok(None)`, writes
//! logged-and-swallowed) so a mcp-data-service outage degrades to
//! replica-local sessions rather than 500-ing every request.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use rmcp::model::InitializeRequestParams;
use rmcp::transport::streamable_http_server::session::store::{
    SessionState, SessionStore, SessionStoreError,
};

use super::config::McpAuthConfig;
use super::db_stores::{enc, McpDataServiceClient};

/// Default session TTL refreshed on every `store` (24h).
const DEFAULT_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// GET body shape — `{ "initializeParams": {…} }`.
#[derive(Deserialize)]
struct RawSession {
    #[serde(rename = "initializeParams")]
    initialize_params: InitializeRequestParams,
}

/// rmcp `SessionStore` backed by mcp-data-service.
pub struct DbSessionStore {
    client: McpDataServiceClient,
    ttl_ms: u64,
}

impl DbSessionStore {
    pub fn new(client: McpDataServiceClient) -> Self {
        Self {
            client,
            ttl_ms: DEFAULT_TTL_MS,
        }
    }

    pub fn with_ttl_ms(client: McpDataServiceClient, ttl_ms: u64) -> Self {
        Self { client, ttl_ms }
    }

    /// Build from the resource-server auth config (reuses its
    /// `mcp_data_service_url` + `mcp_data_service_api_key`).
    pub fn from_config(cfg: &McpAuthConfig) -> Self {
        Self::new(McpDataServiceClient::new(
            cfg.mcp_data_service.url.clone(),
            cfg.mcp_data_service.api_key.clone(),
        ))
    }
}

#[async_trait]
impl SessionStore for DbSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        let path = format!("/api/mcpSession/{}", enc(session_id));
        let Some((status, bytes)) = self.client.req("GET", &path, None).await else {
            return Ok(None); // transport failure → fail-open
        };
        if !(200..300).contains(&status) {
            return Ok(None); // 204/404/error → absent
        }
        match serde_json::from_slice::<RawSession>(&bytes) {
            Ok(raw) => Ok(Some(SessionState::new(raw.initialize_params))),
            Err(e) => {
                tracing::error!("mcpSession {session_id}: malformed stored payload: {e}");
                Ok(None)
            }
        }
    }

    async fn store(&self, session_id: &str, state: &SessionState) -> Result<(), SessionStoreError> {
        let path = format!("/api/mcpSession/{}", enc(session_id));
        let body = json!({
            "initializeParams": state.initialize_params,
            "ttlMs": self.ttl_ms,
        });
        let _ = self.client.req("PUT", &path, Some(body)).await; // logged+swallowed
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let path = format!("/api/mcpSession/{}", enc(session_id));
        let _ = self.client.req("DELETE", &path, None).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_resource_server::db_stores::HttpTransport;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    struct StubTransport {
        calls: Mutex<Vec<(String, String, Option<Value>)>>,
        response: Mutex<(u16, Value)>,
    }
    impl StubTransport {
        fn new(status: u16, body: Value) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                response: Mutex::new((status, body)),
            })
        }
    }
    #[async_trait]
    impl HttpTransport for StubTransport {
        async fn request(
            &self,
            method: &str,
            url: &str,
            _api_key: &str,
            body: Option<Value>,
        ) -> Option<(u16, Vec<u8>)> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), url.to_string(), body));
            let (s, v) = self.response.lock().unwrap().clone();
            Some((s, serde_json::to_vec(&v).unwrap()))
        }
    }

    fn params_json() -> Value {
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1.0.0" }
        })
    }

    fn store_with(t: Arc<StubTransport>) -> DbSessionStore {
        DbSessionStore::new(McpDataServiceClient::with_transport("http://mds:3000/", "k", t))
    }

    #[tokio::test]
    async fn load_200_maps_initialize_params() {
        let t = StubTransport::new(200, json!({ "initializeParams": params_json() }));
        let s = store_with(t.clone());
        let got = s.load("sid 1").await.unwrap();
        assert!(got.is_some());
        // space in the id is percent-encoded into the path.
        assert!(t.calls.lock().unwrap()[0].1.contains("/api/mcpSession/sid%201"));
    }

    #[tokio::test]
    async fn load_404_is_none() {
        let t = StubTransport::new(404, json!({}));
        assert!(store_with(t).load("x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn store_puts_initialize_params_and_ttl() {
        let t = StubTransport::new(200, json!({}));
        let s = store_with(t.clone());
        let state = SessionState::new(
            serde_json::from_value::<InitializeRequestParams>(params_json()).unwrap(),
        );
        s.store("sid", &state).await.unwrap();
        let calls = t.calls.lock().unwrap();
        assert_eq!(calls[0].0, "PUT");
        assert!(calls[0].1.ends_with("/api/mcpSession/sid"));
        let body = calls[0].2.as_ref().unwrap();
        assert!(body.get("initializeParams").is_some());
        assert!(body.get("ttlMs").is_some());
    }

    #[tokio::test]
    async fn delete_issues_delete() {
        let t = StubTransport::new(200, json!({}));
        let s = store_with(t.clone());
        s.delete("sid").await.unwrap();
        assert_eq!(t.calls.lock().unwrap()[0].0, "DELETE");
    }
}
