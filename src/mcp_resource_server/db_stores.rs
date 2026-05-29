//! mcp-data-service-backed store implementations.
//!
//! Mirrors the TypeScript `@hikari-systems/hs.utils`
//! `lib/mcp-auth/dbStores.ts` line-for-line. All requests carry the
//! `X-Api-Key` header; the base URL defaults to
//! `http://mcp-data-service:3000`. Routes:
//!   - ClientStore  `GET/PUT /api/mcpClient/{id}` (204/404 → none)
//!   - DcrRateLimit `POST /api/mcpDcrAttempt/recordAndCheck`
//!     `{ip,windowMs,max}` → `{allowed}`
//!   - JwksCache    `GET /api/mcpJwksCache/byAuthServer?authServerUrl=`,
//!     `PUT /api/mcpJwksCache/byAuthServer`
//!   - AsmCache     `GET /api/mcpAsmCache/byUri?asmUri=&ttlMs=`,
//!     `PUT /api/mcpAsmCache/byUri`
//!
//! The TS impls *throw* on a hard (non-204/404) error. The Rust store
//! traits return `Option`/`bool`/`()`, so a hard error is logged and the
//! call degrades: reads → `None`, `record_and_check` → `false`
//! (fail-closed: a DCR attempt is denied if the limiter is unreachable),
//! writes → swallowed-after-log. This keeps a mcp-data-service outage
//! from 500-ing every request while still surfacing in logs.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use super::stores::{
    AsmCache, ClientRegistration, ClientStore, DcrRateLimitStore, JsonWebKeySet,
    JwksCacheEntry, JwksCacheStore,
};

pub const DEFAULT_MCP_DATA_SERVICE_URL: &str = "http://mcp-data-service:3000";

/// Pluggable HTTP transport so the Db stores are unit-testable without a
/// live mcp-data-service (production impl is reqwest-backed).
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Perform a request. `body` is a JSON value when present. Returns
    /// `(status, body_bytes)` or `None` on a transport-level failure.
    async fn request(
        &self,
        method: &str,
        url: &str,
        api_key: &str,
        body: Option<Value>,
    ) -> Option<(u16, Vec<u8>)>;
}

/// Production reqwest transport.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn request(
        &self,
        method: &str,
        url: &str,
        api_key: &str,
        body: Option<Value>,
    ) -> Option<(u16, Vec<u8>)> {
        let m = reqwest::Method::from_bytes(method.as_bytes()).ok()?;
        let mut req = self.client.request(m, url).header("X-Api-Key", api_key);
        if let Some(b) = body {
            req = req.header("Content-Type", "application/json").json(&b);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                Some((status, bytes))
            }
            Err(err) => {
                tracing::error!("mcp-data-service request to {url} failed: {err}");
                None
            }
        }
    }
}

/// Percent-encode a URL component (mirrors TS `encodeURIComponent`).
pub(crate) fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Shared mcp-data-service connection (base URL + api key + transport).
#[derive(Clone)]
pub struct McpDataServiceClient {
    base_url: String,
    api_key: String,
    transport: std::sync::Arc<dyn HttpTransport>,
}

impl McpDataServiceClient {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self::with_transport(
            base_url,
            api_key,
            std::sync::Arc::new(ReqwestTransport::default()),
        )
    }

    pub fn with_transport(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        transport: std::sync::Arc<dyn HttpTransport>,
    ) -> Self {
        let base = base_url.into();
        let base = base.trim().trim_end_matches('/').to_string();
        Self {
            base_url: if base.is_empty() {
                DEFAULT_MCP_DATA_SERVICE_URL.to_string()
            } else {
                base
            },
            api_key: api_key.into().trim().to_string(),
            transport,
        }
    }

    fn url(&self, path_and_query: &str) -> String {
        if path_and_query.starts_with('/') {
            format!("{}{}", self.base_url, path_and_query)
        } else {
            format!("{}/{}", self.base_url, path_and_query)
        }
    }

    pub(crate) async fn req(
        &self,
        method: &str,
        path_and_query: &str,
        body: Option<Value>,
    ) -> Option<(u16, Vec<u8>)> {
        let url = self.url(path_and_query);
        let res = self
            .transport
            .request(method, &url, &self.api_key, body)
            .await;
        if let Some((status, bytes)) = &res {
            if *status != 204 && *status != 404 && !(200..300).contains(status) {
                let snippet: String = String::from_utf8_lossy(bytes)
                    .chars()
                    .take(500)
                    .collect();
                tracing::error!(
                    "mcp-data-service HTTP {status} for {url}: {snippet}"
                );
            }
        }
        res
    }
}

// ─── ClientStore ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RawMcpClient {
    client_id: String,
    #[serde(default)]
    client_id_issued_at: i64,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    response_types: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: String,
}

pub struct DbClientStore {
    c: McpDataServiceClient,
}
impl DbClientStore {
    pub fn new(c: McpDataServiceClient) -> Self {
        Self { c }
    }
}

#[async_trait]
impl ClientStore for DbClientStore {
    async fn get(&self, id: &str) -> Option<ClientRegistration> {
        let path = format!("/api/mcpClient/{}", enc(id));
        let (status, bytes) = self.c.req("GET", &path, None).await?;
        if status == 204 || status == 404 || !(200..300).contains(&status) {
            return None;
        }
        let raw: RawMcpClient = serde_json::from_slice(&bytes).ok()?;
        Some(ClientRegistration {
            client_id: raw.client_id,
            client_id_issued_at: raw.client_id_issued_at,
            redirect_uris: raw.redirect_uris,
            grant_types: raw.grant_types,
            response_types: raw.response_types,
            token_endpoint_auth_method: raw.token_endpoint_auth_method,
        })
    }

    async fn set(&self, id: &str, reg: ClientRegistration) {
        let path = format!("/api/mcpClient/{}", enc(id));
        let body = json!({
            "client_id_issued_at": reg.client_id_issued_at,
            "redirect_uris": reg.redirect_uris,
            "grant_types": reg.grant_types,
            "response_types": reg.response_types,
            "token_endpoint_auth_method": reg.token_endpoint_auth_method,
        });
        let _ = self.c.req("PUT", &path, Some(body)).await;
    }
}

// ─── DcrRateLimitStore ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AllowedResp {
    #[serde(default)]
    allowed: bool,
}

pub struct DbDcrRateLimitStore {
    c: McpDataServiceClient,
}
impl DbDcrRateLimitStore {
    pub fn new(c: McpDataServiceClient) -> Self {
        Self { c }
    }
}

#[async_trait]
impl DcrRateLimitStore for DbDcrRateLimitStore {
    async fn record_and_check(&self, ip: &str, window_ms: u64, max: usize) -> bool {
        let body = json!({ "ip": ip, "windowMs": window_ms, "max": max });
        let Some((status, bytes)) = self
            .c
            .req("POST", "/api/mcpDcrAttempt/recordAndCheck", Some(body))
            .await
        else {
            return false; // fail-closed: deny when the limiter is unreachable
        };
        if !(200..300).contains(&status) {
            return false;
        }
        serde_json::from_slice::<AllowedResp>(&bytes)
            .map(|r| r.allowed)
            .unwrap_or(false)
    }
}

// ─── JwksCacheStore ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RawJwksCacheEntry {
    jwks_uri: String,
    jwks_document: JsonWebKeySet,
}

pub struct DbJwksCacheStore {
    c: McpDataServiceClient,
}
impl DbJwksCacheStore {
    pub fn new(c: McpDataServiceClient) -> Self {
        Self { c }
    }
}

#[async_trait]
impl JwksCacheStore for DbJwksCacheStore {
    async fn get(&self, auth_server_url: &str) -> Option<JwksCacheEntry> {
        let path = format!(
            "/api/mcpJwksCache/byAuthServer?authServerUrl={}",
            enc(auth_server_url)
        );
        let (status, bytes) = self.c.req("GET", &path, None).await?;
        if status == 204 || status == 404 || !(200..300).contains(&status) {
            return None;
        }
        let raw: RawJwksCacheEntry = serde_json::from_slice(&bytes).ok()?;
        Some(JwksCacheEntry {
            jwks_uri: raw.jwks_uri,
            jwks: raw.jwks_document,
        })
    }

    async fn set(&self, auth_server_url: &str, jwks_uri: &str, jwks: JsonWebKeySet) {
        let body = json!({
            "auth_server_url": auth_server_url,
            "jwks_uri": jwks_uri,
            "jwks_document": jwks,
        });
        let _ = self
            .c
            .req("PUT", "/api/mcpJwksCache/byAuthServer", Some(body))
            .await;
    }
}

// ─── AsmCache ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RawAsmCacheEntry {
    body: Value,
}

pub struct DbAsmCache {
    c: McpDataServiceClient,
}
impl DbAsmCache {
    pub fn new(c: McpDataServiceClient) -> Self {
        Self { c }
    }
}

#[async_trait]
impl AsmCache for DbAsmCache {
    async fn get(&self, asm_uri: &str, ttl_ms: u64) -> Option<Value> {
        let path = format!(
            "/api/mcpAsmCache/byUri?asmUri={}&ttlMs={}",
            enc(asm_uri),
            ttl_ms
        );
        let (status, bytes) = self.c.req("GET", &path, None).await?;
        if status == 204 || status == 404 || !(200..300).contains(&status) {
            return None;
        }
        let raw: RawAsmCacheEntry = serde_json::from_slice(&bytes).ok()?;
        Some(raw.body)
    }

    async fn set(&self, asm_uri: &str, body: Value) {
        let payload = json!({ "asm_uri": asm_uri, "body": body });
        let _ = self
            .c
            .req("PUT", "/api/mcpAsmCache/byUri", Some(payload))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records calls and replays a canned `(status, json)` per request.
    struct StubTransport {
        calls: Mutex<Vec<(String, String, Option<Value>)>>,
        response: Mutex<(u16, Value)>,
    }
    impl StubTransport {
        fn new(status: u16, body: Value) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
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

    fn client(t: std::sync::Arc<StubTransport>) -> McpDataServiceClient {
        McpDataServiceClient::with_transport("http://mds:3000/", "k", t)
    }

    #[tokio::test]
    async fn default_base_url_when_empty() {
        let t = StubTransport::new(204, json!({}));
        let c = McpDataServiceClient::with_transport("", "k", t.clone());
        let _ = DbAsmCache::new(c).get("u", 1).await;
        assert!(t.calls.lock().unwrap()[0]
            .1
            .starts_with(DEFAULT_MCP_DATA_SERVICE_URL));
    }

    #[tokio::test]
    async fn client_store_get_maps_raw() {
        let t = StubTransport::new(
            200,
            json!({
                "client_id": "c1",
                "client_id_issued_at": 7,
                "redirect_uris": ["https://x/cb"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none"
            }),
        );
        let s = DbClientStore::new(client(t.clone()));
        let r = s.get("c 1").await.unwrap();
        assert_eq!(r.client_id, "c1");
        assert_eq!(r.client_id_issued_at, 7);
        // space percent-encoded into the path.
        assert!(t.calls.lock().unwrap()[0].1.contains("/api/mcpClient/c%201"));
    }

    #[tokio::test]
    async fn client_store_get_404_is_none() {
        let t = StubTransport::new(404, json!({}));
        let s = DbClientStore::new(client(t));
        assert!(s.get("x").await.is_none());
    }

    #[tokio::test]
    async fn rate_limit_reads_allowed_and_fails_closed() {
        let t = StubTransport::new(200, json!({ "allowed": true }));
        let s = DbDcrRateLimitStore::new(client(t));
        assert!(s.record_and_check("ip", 1000, 5).await);

        let t2 = StubTransport::new(500, json!({}));
        let s2 = DbDcrRateLimitStore::new(client(t2));
        assert!(!s2.record_and_check("ip", 1000, 5).await);
    }

    #[tokio::test]
    async fn jwks_get_maps_and_set_shapes_body() {
        let t = StubTransport::new(
            200,
            json!({ "jwks_uri": "https://as/jwks",
                    "jwks_document": { "keys": [{ "kid": "k" }] } }),
        );
        let s = DbJwksCacheStore::new(client(t.clone()));
        let e = s.get("https://as").await.unwrap();
        assert_eq!(e.jwks_uri, "https://as/jwks");
        assert_eq!(e.jwks.keys.len(), 1);

        s.set("https://as", "https://as/jwks", JsonWebKeySet { keys: vec![] })
            .await;
        let calls = t.calls.lock().unwrap();
        let put = calls.last().unwrap();
        assert_eq!(put.0, "PUT");
        let body = put.2.as_ref().unwrap();
        assert_eq!(body["auth_server_url"], "https://as");
        assert_eq!(body["jwks_uri"], "https://as/jwks");
    }

    #[tokio::test]
    async fn asm_get_unwraps_body_and_passes_ttl() {
        let t = StubTransport::new(200, json!({ "body": { "issuer": "i" } }));
        let s = DbAsmCache::new(client(t.clone()));
        let b = s.get("https://as/.well-known", 1234).await.unwrap();
        assert_eq!(b["issuer"], "i");
        assert!(t.calls.lock().unwrap()[0].1.contains("ttlMs=1234"));
    }
}
