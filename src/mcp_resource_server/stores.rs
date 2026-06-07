//! Pluggable store contracts for the MCP OAuth resource server.
//!
//! Mirrors the TypeScript `@hikari-systems/hs.utils`
//! `lib/mcp-auth/stores.ts`. Two implementation families exist:
//!   - the in-memory impls in this file (tests / single-instance);
//!   - the mcp-data-service-backed impls in [`super::db_stores`] and the
//!     Hydra-backed [`super::hydra_client_store`] (production default).
//!
//! Every trait is async (`#[async_trait]`) and object-safe so callers
//! can hold `Arc<dyn ClientStore>` etc. and swap implementations freely.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// RFC 7591 client registration subset we persist / serve via CIMD.
/// Field names match the TS `ClientRegistration` exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_id: String,
    pub client_id_issued_at: i64,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

/// Full JWKS document — opaque to us, handed straight to the verifier.
/// Mirrors TS `JsonWebKeySet = { keys: unknown[] }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<Value>,
}

/// A cached JWKS document plus the URI it was fetched from.
#[derive(Debug, Clone)]
pub struct JwksCacheEntry {
    pub jwks_uri: String,
    pub jwks: JsonWebKeySet,
}

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn get(&self, id: &str) -> Option<ClientRegistration>;
    async fn set(&self, id: &str, reg: ClientRegistration);
}

#[async_trait]
pub trait DcrRateLimitStore: Send + Sync {
    /// Atomically record an attempt from `ip` and return whether it is
    /// allowed under a sliding window of `max` per `window_ms`.
    async fn record_and_check(&self, ip: &str, window_ms: u64, max: usize) -> bool;
}

/// JWKS cache contract. Named `JwksCacheStore` (not `JwksCache`) because
/// `super::jwks::JwksCache` is the in-process JWKS *fetcher*; the fetcher
/// consults a `JwksCacheStore` for the shared cache layer (Stage 5).
#[async_trait]
pub trait JwksCacheStore: Send + Sync {
    async fn get(&self, auth_server_url: &str) -> Option<JwksCacheEntry>;
    async fn set(&self, auth_server_url: &str, jwks_uri: &str, jwks: JsonWebKeySet);
}

#[async_trait]
pub trait AsmCache: Send + Sync {
    /// Cached body if present and younger than `ttl_ms`.
    async fn get(&self, asm_uri: &str, ttl_ms: u64) -> Option<Value>;
    async fn set(&self, asm_uri: &str, body: Value);
}

// ─── In-memory implementations (mirror the TS `create*` factories) ──────────

#[derive(Default)]
pub struct InMemoryClientStore {
    store: Mutex<HashMap<String, ClientRegistration>>,
}

#[async_trait]
impl ClientStore for InMemoryClientStore {
    async fn get(&self, id: &str) -> Option<ClientRegistration> {
        self.store.lock().unwrap().get(id).cloned()
    }
    async fn set(&self, id: &str, reg: ClientRegistration) {
        self.store.lock().unwrap().insert(id.to_string(), reg);
    }
}

#[derive(Default)]
pub struct InMemoryDcrRateLimitStore {
    store: Mutex<HashMap<String, Vec<Instant>>>,
}

#[async_trait]
impl DcrRateLimitStore for InMemoryDcrRateLimitStore {
    async fn record_and_check(&self, ip: &str, window_ms: u64, max: usize) -> bool {
        let now = Instant::now();
        let mut guard = self.store.lock().unwrap();
        let window = guard.entry(ip.to_string()).or_default();
        window.retain(|t| now.duration_since(*t).as_millis() < window_ms as u128);
        if window.len() >= max {
            return false;
        }
        window.push(now);
        true
    }
}

#[derive(Default)]
pub struct InMemoryJwksCacheStore {
    store: Mutex<HashMap<String, JwksCacheEntry>>,
}

#[async_trait]
impl JwksCacheStore for InMemoryJwksCacheStore {
    async fn get(&self, auth_server_url: &str) -> Option<JwksCacheEntry> {
        self.store.lock().unwrap().get(auth_server_url).cloned()
    }
    async fn set(&self, auth_server_url: &str, jwks_uri: &str, jwks: JsonWebKeySet) {
        self.store.lock().unwrap().insert(
            auth_server_url.to_string(),
            JwksCacheEntry {
                jwks_uri: jwks_uri.to_string(),
                jwks,
            },
        );
    }
}

#[derive(Default)]
pub struct InMemoryAsmCache {
    store: Mutex<HashMap<String, (Instant, Value)>>,
}

#[async_trait]
impl AsmCache for InMemoryAsmCache {
    async fn get(&self, asm_uri: &str, ttl_ms: u64) -> Option<Value> {
        let guard = self.store.lock().unwrap();
        let (fetched_at, body) = guard.get(asm_uri)?;
        if Instant::now().duration_since(*fetched_at).as_millis() >= ttl_ms as u128 {
            return None;
        }
        Some(body.clone())
    }
    async fn set(&self, asm_uri: &str, body: Value) {
        self.store
            .lock()
            .unwrap()
            .insert(asm_uri.to_string(), (Instant::now(), body));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reg(id: &str) -> ClientRegistration {
        ClientRegistration {
            client_id: id.to_string(),
            client_id_issued_at: 1,
            redirect_uris: vec!["https://x/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: "none".into(),
        }
    }

    #[tokio::test]
    async fn client_store_get_set() {
        let s = InMemoryClientStore::default();
        assert!(s.get("c1").await.is_none());
        s.set("c1", reg("c1")).await;
        assert_eq!(s.get("c1").await.unwrap().client_id, "c1");
    }

    #[tokio::test]
    async fn rate_limit_sliding_window() {
        let s = InMemoryDcrRateLimitStore::default();
        // max=2 per a long window: first two allowed, third denied.
        assert!(s.record_and_check("ip", 60_000, 2).await);
        assert!(s.record_and_check("ip", 60_000, 2).await);
        assert!(!s.record_and_check("ip", 60_000, 2).await);
        // A different ip is independent.
        assert!(s.record_and_check("other", 60_000, 2).await);
    }

    #[tokio::test]
    async fn rate_limit_window_expiry() {
        let s = InMemoryDcrRateLimitStore::default();
        // window_ms = 0 → every prior attempt is immediately stale, so
        // each call sees an empty window and is allowed.
        assert!(s.record_and_check("ip", 0, 1).await);
        assert!(s.record_and_check("ip", 0, 1).await);
    }

    #[tokio::test]
    async fn jwks_cache_get_set() {
        let s = InMemoryJwksCacheStore::default();
        assert!(s.get("as").await.is_none());
        s.set("as", "https://as/jwks", JsonWebKeySet { keys: vec![json!({"kid":"k"})] })
            .await;
        let e = s.get("as").await.unwrap();
        assert_eq!(e.jwks_uri, "https://as/jwks");
        assert_eq!(e.jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn asm_cache_ttl() {
        let s = InMemoryAsmCache::default();
        s.set("u", json!({"issuer":"x"})).await;
        // Fresh under a generous ttl.
        assert!(s.get("u", 60_000).await.is_some());
        // ttl_ms = 0 → treated as already stale.
        assert!(s.get("u", 0).await.is_none());
        assert!(s.get("missing", 60_000).await.is_none());
    }
}
