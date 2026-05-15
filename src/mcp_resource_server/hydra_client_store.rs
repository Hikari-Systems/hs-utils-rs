//! Read-through `ClientStore` backed by Hydra's admin API.
//!
//! Mirrors the TypeScript `@hikari-systems/hs.utils`
//! `lib/mcp-auth/hydraClientStore.ts`. Hydra owns DCR (RFC 7591) — clients
//! register via Hydra's public `/oauth2/register`, so this store is
//! read-only from the resource server's perspective: `get` reads
//! `GET {hydra_admin_url}/admin/clients/{id}` (404/non-ok/err → `None`)
//! and `set` is a no-op (Hydra is the source of truth).

use async_trait::async_trait;
use serde_json::Value;

use super::db_stores::HttpTransport;
use super::stores::{ClientRegistration, ClientStore};

fn enc(s: &str) -> String {
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

fn str_array(v: &Value, key: &str) -> Option<Vec<String>> {
    v.get(key)?.as_array().map(|a| {
        a.iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect()
    })
}

/// Maps a loose Hydra admin client object to `ClientRegistration`,
/// applying the same defaults as the TS `toRegistration`.
fn to_registration(c: &Value) -> ClientRegistration {
    ClientRegistration {
        client_id: c
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        client_id_issued_at: c
            .get("client_id_issued_at")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        redirect_uris: str_array(c, "redirect_uris").unwrap_or_default(),
        grant_types: str_array(c, "grant_types")
            .unwrap_or_else(|| vec!["authorization_code".to_string()]),
        response_types: str_array(c, "response_types")
            .unwrap_or_else(|| vec!["code".to_string()]),
        token_endpoint_auth_method: c
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("none")
            .to_string(),
    }
}

pub struct HydraClientStore {
    admin_url: String,
    transport: std::sync::Arc<dyn HttpTransport>,
}

impl HydraClientStore {
    /// `admin_url` is Hydra's *admin* API base (e.g. `http://hydra:4445`),
    /// not the public OAuth endpoint.
    pub fn new(admin_url: impl Into<String>) -> Self {
        Self::with_transport(
            admin_url,
            std::sync::Arc::new(super::db_stores::ReqwestTransport::default()),
        )
    }

    pub fn with_transport(
        admin_url: impl Into<String>,
        transport: std::sync::Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            admin_url: admin_url.into().trim_end_matches('/').to_string(),
            transport,
        }
    }
}

#[async_trait]
impl ClientStore for HydraClientStore {
    async fn get(&self, id: &str) -> Option<ClientRegistration> {
        let url = format!("{}/admin/clients/{}", self.admin_url, enc(id));
        // api_key unused for Hydra admin (network-isolated); pass "".
        let (status, bytes) = match self
            .transport
            .request("GET", &url, "", None)
            .await
        {
            Some(r) => r,
            None => {
                tracing::error!("Hydra admin lookup for {id} failed (transport)");
                return None;
            }
        };
        if status == 404 {
            return None;
        }
        if !(200..300).contains(&status) {
            let body: String =
                String::from_utf8_lossy(&bytes).chars().take(200).collect();
            tracing::warn!("Hydra admin lookup for {id} → {status}: {body}");
            return None;
        }
        let c: Value = serde_json::from_slice(&bytes).ok()?;
        Some(to_registration(&c))
    }

    async fn set(&self, _id: &str, _reg: ClientRegistration) {
        // Hydra is the source of truth; clients register via Hydra's
        // public /oauth2/register, not via this store.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    struct Stub {
        calls: Mutex<Vec<String>>,
        resp: (u16, Value),
    }
    impl Stub {
        fn new(status: u16, body: Value) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                calls: Mutex::new(vec![]),
                resp: (status, body),
            })
        }
    }
    #[async_trait]
    impl HttpTransport for Stub {
        async fn request(
            &self,
            _m: &str,
            url: &str,
            _k: &str,
            _b: Option<Value>,
        ) -> Option<(u16, Vec<u8>)> {
            self.calls.lock().unwrap().push(url.to_string());
            Some((self.resp.0, serde_json::to_vec(&self.resp.1).unwrap()))
        }
    }

    #[tokio::test]
    async fn get_maps_with_defaults() {
        let t = Stub::new(200, json!({ "client_id": "c1" }));
        let s = HydraClientStore::with_transport("http://hydra:4445/", t.clone());
        let r = s.get("c1").await.unwrap();
        assert_eq!(r.client_id, "c1");
        assert_eq!(r.grant_types, vec!["authorization_code"]);
        assert_eq!(r.response_types, vec!["code"]);
        assert_eq!(r.token_endpoint_auth_method, "none");
        assert!(t.calls.lock().unwrap()[0].ends_with("/admin/clients/c1"));
    }

    #[tokio::test]
    async fn not_found_is_none() {
        let t = Stub::new(404, json!({}));
        let s = HydraClientStore::with_transport("http://hydra:4445", t);
        assert!(s.get("missing").await.is_none());
    }

    #[tokio::test]
    async fn non_ok_is_none() {
        let t = Stub::new(500, json!({}));
        let s = HydraClientStore::with_transport("http://hydra:4445", t);
        assert!(s.get("x").await.is_none());
    }

    #[tokio::test]
    async fn set_is_noop() {
        let t = Stub::new(200, json!({}));
        let s = HydraClientStore::with_transport("http://hydra:4445", t.clone());
        s.set("c", to_registration(&json!({ "client_id": "c" }))).await;
        assert!(t.calls.lock().unwrap().is_empty());
    }
}
