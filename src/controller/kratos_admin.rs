//! Minimal Kratos admin client for the controller toolkit: public-profile
//! lookup, terms-version read, and a `metadata_public` writer. Reuses the
//! resource-server's [`ReqwestKratosFetcher`] for the GET (via `fetch_raw`) so
//! identity fetching is not duplicated; the PUT is hand-rolled here.

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::mcp_resource_server::kratos_resolver::ReqwestKratosFetcher;

/// Owner/public profile resolved from a Kratos identity.
#[derive(Debug, Clone)]
pub struct OwnerProfile {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture_image_service_id: Option<String>,
}

/// Kratos admin operations over `{admin_url}/admin/identities/{sub}`.
#[derive(Clone)]
pub struct KratosAdmin {
    fetcher: ReqwestKratosFetcher,
    http: reqwest::Client,
    admin_url: String,
}

impl KratosAdmin {
    /// `admin_url` is the Kratos admin API base (e.g. `http://kratos:4434`).
    /// Shares the supplied `reqwest::Client`.
    pub fn new(admin_url: impl Into<String>, http: reqwest::Client) -> Self {
        let admin_url = admin_url.into().trim_end_matches('/').to_string();
        let fetcher = ReqwestKratosFetcher::with_client(admin_url.clone(), http.clone());
        Self {
            fetcher,
            http,
            admin_url,
        }
    }

    /// `true` when no admin URL is configured (operations become no-ops/None).
    fn enabled(&self) -> bool {
        !self.admin_url.is_empty()
    }

    /// Look up a user's public profile by Kratos sub.
    pub async fn lookup_by_sub(&self, sub: &str) -> Option<OwnerProfile> {
        let identity = self.fetcher.fetch_raw(sub).await?;
        let traits = identity.get("traits").cloned().unwrap_or(Value::Null);
        let picture_image_service_id = identity
            .pointer("/metadata_public/pictureId")
            .and_then(Value::as_str)
            .or_else(|| traits.get("pictureId").and_then(Value::as_str))
            .or_else(|| traits.get("pictureImageServiceId").and_then(Value::as_str))
            .map(str::to_string);
        Some(OwnerProfile {
            id: sub.to_string(),
            email: traits.get("email").and_then(Value::as_str).map(str::to_string),
            name: name_from_traits(&traits),
            picture_image_service_id,
        })
    }

    /// Read `metadata_public.terms.version` (the accepted terms version). `None`
    /// when the user has never accepted or on any lookup failure.
    pub async fn terms_version(&self, sub: &str) -> Option<String> {
        let identity = self.fetcher.fetch_raw(sub).await?;
        identity
            .pointer("/metadata_public/terms/version")
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    /// Shallow-merge `patch` into the identity's `metadata_public` and PUT it
    /// back. Preserves `schema_id`/`state`/`traits`/`metadata_admin`.
    pub async fn update_metadata_public(&self, sub: &str, patch: Value) -> Result<()> {
        if !self.enabled() {
            return Err(anyhow!("kratos admin_url not configured"));
        }
        let identity = self
            .fetcher
            .fetch_raw(sub)
            .await
            .ok_or_else(|| anyhow!("identity not found: {sub}"))?;

        let mut metadata_public = identity
            .get("metadata_public")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| Value::Object(Default::default()));
        if let (Value::Object(dst), Value::Object(src)) = (&mut metadata_public, &patch) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }

        let mut body = serde_json::Map::new();
        if let Some(schema_id) = identity.get("schema_id") {
            body.insert("schema_id".into(), schema_id.clone());
        }
        if let Some(s) = identity.get("state") {
            body.insert("state".into(), s.clone());
        }
        if let Some(t) = identity.get("traits") {
            body.insert("traits".into(), t.clone());
        }
        if let Some(m) = identity.get("metadata_admin") {
            body.insert("metadata_admin".into(), m.clone());
        }
        body.insert("metadata_public".into(), metadata_public);

        let url = format!("{}/admin/identities/{}", self.admin_url, urlenc(sub));
        let resp = self
            .http
            .put(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&Value::Object(body))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Kratos updateMetadataPublic {sub}: {status}: {text}"));
        }
        Ok(())
    }
}

/// Pull a display name from Kratos traits (`name` may be a string or a
/// `{ first, last }` object).
fn name_from_traits(traits: &Value) -> Option<String> {
    match traits.get("name") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(_)) => {
            let first = traits.pointer("/name/first").and_then(Value::as_str).unwrap_or("");
            let last = traits.pointer("/name/last").and_then(Value::as_str).unwrap_or("");
            let joined = format!("{first} {last}").trim().to_string();
            if joined.is_empty() {
                None
            } else {
                Some(joined)
            }
        }
        _ => None,
    }
}

/// Percent-encode a path segment (mirrors `encodeURIComponent`).
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*'
            | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
