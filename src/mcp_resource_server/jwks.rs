//! JWKS helpers: discover the `jwks_uri`, fetch the JWKS document, and
//! resolve a `kid` to a `DecodingKey`.
//!
//! Mirrors the TS `tokenVerifier.ts` discovery/fetch logic. The *cache*
//! lives behind the [`super::stores::JwksCacheStore`] trait (in-memory,
//! or mcp-data-service-backed) — this module is stateless and only does
//! the discovery + parse, exactly like the TS helpers.

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::DecodingKey;
use serde_json::Value;

use super::stores::JsonWebKeySet;

const JWKS_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value> {
    let resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(JWKS_FETCH_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("fetch {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {} fetching {url}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .with_context(|| format!("parse JSON from {url}"))
}

/// `config.jwks_url` override, else the AS-metadata `jwks_uri`. Mirrors
/// `tokenVerifier.ts:discoverJwksUri`.
pub async fn discover_jwks_uri(
    client: &reqwest::Client,
    auth_server_url: &str,
    jwks_url_override: Option<&str>,
) -> Result<String> {
    if let Some(u) = jwks_url_override {
        if !u.is_empty() {
            return Ok(u.to_string());
        }
    }
    let upstream = format!(
        "{}/.well-known/oauth-authorization-server",
        auth_server_url.trim_end_matches('/')
    );
    let meta = fetch_json(client, &upstream).await?;
    match meta.get("jwks_uri").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(anyhow!(
            "AS metadata at {upstream} did not include a jwks_uri"
        )),
    }
}

/// Fetch the JWKS document. Mirrors `tokenVerifier.ts:fetchJwks`.
pub async fn fetch_jwks(client: &reqwest::Client, jwks_uri: &str) -> Result<JsonWebKeySet> {
    let body = fetch_json(client, jwks_uri).await?;
    let keys = body
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("JWKS at {jwks_uri} did not contain a keys array"))?;
    Ok(JsonWebKeySet { keys: keys.clone() })
}

/// Resolve a `kid` within a JWKS document to a `DecodingKey`. RSA only
/// (the platform's signing keys); `use:enc` keys are skipped.
pub fn decoding_key_for_kid(doc: &JsonWebKeySet, kid: &str) -> Result<DecodingKey> {
    for jwk in &doc.keys {
        if jwk.get("kid").and_then(Value::as_str) != Some(kid) {
            continue;
        }
        if jwk.get("use").and_then(Value::as_str) == Some("enc") {
            continue;
        }
        let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or("");
        if kty != "RSA" {
            return Err(anyhow!("JWKS key kid={kid} kty={kty} unsupported"));
        }
        let n = jwk
            .get("n")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("RSA jwk kid={kid} missing n"))?;
        let e = jwk
            .get("e")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("RSA jwk kid={kid} missing e"))?;
        return DecodingKey::from_rsa_components(n, e)
            .with_context(|| format!("parse RSA jwk kid={kid}"));
    }
    Err(anyhow!("JWKS did not contain a key for kid={kid}"))
}
