//! JWKS fetcher with single-flight refresh and TTL caching.
//!
//! On first request for a `kid`, fetches the full JWKS document from the
//! configured URL, caches each key for `JWKS_TTL`, and returns the matching
//! `DecodingKey`. Concurrent fetches for an unknown `kid` deduplicate via a
//! tokio mutex around the fetch step.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use serde::Deserialize;
use tokio::sync::Mutex;

const JWKS_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

/// JWKS fetcher + per-`kid` decoding-key cache.
pub struct JwksCache {
    jwks_url: String,
    client: reqwest::Client,
    keys: Cache<String, Arc<DecodingKey>>,
    fetch_lock: Mutex<()>,
}

impl JwksCache {
    pub fn new(jwks_url: impl Into<String>) -> Self {
        Self::with_client(jwks_url, reqwest::Client::new())
    }

    pub fn with_client(jwks_url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            jwks_url: jwks_url.into(),
            client,
            keys: Cache::builder()
                .time_to_live(JWKS_TTL)
                .max_capacity(64)
                .build(),
            fetch_lock: Mutex::new(()),
        }
    }

    /// Get the decoding key for a JWT `kid`. Hits cache first; on miss,
    /// fetches the full JWKS document and populates the cache for every
    /// key it contains, then returns the one matching `kid`.
    pub async fn get_key(&self, kid: &str) -> Result<Arc<DecodingKey>> {
        if let Some(key) = self.keys.get(kid).await {
            return Ok(key);
        }

        // Single-flight: serialise concurrent miss-refreshes for the same
        // JWKS url. Re-check after acquiring the lock — another task may
        // have populated the entry already.
        let _guard = self.fetch_lock.lock().await;
        if let Some(key) = self.keys.get(kid).await {
            return Ok(key);
        }

        let map = self.fetch_jwks().await?;
        for (k, v) in map {
            self.keys.insert(k, v).await;
        }
        self.keys
            .get(kid)
            .await
            .ok_or_else(|| anyhow!("JWKS did not contain a key for kid={kid}"))
    }

    async fn fetch_jwks(&self) -> Result<HashMap<String, Arc<DecodingKey>>> {
        let resp = self
            .client
            .get(&self.jwks_url)
            .timeout(JWKS_FETCH_TIMEOUT)
            .send()
            .await
            .with_context(|| format!("fetch JWKS from {}", self.jwks_url))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "JWKS fetch returned status {} from {}",
                resp.status(),
                self.jwks_url
            ));
        }
        let jwks: Jwks = resp.json().await.context("parse JWKS body")?;

        let mut out = HashMap::new();
        for jwk in jwks.keys {
            if jwk.use_.as_deref() == Some("enc") {
                continue;
            }
            let Some(kid) = jwk.kid.clone() else {
                tracing::warn!("JWKS entry missing kid, skipping");
                continue;
            };
            let key = match jwk.kty.as_str() {
                "RSA" => match (jwk.n.as_deref(), jwk.e.as_deref()) {
                    (Some(n), Some(e)) => DecodingKey::from_rsa_components(n, e)
                        .with_context(|| format!("parse RSA jwk for kid={kid}"))?,
                    _ => {
                        tracing::warn!("RSA jwk for kid={kid} missing n/e, skipping");
                        continue;
                    }
                },
                other => {
                    tracing::warn!(
                        "JWKS key kty={other} alg={:?} for kid={kid} not supported, skipping",
                        jwk.alg
                    );
                    continue;
                }
            };
            out.insert(kid, Arc::new(key));
        }
        Ok(out)
    }
}
