//! JWT verification: signature, audience, issuer, expiry.
//!
//! Mirrors TS `tokenVerifier.ts`: the JWKS document is looked up through
//! a [`JwksCacheStore`] keyed by the authorization-server URL; on a miss
//! the `jwks_uri` is discovered (config override or AS metadata), the
//! JWKS fetched, and the document written back to the store. The decoded
//! raw payload is returned so claim-based resolvers can read namespaced
//! custom claims.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, Validation};
use serde::Deserialize;
use serde_json::Value;

use super::jwks;
use super::stores::JwksCacheStore;

/// Verified JWT claims returned by `JwtVerifier::verify`.
#[derive(Debug, Clone)]
pub struct JwtClaims {
    pub sub: String,
    pub aud: String,
    pub iss: Option<String>,
    pub exp: i64,
    pub iat: Option<i64>,
    /// Space-separated scope string (raw).
    pub scope: Option<String>,
    /// OAuth client identifier — typically `azp` or `client_id`.
    pub client_id: Option<String>,
    /// Full payload (for namespaced custom claim extraction).
    pub raw: Value,
}

impl JwtClaims {
    /// The token's scopes: the space-separated `scope` claim (RFC 9068) and
    /// the `scp` claim, an array or a string, in that order, without
    /// duplicates. Ory Hydra issues JWT access tokens with `scp` only, so a
    /// reader of `scope` alone sees every Hydra token as having no scopes,
    /// and any scope check on it fails closed.
    pub fn scopes(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |s: &str| {
            if !s.is_empty() && !out.iter().any(|x| x == s) {
                out.push(s.to_string());
            }
        };
        if let Some(s) = &self.scope {
            s.split_whitespace().for_each(&mut push);
        }
        match self.raw.get("scp") {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).for_each(&mut push),
            Some(Value::String(s)) => s.split_whitespace().for_each(&mut push),
            _ => {}
        }
        out
    }
}

#[derive(Deserialize)]
struct WellKnown {
    sub: String,
    #[serde(default)]
    aud: Option<Value>,
    #[serde(default)]
    iss: Option<String>,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

/// JWT verifier bound to a shared JWKS cache + expected audience/issuer.
pub struct JwtVerifier {
    jwks_store: Arc<dyn JwksCacheStore>,
    auth_server_url: String,
    jwks_url_override: Option<String>,
    expected_audience: String,
    clock_skew_seconds: u64,
    http: reqwest::Client,
}

impl JwtVerifier {
    pub fn new(
        jwks_store: Arc<dyn JwksCacheStore>,
        auth_server_url: impl Into<String>,
        jwks_url_override: Option<String>,
        expected_audience: impl Into<String>,
        clock_skew_seconds: u64,
    ) -> Self {
        Self {
            jwks_store,
            auth_server_url: auth_server_url.into(),
            jwks_url_override,
            expected_audience: expected_audience.into(),
            clock_skew_seconds,
            http: reqwest::Client::new(),
        }
    }

    /// Verify a Bearer access token. Returns `JwtClaims` on success.
    pub async fn verify(&self, token: &str) -> Result<JwtClaims> {
        if token.is_empty() {
            return Err(anyhow!("empty token"));
        }
        let header = decode_header(token).context("decode JWT header")?;
        let kid = header.kid.ok_or_else(|| anyhow!("JWT header missing kid"))?;

        // Shared-cache lookup keyed by the AS URL (mirrors tokenVerifier).
        let doc = match self.jwks_store.get(&self.auth_server_url).await {
            Some(entry) => entry.jwks,
            None => {
                let jwks_uri = jwks::discover_jwks_uri(
                    &self.http,
                    &self.auth_server_url,
                    self.jwks_url_override.as_deref(),
                )
                .await?;
                let doc = jwks::fetch_jwks(&self.http, &jwks_uri).await?;
                self.jwks_store
                    .set(&self.auth_server_url, &jwks_uri, doc.clone())
                    .await;
                doc
            }
        };

        let key = jwks::decoding_key_for_kid(&doc, &kid)?;

        let mut validation = Validation::new(header.alg);
        validation.set_audience(std::slice::from_ref(&self.expected_audience));
        validation.validate_aud = true;
        validation.leeway = self.clock_skew_seconds;
        // Accept iss with or without a trailing slash (Auth0 emits the
        // trailing-slash form regardless of config).
        let iss_with = if self.auth_server_url.ends_with('/') {
            self.auth_server_url.clone()
        } else {
            format!("{}/", self.auth_server_url)
        };
        let iss_without = iss_with.trim_end_matches('/').to_string();
        validation.set_issuer(&[iss_with, iss_without]);

        let token_data = decode::<Value>(token, &key, &validation)
            .context("verify JWT signature/audience/issuer/expiry")?;
        let raw = token_data.claims;

        let well_known: WellKnown = serde_json::from_value(raw.clone())
            .context("parse JWT well-known claims")?;

        let aud = match well_known.aud {
            Some(Value::String(s)) => s,
            Some(Value::Array(arr)) => arr
                .into_iter()
                .find_map(|v| match v {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .unwrap_or_default(),
            _ => String::new(),
        };
        let client_id = well_known.client_id.or(well_known.azp);

        Ok(JwtClaims {
            sub: well_known.sub,
            aud,
            iss: well_known.iss,
            exp: well_known.exp,
            iat: well_known.iat,
            scope: well_known.scope,
            client_id,
            raw,
        })
    }
}

#[cfg(test)]
mod scopes_tests {
    use super::JwtClaims;
    use serde_json::{json, Value};

    fn claims(scope: Option<&str>, raw: Value) -> JwtClaims {
        JwtClaims {
            sub: "u".into(),
            aud: "a".into(),
            iss: None,
            exp: 0,
            iat: None,
            scope: scope.map(str::to_string),
            client_id: None,
            raw,
        }
    }

    #[test]
    fn hydra_scp_array_is_read() {
        let c = claims(
            None,
            json!({ "scp": ["mcp:read", "mcp:write", "offline_access"] }),
        );
        assert_eq!(c.scopes(), vec!["mcp:read", "mcp:write", "offline_access"]);
    }

    #[test]
    fn scope_string_and_scp_string_are_read_and_merged() {
        assert_eq!(
            claims(Some("openid mcp:read"), json!({})).scopes(),
            vec!["openid", "mcp:read"]
        );
        let c = claims(Some("mcp:read"), json!({ "scp": "mcp:read mcp:write" }));
        assert_eq!(c.scopes(), vec!["mcp:read", "mcp:write"], "no duplicates");
    }

    #[test]
    fn no_scope_claims_means_no_scopes() {
        assert!(claims(None, json!({ "sub": "u" })).scopes().is_empty());
        assert!(claims(None, json!({ "scp": 5 })).scopes().is_empty());
    }
}
