//! JWT verification: signature, audience, expiry. The decoded raw payload is
//! returned alongside the well-known fields so claim-based user resolvers can
//! pull namespaced custom claims off it.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use serde_json::Value;

use super::jwks::JwksCache;

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
    pub fn scopes(&self) -> Vec<String> {
        match &self.scope {
            Some(s) => s
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            None => Vec::new(),
        }
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

/// JWT verifier bound to a JWKS cache and an expected audience.
pub struct JwtVerifier {
    jwks: Arc<JwksCache>,
    expected_audience: String,
    clock_skew_seconds: u64,
}

impl JwtVerifier {
    pub fn new(jwks: Arc<JwksCache>, expected_audience: impl Into<String>, clock_skew_seconds: u64) -> Self {
        Self {
            jwks,
            expected_audience: expected_audience.into(),
            clock_skew_seconds,
        }
    }

    /// Verify a Bearer access token. Returns `JwtClaims` on success or an
    /// error describing why validation failed.
    pub async fn verify(&self, token: &str) -> Result<JwtClaims> {
        let header = decode_header(token).context("decode JWT header")?;
        let alg = header.alg;
        let kid = header.kid.ok_or_else(|| anyhow!("JWT header missing kid"))?;

        let key = self.jwks.get_key(&kid).await?;

        let mut validation = Validation::new(alg_from_header(alg)?);
        validation.set_audience(std::slice::from_ref(&self.expected_audience));
        validation.leeway = self.clock_skew_seconds;
        // Issuer check is loose; we accept any issuer that the JWKS keys vouch for.
        validation.validate_aud = true;

        let token_data = decode::<Value>(token, &key, &validation)
            .context("verify JWT signature/audience/expiry")?;
        let raw = token_data.claims;

        let well_known: WellKnown =
            serde_json::from_value(raw.clone()).context("parse JWT well-known claims")?;

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

fn alg_from_header(alg: Algorithm) -> Result<Algorithm> {
    // jsonwebtoken `Algorithm` covers all common JWS algorithms; pass through.
    // We accept the algorithm asserted in the JWT header — the JWKS lookup is
    // what binds it to the issuer's signing key.
    Ok(alg)
}
