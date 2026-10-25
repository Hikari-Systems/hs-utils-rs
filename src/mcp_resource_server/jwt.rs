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
        self.verify_with(token, Audience::Static).await
    }

    /// Verify a Bearer access token for one resource of a server that has
    /// several (RFC 8707 audiences per path). Signature, issuer and expiry
    /// are checked as in [`Self::verify`]; the configured
    /// `expected_audience` is not used. Instead `aud` (a string or an
    /// array) must contain `expected` byte for byte, and no other value
    /// that is `base` or under `base/`.
    ///
    /// Nothing is normalised: no trimming, percent-decoding or case
    /// folding. Ory Hydra copies a requested audience into `aud` verbatim
    /// (`…/mcp/../x`, `%2e%2e`, a trailing `/`, `?`, `#`) and issues
    /// several when several are asked for, so anything but an exact match
    /// would let one token reach a resource it was not issued for. A token
    /// carrying two of this server's audiences is refused at every path.
    /// Values outside `base` (another server's audience) are ignored.
    /// `JwtClaims::aud` is `expected` on success.
    pub async fn verify_for_resource(
        &self,
        token: &str,
        expected: &str,
        base: &str,
    ) -> Result<JwtClaims> {
        self.verify_with(token, Audience::Resource { expected, base })
            .await
    }

    async fn verify_with(&self, token: &str, audience: Audience<'_>) -> Result<JwtClaims> {
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
        match audience {
            Audience::Static => {
                validation.set_audience(std::slice::from_ref(&self.expected_audience));
                validation.validate_aud = true;
            }
            // Checked below on the raw claim: jsonwebtoken's audience check
            // is containment only.
            Audience::Resource { .. } => validation.validate_aud = false,
        }
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

        if let Audience::Resource { expected, base } = audience {
            check_resource_audience(raw.get("aud"), expected, base)?;
        }

        let well_known: WellKnown = serde_json::from_value(raw.clone())
            .context("parse JWT well-known claims")?;

        let aud = match (audience, well_known.aud) {
            (Audience::Resource { expected, .. }, _) => expected.to_string(),
            (Audience::Static, Some(Value::String(s))) => s,
            (Audience::Static, Some(Value::Array(arr))) => arr
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

/// Which audience rule [`JwtVerifier::verify_with`] applies.
#[derive(Clone, Copy)]
enum Audience<'a> {
    /// The configured `expected_audience`, by containment (`verify`).
    Static,
    /// Exactly `expected`, and no other value at or under `base`.
    Resource { expected: &'a str, base: &'a str },
}

/// The `aud` rule of [`JwtVerifier::verify_for_resource`]. A non-string
/// array entry is refused rather than skipped.
fn check_resource_audience(aud: Option<&Value>, expected: &str, base: &str) -> Result<()> {
    let values: Vec<&str> = match aud {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| v.as_str().ok_or_else(|| anyhow!("JWT aud has a non-string entry")))
            .collect::<Result<_>>()?,
        _ => return Err(anyhow!("JWT has no aud")),
    };
    if !values.contains(&expected) {
        return Err(anyhow!("JWT aud does not name this resource"));
    }
    let under = format!("{base}/");
    if values
        .iter()
        .any(|v| *v != expected && (*v == base || v.starts_with(&under)))
    {
        return Err(anyhow!("JWT aud names more than one resource of this server"));
    }
    Ok(())
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

#[cfg(test)]
mod resource_audience_tests {
    use super::check_resource_audience;
    use serde_json::{json, Value};

    const BASE: &str = "https://wh.example.test/mcp";
    const A: &str = "https://wh.example.test/mcp/o/0b6f3c1e-2a4d-4e8f-9b1a-5c7d9e0f1a2b";
    const B: &str = "https://wh.example.test/mcp/o/7d1e2f3a-4b5c-4d6e-8f70-81a2b3c4d5e6";

    fn ok(aud: Value, expected: &str) -> bool {
        check_resource_audience(Some(&aud), expected, BASE).is_ok()
    }

    #[test]
    fn exact_match_at_the_base_and_at_a_sub_resource() {
        assert!(ok(json!(BASE), BASE));
        assert!(ok(json!([BASE]), BASE));
        assert!(ok(json!(A), A));
        assert!(ok(json!([A]), A));
    }

    #[test]
    fn a_base_token_is_not_a_sub_token_and_the_reverse() {
        assert!(!ok(json!(BASE), A));
        assert!(!ok(json!(A), BASE));
        assert!(!ok(json!(A), B), "org A's token at org B's resource");
    }

    #[test]
    fn two_audiences_of_this_server_are_refused_everywhere() {
        for aud in [json!([BASE, A]), json!([A, B])] {
            for expected in [BASE, A, B] {
                assert!(!ok(aud.clone(), expected), "{aud} at {expected}");
            }
        }
        // Any value at or under the base counts, valid resource or not.
        assert!(!ok(json!([A, format!("{BASE}/")]), A));
        assert!(!ok(json!([BASE, format!("{BASE}/../admin")]), BASE));
    }

    /// Hydra copies these into `aud` verbatim (S0); none is the resource.
    #[test]
    fn near_misses_are_never_normalised() {
        let upper = A.to_uppercase().replace(
            "HTTPS://WH.EXAMPLE.TEST/MCP/O/",
            "https://wh.example.test/mcp/o/",
        );
        for (aud, expected) in [
            (format!("{BASE}/"), BASE),
            (format!("{A}/"), A),
            (format!("{BASE}/../admin"), BASE),
            (format!("{BASE}/o/%2e%2e"), BASE),
            (format!("{BASE}/%2e%2e/o/x"), BASE),
            (format!("{BASE}?x"), BASE),
            (format!("{BASE}#f"), BASE),
            (format!("{A}?x"), A),
            (format!("{A}#f"), A),
            (format!("{BASE}x"), BASE),
            (upper.clone(), A),
            (" ".to_string() + BASE, BASE),
        ] {
            assert!(!ok(json!(aud), expected), "{aud} at {expected}");
        }
        // The uppercase form is not even the same string as the resource.
        assert_ne!(upper, A);
    }

    #[test]
    fn another_servers_audience_is_ignored() {
        assert!(ok(json!([A, "https://other.example.test/mcp"]), A));
        assert!(ok(json!(["https://wh.example.test/mcpx", BASE]), BASE));
    }

    #[test]
    fn a_duplicate_of_the_resource_is_still_one_audience() {
        assert!(ok(json!([A, A]), A));
    }

    #[test]
    fn missing_or_malformed_aud_is_refused() {
        assert!(check_resource_audience(None, BASE, BASE).is_err());
        assert!(!ok(json!(null), BASE));
        assert!(!ok(json!([]), BASE));
        assert!(!ok(json!([BASE, 5]), BASE));
        assert!(!ok(json!({ "aud": BASE }), BASE));
    }
}
