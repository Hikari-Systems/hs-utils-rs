//! Namespaced claim extraction from a verified JWT payload.
//!
//! Mirrors `userResolver.ts:buildProfileFromClaims`: pulls
//! `<namespace>email`, `<namespace>name`, `<namespace>picture`, and
//! `<namespace>email_verified` off the access token.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// User profile derived from JWT claims, mirroring the TypeScript
/// `OauthProfileResponse` shape sent to user-data-service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthProfile {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Build an `OauthProfile` from a JWT payload, reading the namespaced custom
/// claims placed there by an IdP post-login action.
pub fn build_profile(payload: &Value, sub: &str, namespace: &str) -> OauthProfile {
    OauthProfile {
        sub: sub.to_string(),
        email: get_string_claim(payload, &format!("{namespace}email")),
        name: get_string_claim(payload, &format!("{namespace}name")),
        picture: get_string_claim(payload, &format!("{namespace}picture")),
        email_verified: payload
            .get(format!("{namespace}email_verified"))
            .and_then(Value::as_bool),
    }
}

fn get_string_claim(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
