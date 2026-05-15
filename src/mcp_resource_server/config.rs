//! Configuration shared across the resource-server modules.

use serde::Deserialize;

/// Configuration for an MCP resource server's OAuth surface. Mirrors the
/// `mcp.auth.*` block in the TypeScript camelid-mcp `config.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuthConfig {
    /// Public URL of this resource server (used as `aud` and as the resource
    /// identifier in RFC 9728 PRM metadata). Example:
    /// `https://camelid-mcp.hikari-systems.com`.
    pub resource_server_url: String,

    /// Required JWT `aud` value. Usually equal to `resource_server_url`.
    pub expected_audience: String,

    /// OAuth scopes advertised in PRM metadata, comma-separated string in
    /// JSON to match the TS config layout.
    #[serde(deserialize_with = "deser_csv_or_vec")]
    pub supported_scopes: Vec<String>,

    /// Whether DCR (`POST /register`) is mounted.
    #[serde(default = "default_true", deserialize_with = "deser_bool_or_str_default_true")]
    pub enable_dcr: bool,

    /// JWT clock-skew tolerance in seconds.
    #[serde(default = "default_clock_skew", deserialize_with = "deser_u64_or_str_default_skew")]
    pub clock_skew_seconds: u64,

    /// Authorization-server URL (for AS metadata proxying + JWKS discovery
    /// when `jwks_url` is not set). Example: `https://sso.hikari-systems.com`.
    /// Optional — when absent, the resource server runs unauthenticated
    /// (useful for local dev). `is_enabled()` reflects this.
    #[serde(default)]
    pub authorization_server_url: Option<String>,

    /// JWKS endpoint. If absent, derived from `authorization_server_url`
    /// `/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,

    /// Namespace prefix for custom claims placed onto the access token by an
    /// IdP post-login action. Defaults to `https://hikari-systems.com/`.
    #[serde(default = "default_namespace")]
    pub claims_namespace: String,

    /// Ory Kratos *admin* API base URL (e.g. `http://kratos:4434`). Used
    /// by the Kratos user resolver's fallback identity lookup. Optional —
    /// when absent the resolver runs claims-only (no admin fallback).
    /// Mirrors the TS `kratos:adminUrl` config key.
    #[serde(default)]
    pub kratos_admin_url: Option<String>,

    /// Whether the Kratos resolver may fall back to
    /// `GET {kratos_admin_url}/admin/identities/{sub}` when the JWT's
    /// namespaced claims carry no email/name/picture. Mirrors the TS
    /// `fallbackToKratosAdmin` (default `true`).
    #[serde(
        default = "default_true",
        deserialize_with = "deser_bool_or_str_default_true"
    )]
    pub fallback_to_kratos_admin: bool,

    /// Ory Hydra *admin* API base URL (e.g. `http://hydra:4445`). When set
    /// (with `kratos_admin_url`), the resource server runs the Hydra+Kratos
    /// backend: clients are read through Hydra. Mirrors TS `hydra:adminUrl`.
    #[serde(default)]
    pub hydra_admin_url: Option<String>,

    /// mcp-data-service base URL backing the shared DCR-rate-limit / JWKS /
    /// ASM caches. Mirrors TS `mcpDataService:url` (same default).
    #[serde(default = "default_mcp_data_service_url")]
    pub mcp_data_service_url: String,

    /// `X-Api-Key` for mcp-data-service. Mirrors TS `mcpDataService:apiKey`.
    #[serde(default)]
    pub mcp_data_service_api_key: String,
}

fn default_mcp_data_service_url() -> String {
    "http://mcp-data-service:3000".to_string()
}

impl McpAuthConfig {
    /// Whether full auth wiring should be enabled. Requires the
    /// authorization-server URL to be configured.
    pub fn is_enabled(&self) -> bool {
        self.authorization_server_url
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    /// Effective JWKS URL when auth is enabled: explicit override or derived
    /// from the AS URL. Returns `None` when auth isn't configured.
    pub fn effective_jwks_url(&self) -> Option<String> {
        if let Some(url) = &self.jwks_url {
            if !url.is_empty() {
                return Some(url.clone());
            }
        }
        self.authorization_server_url.as_ref().and_then(|as_url| {
            if as_url.is_empty() {
                None
            } else {
                Some(format!(
                    "{}/.well-known/jwks.json",
                    as_url.trim_end_matches('/')
                ))
            }
        })
    }
}

fn default_true() -> bool {
    true
}

fn default_clock_skew() -> u64 {
    30
}

fn default_namespace() -> String {
    "https://hikari-systems.com/".to_string()
}

fn deser_csv_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::String(s) => Ok(s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()),
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => Ok(s),
                _ => Err(D::Error::custom("expected string in scopes array")),
            })
            .collect(),
        _ => Err(D::Error::custom(
            "expected string or array for supported_scopes",
        )),
    }
}

fn deser_bool_or_str_default_true<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Bool(b) => Ok(b),
        serde_json::Value::String(s) => match s.as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" | "" => Ok(false),
            _ => Err(D::Error::custom(format!("invalid boolean: {s}"))),
        },
        serde_json::Value::Null => Ok(true),
        _ => Err(D::Error::custom("expected boolean or string")),
    }
}

fn deser_u64_or_str_default_skew<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom("clock_skew_seconds must be a non-negative integer")),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| D::Error::custom(format!("invalid u64: {e}"))),
        serde_json::Value::Null => Ok(default_clock_skew()),
        _ => Err(D::Error::custom("expected number or string")),
    }
}
