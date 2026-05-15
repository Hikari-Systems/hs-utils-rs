//! Configuration shared across the resource-server modules.

use serde::Deserialize;

/// An MCP resource server's OAuth surface. Mirrors the TS
/// `@hikari-systems/hs.utils` `lib/mcp-auth/config.ts:AuthConfig`.
///
/// **Config-key parity with the TS `loadAuthConfig`.** Fields are split
/// by their source key, exactly as the TS reads them:
///
/// - Deserialized from the **`mcp:auth:*`** block (env
///   `mcp__auth__<field>`): `resource_server_url` (`resourceServerUrl`),
///   `expected_audience` (`expectedAudience`), `supported_scopes`
///   (`supportedScopes`), `enable_dcr` (`enableDcr`),
///   `clock_skew_seconds` (`clockSkewSeconds`), `jwks_uri` (`jwksUri`),
///   `claims_namespace` (`claimsNamespace`), `allowed_audiences`
///   (`allowedAudiences`).
/// - Assembled by the host from **top-level** keys and injected via
///   [`McpAuthConfig::with_runtime`] — NOT from the `mcp.auth` block:
///   `authorization_server_url` ← `oauth2:authorizationServer`,
///   `kratos_admin_url` ← `kratos:adminUrl`, `hydra_admin_url` ←
///   `hydra:adminUrl`, `mcp_data_service_url` ← `mcp-data-service:url`,
///   `mcp_data_service_api_key` ← `mcp-data-service:apiKey`.
///
/// (TS sources `fallbackToKratosAdmin` only as a resolver function
/// option, never from config — so there is no such config key here; the
/// Kratos resolver keeps the TS default of `true`.)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuthConfig {
    /// `mcp:auth:resourceServerUrl`. Public URL of this resource server
    /// (`aud` + RFC 9728 PRM resource id).
    pub resource_server_url: String,

    /// `mcp:auth:expectedAudience`. Required JWT `aud`.
    pub expected_audience: String,

    /// `mcp:auth:supportedScopes` (comma-separated string in JSON).
    #[serde(deserialize_with = "deser_csv_or_vec")]
    pub supported_scopes: Vec<String>,

    /// `mcp:auth:enableDcr`. Whether DCR (`POST /register`) is mounted.
    #[serde(default = "default_true", deserialize_with = "deser_bool_or_str_default_true")]
    pub enable_dcr: bool,

    /// `mcp:auth:clockSkewSeconds`. JWT clock-skew tolerance (s).
    #[serde(default = "default_clock_skew", deserialize_with = "deser_u64_or_str_default_skew")]
    pub clock_skew_seconds: u64,

    /// `mcp:auth:jwksUri`. Explicit JWKS endpoint; if absent it is
    /// discovered from the AS metadata. (Matches the TS key name —
    /// `jwksUri`, not `jwksUrl`.)
    #[serde(default)]
    pub jwks_uri: Option<String>,

    /// `mcp:auth:claimsNamespace`. Namespace prefix for custom claims.
    #[serde(default = "default_namespace")]
    pub claims_namespace: String,

    /// `mcp:auth:allowedAudiences` (comma-separated). Carried for AuthConfig
    /// parity; consumed by the DCR proxy, not the resource-server core.
    #[serde(default, deserialize_with = "deser_csv_opt")]
    pub allowed_audiences: Vec<String>,

    /// `oauth2:authorizationServer` (host-injected via `with_runtime`).
    /// Optional — absent ⇒ unauthenticated (local dev). `is_enabled()`
    /// reflects this.
    #[serde(skip)]
    pub authorization_server_url: Option<String>,

    /// `kratos:adminUrl` (host-injected).
    #[serde(skip)]
    pub kratos_admin_url: Option<String>,

    /// `hydra:adminUrl` (host-injected).
    #[serde(skip)]
    pub hydra_admin_url: Option<String>,

    /// `mcp-data-service:url` (host-injected; TS default applied here).
    #[serde(skip, default = "default_mcp_data_service_url")]
    pub mcp_data_service_url: String,

    /// `mcp-data-service:apiKey` (host-injected).
    #[serde(skip)]
    pub mcp_data_service_api_key: String,
}

fn default_mcp_data_service_url() -> String {
    "http://mcp-data-service:3000".to_string()
}

impl McpAuthConfig {
    /// Inject the top-level-sourced values (TS `loadAuthConfig` reads
    /// these from `oauth2:`, `kratos:`, `hydra:`, `mcp-data-service:`
    /// keys — not from the `mcp.auth` block). Empty strings are treated
    /// as unset; an unset `mcp_data_service_url` keeps the TS default.
    pub fn with_runtime(
        mut self,
        authorization_server_url: Option<String>,
        kratos_admin_url: Option<String>,
        hydra_admin_url: Option<String>,
        mcp_data_service_url: Option<String>,
        mcp_data_service_api_key: Option<String>,
    ) -> Self {
        let nonempty = |o: Option<String>| o.filter(|s| !s.is_empty());
        self.authorization_server_url = nonempty(authorization_server_url);
        self.kratos_admin_url = nonempty(kratos_admin_url);
        self.hydra_admin_url = nonempty(hydra_admin_url);
        if let Some(u) = nonempty(mcp_data_service_url) {
            self.mcp_data_service_url = u;
        }
        if let Some(k) = mcp_data_service_api_key {
            self.mcp_data_service_api_key = k;
        }
        self
    }

    /// Whether full auth wiring should be enabled. Requires the
    /// authorization-server URL to be configured.
    pub fn is_enabled(&self) -> bool {
        self.authorization_server_url
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    /// Effective JWKS URL: explicit `jwks_uri` override or derived from
    /// the AS URL. `None` when auth isn't configured.
    pub fn effective_jwks_url(&self) -> Option<String> {
        if let Some(url) = &self.jwks_uri {
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

// Optional CSV/array → Vec<String>, empty when absent/null. Mirrors the
// TS `parseCsv(config.configString('mcp:auth:allowedAudiences',''))`.
fn deser_csv_opt<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(s) => Ok(s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()),
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => Ok(s),
                _ => Err(D::Error::custom("expected string in allowedAudiences")),
            })
            .collect(),
        _ => Err(D::Error::custom(
            "expected string or array for allowed_audiences",
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
