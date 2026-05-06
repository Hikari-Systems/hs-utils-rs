//! Framework-free config for the RFC 7591 Dynamic Client Registration proxy.
//!
//! `HydraDcrProxyConfig` is plain data + a shared `reqwest::Client`. The actix
//! and axum handlers in sibling modules read it through their respective
//! framework extractors but the type itself has no framework dependency.

#[derive(Clone)]
pub struct HydraDcrProxyConfig {
    pub(super) upstream: String,
    pub(super) allowed_audiences: Vec<String>,
    pub(super) client: reqwest::Client,
}

impl HydraDcrProxyConfig {
    /// Build a new DCR proxy config.
    ///
    /// Panics if `allowed_audiences` is empty — matches the TS contract
    /// (`createHydraDcrProxyHandler` throws synchronously on construction).
    /// Set `mcp:auth:allowedAudiences` to a comma-separated list of MCP
    /// resource URLs the proxy is allowed to register clients for.
    pub fn new(
        authorization_server_url: impl Into<String>,
        allowed_audiences: Vec<String>,
    ) -> Self {
        if allowed_audiences.is_empty() {
            panic!(
                "HydraDcrProxyConfig::new: allowed_audiences must be non-empty. \
                 Set mcp:auth:allowedAudiences to a comma-separated list of MCP \
                 resource URLs the proxy is allowed to register clients for."
            );
        }
        let url = authorization_server_url.into();
        let upstream = format!("{}/oauth2/register", url.trim_end_matches('/'));
        Self {
            upstream,
            allowed_audiences,
            client: reqwest::Client::new(),
        }
    }

    /// Build with a caller-supplied `reqwest::Client` (e.g. when sharing a
    /// connection pool with other components).
    pub fn with_client(
        authorization_server_url: impl Into<String>,
        allowed_audiences: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        let mut cfg = Self::new(authorization_server_url, allowed_audiences);
        cfg.client = client;
        cfg
    }
}
