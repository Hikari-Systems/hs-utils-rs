//! Framework-free config for the RFC 7591 Dynamic Client Registration proxy.
//!
//! `HydraDcrProxyConfig` is plain data + a shared `reqwest::Client`. The actix
//! and axum handlers in sibling modules read it through their respective
//! framework extractors but the type itself has no framework dependency.

#[derive(Clone)]
pub struct HydraDcrProxyConfig {
    pub(super) upstream: String,
    /// Hydra **admin** base URL (e.g. `http://hydra:4445`). `skip_consent` is
    /// an Ory privileged client field that Hydra rejects on the public
    /// `/oauth2/register` endpoint, so it is applied via a follow-up
    /// `PATCH /admin/clients/{id}` instead. `None` disables that step.
    pub(super) admin_url: Option<String>,
    pub(super) allowed_audiences: Vec<String>,
    pub(super) skip_consent: bool,
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
            admin_url: None,
            allowed_audiences,
            // Consent-exempt by default; callers opt out via
            // `with_skip_consent(false)`.
            skip_consent: true,
            client: reqwest::Client::new(),
        }
    }

    /// Set Hydra's admin base URL so consent-exempt registrations can be
    /// finalised via `PATCH /admin/clients/{id}`. Without this, `skip_consent`
    /// cannot be applied (Hydra forbids it on public DCR) and the proxy
    /// falls back to the consent bridge's audience-based exemption.
    pub fn with_admin_url(mut self, admin_url: impl Into<String>) -> Self {
        let u = admin_url.into();
        self.admin_url = if u.trim().is_empty() {
            None
        } else {
            Some(u.trim_end_matches('/').to_string())
        };
        self
    }

    /// Control whether proxied client registrations are marked
    /// consent-exempt (`skip_consent: true` injected into the body).
    /// Defaults to `true`.
    pub fn with_skip_consent(mut self, skip_consent: bool) -> Self {
        self.skip_consent = skip_consent;
        self
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
