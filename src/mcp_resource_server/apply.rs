//! `apply_mcp_auth` — the Rust analogue of TS
//! `@hikari-systems/hs.utils` `lib/mcp-auth/index.ts:applyMcpAuth`.
//!
//! Ties the pieces together: the discovery/CIMD router, the optional DCR
//! `/register` route (when `enable_dcr`), the JWKS-cache-aware verifier,
//! and the Kratos user resolver. Returns the public router to merge plus
//! the [`AuthState`] the caller layers onto its protected (`/mcp`)
//! subrouter via `axum::middleware::from_fn_with_state`.
//!
//! `McpAuthStores::from_config` mirrors the TS default selection: when a
//! Hydra admin URL is configured, clients are read through Hydra and the
//! rate-limit/JWKS/ASM caches are mcp-data-service-backed (the
//! Hydra+Kratos production path bioalphaengine-mcp uses); otherwise the
//! in-memory stores are used (single-instance / local dev).

use std::sync::Arc;

use axum::Router;

use super::config::McpAuthConfig;
use super::db_stores::{
    DbAsmCache, DbDcrRateLimitStore, DbJwksCacheStore, McpDataServiceClient,
};
use super::dcr::{dcr_router, DcrState};
use super::hydra_client_store::HydraClientStore;
use super::jwt::JwtVerifier;
use super::kratos_resolver::KratosUserResolver;
use super::metadata::{router as metadata_router, MetadataState};
use super::middleware::AuthState;
use super::stores::{
    AsmCache, ClientStore, DcrRateLimitStore, InMemoryAsmCache,
    InMemoryClientStore, InMemoryDcrRateLimitStore, InMemoryJwksCacheStore,
    JwksCacheStore,
};

/// The four pluggable stores `apply_mcp_auth` wires in.
#[derive(Clone)]
pub struct McpAuthStores {
    pub clients: Arc<dyn ClientStore>,
    pub rate_limit: Arc<dyn DcrRateLimitStore>,
    pub jwks: Arc<dyn JwksCacheStore>,
    pub asm: Arc<dyn AsmCache>,
}

impl McpAuthStores {
    /// All-in-memory (tests / single-instance, no mcp-data-service).
    pub fn in_memory() -> Self {
        Self {
            clients: Arc::new(InMemoryClientStore::default()),
            rate_limit: Arc::new(InMemoryDcrRateLimitStore::default()),
            jwks: Arc::new(InMemoryJwksCacheStore::default()),
            asm: Arc::new(InMemoryAsmCache::default()),
        }
    }

    /// Production selection mirroring TS `applyMcpAuth` + bioalphaengine's
    /// Hydra+Kratos wiring: Hydra client store (when `hydra_admin_url` is
    /// set), mcp-data-service-backed rate-limit / JWKS / ASM caches.
    pub fn from_config(cfg: &McpAuthConfig) -> Self {
        let mds = McpDataServiceClient::new(
            cfg.mcp_data_service_url.clone(),
            cfg.mcp_data_service_api_key.clone(),
        );
        let clients: Arc<dyn ClientStore> = match cfg
            .hydra_admin_url
            .as_deref()
            .filter(|s| !s.is_empty())
        {
            Some(h) => Arc::new(HydraClientStore::new(h)),
            None => Arc::new(InMemoryClientStore::default()),
        };
        Self {
            clients,
            rate_limit: Arc::new(DbDcrRateLimitStore::new(mds.clone())),
            jwks: Arc::new(DbJwksCacheStore::new(mds.clone())),
            asm: Arc::new(DbAsmCache::new(mds)),
        }
    }
}

/// Build the public discovery/DCR router + the protected-resource
/// [`AuthState`]. Caller merges the router and layers the state onto its
/// `/mcp` subrouter. Mirrors `applyMcpAuth`.
pub fn apply_mcp_auth(
    cfg: Arc<McpAuthConfig>,
    stores: McpAuthStores,
    resolver: Arc<KratosUserResolver>,
) -> (Router, AuthState) {
    let auth_server_url = cfg
        .authorization_server_url
        .clone()
        .unwrap_or_default();
    let verifier = Arc::new(JwtVerifier::new(
        Arc::clone(&stores.jwks),
        auth_server_url,
        cfg.jwks_url.clone(),
        cfg.expected_audience.clone(),
        cfg.clock_skew_seconds,
    ));

    let mut router = metadata_router(MetadataState::new(
        Arc::clone(&cfg),
        Arc::clone(&stores.asm),
        Arc::clone(&stores.clients),
    ));

    if cfg.enable_dcr {
        router = router.merge(dcr_router(DcrState {
            clients: Arc::clone(&stores.clients),
            rate_limit: Arc::clone(&stores.rate_limit),
        }));
    }

    let auth_state = AuthState {
        verifier,
        resolver,
        auth_cfg: cfg,
    };
    (router, auth_state)
}
