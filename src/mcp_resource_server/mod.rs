//! MCP resource-server primitives.
//!
//! Building blocks for hosting an MCP server behind OAuth 2.1 / RFC 9728:
//! JWT/JWKS verification, namespaced-claim extraction, Kratos-backed user
//! resolution with TTL caching, RFC 9728 metadata routes, RFC 7591 DCR
//! proxy mounting, and an axum middleware layer that ties them together.
//!
//! Mirrors the TypeScript surface in `@hikari-systems/hs.utils`'s
//! `applyMcpAuth` + `createKratosUserResolver` (Hydra+Kratos backend).
//! User identity is the Kratos identity id (the JWT `sub`); there is no
//! user-data-service upsert.
//!
//! # Feature flag
//!
//! Behind `mcp-resource-server`. Pulls in `mcp-auth-axum` (for the DCR proxy
//! axum adapter), `jsonwebtoken`, `moka`, `tokio`.

pub mod apply;
pub mod claims;
pub mod config;
#[cfg(feature = "mcp-session-store")]
pub mod db_session_store;
pub mod db_stores;
pub mod dcr;
pub mod hydra_client_store;
pub mod jwks;
pub mod jwt;
pub mod kratos_resolver;
pub mod metadata;
pub mod middleware;
pub mod stores;

pub use apply::{apply_mcp_auth, McpAuthStores};
pub use claims::OauthProfile;
pub use config::McpAuthConfig;
pub use dcr::dcr_router;
pub use jwt::{JwtClaims, JwtVerifier};
pub use kratos_resolver::{
    KratosIdentity, KratosIdentityFetcher, KratosUserResolver, ResolvedUser,
};
pub use db_stores::{
    DbAsmCache, DbClientStore, DbDcrRateLimitStore, DbJwksCacheStore,
    HttpTransport, McpDataServiceClient,
};
#[cfg(feature = "mcp-session-store")]
pub use db_session_store::DbSessionStore;
#[cfg(feature = "mcp-session-store")]
pub use rmcp::transport::streamable_http_server::session::store::{SessionState, SessionStore};
pub use hydra_client_store::HydraClientStore;
pub use metadata::MetadataState;
pub use middleware::{AuthExtension, AuthState};
pub use stores::{
    AsmCache, ClientRegistration, ClientStore, DcrRateLimitStore,
    InMemoryAsmCache, InMemoryClientStore, InMemoryDcrRateLimitStore,
    InMemoryJwksCacheStore, JsonWebKeySet, JwksCacheEntry, JwksCacheStore,
};
