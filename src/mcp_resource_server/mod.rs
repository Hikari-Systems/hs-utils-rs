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

pub mod claims;
pub mod config;
pub mod jwks;
pub mod jwt;
pub mod kratos_resolver;
pub mod metadata;
pub mod middleware;

pub use claims::OauthProfile;
pub use config::McpAuthConfig;
pub use jwks::JwksCache;
pub use jwt::{JwtClaims, JwtVerifier};
pub use kratos_resolver::{
    KratosIdentity, KratosIdentityFetcher, KratosUserResolver, ResolvedUser,
};
pub use middleware::{AuthExtension, AuthState};
