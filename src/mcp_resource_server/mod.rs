//! MCP resource-server primitives.
//!
//! Building blocks for hosting an MCP server behind OAuth 2.1 / RFC 9728:
//! JWT/JWKS verification, namespaced-claim extraction, user-data-service
//! upsert with TTL caching, RFC 9728 metadata routes, RFC 7591 DCR proxy
//! mounting, and an axum middleware layer that ties them together.
//!
//! Mirrors the TypeScript surface in `@hikari-systems/hs.utils`'s
//! `applyMcpAuth` + `createClaimsUserResolver`.
//!
//! # Feature flag
//!
//! Behind `mcp-resource-server`. Pulls in `mcp-auth-axum` (for the DCR proxy
//! axum adapter), `jsonwebtoken`, `moka`, `tokio`, `uuid`.

pub mod claims;
pub mod config;
pub mod jwks;
pub mod jwt;
pub mod metadata;
pub mod middleware;
pub mod user_data_service_client;
pub mod user_resolver;

pub use claims::OauthProfile;
pub use config::McpAuthConfig;
pub use jwks::JwksCache;
pub use jwt::{JwtClaims, JwtVerifier};
pub use middleware::{AuthExtension, AuthState};
pub use user_data_service_client::{UserDataServiceClient, UserResponse};
pub use user_resolver::{ClaimsUserResolver, ResolvedUser};
