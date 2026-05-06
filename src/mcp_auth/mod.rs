//! OAuth2 helpers for hosting MCP authentication infrastructure.
//!
//! Currently centred on the RFC 7591 Dynamic Client Registration proxy that
//! forwards client registrations to an authorization server (Ory Hydra in
//! production) and injects a configured `audience` allowlist so MCP clients
//! can request audience-scoped tokens.
//!
//! # Feature flags
//!
//! - `mcp-auth` — framework-free core: `HydraDcrProxyConfig`, `forward_register`.
//! - `mcp-auth-actix` — adds `dcr_actix::proxy` for actix-web hosts.
//! - `mcp-auth-axum` — adds `dcr_axum::proxy` for axum hosts.
//!
//! The bare `mcp-auth` feature carries no framework dependency. Pick the
//! adapter that matches your service.

pub mod config;
pub mod dcr_core;
pub mod hydra_dcr_proxy;

#[cfg(feature = "mcp-auth-actix")]
pub mod dcr_actix;

#[cfg(feature = "mcp-auth-axum")]
pub mod dcr_axum;

pub use config::HydraDcrProxyConfig;
pub use dcr_core::{forward_register, DcrResponse};
