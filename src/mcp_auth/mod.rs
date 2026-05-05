//! MCP-auth helpers: handlers and utilities for hosting OAuth2/OIDC machinery
//! that supports MCP (Model Context Protocol) clients.
//!
//! Currently exposes:
//!
//! - `hydra_dcr_proxy` — RFC 7591 Dynamic Client Registration proxy that
//!   forwards client registrations to Hydra's `/oauth2/register` and injects
//!   a configured `audience` allowlist so MCP clients can request
//!   audience-scoped tokens.

pub mod hydra_dcr_proxy;
