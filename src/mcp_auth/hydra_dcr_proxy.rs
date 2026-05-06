//! Backward-compat module path for the RFC 7591 DCR proxy.
//!
//! Older consumers (`hs-login-controller-rs` ≤ v0.3.0) import directly from
//! `hs_utils::mcp_auth::hydra_dcr_proxy::{proxy, HydraDcrProxyConfig}`. This
//! re-export keeps those imports working unchanged after the v0.4.0 split
//! into framework-free core + per-framework adapters.

pub use super::config::HydraDcrProxyConfig;

#[cfg(feature = "mcp-auth-actix")]
pub use super::dcr_actix::proxy;
