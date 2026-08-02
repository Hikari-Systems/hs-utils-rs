pub mod config;
pub mod healthcheck;
pub mod logging;

#[cfg(feature = "otel")]
pub mod otel;

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "pubsub")]
pub mod pubsub;

#[cfg(feature = "web")]
pub mod middleware;

#[cfg(feature = "web")]
pub mod server;

#[cfg(feature = "mcp-auth")]
pub mod mcp_auth;

#[cfg(feature = "mcp-resource-server")]
pub mod mcp_resource_server;

#[cfg(feature = "web-login")]
pub mod web_login;

// One exported builder for the browser-session store, so controllers stop
// hand-rolling the same selection (and the same silent fallback).
#[cfg(feature = "web-login")]
pub mod session_store;

#[cfg(feature = "web-login-redis")]
pub mod web_login_redis;

#[cfg(feature = "web-login-postgres")]
pub mod web_login_postgres;

#[cfg(feature = "controller")]
pub mod controller;

#[cfg(feature = "consent-bridge")]
pub mod hydra_bridge;

// Its own feature, not consent-bridge's: this hook talks to Kratos and
// image-service and knows nothing about Hydra. See the Cargo.toml comment.
#[cfg(feature = "avatar-hook")]
pub mod avatar_hook;
