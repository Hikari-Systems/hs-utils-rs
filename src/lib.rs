pub mod config;
pub mod healthcheck;
pub mod logging;

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

#[cfg(feature = "web-login-redis")]
pub mod web_login_redis;

#[cfg(feature = "web-login-postgres")]
pub mod web_login_postgres;

#[cfg(feature = "controller")]
pub mod controller;

#[cfg(feature = "consent-bridge")]
pub mod hydra_bridge;

#[cfg(feature = "consent-bridge")]
pub mod avatar_hook;
