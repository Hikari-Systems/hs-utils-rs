//! Shared PostgreSQL pool configuration and builder.
//!
//! Each service embeds `DbConfig` in its own `AppConfig`:
//!
//! ```rust,ignore
//! use hs_utils::db::DbConfig;
//!
//! #[derive(Debug, serde::Deserialize, Clone)]
//! pub struct AppConfig {
//!     pub server: ServerConfig,
//!     pub log: LogConfig,
//!     pub db: DbConfig,
//! }
//! ```
//!
//! Then build the pool in `main.rs`:
//!
//! ```rust,ignore
//! let pool = hs_utils::db::build_pool(&cfg.db).await?;
//! ```

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    PgPool,
};

// ── Structs ──────────────────────────────────────────────────────────────────
// The config structs moved into the always-available `config` module in
// v0.27.0 so `SessionConfig` can name `DbConfig` without requiring the `db`
// feature. Re-exported here so every existing `hs_utils::db::DbConfig` import
// across the estate keeps working unchanged.
pub use crate::config::{DbConfig, DbSslConfig};


// ── Pool builder ─────────────────────────────────────────────────────────────

/// Build a `PgPool` from a `DbConfig`.
///
/// SSL behaviour:
/// - `ssl.enabled = true, verify = true`  → `VerifyFull`
/// - `ssl.enabled = true, verify = false` → `Require`
/// - `ssl.enabled = false` / absent       → `Prefer`
///
/// `ssl.caCertFile` is applied when non-empty and SSL is enabled.
/// Pool sizing defaults: `minpool = 0`, `maxpool = 3`. `idleTimeoutSecs` is
/// unset by default (no idle reaping); set it so an over-grown pool can shed
/// idle connections back toward `minpool`.
pub async fn build_pool(cfg: &DbConfig) -> Result<PgPool> {
    let port: u16 = if cfg.port.is_empty() {
        5432
    } else {
        cfg.port.parse().context("db.port must be a number")?
    };

    let ssl_enabled = cfg.ssl.as_ref().and_then(|s| s.enabled).unwrap_or(false);
    let ssl_mode = if ssl_enabled {
        let verify = cfg.ssl.as_ref().and_then(|s| s.verify).unwrap_or(true);
        if verify {
            PgSslMode::VerifyFull
        } else {
            PgSslMode::Require
        }
    } else {
        PgSslMode::Prefer
    };

    let mut opts = PgConnectOptions::new()
        .host(&cfg.host)
        .port(port)
        .database(&cfg.database)
        .username(&cfg.username)
        .password(&cfg.password)
        .ssl_mode(ssl_mode);

    if let Some(ca) = cfg
        .ssl
        .as_ref()
        .and_then(|s| s.ca_cert_file.as_deref())
        .filter(|s| !s.is_empty())
    {
        opts = opts.ssl_root_cert(ca);
    }

    tracing::info!(
        host = %cfg.host,
        port = %port,
        user = %cfg.username,
        "Connecting to database"
    );

    let mut pool_opts = PgPoolOptions::new()
        .min_connections(cfg.minpool.unwrap_or(0))
        .max_connections(cfg.maxpool.unwrap_or(3));
    if let Some(secs) = cfg.idletimeoutsecs {
        pool_opts = pool_opts.idle_timeout(Duration::from_secs(u64::from(secs)));
    }

    let result = pool_opts
        .connect_with(opts)
        .await
        .context("Failed to connect to database");

    match &result {
        Ok(_) => tracing::info!(host = %cfg.host, user = %cfg.username, "Database connected"),
        Err(e) => tracing::error!(host = %cfg.host, user = %cfg.username, error = %e, "Database connection failed"),
    }

    result
}
