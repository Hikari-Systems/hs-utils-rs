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

use anyhow::{Context, Result};
use serde::Deserialize;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    PgPool,
};

use crate::config::{deser_opt_bool_or_str, deser_opt_u32_or_str};

// ── Structs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DbSslConfig {
    #[serde(default, deserialize_with = "deser_opt_bool_or_str")]
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "deser_opt_bool_or_str")]
    pub verify: Option<bool>,
    #[serde(default)]
    pub ca_cert_file: Option<String>,
}

/// Standard PostgreSQL connection config shared across all hs services.
/// Embed this directly in your service's `AppConfig.db` field.
///
/// `port` is a `String` because some config.json files encode it that way;
/// `build_pool` parses it at runtime.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DbConfig {
    #[serde(default)]
    pub host: String,
    /// Port as a string — tolerates `"5432"` or `5432` in config.json.
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub database: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ssl: Option<DbSslConfig>,
    #[serde(default, deserialize_with = "deser_opt_u32_or_str")]
    pub minpool: Option<u32>,
    #[serde(default, deserialize_with = "deser_opt_u32_or_str")]
    pub maxpool: Option<u32>,
    #[allow(dead_code)]
    #[serde(default)]
    pub debug: Option<bool>,
}

// ── Pool builder ─────────────────────────────────────────────────────────────

/// Build a `PgPool` from a `DbConfig`.
///
/// SSL behaviour:
/// - `ssl.enabled = true, verify = true`  → `VerifyFull`
/// - `ssl.enabled = true, verify = false` → `Require`
/// - `ssl.enabled = false` / absent       → `Prefer`
///
/// `ssl.caCertFile` is applied when non-empty and SSL is enabled.
/// Pool sizing defaults: `minpool = 0`, `maxpool = 10`.
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

    PgPoolOptions::new()
        .min_connections(cfg.minpool.unwrap_or(0))
        .max_connections(cfg.maxpool.unwrap_or(3))
        .connect_with(opts)
        .await
        .context("Failed to connect to database")
}
