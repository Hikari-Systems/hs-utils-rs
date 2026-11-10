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
    ConnectOptions as _, PgPool,
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
    let (opts, port) = connect_options(cfg)?;

    tracing::info!(
        host = %cfg.host,
        port = %port,
        user = %cfg.username,
        "Connecting to database"
    );

    let result = pool_options(cfg)
        .connect_with(opts)
        .await
        .context("Failed to connect to database");

    if let Ok(pool) = &result {
        register_pool_gauges(pool, cfg);
    }
    match &result {
        Ok(_) => tracing::info!(host = %cfg.host, user = %cfg.username, "Database connected"),
        Err(e) => tracing::error!(host = %cfg.host, user = %cfg.username, error = %e, "Database connection failed"),
    }

    result
}

/// How long a caller of a lazy pool waits for a connection. sqlx's 30 s default
/// suits a pool known to have connected; here the database may simply be down,
/// and a request should hear that promptly rather than hang.
const LAZY_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// As [`build_pool`], but opens nothing yet: the first query connects, and each
/// later one tries again until the database answers. Only bad config is an error
/// here; a database that is down or refuses the login surfaces on the queries.
/// Needs a Tokio runtime.
pub fn build_lazy_pool(cfg: &DbConfig) -> Result<PgPool> {
    let (opts, port) = connect_options(cfg)?;
    tracing::info!(
        host = %cfg.host,
        port = %port,
        user = %cfg.username,
        "Database pool ready; it connects on first use"
    );
    let pool = pool_options(cfg).acquire_timeout(LAZY_ACQUIRE_TIMEOUT).connect_lazy_with(opts);
    register_pool_gauges(&pool, cfg);
    Ok(pool)
}

/// `db.client.connection.count{state=idle|used}` and `db.client.connection.max`
/// for `pool`, reported at each metrics collection when `otel` metrics are on
/// (a no-op otherwise). The pool is named `host/database`: never the user or
/// anything from the password.
///
/// `used` at `max` for long stretches, with requests slowing, means the pool is
/// the bottleneck — `maxpool` is 3 by default.
fn register_pool_gauges(pool: &PgPool, cfg: &DbConfig) {
    let pool = pool.clone();
    let name = format!("{}/{}", cfg.host, cfg.database);
    let max = f64::from(cfg.maxpool.unwrap_or(3));
    crate::telemetry::register_gauges(Box::new(move |out| {
        let size = pool.size();
        let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX).min(size);
        let attrs = |state: &str| {
            vec![
                ("db.client.connection.pool.name", name.clone()),
                ("db.client.connection.state", state.to_string()),
            ]
        };
        out.push(crate::telemetry::Sample {
            name: "db.client.connection.count",
            value: f64::from(size - idle),
            attrs: attrs("used"),
        });
        out.push(crate::telemetry::Sample {
            name: "db.client.connection.count",
            value: f64::from(idle),
            attrs: attrs("idle"),
        });
        out.push(crate::telemetry::Sample {
            name: "db.client.connection.max",
            value: max,
            attrs: vec![("db.client.connection.pool.name", name.clone())],
        });
    }));
}

fn connect_options(cfg: &DbConfig) -> Result<(PgConnectOptions, u16)> {
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

    match cfg.slowqueryms {
        None => {}
        Some(0) => opts = opts.log_slow_statements(log::LevelFilter::Off, Duration::ZERO),
        Some(ms) => {
            opts = opts.log_slow_statements(log::LevelFilter::Warn, Duration::from_millis(u64::from(ms)))
        }
    }

    Ok((opts, port))
}

fn pool_options(cfg: &DbConfig) -> PgPoolOptions {
    let mut pool_opts = PgPoolOptions::new()
        .min_connections(cfg.minpool.unwrap_or(0))
        .max_connections(cfg.maxpool.unwrap_or(3));
    if let Some(secs) = cfg.idletimeoutsecs {
        pool_opts = pool_opts.idle_timeout(Duration::from_secs(u64::from(secs)));
    }
    pool_opts
}
