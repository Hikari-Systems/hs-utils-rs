//! One exported way to stand up the browser-session store from config.
//!
//! Every controller in the estate previously hand-rolled a
//! `build_web_session_store(cfg) -> Option<Arc<dyn WebSessionStore>>` that was
//! byte-for-byte the same function, and each one encoded the same two silent
//! failure modes: an absent `session.db` selected an in-memory store, and a
//! Postgres pool that failed to build selected one too. Both returned `None`,
//! and `None` is indistinguishable from "web login is deliberately off". A
//! fleet could therefore run replica-local sessions — logging users out
//! whenever the load balancer moved them — with nothing in the logs saying so.
//!
//! [`build_session_store`] is the single implementation. A controller calls it
//! and holds the result; it does not decide anything.
//!
//! # Choosing the store
//!
//! `session.store` is `postgres`, `redis` or `memory`, matched
//! case-insensitively. **When it is set, the choice is authoritative and a
//! store that cannot be built is an error** — a service that was told to share
//! sessions must not quietly stop sharing them.
//!
//! When it is absent the store is *inferred* and a warning names what was
//! picked and why. That path exists only so deployments predating the key keep
//! working; it is the "behaviour selected by an absent key" shape that this
//! module exists to retire, so it tells you to set the key.
//!
//! # Why the pool comes back with the store
//!
//! [`SessionSetup::pg_pool`] is handed back rather than hidden because the
//! Postgres session pool is also the pool a `LISTEN/NOTIFY` event bus wants.
//! Building the store and then building a second pool against the same database
//! doubles the connection count for no reason.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::SessionConfig;
use crate::web_login::{InMemorySessionStore, WebSessionStore};

/// Session lifetime when `session.ttlSecs` is unset.
pub const DEFAULT_TTL_SECS: u32 = 24 * 60 * 60;

/// Which store [`build_session_store`] actually stood up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStoreKind {
    /// Shared across replicas, in Postgres.
    Postgres,
    /// Shared across replicas, in redis (single node or Sentinel).
    Redis,
    /// **Replica-local.** Correct for a single instance or with web login off;
    /// a silent logout bug behind a load balancer.
    Memory,
}

impl SessionStoreKind {
    /// Whether sessions survive a request landing on a different replica.
    /// The property that actually matters, so it is worth naming.
    pub fn is_shared(&self) -> bool {
        !matches!(self, SessionStoreKind::Memory)
    }

    /// The config value that selects this store.
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStoreKind::Postgres => "postgres",
            SessionStoreKind::Redis => "redis",
            SessionStoreKind::Memory => "memory",
        }
    }
}

/// What a controller gets back: the store, what it is, and the pool if one was
/// built.
pub struct SessionSetup {
    pub store: Arc<dyn WebSessionStore>,
    pub kind: SessionStoreKind,
    /// Present only for [`SessionStoreKind::Postgres`]. Reuse it for anything
    /// else that needs this database — an event bus, a sweeper — instead of
    /// opening a second pool.
    #[cfg(feature = "db")]
    pub pg_pool: Option<sqlx::PgPool>,
}

/// Shows the kind, not the store or the pool: the kind is the thing worth
/// seeing in a log line or an assertion, and a pool's `Debug` carries
/// connection details that have no business being formatted by accident.
impl std::fmt::Debug for SessionSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSetup")
            .field("kind", &self.kind)
            .field("shared", &self.kind.is_shared())
            .finish_non_exhaustive()
    }
}

/// Build the session store named by `session.store`, or infer one.
///
/// Errors when an explicitly requested store cannot be built — including when
/// it was not compiled in, since a binary that cannot honour its config should
/// say so at startup rather than serve traffic with the wrong store.
pub async fn build_session_store(cfg: &SessionConfig) -> Result<SessionSetup> {
    let ttl = Duration::from_secs(cfg.ttl_secs.unwrap_or(DEFAULT_TTL_SECS) as u64);

    match cfg.store.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(requested) => {
            let setup = build_named(requested, cfg, ttl).await?;
            tracing::info!(
                session.store = setup.kind.as_str(),
                session.shared = setup.kind.is_shared(),
                "browser session store ready (explicitly configured)"
            );
            Ok(setup)
        }
        None => infer(cfg, ttl).await,
    }
}

/// Strict path: the caller named a store, so anything short of that store is an
/// error rather than a downgrade.
async fn build_named(requested: &str, cfg: &SessionConfig, ttl: Duration) -> Result<SessionSetup> {
    if requested.eq_ignore_ascii_case("memory") {
        return Ok(memory(ttl));
    }
    if requested.eq_ignore_ascii_case("postgres") {
        return postgres(cfg, ttl).await.context(
            "session.store is \"postgres\" but the Postgres session store could not be built",
        );
    }
    if requested.eq_ignore_ascii_case("redis") {
        return redis_store(cfg, ttl)
            .context("session.store is \"redis\" but the redis session store could not be built");
    }
    anyhow::bail!(
        "session.store is {requested:?}; expected \"postgres\", \"redis\" or \"memory\""
    )
}

/// Legacy path for configs written before `session.store` existed. Mirrors what
/// the hand-rolled builders did, but says out loud what it picked — the silence
/// was the defect, not the inference.
async fn infer(cfg: &SessionConfig, ttl: Duration) -> Result<SessionSetup> {
    let pg_configured = cfg
        .db
        .as_ref()
        .is_some_and(|db| !db.host.trim().is_empty());
    let redis_configured = cfg.redis.as_ref().is_some_and(|r| {
        r.url.as_deref().is_some_and(|u| !u.trim().is_empty()) || !r.hosts.is_empty()
    });

    if pg_configured {
        let setup = postgres(cfg, ttl).await.context(
            "session.db is set but the Postgres session store could not be built; \
             set session.store explicitly to make this a startup failure rather than a surprise",
        )?;
        tracing::warn!(
            session.store = setup.kind.as_str(),
            "session.store is not set — inferred \"postgres\" from session.db. Set session.store explicitly."
        );
        return Ok(setup);
    }

    if redis_configured {
        let setup = redis_store(cfg, ttl)
            .context("session.redis is set but the redis session store could not be built")?;
        tracing::warn!(
            session.store = setup.kind.as_str(),
            "session.store is not set — inferred \"redis\" from session.redis. Set session.store explicitly."
        );
        return Ok(setup);
    }

    // The consequential case. Nothing chose an in-memory store; the absence of
    // config did. If web login is on, this is a logout bug waiting for a second
    // replica, and it is the reason this is `error!` and not `info!`.
    tracing::error!(
        session.store = "memory",
        session.shared = false,
        "no session store is configured — sessions are REPLICA-LOCAL and will not \
         survive a load-balancer decision. Set session.store to \"postgres\" or \
         \"redis\" (or to \"memory\" to say this is deliberate and silence this)."
    );
    Ok(memory(ttl))
}

fn memory(ttl: Duration) -> SessionSetup {
    SessionSetup {
        store: Arc::new(InMemorySessionStore::new(ttl)),
        kind: SessionStoreKind::Memory,
        #[cfg(feature = "db")]
        pg_pool: None,
    }
}

#[cfg(feature = "web-login-postgres")]
async fn postgres(cfg: &SessionConfig, _ttl: Duration) -> Result<SessionSetup> {
    use crate::web_login_postgres::{PgSessionStore, DEFAULT_SESSION_TABLE};

    let db = cfg
        .db
        .as_ref()
        .context("session.db is not set")?;
    anyhow::ensure!(!db.host.trim().is_empty(), "session.db.host is empty");

    let pool = crate::db::build_pool(db).await.context("build session db pool")?;

    let table = cfg
        .table
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SESSION_TABLE);

    let store = PgSessionStore::from_pool(pool.clone())
        .with_table(table)
        .context("invalid session table name")?;

    // Not fatal: a pre-provisioned table the service's role may not ALTER is a
    // supported deployment, and failing startup over it would be worse than the
    // first query failing loudly.
    if let Err(e) = store.ensure_schema().await {
        tracing::warn!("session table ensure_schema failed (pre-provisioned?): {e:#}");
    }

    Ok(SessionSetup {
        store: Arc::new(store),
        kind: SessionStoreKind::Postgres,
        pg_pool: Some(pool),
    })
}

#[cfg(not(feature = "web-login-postgres"))]
async fn postgres(_cfg: &SessionConfig, _ttl: Duration) -> Result<SessionSetup> {
    anyhow::bail!("this binary was built without the `web-login-postgres` feature")
}

#[cfg(feature = "web-login-redis")]
fn redis_store(cfg: &SessionConfig, ttl: Duration) -> Result<SessionSetup> {
    use crate::web_login_redis::{RedisSentinelConfig, RedisSessionStore};

    let r = cfg.redis.as_ref().context("session.redis is not set")?;

    // URL wins: it is the single-node shape, and a config carrying both is
    // likelier to be a local override of a deployed Sentinel block than an
    // instruction to prefer Sentinel.
    if let Some(url) = r.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        let store = RedisSessionStore::from_url(url, ttl)?;
        return Ok(SessionSetup {
            store: Arc::new(store),
            kind: SessionStoreKind::Redis,
            #[cfg(feature = "db")]
            pg_pool: None,
        });
    }

    anyhow::ensure!(
        !r.hosts.is_empty(),
        "session.redis needs either `url` (single node) or `hosts` + `masterName` (sentinel)"
    );
    let master_name = r
        .master_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("session.redis.masterName is required for sentinel mode")?;

    let store = RedisSessionStore::from_sentinel(
        RedisSentinelConfig {
            hosts: r.hosts.clone(),
            master_name: master_name.to_string(),
            db: r.db.unwrap_or(0) as i64,
            username: r.username.clone(),
            password: r.password.clone(),
            tls: r.tls.unwrap_or(false),
        },
        ttl,
    )?;

    Ok(SessionSetup {
        store: Arc::new(store),
        kind: SessionStoreKind::Redis,
        #[cfg(feature = "db")]
        pg_pool: None,
    })
}

#[cfg(not(feature = "web-login-redis"))]
fn redis_store(_cfg: &SessionConfig, _ttl: Duration) -> Result<SessionSetup> {
    anyhow::bail!("this binary was built without the `web-login-redis` feature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SessionRedisConfig, DbConfig};

    fn cfg() -> SessionConfig {
        SessionConfig::default()
    }

    #[tokio::test]
    async fn no_config_at_all_yields_a_replica_local_store() {
        let s = build_session_store(&cfg()).await.unwrap();
        assert_eq!(s.kind, SessionStoreKind::Memory);
        assert!(!s.kind.is_shared(), "memory must not claim to be shared");
    }

    /// The whole point of the named key: "memory" is a choice you can state,
    /// which is what makes its absence a misconfiguration rather than a default.
    #[tokio::test]
    async fn memory_can_be_selected_deliberately() {
        let c = SessionConfig { store: Some("memory".into()), ..cfg() };
        assert_eq!(build_session_store(&c).await.unwrap().kind, SessionStoreKind::Memory);
    }

    #[tokio::test]
    async fn the_store_key_is_matched_case_insensitively() {
        for v in ["MEMORY", "Memory", " memory "] {
            let c = SessionConfig { store: Some(v.into()), ..cfg() };
            assert_eq!(
                build_session_store(&c).await.unwrap().kind,
                SessionStoreKind::Memory,
                "should accept {v:?}"
            );
        }
    }

    /// A typo must not silently become a replica-local store — that is the
    /// failure this module exists to prevent, arriving by a different route.
    #[tokio::test]
    async fn an_unrecognised_store_is_an_error_not_a_fallback() {
        let c = SessionConfig { store: Some("postgress".into()), ..cfg() };
        let err = build_session_store(&c).await.unwrap_err().to_string();
        assert!(err.contains("postgress"), "error should quote the bad value: {err}");
    }

    /// Explicit beats inference: asking for postgres with nothing to connect to
    /// fails, where the inferring path would have degraded to memory.
    #[tokio::test]
    async fn explicitly_requesting_postgres_without_config_fails() {
        let c = SessionConfig { store: Some("postgres".into()), ..cfg() };
        assert!(build_session_store(&c).await.is_err());
    }

    #[tokio::test]
    async fn explicitly_requesting_redis_without_config_fails() {
        let c = SessionConfig { store: Some("redis".into()), ..cfg() };
        assert!(build_session_store(&c).await.is_err());
    }

    /// Sentinel config with no master name cannot be built, and saying so beats
    /// connecting to nothing.
    #[cfg(feature = "web-login-redis")]
    #[tokio::test]
    async fn sentinel_without_a_master_name_is_an_error() {
        let c = SessionConfig {
            store: Some("redis".into()),
            redis: Some(SessionRedisConfig {
                hosts: vec!["sentinel-a:26379".into()],
                ..Default::default()
            }),
            ..cfg()
        };
        assert!(build_session_store(&c).await.is_err());
    }

    #[cfg(feature = "web-login-redis")]
    #[tokio::test]
    async fn a_redis_url_builds_without_touching_the_network() {
        let c = SessionConfig {
            store: Some("redis".into()),
            redis: Some(SessionRedisConfig {
                url: Some("redis://session-redis:6379/0".into()),
                ..Default::default()
            }),
            ..cfg()
        };
        let s = build_session_store(&c).await.unwrap();
        assert_eq!(s.kind, SessionStoreKind::Redis);
        assert!(s.kind.is_shared());
    }

    /// Inference must reproduce what the hand-rolled builders did, or adopting
    /// this changes behaviour for every deployment that has not set the key.
    #[tokio::test]
    async fn an_empty_db_host_does_not_count_as_configured() {
        let c = SessionConfig {
            db: Some(DbConfig { host: "   ".into(), ..Default::default() }),
            ..cfg()
        };
        assert_eq!(build_session_store(&c).await.unwrap().kind, SessionStoreKind::Memory);
    }
}
