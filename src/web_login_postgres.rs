//! PostgreSQL-backed [`WebSessionStore`] for cross-replica browser login.
//!
//! The direct-to-infra analogue of the `web-login-redis` feature's
//! [`RedisSessionStore`](crate::web_login_redis::RedisSessionStore): instead of
//! a shared redis it persists the OAuth `state → original-URL` map and the
//! post-login cookie session in a single Postgres table, so the `gate` (flow
//! start) and `callback` (flow finish) can run on different replicas behind a
//! load balancer without the callback hitting "no stored state".
//!
//! Reuses the service's existing [`sqlx::PgPool`] (build it once with
//! [`crate::db::build_pool`] and share it). One row per session:
//!
//! ```sql
//! CREATE TABLE web_sessions (
//!     sid        TEXT PRIMARY KEY,
//!     data       JSONB NOT NULL,        -- the serialized Session
//!     expires_at TIMESTAMPTZ NOT NULL   -- replaces redis' set_ex TTL
//! );
//! CREATE INDEX web_sessions_expires_at_idx ON web_sessions (expires_at);
//! ```
//!
//! Redis evicts expired keys for you; Postgres does not, so expiry is handled
//! two ways: every `load` filters `expires_at > now()` (an expired row is
//! invisible the instant it lapses), and [`PgSessionStore::sweep_expired`]
//! reclaims the dead rows — call it periodically (e.g. an hourly task).
//!
//! Posture matches the rest of hs-utils' shared stores: **fail open** — a
//! Postgres outage degrades to "the user is asked to log in again", never a
//! 500.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::web_login::{Session, WebSessionStore, DEFAULT_SESSION_TTL_SECS};

/// Postgres [`WebSessionStore`] over a shared [`PgPool`].
#[derive(Clone)]
pub struct PgSessionStore {
    pool: PgPool,
    ttl_secs: i64,
}

impl PgSessionStore {
    /// Build over an existing pool with the given per-session expiry (refreshed
    /// on every write, mirroring redis `set_ex`).
    pub fn new(pool: PgPool, ttl: Duration) -> Self {
        Self {
            pool,
            ttl_secs: ttl.as_secs().max(1) as i64,
        }
    }

    /// Build with the default 24h TTL ([`DEFAULT_SESSION_TTL_SECS`]).
    pub fn from_pool(pool: PgPool) -> Self {
        Self::new(pool, Duration::from_secs(DEFAULT_SESSION_TTL_SECS))
    }

    /// Create the `web_sessions` table and its expiry index if absent.
    /// Idempotent; safe to call on every boot.
    pub async fn ensure_schema(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS web_sessions (\
                 sid        TEXT PRIMARY KEY, \
                 data       JSONB NOT NULL, \
                 expires_at TIMESTAMPTZ NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS web_sessions_expires_at_idx \
             ON web_sessions (expires_at)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete expired rows, returning the number reclaimed. Reads already
    /// ignore expired sessions, so this is housekeeping — run it on a timer.
    pub async fn sweep_expired(&self) -> Result<u64> {
        let res = sqlx::query("DELETE FROM web_sessions WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}

#[async_trait]
impl WebSessionStore for PgSessionStore {
    async fn load(&self, sid: &str) -> Option<Session> {
        let res = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT data FROM web_sessions WHERE sid = $1 AND expires_at > now()",
        )
        .bind(sid)
        .fetch_optional(&self.pool)
        .await;

        let data = match res {
            Ok(v) => v?,
            Err(e) => {
                tracing::error!("web_login pg load {sid}: {e}");
                return None; // fail open
            }
        };

        match serde_json::from_value::<Session>(data) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!("web_login pg load {sid}: malformed payload: {e}");
                None
            }
        }
    }

    async fn store(&self, sid: &str, session: &Session) {
        let data = match serde_json::to_value(session) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("web_login pg store {sid}: serialize failed: {e}");
                return;
            }
        };

        let res = sqlx::query(
            "INSERT INTO web_sessions (sid, data, expires_at) \
             VALUES ($1, $2, now() + ($3 * interval '1 second')) \
             ON CONFLICT (sid) DO UPDATE \
               SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at",
        )
        .bind(sid)
        .bind(data)
        .bind(self.ttl_secs)
        .execute(&self.pool)
        .await;

        if let Err(e) = res {
            tracing::error!("web_login pg store {sid}: {e}");
        }
    }

    async fn remove(&self, sid: &str) {
        let res = sqlx::query("DELETE FROM web_sessions WHERE sid = $1")
            .bind(sid)
            .execute(&self.pool)
            .await;
        if let Err(e) = res {
            tracing::error!("web_login pg remove {sid}: {e}");
        }
    }
}
