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
//! The table name defaults to `web_sessions` ([`DEFAULT_SESSION_TABLE`]) but can
//! be overridden with [`PgSessionStore::with_table`] — useful when several
//! controller services share one database and each needs its own session table
//! (e.g. `lloquent_web_session`). The override is wired from service config:
//!
//! ```ignore
//! let store = PgSessionStore::from_pool(pool)
//!     .with_table(cfg.session_table.as_deref().unwrap_or(DEFAULT_SESSION_TABLE))?;
//! store.ensure_schema().await?;
//! ```
//!
//! Redis evicts expired keys for you; Postgres does not, so expiry is handled
//! two ways: every `load` filters `expires_at > now()` (an expired row is
//! invisible the instant it lapses), and [`PgSessionStore::sweep_expired`]
//! reclaims the dead rows — call it periodically (e.g. an hourly task).
//!
//! Posture matches the rest of hs-utils' shared stores: a failure is logged here
//! **and returned**, and the caller decides what it costs — a caller whose next
//! step depends on the write landing (the session-id rotation in `callback`) can
//! now tell that it did not.
//!
//! **What that costs during an outage is worth knowing before you plan a
//! maintenance window.** The gate's *read* fails open, but the browser tier
//! writes immediately afterwards and that write is fatal, so a Postgres outage
//! is a 503 on every browser-gated page — not "everyone is asked to log in
//! again". Api-gated routes still 401, because they return before the write. See
//! `web_login::gate`, and the oracle both stores share,
//! `web_login::tests::a_store_outage_is_a_401_on_the_api_tier_and_a_503_on_the_browser_tier`.
//!
//! **First-time DB setup** (role, table, grants — one script per consuming
//! service) is templated in `docs/web-login-postgres-db-setup.md`; copy the
//! relevant parts into the service README.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::web_login::{log_safe, Session, WebSessionStore, DEFAULT_SESSION_TTL_SECS};

/// Default session table name, used unless overridden via
/// [`PgSessionStore::with_table`].
pub const DEFAULT_SESSION_TABLE: &str = "web_sessions";

/// Postgres [`WebSessionStore`] over a shared [`PgPool`].
///
/// The table name is fixed for the life of the store: it is validated once at
/// construction and baked into the SQL strings then (a table name can never be a
/// bind parameter — the Postgres protocol parameterises *values* only, so the
/// identifier must be interpolated). The hot-path statements are pre-built here
/// and reused on every call; sqlx prepares-and-caches each by SQL text per
/// connection, so each is prepared once per connection and reused thereafter.
#[derive(Clone)]
pub struct PgSessionStore {
    pool: PgPool,
    ttl_secs: i64,
    table: String,
    sql_load: String,
    sql_store: String,
    sql_remove: String,
}

impl PgSessionStore {
    /// Build over an existing pool with the given per-session expiry (refreshed
    /// on every write, mirroring redis `set_ex`). Uses [`DEFAULT_SESSION_TABLE`];
    /// override with [`with_table`](Self::with_table).
    pub fn new(pool: PgPool, ttl: Duration) -> Self {
        // DEFAULT_SESSION_TABLE is a known-valid identifier.
        Self::build(pool, ttl.as_secs().max(1) as i64, DEFAULT_SESSION_TABLE.to_string())
    }

    /// Build with the default 24h TTL ([`DEFAULT_SESSION_TTL_SECS`]).
    pub fn from_pool(pool: PgPool) -> Self {
        Self::new(pool, Duration::from_secs(DEFAULT_SESSION_TTL_SECS))
    }

    /// Override the session table name (e.g. `"lloquent_web_session"`) — useful
    /// when several services share one database, each with its own session
    /// table. Validated as a Postgres identifier (letters, digits, underscore;
    /// not starting with a digit; ≤63 chars); errors on anything unsafe to
    /// interpolate. Pool and TTL are preserved.
    pub fn with_table(self, table: &str) -> Result<Self> {
        let table = validate_table_name(table)?;
        Ok(Self::build(self.pool, self.ttl_secs, table))
    }

    /// Assemble the struct, baking `table` into the pre-built hot-path SQL.
    /// `table` must already be a validated identifier.
    fn build(pool: PgPool, ttl_secs: i64, table: String) -> Self {
        let sql_load = format!(
            "SELECT data FROM {table} WHERE sid = $1 AND expires_at > now()"
        );
        let sql_store = format!(
            "INSERT INTO {table} (sid, data, expires_at) \
             VALUES ($1, $2, now() + ($3 * interval '1 second')) \
             ON CONFLICT (sid) DO UPDATE \
               SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at"
        );
        let sql_remove = format!("DELETE FROM {table} WHERE sid = $1");
        Self {
            pool,
            ttl_secs,
            table,
            sql_load,
            sql_store,
            sql_remove,
        }
    }

    /// The configured session table name.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Create the session table and its expiry index if absent.
    /// Idempotent; safe to call on every boot.
    pub async fn ensure_schema(&self) -> Result<()> {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {} (\
                 sid        TEXT PRIMARY KEY, \
                 data       JSONB NOT NULL, \
                 expires_at TIMESTAMPTZ NOT NULL\
             )",
            self.table
        ))
        .execute(&self.pool)
        .await?;
        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS {table}_expires_at_idx \
             ON {table} (expires_at)",
            table = self.table
        ))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete expired rows, returning the number reclaimed. Reads already
    /// ignore expired sessions, so this is housekeeping — run it on a timer.
    pub async fn sweep_expired(&self) -> Result<u64> {
        let res = sqlx::query(&format!(
            "DELETE FROM {} WHERE expires_at <= now()",
            self.table
        ))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

/// Validate a Postgres identifier safe to interpolate into a SQL statement:
/// `^[A-Za-z_][A-Za-z0-9_]*$`, 1..=63 bytes. This is the injection guard for the
/// (necessarily) interpolated table name.
fn validate_table_name(name: &str) -> Result<String> {
    let valid = (1..=63).contains(&name.len())
        && name.bytes().enumerate().all(|(i, b)| {
            b == b'_'
                || b.is_ascii_alphabetic()
                || (i > 0 && b.is_ascii_digit())
        });
    if !valid {
        anyhow::bail!(
            "invalid session table name {name:?}: must be a Postgres identifier \
             (letters, digits, underscore; not starting with a digit; 1..=63 chars)"
        );
    }
    Ok(name.to_string())
}

// **No error path below names the `sid`, and that is load-bearing.** The
// `hs_session` value is an unsigned bearer credential — possession is
// authentication — and these are the *error* branches, so during a database
// outage they fire for every in-flight authenticated request at once: naming it
// writes the whole logged-in fleet's live credentials into the container log,
// which then leaves the building with the logs. Nothing derived from it is an
// acceptable stand-in either — a truncation is still a partial disclosure of a
// credential, and a hash is a stable handle to one — so the sid is *dropped*
// rather than redacted. The invariant, so it survives a refactor of these same
// lines: the sid never enters a formatted string in this module, not a message,
// not an `anyhow::Context`, not an error.
//
// What a reader gets instead is `session.store` / `session.op` / `session.table`
// as fields, plus whatever spans enclose the call — the fmt layer renders the
// scope as a prefix. **How much that is depends on the consumer, so do not read
// it as a guarantee.** `auth.gate` is this crate's only span and it wraps
// `decide` alone, so it covers the gate's `load`/`store` and NOT `callback`'s;
// an `http.server` span exists only in a service that installs one
// (`otel::axum_trace_layer`), which botsafely-controller does and two of the
// three consumers of this store do not. Where neither applies the line stands on
// its own fields. That is accepted: correlation is a compensating control, and
// dropping the credential is right with or without it.
// `error.message` is a **bare `&str`, never `%e`**: sqlx' `Display` output
// is downstream-derived, and `%` emits bytes raw, so a newline in it would forge
// a whole log line. `session.*` take `%` because they are compile-time literals
// and a validated identifier.
//
// **Every failure is now both logged here and returned to the caller**, and the
// two are not redundant. The `error!` is the cause, at the only place that has
// it in full; the `Err` is the *fact* of the failure, which is what the caller
// needs in order to stop — it used to be swallowed here, so `callback` deleted a
// live session on the strength of a write that never landed. The returned error
// carries a fixed context string and the backend's own error as its source;
// neither names the sid, per the invariant above.
#[async_trait]
impl WebSessionStore for PgSessionStore {
    async fn load(&self, sid: &str) -> Result<Option<Session>> {
        let res = sqlx::query_scalar::<_, serde_json::Value>(&self.sql_load)
            .bind(sid)
            .fetch_optional(&self.pool)
            .await;

        let data = match res {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => {
                tracing::error!(
                    session.store = %"postgres",
                    session.op = %"load",
                    session.table = %self.table,
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login pg load failed"
                );
                return Err(anyhow::Error::new(e).context("web_login pg load"));
            }
        };

        match serde_json::from_value::<Session>(data) {
            Ok(s) => Ok(Some(s)),
            Err(e) => {
                tracing::error!(
                    session.store = %"postgres",
                    session.op = %"load",
                    session.table = %self.table,
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login pg load: malformed payload"
                );
                Err(anyhow::Error::new(e).context("web_login pg load: malformed payload"))
            }
        }
    }

    async fn store(&self, sid: &str, session: &Session) -> Result<()> {
        let data = match serde_json::to_value(session) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    session.store = %"postgres",
                    session.op = %"store",
                    session.table = %self.table,
                    error.message = log_safe(&e.to_string()).as_str(),
                    "web_login pg store: serialize failed"
                );
                return Err(anyhow::Error::new(e).context("web_login pg store: serialize failed"));
            }
        };

        let res = sqlx::query(&self.sql_store)
            .bind(sid)
            .bind(data)
            .bind(self.ttl_secs)
            .execute(&self.pool)
            .await;

        if let Err(e) = res {
            tracing::error!(
                session.store = %"postgres",
                session.op = %"store",
                session.table = %self.table,
                error.message = log_safe(&e.to_string()).as_str(),
                "web_login pg store failed"
            );
            return Err(anyhow::Error::new(e).context("web_login pg store"));
        }
        Ok(())
    }

    async fn remove(&self, sid: &str) -> Result<()> {
        let res = sqlx::query(&self.sql_remove)
            .bind(sid)
            .execute(&self.pool)
            .await;
        if let Err(e) = res {
            tracing::error!(
                session.store = %"postgres",
                session.op = %"remove",
                session.table = %self.table,
                error.message = log_safe(&e.to_string()).as_str(),
                "web_login pg remove failed"
            );
            return Err(anyhow::Error::new(e).context("web_login pg remove"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_identifiers() {
        for ok in ["web_sessions", "lloquent_web_session", "_x", "T1", "a", &"a".repeat(63)] {
            assert!(validate_table_name(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn rejects_unsafe_identifiers() {
        for bad in [
            "",
            "1abc",
            "web sessions",
            "web-sessions",
            "web;drop",
            "x; DROP TABLE users; --",
            &"a".repeat(64),
        ] {
            assert!(validate_table_name(bad).is_err(), "should reject {bad:?}");
        }
    }
}
