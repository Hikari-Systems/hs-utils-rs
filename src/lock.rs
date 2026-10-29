//! Named locks that hold across replicas, for short critical sections: a
//! read-change-write of something external that cannot do compare-and-set
//! itself (hs-deploy-controller's one-key edit of an AWS Secrets Manager JSON
//! secret is the first user).
//!
//! A [`LockManager`] comes back from [`crate::session_store::build_session_store`]
//! (`SessionSetup::locks`), on the session store's own backend, and nothing of
//! that backend leaves this module: callers get locks, never a pool or a
//! connection. Backends, by feature:
//!
//! - **`lock-postgres`** (`session.store = "postgres"`): a session-level advisory
//!   lock (`pg_try_advisory_lock`) on a connection taken from the session pool
//!   and held for exactly as long as the [`LockGuard`]. The key is
//!   `hashtextextended('hs_utils.lock:' || name, 0)`, so names can't collide
//!   with another advisory-lock user of the same database by accident. A guard
//!   dropped without [`LockGuard::release`] closes its connection, and Postgres
//!   frees a session's locks when the session ends, so a panic or a cancelled
//!   future can never leave a lock held; nor can a replica that dies, once its
//!   TCP connection is gone.
//! - **`lock-redis`** (`session.store = "redis"`): `SET hs_utils:lock:<name>
//!   <token> NX PX <lease>`, released by a script that deletes the key only if
//!   it still holds this guard's token. **A lease, not a connection**: a holder
//!   that dies frees it after [`LockManager::with_lease`] (default 60 s), and a
//!   holder that stalls longer than that loses it while still running, so the
//!   lease must comfortably exceed the longest critical section.
//! - **`lock`** alone (`memory` sessions, or [`LockManager::local`]): an
//!   in-process mutex per name. **Replica-local**, like the memory session
//!   store, and correct only for a single process; [`LockManager::is_shared`]
//!   says which one you have.
//!
//! A store whose backend wasn't compiled in gets `None` from
//! `SessionSetup::locks`, never a local lock that would look shared.
//!
//! Locks are for seconds, not minutes. A waiter polls every 100 ms until
//! [`LockManager::acquire`]'s `wait`; a held Postgres lock (and a Postgres
//! waiter) is a connection out of the session pool for that long.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Why [`LockManager::acquire`] returned without the lock.
#[derive(Debug)]
pub enum LockError {
    /// Someone else held it for the whole `wait`.
    Busy,
    /// The backend failed (e.g. no connection could be had).
    Backend(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Busy => f.write_str("the lock is held by someone else"),
            LockError::Backend(m) => write!(f, "lock backend: {m}"),
        }
    }
}

impl std::error::Error for LockError {}

/// Cheap to clone; every clone shares the same locks.
#[derive(Clone)]
pub struct LockManager {
    inner: Arc<Backend>,
    /// How long a lease-based (redis) lock outlives a holder that vanished.
    #[cfg_attr(not(feature = "lock-redis"), allow(dead_code))]
    lease: Duration,
}

enum Backend {
    Local(Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>),
    #[cfg(feature = "lock-postgres")]
    Postgres(sqlx::PgPool),
    #[cfg(feature = "lock-redis")]
    Redis(Arc<crate::web_login_redis::RedisConn>),
}

/// Shows the backend, never the pool or connection (their `Debug` carries
/// connection details).
impl std::fmt::Debug for LockManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockManager").field("shared", &self.is_shared()).finish_non_exhaustive()
    }
}

/// The default redis lease.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(60);
#[cfg(any(feature = "lock-postgres", feature = "lock-redis"))]
const POLL: Duration = Duration::from_millis(100);

impl LockManager {
    fn new(b: Backend) -> Self {
        Self {
            inner: Arc::new(b),
            lease: DEFAULT_LEASE,
        }
    }

    /// In-process locks: correct for one process only.
    pub fn local() -> Self {
        Self::new(Backend::Local(Mutex::new(HashMap::new())))
    }

    /// Advisory locks on `pool`'s database. Crate-private: a consumer gets one
    /// from `SessionSetup::locks`, so the pool stays here.
    #[cfg(feature = "lock-postgres")]
    pub(crate) fn postgres(pool: sqlx::PgPool) -> Self {
        Self::new(Backend::Postgres(pool))
    }

    /// Lease locks on the session store's redis.
    #[cfg(feature = "lock-redis")]
    pub(crate) fn redis(conn: Arc<crate::web_login_redis::RedisConn>) -> Self {
        Self::new(Backend::Redis(conn))
    }

    /// For a lease-based backend (redis), how long a lock outlives a holder
    /// that died or stalled. Ignored by the others, which free a lock exactly
    /// when its holder goes. Rounded up to whole milliseconds, at least 1.
    pub fn with_lease(mut self, lease: Duration) -> Self {
        self.lease = lease.max(Duration::from_millis(1));
        self
    }

    /// Whether a lock taken here excludes other replicas too.
    pub fn is_shared(&self) -> bool {
        !matches!(&*self.inner, Backend::Local(_))
    }

    /// Takes the lock `name`, waiting up to `wait` for its holder to finish.
    pub async fn acquire(&self, name: &str, wait: Duration) -> Result<LockGuard, LockError> {
        match &*self.inner {
            Backend::Local(map) => {
                let m = {
                    let mut map = map.lock().unwrap_or_else(|p| p.into_inner());
                    // Forget names nobody holds or waits on, so the map stays small.
                    map.retain(|_, m| Arc::strong_count(m) > 1);
                    map.entry(name.to_string()).or_default().clone()
                };
                match tokio::time::timeout(wait, m.lock_owned()).await {
                    Ok(g) => Ok(LockGuard {
                        inner: Guard::Local(Some(g)),
                    }),
                    Err(_) => Err(LockError::Busy),
                }
            }
            #[cfg(feature = "lock-postgres")]
            Backend::Postgres(pool) => {
                let deadline = tokio::time::Instant::now() + wait;
                let mut conn = pool.acquire().await.map_err(|e| LockError::Backend(e.to_string()))?;
                loop {
                    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended('hs_utils.lock:' || $1, 0))")
                        .bind(name)
                        .fetch_one(&mut *conn)
                        .await
                        .map_err(|e| LockError::Backend(e.to_string()))?;
                    if got {
                        return Ok(LockGuard {
                            inner: Guard::Postgres {
                                conn: Some(conn),
                                name: name.to_string(),
                            },
                        });
                    }
                    if tokio::time::Instant::now() + POLL > deadline {
                        return Err(LockError::Busy);
                    }
                    tokio::time::sleep(POLL).await;
                }
            }
            #[cfg(feature = "lock-redis")]
            Backend::Redis(conn) => {
                let deadline = tokio::time::Instant::now() + wait;
                let key = redis_key(name);
                let token = uuid::Uuid::new_v4().to_string();
                let lease_ms = u64::try_from(self.lease.as_millis()).unwrap_or(u64::MAX).max(1);
                let mut c = conn.conn().await.map_err(|e| LockError::Backend(format!("{e:#}")))?;
                loop {
                    let set: Option<String> = redis::cmd("SET")
                        .arg(&key)
                        .arg(&token)
                        .arg("NX")
                        .arg("PX")
                        .arg(lease_ms)
                        .query_async(&mut c)
                        .await
                        .map_err(|e| LockError::Backend(e.to_string()))?;
                    if set.is_some() {
                        return Ok(LockGuard {
                            inner: Guard::Redis {
                                conn: Some(conn.clone()),
                                key,
                                token,
                            },
                        });
                    }
                    if tokio::time::Instant::now() + POLL > deadline {
                        return Err(LockError::Busy);
                    }
                    tokio::time::sleep(POLL).await;
                }
            }
        }
    }
}

#[cfg(feature = "lock-redis")]
fn redis_key(name: &str) -> String {
    format!("hs_utils:lock:{name}")
}

/// Deletes the key only while it still holds this guard's token: a lease that
/// expired and was taken by someone else is theirs, not ours to delete.
#[cfg(feature = "lock-redis")]
const REDIS_RELEASE: &str = r#"if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end"#;

#[cfg(feature = "lock-redis")]
async fn redis_release(conn: &crate::web_login_redis::RedisConn, key: &str, token: &str) -> Result<bool, String> {
    let mut c = conn.conn().await.map_err(|e| format!("{e:#}"))?;
    let n: i64 = redis::Script::new(REDIS_RELEASE)
        .key(key)
        .arg(token)
        .invoke_async(&mut c)
        .await
        .map_err(|e| e.to_string())?;
    Ok(n == 1)
}

/// A held lock. Call [`LockGuard::release`] when done. Dropping it releases
/// too: a Postgres guard by closing its connection (which frees the lock
/// server-side), a redis guard by releasing in a spawned task (or, with no
/// runtime left, by its lease expiring), so an early return or a panic can't
/// leave it held.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct LockGuard {
    inner: Guard,
}

enum Guard {
    Local(Option<tokio::sync::OwnedMutexGuard<()>>),
    #[cfg(feature = "lock-postgres")]
    Postgres {
        conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
        name: String,
    },
    #[cfg(feature = "lock-redis")]
    Redis {
        conn: Option<Arc<crate::web_login_redis::RedisConn>>,
        key: String,
        token: String,
    },
}

impl std::fmt::Debug for LockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockGuard")
    }
}

impl LockGuard {
    /// Releases the lock (and, for Postgres, returns its connection to the pool).
    pub async fn release(mut self) {
        match &mut self.inner {
            Guard::Local(g) => drop(g.take()),
            #[cfg(feature = "lock-postgres")]
            Guard::Postgres { conn, name } => {
                if let Some(mut c) = conn.take() {
                    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(hashtextextended('hs_utils.lock:' || $1, 0))")
                        .bind(&*name)
                        .fetch_one(&mut *c)
                        .await;
                    match unlocked {
                        // Back to the pool only once the lock is certainly off it.
                        Ok(true) => drop(c),
                        other => {
                            tracing::warn!(lock = %name, "advisory unlock did not confirm ({other:?}); closing the connection instead");
                            drop(c.detach());
                        }
                    }
                }
            }
            #[cfg(feature = "lock-redis")]
            Guard::Redis { conn, key, token } => {
                if let Some(c) = conn.take() {
                    match redis_release(&c, key, token).await {
                        Ok(true) => {}
                        Ok(false) => tracing::warn!(lock = %key, "the lease had already expired and been taken; held past its lease"),
                        Err(e) => tracing::warn!(lock = %key, "redis unlock failed ({e}); the lease will expire"),
                    }
                }
            }
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        match &mut self.inner {
            Guard::Local(_) => {}
            // Not released: closing the connection ends the session, and with
            // it the lock. Returning it to the pool would keep it held.
            #[cfg(feature = "lock-postgres")]
            Guard::Postgres { conn, .. } => {
                if let Some(c) = conn.take() {
                    drop(c.detach());
                }
            }
            #[cfg(feature = "lock-redis")]
            Guard::Redis { conn, key, token } => {
                if let (Some(c), Ok(rt)) = (conn.take(), tokio::runtime::Handle::try_current()) {
                    let (key, token) = (std::mem::take(key), std::mem::take(token));
                    rt.spawn(async move {
                        let _ = redis_release(&c, &key, &token).await;
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_excludes_and_releases() {
        let m = LockManager::local();
        assert!(!m.is_shared());
        let g = m.acquire("a", Duration::from_millis(10)).await.unwrap();
        assert!(matches!(m.acquire("a", Duration::from_millis(20)).await, Err(LockError::Busy)));
        let other = m.acquire("b", Duration::from_millis(10)).await.expect("names are independent");
        g.release().await;
        let again = m.acquire("a", Duration::from_millis(10)).await.expect("released");
        drop(again);
        m.acquire("a", Duration::from_millis(10)).await.expect("dropping releases too");
        drop(other);
    }

    #[tokio::test]
    async fn local_waiter_gets_it_when_the_holder_lets_go() {
        let m = LockManager::local();
        let g = m.acquire("a", Duration::from_millis(10)).await.unwrap();
        let m2 = m.clone();
        let waiter = tokio::spawn(async move { m2.acquire("a", Duration::from_secs(2)).await.is_ok() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        g.release().await;
        assert!(waiter.await.unwrap());
    }

    /// Against a real Postgres when `HS_UTILS_TEST_PG_URL` is set
    /// (e.g. `postgres://postgres:postgres@127.0.0.1:5432/postgres`); skipped otherwise.
    #[cfg(feature = "lock-postgres")]
    #[tokio::test]
    async fn postgres_excludes_across_managers_and_frees_on_drop() {
        let Ok(url) = std::env::var("HS_UTILS_TEST_PG_URL") else {
            eprintln!("HS_UTILS_TEST_PG_URL not set; skipping");
            return;
        };
        let pool = || async { sqlx::postgres::PgPoolOptions::new().max_connections(3).connect(&url).await.unwrap() };
        // Two managers on two pools: two replicas.
        let (a, b) = (LockManager::postgres(pool().await), LockManager::postgres(pool().await));
        assert!(a.is_shared());
        let name = format!("t-{}", std::process::id());
        let g = a.acquire(&name, Duration::from_millis(10)).await.unwrap();
        assert!(matches!(b.acquire(&name, Duration::from_millis(300)).await, Err(LockError::Busy)));
        g.release().await;
        let g = b.acquire(&name, Duration::from_millis(300)).await.expect("released");
        drop(g);
        // The dropped guard's connection is closed; the server frees the lock with it.
        let g = a.acquire(&name, Duration::from_secs(2)).await.expect("freed by the drop");
        g.release().await;
    }

    /// Against a real redis when `HS_UTILS_TEST_REDIS_URL` is set
    /// (e.g. `redis://127.0.0.1:6379/15`); skipped otherwise.
    #[cfg(feature = "lock-redis")]
    #[tokio::test]
    async fn redis_excludes_across_managers_expires_and_never_frees_anothers() {
        let Ok(url) = std::env::var("HS_UTILS_TEST_REDIS_URL") else {
            eprintln!("HS_UTILS_TEST_REDIS_URL not set; skipping");
            return;
        };
        let conn = || {
            crate::web_login_redis::RedisSessionStore::from_url(&url, Duration::from_secs(60))
                .unwrap()
                .shared_conn()
        };
        let (a, b) = (LockManager::redis(conn()), LockManager::redis(conn()).with_lease(Duration::from_millis(300)));
        assert!(a.is_shared());
        let name = format!("t-{}", std::process::id());
        let g = a.acquire(&name, Duration::from_millis(10)).await.unwrap();
        assert!(matches!(b.acquire(&name, Duration::from_millis(300)).await, Err(LockError::Busy)));
        g.release().await;

        // b's short lease expires while b "stalls"; a takes it; b's late release must not free a's.
        let stalled = b.acquire(&name, Duration::from_millis(10)).await.unwrap();
        let mine = a.acquire(&name, Duration::from_secs(2)).await.expect("the lease expired");
        stalled.release().await;
        assert!(matches!(b.acquire(&name, Duration::from_millis(200)).await, Err(LockError::Busy)), "still a's");
        drop(mine);
        tokio::time::sleep(Duration::from_millis(100)).await;
        b.acquire(&name, Duration::from_secs(1)).await.expect("dropping releases").release().await;
    }
}
