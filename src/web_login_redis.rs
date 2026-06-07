//! Redis (Sentinel-aware) [`WebSessionStore`] for cross-replica browser login.
//!
//! Backs [`crate::web_login::WebLogin`]'s `state → URL` map and post-login
//! cookie session in a shared redis so the `gate` (flow start) and `callback`
//! (flow finish) can run on different replicas behind a load balancer without
//! the callback hitting "no stored state".
//!
//! Mirrors the FalkorDB/graph-data-service Sentinel pattern: discover the
//! current master through Redis Sentinel and re-resolve on failover. The same
//! FalkorDB Sentinel cluster is reused (it is just redis) on a dedicated db
//! index.
//!
//! Posture matches the rest of hs-utils' shared stores: **fail open** — a redis
//! outage degrades to "the user is asked to log in again", never a 500.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::sentinel::{SentinelClient, SentinelNodeConnectionInfo, SentinelServerType};
use redis::{AsyncCommands, RedisConnectionInfo, TlsMode};
use tokio::sync::Mutex;

use crate::web_login::{Session, WebSessionStore};

/// Connection settings for the redis Sentinel cluster backing the session
/// store. Mirrors the `session.redis` config block / `session__redis__*` env
/// keys (`auth` is the password, matching the existing controllers).
#[derive(Debug, Clone, Default)]
pub struct RedisSentinelConfig {
    /// Sentinel addresses (`host:port`, with or without a `redis://` scheme).
    pub hosts: Vec<String>,
    /// Sentinel master group name.
    pub master_name: String,
    /// Redis logical db index.
    pub db: i64,
    /// Redis ACL username (optional).
    pub username: Option<String>,
    /// Redis password (the `auth` key).
    pub password: Option<String>,
    /// Use TLS to the redis node (insecure verification, in-VPC).
    pub tls: bool,
}

/// Sentinel-aware redis [`WebSessionStore`].
pub struct RedisSessionStore {
    sentinel: Arc<Mutex<SentinelClient>>,
    ttl_secs: u64,
    prefix: String,
}

impl RedisSessionStore {
    /// Default key prefix for session entries.
    pub const DEFAULT_PREFIX: &'static str = "weblogin:sess:";

    /// Build from Sentinel settings. `ttl` is the per-session expiry (refreshed
    /// on every write).
    pub fn from_sentinel(cfg: RedisSentinelConfig, ttl: Duration) -> Result<Self> {
        let hosts: Vec<String> = cfg
            .hosts
            .iter()
            .map(|h| {
                if h.starts_with("redis://") {
                    h.clone()
                } else {
                    format!("redis://{h}")
                }
            })
            .collect();
        anyhow::ensure!(!hosts.is_empty(), "redis sentinel hosts list is empty");

        let node_info = SentinelNodeConnectionInfo {
            tls_mode: Some(TlsMode::Insecure).filter(|_| cfg.tls),
            redis_connection_info: Some(RedisConnectionInfo {
                db: cfg.db,
                username: cfg.username.clone(),
                password: cfg.password.clone(),
                protocol: redis::ProtocolVersion::RESP2,
            }),
        };

        let sentinel = SentinelClient::build(
            hosts,
            cfg.master_name.clone(),
            Some(node_info),
            SentinelServerType::Master,
        )
        .context("build redis sentinel client")?;

        Ok(Self {
            sentinel: Arc::new(Mutex::new(sentinel)),
            ttl_secs: ttl.as_secs().max(1),
            prefix: Self::DEFAULT_PREFIX.to_string(),
        })
    }

    fn key(&self, sid: &str) -> String {
        format!("{}{sid}", self.prefix)
    }

    /// Borrow a fresh master connection (re-resolves via Sentinel each call).
    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection> {
        let mut s = self.sentinel.lock().await;
        s.get_async_connection()
            .await
            .context("sentinel get_async_connection")
    }
}

#[async_trait]
impl WebSessionStore for RedisSessionStore {
    async fn load(&self, sid: &str) -> Option<Session> {
        let key = self.key(sid);
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("web_login redis load: connection failed: {e:#}");
                return None; // fail open
            }
        };
        let raw: Option<String> = match conn.get(&key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("web_login redis load {sid}: {e}");
                return None;
            }
        };
        let raw = raw?;
        match serde_json::from_str::<Session>(&raw) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!("web_login redis load {sid}: malformed payload: {e}");
                None
            }
        }
    }

    async fn store(&self, sid: &str, session: &Session) {
        let key = self.key(sid);
        let json = match serde_json::to_string(session) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("web_login redis store {sid}: serialize failed: {e}");
                return;
            }
        };
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("web_login redis store: connection failed: {e:#}");
                return;
            }
        };
        let res: redis::RedisResult<()> = conn.set_ex(&key, json, self.ttl_secs).await;
        if let Err(e) = res {
            tracing::error!("web_login redis store {sid}: {e}");
        }
    }

    async fn remove(&self, sid: &str) {
        let key = self.key(sid);
        let Ok(mut conn) = self.conn().await else {
            return;
        };
        let res: redis::RedisResult<()> = conn.del(&key).await;
        if let Err(e) = res {
            tracing::error!("web_login redis remove {sid}: {e}");
        }
    }
}
