//! Generic realtime pub/sub backplane (`pubsub` feature).
//!
//! A small abstraction for fanning a typed event out to many subscribers —
//! e.g. an SSE/WebSocket endpoint pushing change notifications to browsers.
//! The [`EventBus`] trait is generic over the payload `E`; pick an
//! implementation by transport:
//!
//! - [`PgEventBus`] — Postgres `LISTEN/NOTIFY`. `publish` issues `pg_notify`
//!   on the channel; a background task `LISTEN`s and rebroadcasts every
//!   notification onto a local [`tokio::sync::broadcast`] channel that
//!   subscribers read. Because Postgres delivers a `NOTIFY` to *all* listeners
//!   on the channel (including the publishing process), this is the single
//!   delivery path — and it fans out across every replica that holds the same
//!   `LISTEN`, so no sticky sessions are needed. Reuses any [`sqlx::PgPool`]
//!   (build one with [`crate::db::build_pool`]); the channel carries no rows,
//!   so any reachable database works.
//! - [`RedisEventBus`] (`pubsub-redis`) — redis `PUBLISH`/`SUBSCRIBE` on the
//!   session store's redis (Sentinel or single node). The same shape as
//!   [`PgEventBus`]: `publish` issues `PUBLISH`, a background task holds a
//!   dedicated `SUBSCRIBE` connection and rebroadcasts locally, re-resolving
//!   the master (Sentinel) and reconnecting with backoff when it drops.
//!   Delivery is fire-and-forget, as with `NOTIFY`.
//! - [`InMemoryEventBus`] — a single-process [`tokio::sync::broadcast`] with no
//!   cross-replica fan-out. The dev / no-Postgres fallback.
//!
//! With the `pubsub-axum` feature, [`sse_stream`] turns a subscriber receiver
//! into an axum Server-Sent Events response (unnamed `message` events whose data
//! is the JSON-serialised payload, plus keep-alive comments).
//!
//! ```ignore
//! #[derive(Clone, serde::Serialize, serde::Deserialize)]
//! #[serde(tag = "type", rename_all = "lowercase")]
//! enum Change { Item { id: String }, List }
//!
//! let bus: Arc<dyn EventBus<Change>> = match cfg.transport {
//!     Transport::Postgres => Arc::new(PgEventBus::new(pool, "item_events", 256)),
//!     Transport::Memory   => Arc::new(InMemoryEventBus::new(256)),
//! };
//! bus.publish(Change::List);                 // after a write
//! let sse = sse_stream(bus.subscribe());     // in a GET /events handler
//! ```

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::sync::broadcast;
use tracing::Instrument;

/// Default local fan-out channel depth. A subscriber that falls this far behind
/// is dropped (`Lagged`) and skips the gap — appropriate for "nudge" events
/// where a client re-syncs on reconnect.
pub const DEFAULT_CAPACITY: usize = 256;

/// Pub/sub transport for a typed event `E`. Implementations fan a published
/// event out to every [`subscribe`](EventBus::subscribe)r (and, for
/// cross-replica transports, every replica).
pub trait EventBus<E>: Send + Sync {
    /// Publish an event to all subscribers. Fire-and-forget and best-effort:
    /// callers publish *after* the originating write has already committed, so a
    /// publish failure costs only freshness, never correctness.
    fn publish(&self, event: E);
    /// Subscribe to this process's local fan-out stream (one receiver per
    /// consumer, e.g. per SSE connection).
    fn subscribe(&self) -> broadcast::Receiver<E>;
}

/// In-memory, single-process bus (dev / no-Postgres fallback). No cross-replica
/// fan-out — `publish` sends straight to local subscribers.
pub struct InMemoryEventBus<E> {
    tx: broadcast::Sender<E>,
}

impl<E: Clone + Send + 'static> InMemoryEventBus<E> {
    /// Create a bus with the given local channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }
}

impl<E: Clone + Send + 'static> EventBus<E> for InMemoryEventBus<E> {
    fn publish(&self, event: E) {
        let _ = self.tx.send(event); // Err only means "no subscribers" — ignore.
    }
    fn subscribe(&self) -> broadcast::Receiver<E> {
        self.tx.subscribe()
    }
}

/// Postgres `LISTEN/NOTIFY` bus. `publish` → `pg_notify(channel, json)`; a
/// background task `LISTEN`s and rebroadcasts onto the local channel.
pub struct PgEventBus<E> {
    pool: PgPool,
    tx: broadcast::Sender<E>,
    channel: String,
}

impl<E> PgEventBus<E>
where
    E: Serialize + DeserializeOwned + Clone + Send + 'static,
{
    /// Build the bus and spawn its `LISTEN` task (which reconnects on error).
    /// Requires a Tokio runtime. `channel` is the `NOTIFY/LISTEN` channel name.
    pub fn new(pool: PgPool, channel: impl Into<String>, capacity: usize) -> Self {
        let channel = channel.into();
        let (tx, _) = broadcast::channel(capacity);
        tokio::spawn(listen_loop::<E>(pool.clone(), tx.clone(), channel.clone()));
        Self { pool, tx, channel }
    }
}

impl<E> EventBus<E> for PgEventBus<E>
where
    E: Serialize + DeserializeOwned + Clone + Send + 'static,
{
    fn publish(&self, event: E) {
        let pool = self.pool.clone();
        let channel = self.channel.clone();
        // Made here, so the spawned NOTIFY is a child of whatever published.
        let span = publish_span("postgresql", "NOTIFY", pool.connect_options().get_host(), &channel);
        tokio::spawn(
            async move {
                let payload = match serde_json::to_string(&event) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("pubsub publish: serialise failed: {e:#}");
                        published(&channel, "postgres", "error");
                        return;
                    }
                };
                let outcome = match sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(&channel)
                    .bind(&payload)
                    .execute(&pool)
                    .await
                {
                    Ok(_) => "ok",
                    Err(e) => {
                        tracing::warn!("pubsub publish (pg_notify) failed: {e:#}");
                        "error"
                    }
                };
                published(&channel, "postgres", outcome);
            }
            .instrument(span),
        );
    }
    fn subscribe(&self) -> broadcast::Receiver<E> {
        self.tx.subscribe()
    }
}

// ── telemetry ──────────────────────────────────────────────────────────────
//
// `hs.pubsub.*` counters, labelled by `channel` (a name from code) and
// `backend`. The span is the publish's; delivery happens on the listener task,
// which no request owns, so it is counted rather than traced.

/// The client span of one publish, made in the publisher's context so the
/// spawned send is its child.
fn publish_span(system: &str, op: &str, peer: &str, channel: &str) -> tracing::Span {
    let span = crate::telemetry::client_span(system, op, peer);
    span.record("client.target", crate::telemetry::truncate(channel, crate::telemetry::MAX_ATTR_LEN));
    span
}

/// Count a publish, and close its span's outcome.
fn published(channel: &str, backend: &str, outcome: &'static str) {
    crate::telemetry::record_outcome(&tracing::Span::current(), outcome);
    crate::telemetry::count("hs.pubsub.published", 1, &[("channel", channel), ("backend", backend), ("outcome", outcome)]);
}

/// Hand an event from the backend to local subscribers. `delivered` counts
/// events received (not copies): `outcome=no_subscribers` when no one on this
/// replica was listening.
fn delivered<E>(tx: &broadcast::Sender<E>, event: E, channel: &str, backend: &str) {
    let outcome = if tx.send(event).is_ok() { "delivered" } else { "no_subscribers" };
    crate::telemetry::count("hs.pubsub.received", 1, &[("channel", channel), ("backend", backend), ("outcome", outcome)]);
}

/// The listener lost (or never got) its connection and is about to retry.
/// A steady rate of these is a bus that delivers nothing.
fn reconnecting(channel: &str, backend: &str) {
    crate::telemetry::count("hs.pubsub.listener_reconnects", 1, &[("channel", channel), ("backend", backend)]);
}

/// Long-lived `LISTEN` task: (re)connect, listen, rebroadcast each notification
/// (skipping any that don't deserialise to `E`), and reconnect with exponential
/// backoff (1s→30s) if the connection drops.
async fn listen_loop<E>(pool: PgPool, tx: broadcast::Sender<E>, channel: String)
where
    E: DeserializeOwned + Clone + Send + 'static,
{
    const BASE: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);
    let mut backoff = BASE;
    loop {
        match PgListener::connect_with(&pool).await {
            Ok(mut listener) => match listener.listen(&channel).await {
                Ok(()) => {
                    backoff = BASE; // healthy connection — reset backoff
                    tracing::info!("pubsub LISTENing on '{channel}'");
                    loop {
                        match listener.recv().await {
                            Ok(notification) => {
                                match serde_json::from_str::<E>(notification.payload()) {
                                    Ok(event) => delivered(&tx, event, &channel, "postgres"),
                                    Err(e) => tracing::debug!(
                                        "pubsub: ignoring unparseable payload on '{channel}': {e}"
                                    ),
                                }
                            }
                            Err(e) => {
                                tracing::warn!("pubsub recv error on '{channel}': {e:#}; reconnecting");
                                break;
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!("pubsub LISTEN failed on '{channel}': {e:#}"),
            },
            Err(e) => tracing::warn!("pubsub connect failed: {e:#}"),
        }
        reconnecting(&channel, "postgres");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX);
    }
}

/// Redis `PUBLISH`/`SUBSCRIBE` bus. Built by `SessionSetup::event_bus` for a
/// redis session store; the connection never leaves the crate.
#[cfg(feature = "pubsub-redis")]
pub struct RedisEventBus<E> {
    conn: std::sync::Arc<crate::web_login_redis::RedisConn>,
    tx: broadcast::Sender<E>,
    channel: String,
}

#[cfg(feature = "pubsub-redis")]
impl<E> RedisEventBus<E>
where
    E: Serialize + DeserializeOwned + Clone + Send + 'static,
{
    /// Build the bus and spawn its `SUBSCRIBE` task. Requires a Tokio runtime.
    pub(crate) fn new(conn: std::sync::Arc<crate::web_login_redis::RedisConn>, channel: impl Into<String>, capacity: usize) -> Self {
        let channel = channel.into();
        let (tx, _) = broadcast::channel(capacity);
        tokio::spawn(redis_subscribe_loop::<E>(conn.clone(), tx.clone(), channel.clone()));
        Self { conn, tx, channel }
    }
}

#[cfg(feature = "pubsub-redis")]
impl<E> EventBus<E> for RedisEventBus<E>
where
    E: Serialize + DeserializeOwned + Clone + Send + 'static,
{
    fn publish(&self, event: E) {
        let conn = self.conn.clone();
        let channel = self.channel.clone();
        let span = publish_span("redis", "PUBLISH", &conn.peer(), &channel);
        tokio::spawn(
            async move {
                let payload = match serde_json::to_string(&event) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("pubsub publish: serialise failed: {e:#}");
                        published(&channel, "redis", "error");
                        return;
                    }
                };
                let res = async {
                    let mut c = conn.conn().await?;
                    redis::cmd("PUBLISH")
                        .arg(&channel)
                        .arg(&payload)
                        .query_async::<i64>(&mut c)
                        .await
                        .map_err(anyhow::Error::from)
                }
                .await;
                let outcome = match res {
                    Ok(_) => "ok",
                    Err(e) => {
                        tracing::warn!("pubsub publish (redis PUBLISH) failed: {e:#}");
                        "error"
                    }
                };
                published(&channel, "redis", outcome);
            }
            .instrument(span),
        );
    }
    fn subscribe(&self) -> broadcast::Receiver<E> {
        self.tx.subscribe()
    }
}

/// Long-lived `SUBSCRIBE` task, as [`listen_loop`]: (re)connect, subscribe,
/// rebroadcast each message (skipping any that don't deserialise to `E`), and
/// reconnect with exponential backoff (1s→30s) when the connection drops.
#[cfg(feature = "pubsub-redis")]
async fn redis_subscribe_loop<E>(
    conn: std::sync::Arc<crate::web_login_redis::RedisConn>,
    tx: broadcast::Sender<E>,
    channel: String,
) where
    E: DeserializeOwned + Clone + Send + 'static,
{
    use futures_util::StreamExt;
    const BASE: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);
    let mut backoff = BASE;
    loop {
        match conn.pubsub().await {
            Ok(mut ps) => match ps.subscribe(&channel).await {
                Ok(()) => {
                    backoff = BASE;
                    tracing::info!("pubsub SUBSCRIBEd to '{channel}'");
                    let mut stream = ps.on_message();
                    while let Some(msg) = stream.next().await {
                        let Ok(payload) = msg.get_payload::<String>() else { continue };
                        match serde_json::from_str::<E>(&payload) {
                            Ok(event) => delivered(&tx, event, &channel, "redis"),
                            Err(e) => tracing::debug!("pubsub: ignoring unparseable payload on '{channel}': {e}"),
                        }
                    }
                    tracing::warn!("pubsub subscription to '{channel}' ended; reconnecting");
                }
                Err(e) => tracing::warn!("pubsub SUBSCRIBE failed on '{channel}': {e:#}"),
            },
            Err(e) => tracing::warn!("pubsub redis connect failed: {e:#}"),
        }
        reconnecting(&channel, "redis");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX);
    }
}

#[cfg(feature = "pubsub-axum")]
pub use self::sse::sse_stream;

#[cfg(feature = "pubsub-axum")]
mod sse {
    use std::convert::Infallible;

    use axum::response::sse::{Event, KeepAlive, Sse};
    use serde::Serialize;
    use tokio::sync::broadcast;
    use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};

    /// Turn a [`broadcast::Receiver`] of events into an axum SSE response. Each
    /// event is sent as an unnamed `message` whose data is the JSON-serialised
    /// payload (so a browser `EventSource`'s `onmessage` receives it); `Lagged`
    /// and serialise errors are skipped rather than tearing down the stream.
    /// Keep-alive comments hold the connection open through idle periods/proxies.
    pub fn sse_stream<E>(
        rx: broadcast::Receiver<E>,
    ) -> Sse<impl Stream<Item = Result<Event, Infallible>>>
    where
        E: Serialize + Clone + Send + 'static,
    {
        let open = Open::new();
        let stream = BroadcastStream::new(rx).filter_map(move |res| {
            let _held = &open; // counted open until the stream is dropped
            let event = match res {
                Ok(e) => e,
                // This client fell behind and missed `n` events: the bus's
                // `capacity` is too small for it, or it is too slow.
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    crate::telemetry::count("hs.sse.lagged_events", n, &[]);
                    return None;
                }
            };
            let data = serde_json::to_string(&event).ok()?;
            Some(Ok(Event::default().data(data)))
        });
        Sse::new(stream).keep_alive(KeepAlive::default())
    }

    /// `hs.sse.connections`: +1 while an SSE stream exists, −1 when axum drops
    /// it (the client disconnected, or the server is shutting down).
    struct Open;

    impl Open {
        fn new() -> Self {
            crate::telemetry::up_down("hs.sse.connections", 1, &[]);
            Open
        }
    }

    impl Drop for Open {
        fn drop(&mut self) {
            crate::telemetry::up_down("hs.sse.connections", -1, &[]);
        }
    }
}

#[cfg(all(test, feature = "pubsub"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_publish_reaches_subscriber() {
        let bus = InMemoryEventBus::<String>::new(16);
        let mut rx = bus.subscribe();
        bus.publish("hello".to_string());
        assert_eq!(rx.recv().await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn in_memory_is_object_safe() {
        // The whole point of the trait: store behind a trait object and swap impls.
        let bus: std::sync::Arc<dyn EventBus<u32>> =
            std::sync::Arc::new(InMemoryEventBus::<u32>::new(16));
        let mut rx = bus.subscribe();
        bus.publish(42);
        assert_eq!(rx.recv().await.unwrap(), 42);
    }
}

#[cfg(all(test, feature = "pubsub-redis"))]
mod redis_tests {
    use super::*;

    /// Two buses on two connections (two replicas) when `HS_UTILS_TEST_REDIS_URL`
    /// is set; skipped otherwise.
    #[tokio::test]
    async fn redis_bus_fans_out_across_replicas() {
        let Ok(url) = std::env::var("HS_UTILS_TEST_REDIS_URL") else {
            eprintln!("HS_UTILS_TEST_REDIS_URL not set; skipping");
            return;
        };
        let conn = || crate::web_login_redis::RedisSessionStore::from_url(&url, Duration::from_secs(60)).unwrap().shared_conn();
        let channel = format!("hs-utils-test-{}", std::process::id());
        let (a, b) = (RedisEventBus::<String>::new(conn(), &channel, 8), RedisEventBus::<String>::new(conn(), &channel, 8));
        let mut rx = b.subscribe();
        // Let b's SUBSCRIBE land before publishing (fire-and-forget, like NOTIFY).
        tokio::time::sleep(Duration::from_millis(300)).await;
        a.publish("hello".into());
        let got = tokio::time::timeout(Duration::from_secs(3), rx.recv()).await.expect("delivered").unwrap();
        assert_eq!(got, "hello");
    }
}
