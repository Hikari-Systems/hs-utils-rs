//! OpenTelemetry metrics: the meter provider [`super::init`] builds, the
//! instruments behind [`crate::telemetry`]'s facade, the gauge catalog, and the
//! `tracing` layer that turns this crate's server and client spans into
//! request-duration and in-flight metrics.
//!
//! # What is reported
//!
//! From spans (so the axum and actix layers, `http_client::send` and every
//! `telemetry::client_span` need nothing extra):
//! * `http.server.request.duration` (s, histogram) — `http.request.method`,
//!   `http.route`, `http.response.status_code`. Measured to the moment the
//!   response status is known, so an SSE stream is not one enormous request.
//! * `http.server.active_requests` (up-down) — `http.request.method`.
//! * `http.client.request.duration` (s) — method, `server.address`, status.
//! * `hs.client.operation.duration` (s) — `client.system`, `client.operation`,
//!   `client.outcome`: redis, locks (the lock-wait histogram; `busy` is an
//!   outcome), pub/sub, a service's own SMTP.
//!
//! From gauge sources, at each collection: process CPU/memory/threads/fds/disk
//! I/O, container CPU/throttling/memory/pressure (see [`super::procfs`]), the
//! tokio runtime, DB pools (`db::build_pool` registers them) and session counts.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider as _, UpDownCounter};
use opentelemetry::KeyValue;
use tracing::span;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::telemetry::{GaugeSource, Sample, CLIENT_SPAN, HTTP_CLIENT_SPAN, SERVER_SPAN};

/// Instrumentation scope of everything this crate reports.
pub(crate) const SCOPE: &str = "hs-utils";


/// Bucket boundaries (seconds) for every duration histogram: the semantic
/// conventions' HTTP set. The SDK default (0, 5, 10, 25 … 10000) assumes
/// milliseconds and would put every request in the first bucket.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

// ── the meter, once `init` has made one ─────────────────────────────────────

static METER: OnceLock<Meter> = OnceLock::new();
static ON: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)] // reached through `crate::telemetry`, whose callers are feature-gated
fn meter() -> Option<&'static Meter> {
    if ON.load(Ordering::Relaxed) {
        METER.get()
    } else {
        None
    }
}

fn kv(attrs: &[(&'static str, &str)]) -> Vec<KeyValue> {
    attrs.iter().map(|(k, v)| KeyValue::new(*k, v.to_string())).collect()
}

// ── facade instruments ──────────────────────────────────────────────────────

static COUNTERS: OnceLock<Mutex<HashMap<&'static str, Counter<u64>>>> = OnceLock::new();
static UP_DOWNS: OnceLock<Mutex<HashMap<&'static str, UpDownCounter<i64>>>> = OnceLock::new();

#[allow(dead_code)] // reached through `crate::telemetry`, whose callers are feature-gated
pub(crate) fn count(name: &'static str, n: u64, attrs: &[(&'static str, &str)]) {
    let Some(m) = meter() else { return };
    let mut map = COUNTERS.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner());
    map.entry(name).or_insert_with(|| m.u64_counter(name).build()).add(n, &kv(attrs));
}

#[allow(dead_code)] // reached through `crate::telemetry`, whose callers are feature-gated
pub(crate) fn up_down(name: &'static str, delta: i64, attrs: &[(&'static str, &str)]) {
    let Some(m) = meter() else { return };
    let mut map = UP_DOWNS.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner());
    map.entry(name).or_insert_with(|| m.i64_up_down_counter(name).build()).add(delta, &kv(attrs));
}

// ── gauge sources ───────────────────────────────────────────────────────────

/// Registered sources. `Arc` so a collection can run them without holding
/// the lock (a source that registered another would otherwise deadlock).
static SOURCES: Mutex<Vec<Arc<GaugeSource>>> = Mutex::new(Vec::new());

#[allow(dead_code)] // reached through `crate::telemetry`, whose callers are feature-gated
pub(crate) fn register_source(source: GaugeSource) {
    SOURCES.lock().unwrap_or_else(|p| p.into_inner()).push(Arc::new(source));
}

/// Every gauge's callback runs during the same collection; run the sources
/// once per collection, not once per gauge. Anything older than this is a
/// previous collection's.
const SNAPSHOT_TTL: Duration = Duration::from_millis(500);
static SNAPSHOT: Mutex<Option<(Instant, Arc<Vec<Sample>>)>> = Mutex::new(None);

fn snapshot() -> Arc<Vec<Sample>> {
    let mut snap = SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, samples)) = snap.as_ref() {
        if at.elapsed() < SNAPSHOT_TTL {
            return samples.clone();
        }
    }
    let sources: Vec<_> = SOURCES.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let mut out = Vec::new();
    for s in sources {
        s(&mut out);
    }
    let samples = Arc::new(out);
    *snap = Some((Instant::now(), samples.clone()));
    samples
}

/// How a sampled name is exported.
#[derive(Clone, Copy)]
enum Kind {
    /// A level (memory, connections, pressure).
    Gauge,
    /// A cumulative count the OS keeps (CPU seconds, bytes): exported as a
    /// monotonic sum, so the backend computes rates and handles restarts.
    Cumulative,
}

/// Every name a [`GaugeSource`] may report. A sample under a name not listed
/// here is dropped: an instrument has to exist before collection, and this
/// keeps the exported set reviewable in one place.
const CATALOG: &[(&str, Kind, &str, &str)] = &[
    // process (/proc/self)
    ("process.cpu.time", Kind::Cumulative, "s", "CPU time used by this process, by cpu.mode"),
    ("process.cpu.utilization", Kind::Gauge, "1", "Share of the CPU available to this process (its container's quota, else all CPUs) used since the last collection"),
    ("process.memory.usage", Kind::Gauge, "By", "Resident set size"),
    ("process.memory.virtual", Kind::Gauge, "By", "Virtual memory size"),
    ("process.thread.count", Kind::Gauge, "{thread}", "Threads in this process"),
    ("process.open_file_descriptor.count", Kind::Gauge, "{file_descriptor}", "Open file descriptors"),
    ("process.disk.io", Kind::Cumulative, "By", "Bytes this process read from / wrote to storage, by disk.io.direction"),
    ("hs.process.blkio_delay", Kind::Cumulative, "s", "Time this process spent blocked on block I/O (kernel delay accounting)"),
    // container (cgroup v2)
    ("container.cpu.time", Kind::Cumulative, "s", "CPU time used by every process in this container"),
    ("hs.container.cpu.throttled_time", Kind::Cumulative, "s", "Time this container was throttled by its CPU quota"),
    ("hs.container.cpu.limit", Kind::Gauge, "{cpu}", "This container's CPU quota"),
    ("container.memory.usage", Kind::Gauge, "By", "Memory charged to this container (cgroup memory.current)"),
    ("hs.container.memory.limit", Kind::Gauge, "By", "This container's memory limit (cgroup memory.max)"),
    ("hs.container.pressure", Kind::Gauge, "%", "Share of the last 10 s tasks in this container were stalled on a resource (PSI avg10), by resource (cpu|memory|io) and kind (some|full). resource=io is the container's iowait"),
    // tokio
    ("hs.tokio.workers", Kind::Gauge, "{thread}", "Tokio runtime worker threads"),
    ("hs.tokio.alive_tasks", Kind::Gauge, "{task}", "Tasks alive in the tokio runtime"),
    ("hs.tokio.global_queue_depth", Kind::Gauge, "{task}", "Tasks waiting in the runtime's global queue: a sustained non-zero value means the workers cannot keep up"),
    // db pools
    ("db.client.connection.count", Kind::Gauge, "{connection}", "Pool connections, by state (idle|used)"),
    ("db.client.connection.max", Kind::Gauge, "{connection}", "The pool's maximum size"),
    // sessions
    ("hs.web_session.active", Kind::Gauge, "{session}", "Unexpired browser sessions in this service's store, by window (ttl|5m)"),
];

/// What `init` keeps alive for as long as the provider: the observable
/// instruments (their callbacks stop when these are dropped).
pub(crate) struct Instruments {
    _held: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

fn observe_into(name: &'static str) -> impl Fn() -> Vec<(f64, Vec<KeyValue>)> {
    move || {
        snapshot()
            .iter()
            .filter(|s| s.name == name)
            .map(|s| (s.value, s.attrs.iter().map(|(k, v)| KeyValue::new(*k, v.clone())).collect()))
            .collect()
    }
}

/// Install `meter` for the facade and create the catalog's observable
/// instruments. Called once from [`super::init`].
pub(crate) fn install(provider: &opentelemetry_sdk::metrics::SdkMeterProvider, process: bool) -> Instruments {
    let m = provider.meter(SCOPE);
    let mut held: Vec<Box<dyn std::any::Any + Send + Sync>> = Vec::new();
    for &(name, kind, unit, description) in CATALOG {
        let read = observe_into(name);
        match kind {
            Kind::Gauge => held.push(Box::new(
                m.f64_observable_gauge(name)
                    .with_unit(unit)
                    .with_description(description)
                    .with_callback(move |o| {
                        for (v, attrs) in read() {
                            o.observe(v, &attrs);
                        }
                    })
                    .build(),
            )),
            Kind::Cumulative => held.push(Box::new(
                m.f64_observable_counter(name)
                    .with_unit(unit)
                    .with_description(description)
                    .with_callback(move |o| {
                        for (v, attrs) in read() {
                            o.observe(v, &attrs);
                        }
                    })
                    .build(),
            )),
        }
    }
    if process {
        register_source(super::procfs::source(super::procfs::Paths::default()));
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        register_source(Box::new(move |out: &mut Vec<Sample>| {
            let rt = handle.metrics();
            for (name, value) in [
                ("hs.tokio.workers", rt.num_workers() as f64),
                ("hs.tokio.alive_tasks", rt.num_alive_tasks() as f64),
                ("hs.tokio.global_queue_depth", rt.global_queue_depth() as f64),
            ] {
                out.push(Sample { name, value, attrs: Vec::new() });
            }
        }));
    }
    let _ = METER.set(m);
    ON.store(true, Ordering::Relaxed);
    Instruments { _held: held }
}

// ── span → metrics ──────────────────────────────────────────────────────────

/// Which of this crate's spans a span is.
#[derive(Clone, Copy, PartialEq)]
enum SpanKind {
    Server,
    HttpClient,
    Client,
}

/// Field values the metrics need, captured as the span records them.
#[derive(Default)]
struct Fields {
    method: Option<String>,
    route: Option<String>,
    status: Option<i64>,
    address: Option<String>,
    system: Option<String>,
    operation: Option<String>,
    outcome: Option<String>,
}

impl tracing::field::Visit for Fields {
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        let slot = match f.name() {
            "http.request.method" => &mut self.method,
            "http.route" => &mut self.route,
            "server.address" => &mut self.address,
            "client.system" => &mut self.system,
            "client.operation" => &mut self.operation,
            "client.outcome" => &mut self.outcome,
            _ => return,
        };
        *slot = Some(v.to_string());
    }
    fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
        if f.name() == "http.response.status_code" {
            self.status = i64::try_from(v).ok();
        }
    }
    fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
        if f.name() == "http.response.status_code" {
            self.status = Some(v);
        }
    }
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        // `%value` fields arrive here as their `Display`; a `?value` string
        // would arrive quoted, so the quotes are trimmed either way.
        self.record_str(f, format!("{v:?}").trim_matches('"'));
    }
}

struct Timing {
    kind: SpanKind,
    start: Instant,
    fields: Fields,
    /// The server duration has been recorded (at the status).
    done: bool,
}

/// The layer `init` adds when metrics are on.
pub(crate) struct SpanMetrics {
    server_duration: Histogram<f64>,
    active: UpDownCounter<i64>,
    client_http_duration: Histogram<f64>,
    client_duration: Histogram<f64>,
}

impl SpanMetrics {
    pub(crate) fn new(provider: &opentelemetry_sdk::metrics::SdkMeterProvider) -> Self {
        let m = provider.meter(SCOPE);
        let hist = |name: &'static str, desc: &'static str| {
            m.f64_histogram(name)
                .with_unit("s")
                .with_description(desc)
                .with_boundaries(DURATION_BUCKETS.to_vec())
                .build()
        };
        Self {
            server_duration: hist("http.server.request.duration", "Inbound request duration, to the response status"),
            active: m
                .i64_up_down_counter("http.server.active_requests")
                .with_unit("{request}")
                .with_description("Inbound requests in progress")
                .build(),
            client_http_duration: hist("http.client.request.duration", "Outbound HTTP request duration"),
            client_duration: hist("hs.client.operation.duration", "Outbound call duration (redis, locks, pub/sub, SMTP …), by outcome"),
        }
    }

    fn server_attrs(f: &Fields) -> Vec<KeyValue> {
        let mut a = vec![
            KeyValue::new("http.request.method", f.method.clone().unwrap_or_default()),
            KeyValue::new("http.route", f.route.clone().unwrap_or_default()),
        ];
        if let Some(s) = f.status {
            a.push(KeyValue::new("http.response.status_code", s));
        }
        a
    }
}

impl<S> tracing_subscriber::Layer<S> for SpanMetrics
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let meta = attrs.metadata();
        // Only this crate's spans: another crate's span named "client" is not
        // one of ours and has none of the fields.
        if !meta.target().starts_with("hs_utils") {
            return;
        }
        let kind = match meta.name() {
            SERVER_SPAN => SpanKind::Server,
            HTTP_CLIENT_SPAN => SpanKind::HttpClient,
            CLIENT_SPAN => SpanKind::Client,
            _ => return,
        };
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if kind == SpanKind::Server {
            self.active.add(1, &[KeyValue::new("http.request.method", fields.method.clone().unwrap_or_default())]);
        }
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(Timing { kind, start: Instant::now(), fields, done: false });
        }
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        let Some(t) = ext.get_mut::<Timing>() else { return };
        values.record(&mut t.fields);
        if t.kind == SpanKind::Server && !t.done && t.fields.status.is_some() {
            t.done = true;
            self.server_duration.record(t.start.elapsed().as_secs_f64(), &Self::server_attrs(&t.fields));
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(t) = span.extensions_mut().remove::<Timing>() else { return };
        let secs = t.start.elapsed().as_secs_f64();
        let f = &t.fields;
        match t.kind {
            // A request that never produced a status (the client went away,
            // the future was dropped) leaves the in-flight count, and is not a
            // duration: there was no response to time.
            SpanKind::Server => {
                self.active.add(-1, &[KeyValue::new("http.request.method", f.method.clone().unwrap_or_default())]);
            }
            SpanKind::HttpClient => {
                let mut a = vec![
                    KeyValue::new("http.request.method", f.method.clone().unwrap_or_default()),
                    KeyValue::new("server.address", f.address.clone().unwrap_or_default()),
                ];
                match f.status {
                    Some(s) => a.push(KeyValue::new("http.response.status_code", s)),
                    None => a.push(KeyValue::new("error.type", "no_response")),
                }
                self.client_http_duration.record(secs, &a);
            }
            SpanKind::Client => {
                self.client_duration.record(
                    secs,
                    &[
                        KeyValue::new("client.system", f.system.clone().unwrap_or_default()),
                        KeyValue::new("client.operation", f.operation.clone().unwrap_or_default()),
                        KeyValue::new("client.outcome", f.outcome.clone().unwrap_or_else(|| "unknown".into())),
                    ],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use tracing_subscriber::layer::SubscriberExt;

    /// One exported data point, flattened: (metric, value-or-count, attributes).
    type Point = (String, f64, Vec<(String, String)>);

    fn provider() -> (SdkMeterProvider, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        (provider, exporter)
    }

    fn points(provider: &SdkMeterProvider, exporter: &InMemoryMetricExporter) -> Vec<Point> {
        provider.force_flush().unwrap();
        let mut out = Vec::new();
        let attrs = |a: &mut dyn Iterator<Item = &KeyValue>| {
            a.map(|kv| (kv.key.to_string(), kv.value.to_string())).collect::<Vec<_>>()
        };
        for rm in exporter.get_finished_metrics().unwrap() {
            for sm in rm.scope_metrics() {
                for m in sm.metrics() {
                    let name = m.name().to_string();
                    match m.data() {
                        AggregatedMetrics::F64(MetricData::Histogram(h)) => {
                            for p in h.data_points() {
                                out.push((name.clone(), p.count() as f64, attrs(&mut p.attributes())));
                            }
                        }
                        AggregatedMetrics::F64(MetricData::Gauge(g)) => {
                            for p in g.data_points() {
                                out.push((name.clone(), p.value(), attrs(&mut p.attributes())));
                            }
                        }
                        AggregatedMetrics::F64(MetricData::Sum(s)) => {
                            for p in s.data_points() {
                                out.push((name.clone(), p.value(), attrs(&mut p.attributes())));
                            }
                        }
                        AggregatedMetrics::I64(MetricData::Sum(s)) => {
                            for p in s.data_points() {
                                out.push((name.clone(), p.value() as f64, attrs(&mut p.attributes())));
                            }
                        }
                        AggregatedMetrics::U64(MetricData::Sum(s)) => {
                            for p in s.data_points() {
                                out.push((name.clone(), p.value() as f64, attrs(&mut p.attributes())));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        out
    }

    fn has(p: &[Point], name: &str, attr: (&str, &str)) -> Option<f64> {
        p.iter()
            .rev()
            .find(|(n, _, a)| n == name && a.iter().any(|(k, v)| k == attr.0 && v == attr.1))
            .map(|(_, v, _)| *v)
    }

    /// The span → metric path, through the real SDK: a server span yields a
    /// duration (labelled by route TEMPLATE and status) and leaves the
    /// in-flight count at zero; a client span yields an operation duration by
    /// outcome; a dropped request that never got a status is no duration.
    #[test]
    fn spans_become_request_and_client_metrics() {
        let (provider, exporter) = provider();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(SpanMetrics::new(&provider)));

        let req = tracing::info_span!(
            "http.server",
            http.request.method = "GET",
            http.route = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
        );
        req.record("http.route", "/api/items/{id}");
        req.record("http.response.status_code", 503u16);
        drop(req);

        // A request whose client went away before any response.
        drop(tracing::info_span!("http.server", http.request.method = "POST", http.response.status_code = tracing::field::Empty));

        let lock = crate::telemetry::client_span("postgresql", "lock.acquire", "db");
        crate::telemetry::record_outcome(&lock, "busy");
        drop(lock);

        let p = points(&provider, &exporter);
        assert_eq!(has(&p, "http.server.request.duration", ("http.route", "/api/items/{id}")), Some(1.0), "{p:?}");
        assert_eq!(has(&p, "http.server.request.duration", ("http.response.status_code", "503")), Some(1.0));
        assert_eq!(has(&p, "http.server.request.duration", ("http.request.method", "POST")), None, "no status, no duration");
        assert_eq!(has(&p, "http.server.active_requests", ("http.request.method", "GET")), Some(0.0), "in-flight must return to zero");
        assert_eq!(has(&p, "http.server.active_requests", ("http.request.method", "POST")), Some(0.0), "a dropped request leaves the count");
        assert_eq!(has(&p, "hs.client.operation.duration", ("client.outcome", "busy")), Some(1.0));
    }

    /// Another crate's span named like ours is not ours.
    #[test]
    fn foreign_spans_are_ignored() {
        let (provider, exporter) = provider();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(SpanMetrics::new(&provider)));
        drop(tracing::info_span!(target: "some_other_crate", "client", client.system = "x"));
        assert!(points(&provider, &exporter).iter().all(|(n, ..)| n != "hs.client.operation.duration"));
    }

    /// `install` wires the catalog: a registered source's samples are
    /// exported under their names, the process source runs, the facade's
    /// counters work once installed, and an uncatalogued name is dropped.
    #[test]
    fn gauge_sources_and_facade_counters_are_exported() {
        let (provider, exporter) = provider();
        crate::telemetry::count("hs.pubsub.published", 1, &[("channel", "before-install")]);
        let _held = install(&provider, true);
        register_source(Box::new(|out| {
            out.push(Sample {
                name: "db.client.connection.count",
                value: 2.0,
                attrs: vec![("db.client.connection.state", "used".into())],
            });
            out.push(Sample { name: "not.in.the.catalog", value: 1.0, attrs: vec![] });
        }));
        crate::telemetry::count("hs.pubsub.published", 3, &[("channel", "orders")]);

        let p = points(&provider, &exporter);
        assert_eq!(has(&p, "db.client.connection.count", ("db.client.connection.state", "used")), Some(2.0));
        assert_eq!(has(&p, "hs.pubsub.published", ("channel", "orders")), Some(3.0));
        assert_eq!(has(&p, "hs.pubsub.published", ("channel", "before-install")), None, "a count before init is dropped, not cached as a no-op");
        assert!(p.iter().all(|(n, ..)| n != "not.in.the.catalog"));
        if cfg!(target_os = "linux") {
            assert!(p.iter().any(|(n, v, _)| n == "process.memory.usage" && *v > 0.0), "{p:?}");
        }
    }
}
