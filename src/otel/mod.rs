//! OpenTelemetry traces and metrics (OTLP → Honeycomb, or a local Collector)
//! shared across all hs Rust services.
//!
//! # What this gives you
//!
//! * An OTLP/HTTP-protobuf span exporter wired into the existing `tracing`
//!   macros — every `#[tracing::instrument]`, `tracing::info_span!` and
//!   `tracing::error!` already in the codebase becomes a span/event with no
//!   further changes.
//! * W3C `traceparent` propagation, so a trace started at one service
//!   continues into the next instead of starting a fresh root: adopted by the
//!   server layers, written by [`send`] / `SendTraced` (and [`inject_context`]
//!   for anything else).
//! * Server layers for both frameworks, recording the same HTTP
//!   semantic-convention attributes (route-template span names, query values
//!   redacted, attacker-supplied strings capped): [`axum_trace_layer`]
//!   (`otel-axum`) and [`actix_trace`] (`otel-actix`).
//! * Client spans for this crate's own outbound calls — HTTP (Kratos, Hydra,
//!   JWKS, Stripe, data services), redis, Postgres locks, pub/sub — and
//!   [`client_span`] for a service's own (SMTP, say).
//! * An OTLP metrics exporter: request durations and in-flight counts (from
//!   the spans above), DB pool use, active sessions, pub/sub and SSE counts,
//!   and process / container CPU, memory, I/O and pressure-stall — the
//!   container's iowait. The full list is in `metrics.rs`.
//!
//! # Usage
//!
//! Call [`init`] *instead of* [`crate::logging::init`] — it installs the fmt
//! layer too, and a subscriber can only be installed once. Call it inside the
//! Tokio runtime, and hold the returned [`OtelGuard`] for the lifetime of the
//! process; dropping it flushes metrics and any spans still queued.
//!
//! ```rust,ignore
//! let _otel = hs_utils::otel::init(&cfg.log.level, &cfg.otel)?;
//! let router = router.layer(hs_utils::otel::axum_trace_layer());   // axum
//! App::new().wrap(hs_utils::otel::actix_trace())                     // actix
//! ```
//!
//! # Config
//!
//! ```json
//! {
//!   "otel": {
//!     "enabled": "true",
//!     "endpoint": "https://api.honeycomb.io",
//!     "apiKey": "[SECRET]:/run/secrets/honeycomb-api-key",
//!     "serviceName": "bioalphaengine-mcp",
//!     "environment": "preview",
//!     "sampleRatio": "1.0"
//!   }
//! }
//! ```
//!
//! Optional, all defaulted to the pre-v0.37.0 behaviour: `level` (what is
//! exported, as an `EnvFilter` directive; default the log level),
//! `metricsEnabled` (true), `metricsIntervalSecs` (60), `processMetrics`
//! (true), `metricsDataset` (unset: Honeycomb routes native OTLP metrics
//! itself), and `apiKeyRequired` (true; false for a Collector endpoint such as
//! `http://<host>:4318` that holds the key).
//!
//! When `enabled` is false (the default) nothing is exported and no OTLP
//! machinery is started — [`init`] falls back to plain fmt logging, so a
//! service with the feature compiled in behaves exactly as before until it is
//! switched on. A blank `apiKey` is treated the same way (disabled + a warning)
//! rather than silently shipping unauthenticated spans that Honeycomb drops.

use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_otlp::MetricExporter;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
    propagation::TraceContextPropagator,
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};
use serde::Deserialize;
use tracing_subscriber::{EnvFilter, Layer as _, layer::SubscriberExt, util::SubscriberInitExt};

/// `otel` config block. Deserialises from the all-strings tree that
/// `prepare_config` produces, hence the `deser_*_or_str` helpers.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtelConfig {
    /// Master switch. Off by default so enabling the cargo feature alone
    /// never changes runtime behaviour.
    #[serde(default, deserialize_with = "crate::config::deser_bool_or_str")]
    pub enabled: bool,
    /// OTLP base endpoint. `/v1/traces` is appended automatically.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Honeycomb ingest key, sent as the `x-honeycomb-team` header. Use the
    /// `[SECRET]:/run/secrets/...` indirection — never an inline literal.
    #[serde(default)]
    pub api_key: String,
    /// `service.name` resource attribute — this is what Honeycomb routes on
    /// to pick the dataset.
    #[serde(default)]
    pub service_name: String,
    /// `deployment.environment.name` resource attribute (`preview`, `prod`).
    #[serde(default)]
    pub environment: String,
    /// Head-sampling ratio, 0.0–1.0. Applied parent-based, so a sampled
    /// upstream trace stays sampled through this service.
    #[serde(default = "default_sample_ratio", deserialize_with = "crate::config::deser_f64_or_str")]
    pub sample_ratio: f64,
    /// What is EXPORTED, as an `EnvFilter` directive (`"info"`,
    /// `"info,sqlx::query=debug"`). Empty (the default) → the same as the
    /// service's log level, which is what every release before v0.37.0 did.
    /// Set it to stop a stdout `log.level=debug` (for a diagnosis) from also
    /// shipping debug spans and events to the trace store, or to export
    /// sqlx's per-statement events without printing them.
    #[serde(default)]
    pub level: String,
    /// Export metrics as well as traces. Default true: with `enabled` off,
    /// nothing is exported either way.
    #[serde(default = "default_true", deserialize_with = "crate::config::deser_bool_or_str")]
    pub metrics_enabled: bool,
    /// How often metrics are collected and exported, in seconds (default 60).
    #[serde(default = "default_metrics_interval", deserialize_with = "crate::config::deser_u32_or_str")]
    pub metrics_interval_secs: u32,
    /// Sent as `x-honeycomb-dataset` on metrics exports only, when set. Leave
    /// it empty for Honeycomb's native OTLP metrics, which route themselves; it
    /// exists for legacy routing to a named dataset.
    #[serde(default)]
    pub metrics_dataset: String,
    /// Report this process's and its container's CPU, memory, I/O and
    /// pressure (`/proc/self`, cgroup v2). Default true.
    #[serde(default = "default_true", deserialize_with = "crate::config::deser_bool_or_str")]
    pub process_metrics: bool,
    /// Refuse to export without an `apiKey` (default true — Honeycomb drops
    /// unauthenticated OTLP silently). Set false when `endpoint` is a local
    /// OpenTelemetry Collector that holds the key itself.
    #[serde(default = "default_true", deserialize_with = "crate::config::deser_bool_or_str")]
    pub api_key_required: bool,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            api_key: String::new(),
            service_name: String::new(),
            environment: String::new(),
            sample_ratio: default_sample_ratio(),
            level: String::new(),
            metrics_enabled: true,
            metrics_interval_secs: default_metrics_interval(),
            metrics_dataset: String::new(),
            process_metrics: true,
            api_key_required: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_metrics_interval() -> u32 {
    60
}

/// Never exported, whatever `level` says: the exporter's own stack logs
/// through `tracing` (the `internal-logs` feature), and an export failure
/// exported as an event is a feedback loop — each failed batch would queue
/// another. They still reach stdout, where someone diagnosing a dead endpoint
/// will look.
const NEVER_EXPORTED: &[&str] = &[
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "opentelemetry_http",
    "reqwest",
    "hyper",
    "hyper_util",
    "h2",
    "rustls",
];

/// The export filter: `level` (or the log level), with the exporter's own
/// crates switched off.
fn export_filter(log_level: &str, cfg: &OtelConfig) -> EnvFilter {
    let base = if cfg.level.trim().is_empty() { log_level } else { cfg.level.trim() };
    let mut directive = base.to_string();
    for target in NEVER_EXPORTED {
        directive.push_str(&format!(",{target}=off"));
    }
    EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"))
}

fn default_endpoint() -> String {
    "https://api.honeycomb.io".to_string()
}

fn default_sample_ratio() -> f64 {
    1.0
}

/// Flushes the batch span processor when dropped. Keep it alive for the whole
/// process — `let _otel = init(..)?;` in `main`, not `let _ = init(..)?;`,
/// which would drop it immediately and export nothing.
#[must_use = "dropping the guard immediately shuts the exporter down; bind it to a named variable"]
pub struct OtelGuard {
    provider: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
    _instruments: Option<metrics::Instruments>,
}

impl OtelGuard {
    fn off() -> Self {
        Self { provider: None, meter: None, _instruments: None }
    }

    /// Flush and stop the exporters early. Idempotent; `Drop` will not repeat
    /// it. Metrics go first, so their final collection (taken at shutdown) is
    /// not the casualty of a slow span flush under a shutdown deadline.
    pub fn shutdown(&mut self) {
        if let Some(meter) = self.meter.take() {
            if let Err(e) = meter.shutdown() {
                tracing::warn!("otel metrics shutdown failed: {e}");
            }
        }
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                tracing::warn!("otel shutdown failed: {e}");
            }
        }
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Install the global subscriber: fmt logging always, plus the OTLP trace
/// and metrics exporters when `cfg.enabled`. Replaces [`crate::logging::init`].
///
/// Call it from inside the Tokio runtime (`#[tokio::main]`, or
/// `#[actix_web::main]`) so the runtime gauges can find it; outside one they
/// are simply not reported.
///
/// Each layer has its own filter: stdout follows `level`, the export follows
/// `otel.level` (default: the same), and the metrics layer always sees this
/// crate's request and client spans — so a service logging at `warn` still
/// reports its request durations.
pub fn init(level: &str, cfg: &OtelConfig) -> Result<OtelGuard> {
    let fmt_layer = || {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .with_filter(EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info")))
    };

    if !cfg.enabled {
        tracing_subscriber::registry().with(fmt_layer()).init();
        return Ok(OtelGuard::off());
    }

    let keyless = cfg.api_key.trim().is_empty();
    if keyless && cfg.api_key_required {
        tracing_subscriber::registry().with(fmt_layer()).init();
        tracing::warn!(
            "otel.enabled is true but otel.apiKey is empty — tracing export disabled \
             (Honeycomb rejects unauthenticated OTLP silently; set otel.apiKeyRequired=false \
             to export to a Collector that holds the key)"
        );
        return Ok(OtelGuard::off());
    }

    // Deliberately NOT `env!("CARGO_PKG_NAME")` — that expands at compile time
    // inside this crate and would label every service "hs-utils", collapsing
    // the whole fleet into one Honeycomb dataset.
    let unnamed = cfg.service_name.trim().is_empty();
    let service_name = if unnamed {
        "unknown_service".to_string()
    } else {
        cfg.service_name.clone()
    };

    // The exporter builds its own reqwest client internally, and that client is
    // compiled with rustls `no-provider` (see the reqwest13 dep note in
    // Cargo.toml), so it looks up the process-default CryptoProvider. Nothing
    // else installs one, and without it every HTTPS export fails at client
    // construction. `Err` just means someone got here first — theirs is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let base = cfg.endpoint.trim_end_matches('/');
    let mut headers: std::collections::HashMap<String, String> = Default::default();
    if !keyless {
        headers.insert("x-honeycomb-team".to_string(), cfg.api_key.clone());
    }

    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/traces"))
        .with_protocol(Protocol::HttpBinary)
        .with_headers(headers.clone())
        .with_timeout(Duration::from_secs(10))
        .build()
        .context("build OTLP span exporter")?;

    let mut resource = Resource::builder().with_service_name(service_name.clone());
    if !cfg.environment.trim().is_empty() {
        resource = resource.with_attributes([KeyValue::new(
            "deployment.environment.name",
            cfg.environment.clone(),
        )]);
    }
    let resource = resource.build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_id_generator(RandomIdGenerator::default())
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            cfg.sample_ratio.clamp(0.0, 1.0),
        ))))
        .with_resource(resource.clone())
        .build();

    let tracer = provider.tracer(service_name.clone());
    global::set_tracer_provider(provider.clone());
    // Without this, outbound `traceparent` headers are never written and every
    // downstream service starts its own disconnected root trace.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let (meter, span_metrics) = if cfg.metrics_enabled {
        let mut metric_headers = headers;
        if !cfg.metrics_dataset.trim().is_empty() {
            metric_headers.insert("x-honeycomb-dataset".to_string(), cfg.metrics_dataset.clone());
        }
        let exporter = MetricExporter::builder()
            .with_http()
            .with_endpoint(format!("{base}/v1/metrics"))
            .with_protocol(Protocol::HttpBinary)
            .with_headers(metric_headers)
            .with_timeout(Duration::from_secs(10))
            .build()
            .context("build OTLP metric exporter")?;
        // The reader runs on its own thread, like the batch span processor —
        // which is why the blocking reqwest client is the right one here too.
        let reader = PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(u64::from(cfg.metrics_interval_secs.max(1))))
            .build();
        let meter = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();
        global::set_meter_provider(meter.clone());
        let span_metrics = metrics::SpanMetrics::new(&meter);
        (Some(meter), Some(span_metrics))
    } else {
        (None, None)
    };

    // The metrics layer sees this crate's request/client spans at INFO
    // whatever the log level says; nothing else.
    let metrics_filter = tracing_subscriber::filter::Targets::new()
        .with_target("hs_utils", tracing::Level::INFO);

    tracing_subscriber::registry()
        .with(fmt_layer())
        .with(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(export_filter(level, cfg)),
        )
        .with(span_metrics.map(|m| m.with_filter(metrics_filter)))
        .init();

    let instruments = meter.as_ref().map(|m| metrics::install(m, cfg.process_metrics));

    tracing::info!(
        service.name = %service_name,
        endpoint = %cfg.endpoint,
        sample_ratio = cfg.sample_ratio,
        metrics = cfg.metrics_enabled,
        metrics_interval_secs = cfg.metrics_interval_secs,
        "otel enabled (OTLP/http-protobuf)"
    );
    if unnamed {
        tracing::warn!(
            "otel.serviceName is not set — exporting as \"unknown_service\"; set \
             otel__serviceName so Honeycomb routes this to its own dataset"
        );
    }

    Ok(OtelGuard {
        provider: Some(provider),
        meter,
        _instruments: instruments,
    })
}

// ── HTTP context propagation ────────────────────────────────────────────────

/// Inject the current trace context into outbound request headers as W3C
/// `traceparent`, so the receiving service continues this trace.
///
/// ```rust,ignore
/// let mut req = client.get(&url).header("X-API-Key", &key).build()?;
/// hs_utils::otel::inject_context(req.headers_mut());
/// let resp = client.execute(req).await?;
/// ```
///
/// A no-op when tracing is disabled or no span is active.
pub fn inject_context(headers: &mut http::HeaderMap) {
    inject_span_context(&tracing::Span::current(), headers);
}

/// As [`inject_context`], for a given span rather than the current one — a
/// client span that has been built but not yet entered.
pub fn inject_span_context(span: &tracing::Span, headers: &mut http::HeaderMap) {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let cx = span.context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(headers));
    });
}

/// Send a reqwest 0.12 request in a client span with `traceparent`; see
/// [`crate::http_client::send`].
#[cfg(feature = "http-client")]
pub use crate::http_client::{send, send_opaque};

/// Client spans for other calls (SMTP, a queue); see [`crate::telemetry`].
pub use crate::telemetry::{client_span, record_error, record_outcome, set_path_redactor};

/// Extract a remote trace context from inbound request headers.
pub fn extract_context(headers: &http::HeaderMap) -> opentelemetry::Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)))
}

struct HeaderInjector<'a>(&'a mut http::HeaderMap);

impl opentelemetry::propagation::Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = http::header::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}

struct HeaderExtractor<'a>(&'a http::HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}


pub(crate) mod metrics;
mod procfs;

// ── framework layers ────────────────────────────────────────────────────────

#[cfg(any(feature = "otel-axum", feature = "otel-actix"))]
mod http_span;

// Named `*_layer`, not `axum` / `actix`, so the module never shadows the crate
// of the same name inside this one.
#[cfg(feature = "otel-axum")]
mod axum_layer;
#[cfg(feature = "otel-axum")]
pub use axum_layer::axum_trace_layer;

#[cfg(feature = "otel-actix")]
mod actix_layer;
#[cfg(feature = "otel-actix")]
pub use actix_layer::{actix_trace, ActixTrace, ActixTraceMiddleware};
