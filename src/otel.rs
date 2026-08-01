//! OpenTelemetry tracing (OTLP → Honeycomb) shared across all hs Rust services.
//!
//! # What this gives you
//!
//! * An OTLP/HTTP-protobuf span exporter pointed at Honeycomb (or any OTLP
//!   endpoint), wired into the existing `tracing` macros — every
//!   `#[tracing::instrument]`, `tracing::info_span!` and `tracing::error!`
//!   already in the codebase becomes a span/event with no further changes.
//! * W3C `traceparent` propagation, so a trace started at one service
//!   continues into the next instead of starting a fresh root.
//! * An axum `TraceLayer` preconfigured with HTTP semantic-convention
//!   attributes, which adopts an inbound `traceparent` as the span parent.
//!
//! # Usage
//!
//! Call [`init`] *instead of* [`crate::logging::init`] — it installs the fmt
//! layer too, and a subscriber can only be installed once. Hold the returned
//! [`OtelGuard`] for the lifetime of the process; dropping it flushes any
//! spans still sitting in the batch queue.
//!
//! ```rust,ignore
//! let _otel = hs_utils::otel::init(&cfg.log.level, &cfg.otel)?;
//! let router = router.layer(hs_utils::otel::axum_trace_layer());
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
//! When `enabled` is false (the default) nothing is exported and no OTLP
//! machinery is started — [`init`] falls back to plain fmt logging, so a
//! service with the feature compiled in behaves exactly as before until it is
//! switched on. A blank `apiKey` is treated the same way (disabled + a warning)
//! rather than silently shipping unauthenticated spans that Honeycomb drops.

use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};
use serde::Deserialize;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

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
        }
    }
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
}

impl OtelGuard {
    /// Flush and stop the exporter early. Idempotent; `Drop` will not repeat it.
    pub fn shutdown(&mut self) {
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

/// Install the global subscriber: fmt logging always, plus the OTLP tracing
/// bridge when `cfg.enabled`. Replaces [`crate::logging::init`].
pub fn init(level: &str, cfg: &OtelConfig) -> Result<OtelGuard> {
    let filter = || {
        EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
    };
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false);

    if !cfg.enabled {
        tracing_subscriber::registry()
            .with(filter())
            .with(fmt_layer)
            .init();
        return Ok(OtelGuard { provider: None });
    }

    if cfg.api_key.trim().is_empty() {
        tracing_subscriber::registry()
            .with(filter())
            .with(fmt_layer)
            .init();
        tracing::warn!(
            "otel.enabled is true but otel.apiKey is empty — tracing export disabled \
             (Honeycomb rejects unauthenticated OTLP silently)"
        );
        return Ok(OtelGuard { provider: None });
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

    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/traces", cfg.endpoint.trim_end_matches('/')))
        .with_protocol(Protocol::HttpBinary)
        .with_headers(
            [("x-honeycomb-team".to_string(), cfg.api_key.clone())]
                .into_iter()
                .collect(),
        )
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

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_id_generator(RandomIdGenerator::default())
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            cfg.sample_ratio.clamp(0.0, 1.0),
        ))))
        .with_resource(resource.build())
        .build();

    let tracer = provider.tracer(service_name.clone());
    global::set_tracer_provider(provider.clone());
    // Without this, outbound `traceparent` headers are never written and every
    // downstream service starts its own disconnected root trace.
    global::set_text_map_propagator(TraceContextPropagator::new());

    tracing_subscriber::registry()
        .with(filter())
        .with(fmt_layer)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    tracing::info!(
        service.name = %service_name,
        endpoint = %cfg.endpoint,
        sample_ratio = cfg.sample_ratio,
        "otel tracing enabled (OTLP/http-protobuf)"
    );
    if unnamed {
        tracing::warn!(
            "otel.serviceName is not set — exporting as \"unknown_service\"; set \
             otel__serviceName so Honeycomb routes this to its own dataset"
        );
    }

    Ok(OtelGuard {
        provider: Some(provider),
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
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let cx = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(headers));
    });
}

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

// ── axum integration ────────────────────────────────────────────────────────

#[cfg(feature = "otel-axum")]
pub use axum_support::axum_trace_layer;

#[cfg(feature = "otel-axum")]
mod axum_support {
    use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
    use tower_http::trace::TraceLayer;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    type MakeSpan = fn(&http::Request<axum::body::Body>) -> tracing::Span;
    type OnResponse = fn(&http::Response<axum::body::Body>, std::time::Duration, &tracing::Span);

    /// A `TraceLayer` that names the server span `{METHOD} {path}` and records
    /// HTTP semantic-convention attributes, adopting an inbound `traceparent`
    /// as the parent so the trace spans service boundaries.
    ///
    /// Use this in place of a bare `TraceLayer::new_for_http()`.
    pub fn axum_trace_layer()
    -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>, MakeSpan, (), OnResponse> {
        TraceLayer::new_for_http()
            .make_span_with(make_span as MakeSpan)
            .on_request(())
            .on_response(on_response as OnResponse)
    }

    fn make_span(req: &http::Request<axum::body::Body>) -> tracing::Span {
        let method = req.method().as_str();
        let path = req.uri().path();
        // Span names must stay low-cardinality for aggregation, so this uses
        // the raw path — fine here because these services route on a small
        // fixed set (/mcp, /healthcheck, discovery). Add a route-matching
        // layer before reusing this on a service with :id path params.
        let span = tracing::info_span!(
            "http.server",
            otel.name = %format!("{method} {path}"),
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            http.request.method = %method,
            url.path = %path,
            url.query = req.uri().query().unwrap_or_default(),
            network.protocol.version = ?req.version(),
            user_agent.original = req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            http.response.status_code = tracing::field::Empty,
        );
        // Fails only when the subscriber has no OpenTelemetry layer (tracing
        // disabled) — in that case there is no parent to adopt and the local
        // span is still perfectly good, so this is not worth logging per request.
        let _ = span.set_parent(super::extract_context(req.headers()));
        span
    }

    fn on_response(
        res: &http::Response<axum::body::Body>,
        _latency: std::time::Duration,
        span: &tracing::Span,
    ) {
        let status = res.status();
        span.record("http.response.status_code", status.as_u16());
        // Only 5xx marks the span errored; 4xx is a client problem and would
        // otherwise drown the error rate in routine 401s from MCP auth probes.
        if status.is_server_error() {
            span.record("otel.status_code", "ERROR");
        }
    }
}
