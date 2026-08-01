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

    /// Cap for attacker-controlled string attributes. Honeycomb charges per
    /// span and truncates anyway; an unbounded `User-Agent` is free inbound
    /// bytes turned into billable outbound ones.
    const MAX_ATTR_LEN: usize = 256;

    const REDACTED: &str = "<redacted>";

    fn truncate(s: &str, max: usize) -> String {
        if s.len() <= max {
            return s.to_string();
        }
        // Do not split a UTF-8 code point.
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }

    /// Record which query parameters were present, never their values.
    ///
    /// `?a=1&b` becomes `a=<redacted>&b=<redacted>`.
    ///
    /// This span wraps whole routers, so it sees every query string the service
    /// will ever receive — including the OAuth2 callback, where the provider
    /// puts `code` and `state`. **An authorization code is a single-use
    /// credential exchangeable for tokens, and spans leave the building**: they
    /// land in a third-party store with long retention. Recording the raw query
    /// published that credential to Honeycomb for every service that mounts a
    /// callback under this layer.
    ///
    /// Redacting *every* value was chosen over the two obvious alternatives,
    /// because both fail open:
    ///
    /// * A **deny-list** (`code`, `token`, `secret`, …) leaks the next sensitive
    ///   parameter anyone adds, silently, and the failure is invisible until
    ///   someone reads a trace.
    /// * An **allow-list** fails safe on secrets but has to be maintained per
    ///   service, and this is a shared layer with no idea what its host routes.
    ///
    /// Keeping the names preserves nearly all the debugging value — "was `state`
    /// present?", "did the client send a filter?" — at no risk. If a service
    /// genuinely needs a value, it should record that field itself, at the
    /// handler, where the type is known and the decision is visible in review.
    fn redact_query(query: Option<&str>) -> String {
        let Some(q) = query.filter(|q| !q.is_empty()) else {
            return String::new();
        };
        let mut out = String::with_capacity(q.len().min(MAX_ATTR_LEN));
        for (i, pair) in q.split('&').enumerate() {
            if i > 0 {
                out.push('&');
            }
            // A bare token — `?sometoken` with no `=` — carries no name to keep
            // and could itself be a secret, so it is replaced whole. Splitting
            // on `=` and treating the left side as a "name" would echo exactly
            // such a token verbatim, which is how a fail-safe design fails open.
            match pair.split_once('=') {
                Some((name, _)) if !name.is_empty() => {
                    out.push_str(name);
                    out.push('=');
                    out.push_str(REDACTED);
                }
                _ => out.push_str(REDACTED),
            }
            // Parameter *names* are attacker-supplied too; bound the result.
            if out.len() >= MAX_ATTR_LEN {
                return truncate(&out, MAX_ATTR_LEN);
            }
        }
        out
    }

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

    /// What the span is named when axum did not match a route — a 404, or a
    /// `ServeDir`/fallback hit. Deliberately constant: the raw path there is
    /// entirely attacker-chosen, and using it would mint one span name per
    /// probe. The real path is still on `url.path`, bounded.
    const UNMATCHED: &str = "<unmatched>";

    fn make_span(req: &http::Request<axum::body::Body>) -> tracing::Span {
        let method = req.method().as_str();
        // `url.path` is attacker-supplied and unbounded — the same "free
        // inbound bytes turned into billable outbound ones" argument that
        // bounds the user agent. A 4 KB path produced a 4 KB attribute.
        let path = truncate(req.uri().path(), MAX_ATTR_LEN);
        // The span NAME is the primary aggregation key, so it must stay
        // low-cardinality. `MatchedPath` is axum's route template
        // (`/api/image/url/{id}`) rather than the concrete path, and it is in
        // the extensions because `Router::layer` runs after routing. Without
        // this, a service with `:id` params or a `ServeDir` catch-all mints a
        // distinct span name per request — which is exactly what the previous
        // revision of this comment told callers to go and fix themselves, and
        // which none of them did.
        let route = req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|m| m.as_str())
            .unwrap_or(UNMATCHED);
        let span = tracing::info_span!(
            "http.server",
            otel.name = %format!("{method} {route}"),
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            http.request.method = %method,
            url.path = %path,
            url.query = %redact_query(req.uri().query()),
            network.protocol.version = ?req.version(),
            user_agent.original = %truncate(
                req.headers()
                    .get(http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default(),
                MAX_ATTR_LEN,
            ),
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;
        use tracing_subscriber::layer::SubscriberExt;

        type Fields = Arc<Mutex<Vec<(String, String)>>>;

        fn capture() -> Fields {
            Arc::new(Mutex::new(Vec::new()))
        }

        struct Grab(Fields);
        impl tracing::field::Visit for Grab {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.lock().unwrap().push((f.name().into(), format!("{v:?}")));
            }
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                self.0.lock().unwrap().push((f.name().into(), v.into()));
            }
        }

        struct Capture(Fields);
        impl<S> tracing_subscriber::Layer<S> for Capture
        where
            S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
        {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _: &tracing::Id,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                attrs.record(&mut Grab(self.0.clone()));
            }
        }

        /// The regression this module exists for. An OAuth2 provider redirects
        /// to the callback with `?code=…&state=…`; before v0.26.0 the raw query
        /// went onto the span verbatim and was exported to Honeycomb.
        #[test]
        fn oauth_callback_query_does_not_carry_the_authorization_code() {
            let out = redact_query(Some("code=ory_ac_live_9f3&state=csrf-1"));
            assert_eq!(out, "code=<redacted>&state=<redacted>");
            assert!(!out.contains("ory_ac_live_9f3"), "authorization code leaked: {out}");
            assert!(!out.contains("csrf-1"), "csrf state leaked: {out}");
        }

        /// Names are kept because they carry the debugging value — "was `state`
        /// present at all?" is most of what you want from a failed login.
        #[test]
        fn parameter_names_are_preserved() {
            assert_eq!(redact_query(Some("page=2&sort=name")), "page=<redacted>&sort=<redacted>");
        }

        /// A bare token has no name to keep and could itself be a secret, so it
        /// is replaced whole rather than passed through as a "name".
        ///
        /// v0.26.0 got this wrong: it split on `=` and treated the left side as
        /// a name, so `?ory_at_live_SECRET` came out as
        /// `ory_at_live_SECRET=<redacted>` — the token echoed verbatim by the
        /// function whose entire job is to not do that. Fail-safe by design,
        /// fail-open in fact.
        #[test]
        fn a_valueless_parameter_is_redacted_whole_not_echoed_as_a_name() {
            assert_eq!(redact_query(Some("verbose")), "<redacted>");
            assert_eq!(redact_query(Some("=orphan")), "<redacted>");

            let out = redact_query(Some("ory_at_live_SUPERSECRET"));
            assert!(!out.contains("SUPERSECRET"), "bare token echoed as a name: {out}");

            // Mixed: the named one keeps its name, the bare one does not.
            assert_eq!(redact_query(Some("page=2&ory_at_live_X")), "page=<redacted>&<redacted>");
        }

        /// `url.path` is as attacker-supplied as the user agent, and it is worse
        /// because it also feeds the span name. A 4 KB path produced a 4 KB
        /// attribute until this bound existed.
        #[test]
        fn an_absurd_path_is_bounded() {
            let out = truncate(&"A".repeat(4000), MAX_ATTR_LEN);
            assert!(out.len() <= MAX_ATTR_LEN + 4, "path unbounded: {} bytes", out.len());
        }

        /// `=` inside a value must not resurrect it — base64 and JWTs are full
        /// of them, and splitting on the last `=` instead of the first would
        /// publish the payload.
        #[test]
        fn only_the_first_equals_delimits_the_name() {
            assert_eq!(redact_query(Some("t=aGVsbG8=world=")), "t=<redacted>");
        }

        #[test]
        fn empty_and_absent_queries_are_empty() {
            assert_eq!(redact_query(None), "");
            assert_eq!(redact_query(Some("")), "");
        }

        /// Parameter names are attacker-supplied, so the redacted result is
        /// bounded too — otherwise redaction just moves the amplification.
        #[test]
        fn attacker_supplied_names_cannot_grow_the_attribute_without_bound() {
            let hostile = (0..1000).map(|i| format!("p{i}=x")).collect::<Vec<_>>().join("&");
            let out = redact_query(Some(&hostile));
            assert!(out.len() <= MAX_ATTR_LEN + 4, "unbounded attribute: {} bytes", out.len());
        }

        /// Drives the **real** `axum_trace_layer` over a router that mounts a
        /// callback at the same path `web_login` uses, and asserts on what the
        /// span actually recorded.
        ///
        /// The unit tests above prove `redact_query` is correct; this proves
        /// `make_span` still calls it. Without this, deleting the call site
        /// would leave every test above green while the leak came back.
        #[tokio::test]
        async fn the_real_layer_records_no_credential_from_a_callback_request() {
            let fields: Fields = capture();
            let _guard = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(Capture(fields.clone())),
            );

            let app = axum::Router::new()
                .route("/api/oauth2/callback", axum::routing::get(|| async { "ok" }))
                .layer(axum_trace_layer());

            let req = http::Request::builder()
                .uri("/api/oauth2/callback?code=ory_ac_live_9f3&state=csrf-1")
                .header(http::header::USER_AGENT, "u".repeat(4096))
                .body(axum::body::Body::empty())
                .unwrap();
            let _ = app.oneshot(req).await.unwrap();

            let recorded = fields.lock().unwrap().clone();
            assert!(!recorded.is_empty(), "the layer recorded no span at all");
            let all = recorded
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" | ");

            assert!(!all.contains("ory_ac_live_9f3"), "authorization code reached the span: {all}");
            assert!(!all.contains("csrf-1"), "csrf state reached the span: {all}");

            let ua = recorded
                .iter()
                .find(|(k, _)| k == "user_agent.original")
                .expect("user_agent.original should be recorded");
            assert!(ua.1.len() <= MAX_ATTR_LEN + 8, "user agent unbounded: {} bytes", ua.1.len());
        }

        /// Span names are the primary aggregation key, so they must not carry a
        /// path parameter or an attacker-chosen 404 path. Drives the real layer
        /// over a router with an `{id}` route and a fallback.
        #[tokio::test]
        async fn span_names_use_the_route_template_not_the_concrete_path() {
            let cap = capture();
            let _guard = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(Capture(cap.clone())),
            );

            let app = axum::Router::new()
                .route("/api/image/url/{id}", axum::routing::get(|| async { "ok" }))
                .fallback(|| async { "not found" })
                .layer(axum_trace_layer());

            let get = |uri: &str| {
                http::Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap()
            };

            let _ = app.clone().oneshot(get("/api/image/url/abc-123")).await.unwrap();
            let _ = app.oneshot(get(&format!("/{}", "A".repeat(4000)))).await.unwrap();

            let rec = cap.lock().unwrap().clone();
            let names: Vec<&str> = rec
                .iter()
                .filter(|(k, _)| k == "otel.name")
                .map(|(_, v)| v.as_str())
                .collect();

            assert!(
                names.contains(&"GET /api/image/url/{id}"),
                "span name should be the route template, got {names:?}"
            );
            assert!(
                !names.iter().any(|n| n.contains("abc-123")),
                "concrete id leaked into the span name: {names:?}"
            );
            assert!(
                names.contains(&"GET <unmatched>"),
                "an unmatched path should collapse to a constant, got {names:?}"
            );
            for (k, v) in &rec {
                assert!(
                    v.len() <= MAX_ATTR_LEN + 8,
                    "{k} is unbounded at {} bytes — attacker-supplied paths must be capped",
                    v.len()
                );
            }
        }

        #[test]
        fn user_agent_is_truncated_on_a_char_boundary() {
            let long = "é".repeat(500);
            let out = truncate(&long, MAX_ATTR_LEN);
            assert!(out.len() <= MAX_ATTR_LEN + 4);
            assert!(out.ends_with('…'));
            assert_eq!(truncate("curl/8.5.0", MAX_ATTR_LEN), "curl/8.5.0");
        }
    }
}
