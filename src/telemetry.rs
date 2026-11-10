//! Span builders shared by everything in this crate that calls out — HTTP,
//! redis, Postgres locks and pub/sub — and by services that want their own
//! client calls (SMTP, say) to look the same.
//!
//! Always compiled: these are plain `tracing` spans, which cost next to
//! nothing without a subscriber that wants them. The `otel` feature is what
//! exports them (and injects `traceparent` into outbound HTTP); without it they
//! are still visible to the fmt layer's span context.
//!
//! # A client span for a call this crate does not make
//!
//! ```rust,ignore
//! use tracing::Instrument;
//! let span = hs_utils::telemetry::client_span("smtp", "send", &relay_host);
//! let res = mailer.send(message).instrument(span.clone()).await;
//! if let Err(e) = &res { hs_utils::telemetry::record_error(&span, e); }
//! ```
//!
//! **Name the operation, never the data.** `operation` and `peer` become the
//! span name and an attribute; a recipient address, a redis key or a SQL
//! literal there is published to the trace store and mints one span name per
//! value.

// The crate-private helpers here are called from modules behind other features
// (`http-client`, `web-login-redis`, `pubsub`, `db`, `otel`); which of them are
// live depends on the feature set, so dead-code analysis of any one build is
// noise. Public items are unaffected.
#![allow(dead_code)]

/// Cap for attacker-controlled string attributes. Honeycomb charges per
/// span and truncates anyway; an unbounded `User-Agent` is free inbound
/// bytes turned into billable outbound ones.
pub(crate) const MAX_ATTR_LEN: usize = 256;

pub(crate) const REDACTED: &str = "<redacted>";

pub(crate) fn truncate(s: &str, max: usize) -> String {
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
pub(crate) fn redact_query(query: Option<&str>) -> String {
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

/// Span name of every inbound request span, whichever framework made it; the
/// span-metrics layer keys on it.
pub(crate) const SERVER_SPAN: &str = "http.server";

/// Span name of an outbound HTTP request; the span-metrics layer keys on it.
pub(crate) const HTTP_CLIENT_SPAN: &str = "http.client";

/// Span name of any other outbound call made through [`client_span`].
pub(crate) const CLIENT_SPAN: &str = "client";

/// Systems whose calls are database calls in the semantic conventions, so
/// they also get `db.system.name` / `db.operation.name`.
const DB_SYSTEMS: &[&str] = &["redis", "postgresql"];

/// A client span for one call to an external system: `{system} {operation}`,
/// e.g. `redis GET`, `postgresql pg_try_advisory_lock`, `smtp send`.
///
/// `system` and `operation` must be low-cardinality constants: they are the
/// span name. `peer` is the host (or logical name) called; it is capped in
/// length. Record a failure with [`record_error`]; the span's duration is the
/// call's, and with `otel` metrics on it feeds `hs.client.operation.duration`.
///
/// Two optional fields can be recorded on it afterwards:
/// * `client.target` — what was operated on, when that is a name from code (a
///   lock name, a pub/sub channel). Span attribute only; never a metric label.
/// * `client.outcome` — `ok`, `error`, or a domain answer such as `busy`. It is
///   a metric label, so keep it to a handful of values. [`record_outcome`]
///   sets it.
pub fn client_span(system: &str, operation: &str, peer: &str) -> tracing::Span {
    let span = tracing::info_span!(
        "client",
        otel.name = %format!("{system} {operation}"),
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        client.system = %system,
        client.operation = %operation,
        server.address = %truncate(peer, MAX_ATTR_LEN),
        client.target = tracing::field::Empty,
        client.outcome = tracing::field::Empty,
        db.system.name = tracing::field::Empty,
        db.operation.name = tracing::field::Empty,
    );
    if DB_SYSTEMS.contains(&system) {
        span.record("db.system.name", system);
        span.record("db.operation.name", operation);
    }
    span
}

/// Record `client.outcome` (see [`client_span`]); `"error"` also marks the
/// span errored.
pub fn record_outcome(span: &tracing::Span, outcome: &'static str) {
    span.record("client.outcome", outcome);
    if outcome == "error" {
        span.record("otel.status_code", "ERROR");
    }
}

/// Mark `span` failed and attach the error as an event on it (exported as an
/// OpenTelemetry exception). The message is capped in length; keep data a
/// caller supplied out of error messages you pass here.
pub fn record_error(span: &tracing::Span, error: &dyn std::fmt::Display) {
    record_outcome(span, "error");
    tracing::error!(
        parent: span,
        error = %truncate(&error.to_string(), MAX_ATTR_LEN),
        "{} failed",
        span.metadata().map(|m| m.name()).unwrap_or("call"),
    );
}

/// Run `fut` inside `span`, marking the span errored if it returns `Err`.
///
/// No error message is attached: the call sites this is for already log a
/// scrubbed one (`log_safe`), and the raw error of a store or lock can name a
/// key derived from a session id. Use [`record_error`] where the message is
/// known to be safe.
pub(crate) async fn traced<T, E>(
    span: tracing::Span,
    fut: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, E> {
    use tracing::Instrument;
    let out = fut.instrument(span.clone()).await;
    record_outcome(&span, if out.is_ok() { "ok" } else { "error" });
    out
}

// ── path redaction ──────────────────────────────────────────────────────────

static PATH_REDACTOR: std::sync::OnceLock<fn(&str) -> String> = std::sync::OnceLock::new();

/// Install a process-wide redactor for the concrete request path the server
/// layers record as `url.path` — for a service whose paths carry a credential,
/// such as `/hooks/{token}/…`. The span NAME is already the route template, so
/// only the attribute needs it. Call it once, before serving; a second call is
/// ignored (and returns `false`), so the first redactor cannot be swapped out.
///
/// ```rust,ignore
/// hs_utils::otel::set_path_redactor(routes::redact_hook_token);
/// ```
pub fn set_path_redactor(redact: fn(&str) -> String) -> bool {
    let set = PATH_REDACTOR.set(redact).is_ok();
    if !set {
        tracing::warn!("otel path redactor already installed; the second one is ignored");
    }
    set
}

/// `path` as the server span may record it.
pub(crate) fn redact_path(path: &str) -> String {
    match PATH_REDACTOR.get() {
        Some(redact) => redact(path),
        None => path.to_string(),
    }
}

/// The parts of an outbound URL a span may carry.
pub(crate) struct Outbound<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: Option<u16>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    /// Record the origin only: the URL's path is (or may be) a credential.
    pub opaque: bool,
}

/// A client span for one outbound HTTP request, named `{METHOD} {host}`.
///
/// The host, not the path: paths carry ids, and the span name is the
/// aggregation key. The path is on `url.full`, with query VALUES redacted as
/// for inbound requests — outbound URLs carry tokens too (a JWKS or Kratos
/// URL with a session token, a Stripe idempotency key).
pub(crate) fn http_client_span(out: Outbound<'_>) -> tracing::Span {
    let port = out.port.map(|p| format!(":{p}")).unwrap_or_default();
    let full = if out.opaque {
        truncate(&format!("{}://{}{port}", out.scheme, out.host), MAX_ATTR_LEN)
    } else {
        let query = redact_query(out.query);
        let sep = if query.is_empty() { "" } else { "?" };
        truncate(&format!("{}://{}{port}{}{sep}{query}", out.scheme, out.host, out.path), MAX_ATTR_LEN)
    };
    tracing::info_span!(
        "http.client",
        otel.name = %format!("{} {}", out.method, out.host),
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        http.request.method = %out.method,
        server.address = %truncate(out.host, MAX_ATTR_LEN),
        server.port = out.port.map(i64::from),
        url.full = %full,
        http.response.status_code = tracing::field::Empty,
    )
}

/// Record an outbound response. A 5xx from the far end marks the span
/// errored; a 4xx is often expected (a 404 lookup, a 401 probe) and is left to
/// the caller, who knows.
pub(crate) fn record_http_client_status(span: &tracing::Span, status: u16) {
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "ERROR");
    }
}

// ── metrics facade ──────────────────────────────────────────────────────────
//
// Called from modules that know nothing about the `otel` feature (pub/sub, db,
// session stores). Without `otel` each is a no-op; with it, each is a no-op
// until `otel::init` has installed the meter provider — an instrument taken
// from the global provider before that would be a no-op forever.

/// Add `n` to the counter `name`. `attrs` become metric labels: constants and
/// bounded values only (a channel name from code, a backend), never ids.
#[inline]
pub(crate) fn count(name: &'static str, n: u64, attrs: &[(&'static str, &str)]) {
    #[cfg(feature = "otel")]
    crate::otel::metrics::count(name, n, attrs);
    #[cfg(not(feature = "otel"))]
    let _ = (name, n, attrs);
}

/// Add `delta` (±) to the up-down counter `name` — a level, like open
/// connections, maintained by its increments.
#[inline]
pub(crate) fn up_down(name: &'static str, delta: i64, attrs: &[(&'static str, &str)]) {
    #[cfg(feature = "otel")]
    crate::otel::metrics::up_down(name, delta, attrs);
    #[cfg(not(feature = "otel"))]
    let _ = (name, delta, attrs);
}

/// One observed value of a gauge (or of a cumulative counter read from the
/// OS) — see [`register_gauges`].
#[derive(Debug, Clone)]
pub(crate) struct Sample {
    pub name: &'static str,
    pub value: f64,
    pub attrs: Vec<(&'static str, String)>,
}

/// Something that can report gauge values when the metrics are collected:
/// it pushes zero or more [`Sample`]s. Runs synchronously on the exporter's
/// thread, so it must only read memory or tiny files — anything needing a
/// query is refreshed by its own task and read from there.
pub(crate) type GaugeSource = Box<dyn Fn(&mut Vec<Sample>) + Send + Sync>;

/// Register a gauge source for the life of the process. Without `otel` this
/// drops `source` (so it cannot keep, say, a pool alive for nothing).
pub(crate) fn register_gauges(source: GaugeSource) {
    #[cfg(feature = "otel")]
    crate::otel::metrics::register_source(source);
    #[cfg(not(feature = "otel"))]
    drop(source);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_url_carries_query_names_not_values() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        let _span = http_client_span(Outbound {
            method: "GET",
            scheme: "https",
            host: "kratos-admin",
            port: Some(4434),
            path: "/admin/identities/abc",
            query: Some("token=ory_st_SECRET&page=2"),
            opaque: false,
        });
        let rec = cap.lock().unwrap().clone();
        let url = rec.iter().find(|(k, _)| k == "url.full").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(url, "https://kratos-admin:4434/admin/identities/abc?token=<redacted>&page=<redacted>");
        let name = rec.iter().find(|(k, _)| k == "otel.name").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(name, "GET kratos-admin", "the path (and its id) must stay out of the name");
    }

    /// A webhook URL is its own credential (`hooks.slack.com/services/T/B/<secret>`):
    /// an opaque call records the origin and nothing after it.
    #[test]
    fn an_opaque_url_records_only_its_origin() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        let _span = http_client_span(Outbound {
            method: "POST",
            scheme: "https",
            host: "hooks.slack.com",
            port: None,
            path: "/services/T000/B000/XXXXSECRETXXXX",
            query: Some("x=1"),
            opaque: true,
        });
        let rec = cap.lock().unwrap().clone();
        let url = rec.iter().find(|(k, _)| k == "url.full").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(url, "https://hooks.slack.com");
        assert!(!rec.iter().any(|(_, v)| v.contains("SECRET")), "{rec:?}");
    }

    #[test]
    fn db_systems_get_db_semconv_fields() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        let _redis = client_span("redis", "SET", "redis-sentinel");
        let _smtp = client_span("smtp", "send", "smtp.example.com");
        let rec = cap.lock().unwrap().clone();
        let systems: Vec<_> = rec.iter().filter(|(k, _)| k == "db.system.name").map(|(_, v)| v.as_str()).collect();
        assert_eq!(systems, ["redis"], "only db systems carry db.system.name");
        assert!(rec.iter().any(|(k, v)| k == "otel.name" && v == "smtp send"));
    }
}

/// Field capture for tests in any module, with or without `otel`.
#[cfg(test)]
pub(crate) mod test_capture {
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    pub(crate) type Fields = Arc<Mutex<Vec<(String, String)>>>;

    pub(crate) fn capture() -> Fields {
        Arc::new(Mutex::new(Vec::new()))
    }

    /// Install a thread-local subscriber recording into `fields`.
    pub(crate) fn install(fields: &Fields) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(tracing_subscriber::registry().with(Capture(fields.clone())))
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

    /// Records fields given at creation AND recorded later (span names and
    /// statuses are both filled in after the span exists), and event fields.
    pub(crate) struct Capture(pub Fields);
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

        fn on_record(
            &self,
            _: &tracing::Id,
            values: &tracing::span::Record<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            values.record(&mut Grab(self.0.clone()));
        }

        fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            event.record(&mut Grab(self.0.clone()));
        }
    }
}
