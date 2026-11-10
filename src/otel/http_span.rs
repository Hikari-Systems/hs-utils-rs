//! Pieces shared by every HTTP span this crate makes: the server spans of the
//! axum and actix layers and the client span of [`super::send`]. Kept in one
//! place so the frameworks cannot drift apart on what they record or redact.

use tracing_opentelemetry::OpenTelemetrySpanExt;

pub(crate) use crate::telemetry::{MAX_ATTR_LEN, redact_query, truncate};

/// What a server span is named when no route matched — a 404, or a
/// `ServeDir`/fallback hit. Deliberately constant: the raw path there is
/// entirely attacker-chosen, and using it would mint one span name per
/// probe. The real path is still on `url.path`, bounded.
pub(crate) const UNMATCHED: &str = "<unmatched>";


/// The framework-neutral view of an inbound request.
pub(crate) struct Inbound<'a> {
    pub method: &'a str,
    /// The route TEMPLATE (`/api/item/{id}`), never the concrete path. `None`
    /// when it is not known yet (actix resolves it during routing) or nothing
    /// matched; see [`record_route`].
    pub route: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    /// `HTTP/1.1` etc. — the `Debug` form of either `http` crate's `Version`.
    pub version: String,
    pub user_agent: Option<&'a str>,
}

/// The path a container's Docker healthcheck polls, every few seconds, on
/// every service. Its server span is `DEBUG`, so an `otel.level=info` export
/// never sees it or anything beneath it; see [`server_span`].
pub(crate) const HEALTHCHECK_PATH: &str = "/healthcheck";

/// The server span for one inbound request, adopting `parent` (the context
/// extracted from its `traceparent`).
///
/// A request for exactly [`HEALTHCHECK_PATH`] (any method) gets a `DEBUG`
/// span: same name, same fields, so `http.server.request.duration` still
/// counts it, but an `otel.level=info` export does not see it. Its children
/// would then be orphans the export DOES see — new roots, one trace per poll
/// — so the request is also marked for [`super::QuietLayer`], which makes an
/// unsampled context current while it runs: everything beneath it, and the
/// `traceparent` it sends on, is dropped by the parent-based sampler. With
/// `otel.level=debug` the span is exported like any other, children and all.
pub(crate) fn server_span(req: Inbound<'_>, parent: opentelemetry::Context) -> tracing::Span {
    // `url.path` is attacker-supplied and unbounded — the same "free inbound
    // bytes turned into billable outbound ones" argument that bounds the user
    // agent. A 4 KB path produced a 4 KB attribute.
    // Through the service's redactor first, if it installed one: a path can
    // carry a credential (`/hooks/{token}/…`) that the template hides from the
    // span name but the concrete path would publish.
    let path = truncate(&crate::telemetry::redact_path(req.path), MAX_ATTR_LEN);
    let query = redact_query(req.query);
    let user_agent = truncate(req.user_agent.unwrap_or_default(), MAX_ATTR_LEN);
    let quiet = req.path == HEALTHCHECK_PATH;
    // A span's level is fixed at its callsite, so one callsite per level.
    macro_rules! span_at {
        ($mac:ident) => {
            // The name must stay `telemetry::SERVER_SPAN`; the metrics layer keys on it.
            tracing::$mac!(
                "http.server",
                otel.name = tracing::field::Empty,
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                http.request.method = %req.method,
                http.route = tracing::field::Empty,
                url.path = %path,
                url.query = %query,
                network.protocol.version = %req.version,
                user_agent.original = %user_agent,
                http.response.status_code = tracing::field::Empty,
            )
        };
    }
    let span = if quiet { span_at!(debug_span) } else { span_at!(info_span) };
    record_route(&span, req.method, req.route);
    // Fails only when the subscriber has no OpenTelemetry layer (tracing
    // disabled) — in that case there is no parent to adopt and the local span
    // is still perfectly good, so this is not worth logging per request.
    let _ = span.set_parent(parent);
    if quiet {
        super::quiet_unless_exported(&span);
    }
    span
}

/// Name the span `{METHOD} {route}` and set `http.route`. The span NAME is the
/// primary aggregation key, so it must stay low-cardinality: the template, or
/// [`UNMATCHED`]. Recording it again later (actix, once routing has run)
/// replaces the earlier name.
pub(crate) fn record_route(span: &tracing::Span, method: &str, route: Option<&str>) {
    let route = route.unwrap_or(UNMATCHED);
    span.record("otel.name", format!("{method} {route}"));
    span.record("http.route", route);
}

/// Record the response status. Only 5xx marks the span errored; 4xx is a
/// client problem and would otherwise drown the error rate in routine 401s
/// from MCP auth probes.
///
/// The span-metrics layer takes this moment as the end of the request (the
/// headers are going out), so a long-lived body — SSE — is not one enormous
/// "request duration". Record the route before this, not after.
pub(crate) fn record_response(span: &tracing::Span, status: u16) {
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "ERROR");
    }
}

/// Record a request that failed before producing any response (a handler
/// error the framework did not turn into one, or a dropped connection).
#[cfg_attr(not(feature = "otel-actix"), allow(dead_code))] // axum reports failures through the status
pub(crate) fn record_failure(span: &tracing::Span, error: &dyn std::fmt::Display) {
    span.record("otel.status_code", "ERROR");
    tracing::error!(parent: span, error = %truncate(&error.to_string(), MAX_ATTR_LEN), "request failed");
}
