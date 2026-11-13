//! axum: a `tower-http` `TraceLayer` built on the shared span in [`super::http_span`].

use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;

#[cfg(test)]
use super::http_span::{MAX_ATTR_LEN, redact_query, truncate};
use super::http_span::{Inbound, record_response, server_span};

type MakeSpan = fn(&http::Request<axum::body::Body>) -> tracing::Span;
type OnResponse = fn(&http::Response<axum::body::Body>, std::time::Duration, &tracing::Span);

/// A `TraceLayer` that names the server span `{METHOD} {route}` and records
/// HTTP semantic-convention attributes, adopting an inbound `traceparent`
/// as the parent so the trace spans service boundaries. With `otel` metrics
/// on, the same span also feeds `http.server.request.duration` and
/// `http.server.active_requests`.
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
    // `MatchedPath` is axum's route template (`/api/image/url/{id}`) rather
    // than the concrete path, and it is in the extensions because
    // `Router::layer` runs after routing. Without it, a service with `{id}`
    // params or a `ServeDir` catch-all mints a distinct span name per request.
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str());
    server_span(
        Inbound {
            method: req.method().as_str(),
            route,
            path: req.uri().path(),
            query: req.uri().query(),
            version: format!("{:?}", req.version()),
            user_agent: req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
            session_recording: req
                .headers()
                .get(super::http_span::SESSION_RECORDING_HEADER)
                .and_then(|v| v.to_str().ok()),
        },
        super::extract_context(req.headers()),
    )
}

fn on_response(
    res: &http::Response<axum::body::Body>,
    _latency: std::time::Duration,
    span: &tracing::Span,
) {
    record_response(span, res.status().as_u16());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::test_capture::{Capture, Fields, capture};
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;

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

    /// A request from a session-recorded page carries the recording's id, and
    /// the server span records it so the session's requests can be found in
    /// the traces. A value that is not a UUID is caller-chosen bytes and is
    /// dropped, not recorded.
    #[tokio::test]
    async fn the_session_recording_header_is_recorded_only_when_it_is_a_session_id() {
        let fields: Fields = capture();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(Capture(fields.clone())),
        );
        let app = axum::Router::new()
            .route("/api/x", axum::routing::get(|| async { "ok" }))
            .layer(axum_trace_layer());

        let id = "123e4567-e89b-42d3-a456-426614174000";
        for value in [id, "not-a-session", &"a".repeat(4096)] {
            let req = http::Request::builder()
                .uri("/api/x")
                .header(super::super::SESSION_RECORDING_HEADER, value)
                .body(axum::body::Body::empty())
                .unwrap();
            let _ = app.clone().oneshot(req).await.unwrap();
        }

        let recorded: Vec<String> = fields
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k == "session_recording.id")
            .map(|(_, v)| v.clone())
            .collect();
        assert_eq!(recorded, vec![id.to_string()], "only the UUID should be recorded");
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

    /// The axum twin of the actix healthcheck test: nothing of a
    /// `/healthcheck` request is exported at `otel.level=info` (span, child,
    /// backend call), the next hop is told not to sample, and the request is
    /// still counted; at `debug` it is an ordinary trace.
    #[tokio::test]
    async fn a_healthcheck_exports_nothing_at_info_but_is_still_counted() {
        use tracing::Instrument;
        for level in ["info", "debug"] {
            let ex = crate::otel::test_export::install(level);
            #[cfg(feature = "http-client")]
            let (next, seen) = crate::otel::test_export::next_hop().await;
            #[cfg(not(feature = "http-client"))]
            let next = String::new();

            let app = axum::Router::new()
                .route(
                    "/healthcheck",
                    axum::routing::get(move || async move {
                        let _ = &next;
                        async {
                            tracing::info!("checking");
                            #[cfg(feature = "http-client")]
                            {
                                use crate::http_client::SendTraced as _;
                                let _ = reqwest::Client::new().get(next.as_str()).send_traced().await;
                            }
                        }
                        .instrument(tracing::info_span!("healthcheck.child"))
                        .await;
                        "ok"
                    }),
                )
                .route("/api/items/{id}", axum::routing::get(|| async { "ok" }))
                .layer(axum_trace_layer());
            let get = |uri: &str| http::Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap();
            let _ = app.clone().oneshot(get("/healthcheck")).await.unwrap();
            let _ = app.oneshot(get("/api/items/1")).await.unwrap();

            let spans = ex.finished();
            let names: Vec<&str> = spans.iter().map(|s| s.name.as_ref()).collect();
            if level == "info" {
                assert_eq!(names, ["GET /api/items/{id}"], "only the ordinary request is exported");
                #[cfg(feature = "http-client")]
                {
                    let req = seen.await.unwrap();
                    let tp = req.lines().find(|l| l.starts_with("traceparent:")).expect("traceparent still sent");
                    assert!(tp.trim_end().ends_with("-00"), "the next hop must be told not to sample: {tp}");
                }
            } else {
                let server = spans.iter().find(|s| s.name == "GET /healthcheck").expect("exported at debug");
                let child = spans.iter().find(|s| s.name == "healthcheck.child").expect("child exported");
                assert_eq!(child.parent_span_id, server.span_context.span_id());
                #[cfg(feature = "http-client")]
                let _ = seen.await;
            }
            let p = ex.points();
            assert_eq!(
                crate::otel::metrics::tests::has(&p, "http.server.request.duration", ("http.route", "/healthcheck")),
                Some(1.0),
                "{level}: {p:?}"
            );
        }
    }

    /// A path installed with `set_quiet_paths` (a long poll) is quiet like
    /// `/healthcheck`: at `info` its span and its children are not exported,
    /// it is still counted, and work it does under an explicit `parent: None`
    /// span is exported as a trace of its own.
    #[tokio::test]
    async fn a_quiet_path_is_not_exported_but_a_fresh_root_beneath_it_is() {
        use tracing::Instrument;
        crate::telemetry::set_quiet_paths(&["/test/long-poll"]);
        let ex = crate::otel::test_export::install("info");
        let app = axum::Router::new()
            .route(
                "/test/long-poll",
                axum::routing::post(|| async {
                    async { tracing::info!("waiting") }
                        .instrument(tracing::info_span!("poll.child"))
                        .await;
                    // Work arrived: trace it on its own.
                    async { tracing::info!("granted") }
                        .instrument(tracing::info_span!(parent: None, "poll.granted"))
                        .await;
                    "ok"
                }),
            )
            .layer(axum_trace_layer());
        let req = http::Request::builder()
            .method("POST")
            .uri("/test/long-poll")
            .body(axum::body::Body::empty())
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();

        let spans = ex.finished();
        let names: Vec<&str> = spans.iter().map(|s| s.name.as_ref()).collect();
        assert_eq!(names, ["poll.granted"], "only the fresh root is exported");
        let granted = &spans[0];
        assert_eq!(granted.parent_span_id, opentelemetry::trace::SpanId::INVALID, "a root");
        assert!(granted.span_context.is_sampled());
        let p = ex.points();
        assert_eq!(
            crate::otel::metrics::tests::has(&p, "http.server.request.duration", ("http.route", "/test/long-poll")),
            Some(1.0),
            "{p:?}"
        );
    }
}
