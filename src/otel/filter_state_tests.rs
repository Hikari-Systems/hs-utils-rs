//! Regression suite for per-layer filter state leaking between callsites.
//!
//! `tracing-subscriber`'s per-layer filters keep each layer's verdict from the
//! last `enabled()` check in a thread-local, and a callsite every filter
//! registered as `Interest::always` skips the check and consumes whatever is
//! left there. Any `enabled()` check that no span or event follows leaves
//! stale verdicts behind: sqlx's per-statement `log::log_enabled!` through the
//! `tracing-log` bridge, a `tracing::enabled!`, a disabled span. Before
//! v0.40.1 the next request span on that thread was created but neither
//! exported nor counted, so a database-backed service lost most of its
//! request telemetry.
//!
//! Every test here crosses one of those "poisoners" with one kind of telemetry
//! this crate produces, on both server frameworks, with the poisoner run both
//! inside the handler (as a query does) and between requests on the same
//! thread. Each case asserts nothing is lost: spans exported, requests
//! counted, in-flight back to zero, client calls counted.

use crate::otel::metrics::tests::{has, Point};
use crate::otel::test_export;

/// Ways to leave stale per-layer verdicts on the current thread.
#[derive(Clone, Copy, Debug)]
enum Poison {
    /// What `tracing_log::LogTracer::enabled` does for `log::log_enabled!`
    /// at DEBUG (sqlx's query logger, once per statement): every layer says no.
    LogBridgeDebug,
    /// `tracing::enabled!` at INFO for a foreign target: only some layers say yes.
    EnabledInfo,
    /// `tracing::enabled!` at DEBUG for a foreign target: every layer says no.
    EnabledDebug,
    /// A span nothing is interested in, created and dropped.
    DisabledSpan,
    /// Several of the above back to back, as a handler running many queries does.
    Repeated,
}

const POISONS: [Poison; 5] =
    [Poison::LogBridgeDebug, Poison::EnabledInfo, Poison::EnabledDebug, Poison::DisabledSpan, Poison::Repeated];

fn poison(p: Poison) {
    match p {
        Poison::LogBridgeDebug => {
            let span = tracing::debug_span!(target: "sqlx::query", "log record");
            let meta = span.metadata().expect("a disabled span keeps its metadata");
            let _ = tracing::dispatcher::get_default(|d| d.enabled(meta));
        }
        Poison::EnabledInfo => {
            let _ = tracing::enabled!(target: "sqlx::query", tracing::Level::INFO);
        }
        Poison::EnabledDebug => {
            let _ = tracing::enabled!(target: "sqlx::query", tracing::Level::DEBUG);
        }
        Poison::DisabledSpan => drop(tracing::trace_span!(target: "sqlx::query", "unwanted")),
        Poison::Repeated => {
            for _ in 0..3 {
                poison(Poison::LogBridgeDebug);
                poison(Poison::EnabledInfo);
                poison(Poison::EnabledDebug);
            }
        }
    }
}

/// Where the poisoner runs relative to the request.
#[derive(Clone, Copy, Debug)]
enum When {
    /// In the handler, before the response, as a database query does.
    InHandler,
    /// On the same thread between requests (a background task, a log check).
    Between,
}

const WHENS: [When; 2] = [When::InHandler, When::Between];

/// Requests per route per case.
const N: usize = 4;

fn server_count(p: &[Point], route: &str) -> Option<f64> {
    has(p, "http.server.request.duration", ("http.route", route))
}

fn in_flight(p: &[Point]) -> f64 {
    p.iter()
        .filter(|(n, _, _)| n == "http.server.active_requests")
        .map(|(_, v, _)| *v)
        .sum()
}

/// What one case must see: every ordinary request exported and counted,
/// every quiet healthcheck counted (never exported), and nothing left in flight.
fn assert_complete(case: &str, ex: &test_export::Export) {
    let spans = ex.finished();
    let p = ex.points();
    let work = spans.iter().filter(|s| s.name == "GET /work").count();
    assert_eq!(work, N, "{case}: server spans exported for /work");
    assert_eq!(server_count(&p, "/work"), Some(N as f64), "{case}: /work requests counted: {p:?}");
    assert_eq!(server_count(&p, "/healthcheck"), Some(N as f64), "{case}: /healthcheck requests counted: {p:?}");
    assert!(
        !spans.iter().any(|s| s.name.contains("healthcheck")),
        "{case}: a healthcheck must still not be exported at info"
    );
    assert_eq!(in_flight(&p), 0.0, "{case}: in-flight count must return to zero: {p:?}");
}

#[cfg(feature = "otel-actix")]
mod actix {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    #[actix_web::test]
    async fn requests_are_exported_and_counted_whatever_poisons_the_filter_state() {
        for p in POISONS {
            for when in WHENS {
                let case = format!("actix {p:?} {when:?}");
                let ex = test_export::install("info");
                let handler = move || async move {
                    if matches!(when, When::InHandler) {
                        poison(p);
                    }
                    HttpResponse::Ok().finish()
                };
                let app = test::init_service(
                    App::new()
                        .wrap(crate::otel::actix_trace())
                        .route("/work", web::get().to(handler))
                        .route("/healthcheck", web::get().to(handler)),
                )
                .await;
                for _ in 0..N {
                    for path in ["/work", "/healthcheck"] {
                        if matches!(when, When::Between) {
                            poison(p);
                        }
                        let r = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
                        assert_eq!(r.status(), 200, "{case}");
                    }
                }
                assert_complete(&case, &ex);
            }
        }
    }
}

#[cfg(feature = "otel-axum")]
mod axum_tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn requests_are_exported_and_counted_whatever_poisons_the_filter_state() {
        for p in POISONS {
            for when in WHENS {
                let case = format!("axum {p:?} {when:?}");
                let ex = test_export::install("info");
                let handler = move || async move {
                    if matches!(when, When::InHandler) {
                        poison(p);
                    }
                    "ok"
                };
                let app = axum::Router::new()
                    .route("/work", axum::routing::get(handler))
                    .route("/healthcheck", axum::routing::get(handler))
                    .layer(crate::otel::axum_trace_layer());
                for _ in 0..N {
                    for path in ["/work", "/healthcheck"] {
                        if matches!(when, When::Between) {
                            poison(p);
                        }
                        let req = axum::http::Request::get(path).body(axum::body::Body::empty()).unwrap();
                        let r = app.clone().oneshot(req).await.unwrap();
                        assert_eq!(r.status(), 200, "{case}");
                    }
                }
                assert_complete(&case, &ex);
            }
        }
    }
}

/// Client spans have the same exposure: a call made after a query on the same
/// thread must still be counted (and, for HTTP, exported).
mod client {
    use super::*;

    #[tokio::test]
    async fn client_operations_are_counted_after_each_poison() {
        for p in POISONS {
            let ex = test_export::install("info");
            for _ in 0..N {
                poison(p);
                let span = crate::telemetry::client_span("redis", "GET", "cache");
                crate::telemetry::record_outcome(&span, "ok");
                drop(span);
            }
            let points = ex.points();
            assert_eq!(
                has(&points, "hs.client.operation.duration", ("client.operation", "GET")),
                Some(N as f64),
                "{p:?}: client operations counted: {points:?}"
            );
        }
    }

    #[cfg(feature = "http-client")]
    #[tokio::test]
    async fn outbound_http_calls_are_exported_and_counted_after_each_poison() {
        for p in POISONS {
            let ex = test_export::install("info");
            let client = reqwest::Client::new();
            for _ in 0..N {
                let (next, seen) = test_export::next_hop().await;
                poison(p);
                let r = crate::http_client::send(client.get(&next)).await.unwrap();
                assert_eq!(r.status(), 204, "{p:?}");
                let _ = seen.await;
            }
            let spans = ex.finished();
            let points = ex.points();
            let client_spans = spans.iter().filter(|s| s.name.starts_with("GET ")).count();
            assert_eq!(client_spans, N, "{p:?}: outbound HTTP spans exported");
            let counted: f64 = points
                .iter()
                .filter(|(n, _, _)| n == "http.client.request.duration")
                .map(|(_, v, _)| *v)
                .sum();
            assert_eq!(counted, N as f64, "{p:?}: outbound HTTP calls counted: {points:?}");
        }
    }
}

/// With the metrics layer off (`otel.metricsEnabled=false`) no layer is left
/// whose filter is `sometimes`, unless the quiet layer's is: the same stale
/// verdicts must not hide request spans from the export.
#[cfg(feature = "otel-actix")]
mod metrics_off {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    #[actix_web::test]
    async fn request_spans_are_exported_whatever_poisons_the_filter_state() {
        for p in POISONS {
            for when in WHENS {
                let case = format!("metrics off {p:?} {when:?}");
                let ex = test_export::install_without_metrics("info");
                let handler = move || async move {
                    if matches!(when, When::InHandler) {
                        poison(p);
                    }
                    HttpResponse::Ok().finish()
                };
                let app = test::init_service(App::new().wrap(crate::otel::actix_trace()).route("/work", web::get().to(handler))).await;
                for _ in 0..N {
                    if matches!(when, When::Between) {
                        poison(p);
                    }
                    let r = test::call_service(&app, test::TestRequest::get().uri("/work").to_request()).await;
                    assert_eq!(r.status(), 200, "{case}");
                }
                let work = ex.finished().iter().filter(|s| s.name == "GET /work").count();
                assert_eq!(work, N, "{case}: server spans exported");
            }
        }
    }
}
