//! actix-web: middleware producing the same server span as the axum layer,
//! built on [`super::http_span`].

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use opentelemetry::global;
use tracing::Instrument;

use super::http_span::{record_failure, record_response, record_route, server_span, Inbound};

/// Middleware that opens a server span per request, named `{METHOD} {route}`
/// after actix's route template (`/api/items/{id}`), with the same HTTP
/// semantic-convention attributes, query redaction and length caps as
/// [`super::axum_trace_layer`]. It adopts an inbound `traceparent`, so a
/// controller's trace continues into this service. With `otel` metrics on, the
/// span also feeds `http.server.request.duration` and
/// `http.server.active_requests`.
///
/// ```rust,ignore
/// App::new()
///     .wrap(hs_utils::otel::actix_trace())   // in place of middleware::timing()
/// ```
///
/// Wrap it on the `App` (outermost), not on a scope, so it sees every request
/// including the 404s. It replaces `middleware::timing()`: the fmt layer still
/// prints each request's events, and the duration is on the span.
pub fn actix_trace() -> ActixTrace {
    ActixTrace
}

/// See [`actix_trace`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ActixTrace;

impl<S, B> Transform<S, ServiceRequest> for ActixTrace
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = ActixTraceMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ActixTraceMiddleware { service }))
    }
}

/// The service [`ActixTrace`] wraps around the app.
pub struct ActixTraceMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ActixTraceMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().as_str().to_owned();
        // Before routing, actix can still resolve the template by matching the
        // path against its resource map. After routing (below) it knows exactly
        // which resource ran, so the name is set again from the response.
        let early_route = req.match_pattern();
        let parent = global::get_text_map_propagator(|p| p.extract(&ActixHeaders(req.headers())));
        let span = server_span(
            Inbound {
                method: &method,
                route: early_route.as_deref(),
                path: req.path(),
                query: Some(req.query_string()),
                version: format!("{:?}", req.version()),
                user_agent: req
                    .headers()
                    .get(actix_web::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok()),
                session_recording: req
                    .headers()
                    .get(super::http_span::SESSION_RECORDING_HEADER)
                    .and_then(|v| v.to_str().ok()),
            },
            parent,
        );

        // The synchronous part of the inner call (extractors that run eagerly,
        // other middleware's `call`) belongs to the request too.
        let fut = {
            let _entered = span.enter();
            self.service.call(req)
        };

        Box::pin(async move {
            let out = fut.instrument(span.clone()).await;
            match &out {
                Ok(res) => {
                    let route = res.request().match_pattern().or(early_route);
                    record_route(&span, &method, route.as_deref());
                    let status = res.status().as_u16();
                    // A handler `Err` that actix has already rendered into a
                    // response: the status says 5xx, this says why.
                    if status >= 500 {
                        if let Some(err) = res.response().error() {
                            record_failure(&span, err);
                        }
                    }
                    record_response(&span, status);
                }
                Err(err) => {
                    record_route(&span, &method, early_route.as_deref());
                    let status = err.as_response_error().status_code().as_u16();
                    if status >= 500 {
                        record_failure(&span, err);
                    }
                    record_response(&span, status);
                }
            }
            out
        })
    }
}

/// actix-web 4 carries `http` 0.2 header types, so the `http` 1 extractor in
/// the parent module cannot read them.
struct ActixHeaders<'a>(&'a actix_web::http::header::HeaderMap);

impl opentelemetry::propagation::Extractor for ActixHeaders<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otel::http_span::MAX_ATTR_LEN;
    use crate::telemetry::test_capture::{capture, Capture, Fields};
    use actix_web::{test, web, App, HttpResponse};
    use tracing_subscriber::layer::SubscriberExt;

    fn values<'a>(rec: &'a [(String, String)], key: &str) -> Vec<&'a str> {
        rec.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
    }

    fn last<'a>(rec: &'a [(String, String)], key: &str) -> Option<&'a str> {
        values(rec, key).last().copied()
    }

    /// The span is named by the route template; the concrete id never reaches
    /// the name, and an unmatched probe collapses to a constant.
    #[actix_web::test]
    async fn span_names_use_the_route_template_not_the_concrete_path() {
        let cap: Fields = capture();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(Capture(cap.clone())),
        );
        let app = test::init_service(
            App::new()
                .wrap(actix_trace())
                .route("/api/items/{id}", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let _ = test::call_service(&app, test::TestRequest::get().uri("/api/items/abc-123").to_request()).await;
        let _ = test::call_service(
            &app,
            test::TestRequest::get().uri(&format!("/{}", "A".repeat(4000))).to_request(),
        )
        .await;

        let rec = cap.lock().unwrap().clone();
        let names = values(&rec, "otel.name");
        assert!(names.contains(&"GET /api/items/{id}"), "want the template, got {names:?}");
        assert!(!names.iter().any(|n| n.contains("abc-123")), "concrete id in the name: {names:?}");
        assert!(names.contains(&"GET <unmatched>"), "a 404 should collapse, got {names:?}");
        assert!(values(&rec, "http.route").contains(&"/api/items/{id}"));
        for (k, v) in &rec {
            assert!(v.len() <= MAX_ATTR_LEN + 8, "{k} unbounded at {} bytes", v.len());
        }
    }

    /// Same regression as the axum layer's: query values (an OAuth2 `code`)
    /// must never reach the span.
    #[actix_web::test]
    async fn query_values_are_redacted() {
        let cap = capture();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(Capture(cap.clone())),
        );
        let app = test::init_service(
            App::new()
                .wrap(actix_trace())
                .route("/api/oauth2/callback", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let _ = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/oauth2/callback?code=ory_ac_live_9f3&state=csrf-1")
                .to_request(),
        )
        .await;

        let rec = cap.lock().unwrap().clone();
        let all = rec.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" | ");
        assert!(!all.contains("ory_ac_live_9f3"), "authorization code reached the span: {all}");
        assert_eq!(last(&rec, "url.query"), Some("code=<redacted>&state=<redacted>"));
    }

    /// 4xx is the client's problem; only 5xx marks the span errored — whether
    /// the handler returned a 500 response or an `Err` actix rendered as one.
    #[actix_web::test]
    async fn only_server_errors_mark_the_span_errored() {
        async fn boom() -> Result<HttpResponse, actix_web::Error> {
            Err(actix_web::error::ErrorInternalServerError("db down"))
        }
        for (path, want_status, want_error) in [
            ("/ok", "200", false),
            ("/missing", "404", false),
            ("/boom", "500", true),
        ] {
            let cap = capture();
            let _guard = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(Capture(cap.clone())),
            );
            let app = test::init_service(
                App::new()
                    .wrap(actix_trace())
                    .route("/ok", web::get().to(HttpResponse::Ok))
                    .route("/boom", web::get().to(boom)),
            )
            .await;
            let _ = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;

            let rec = cap.lock().unwrap().clone();
            assert_eq!(last(&rec, "http.response.status_code"), Some(want_status), "{path}");
            assert_eq!(last(&rec, "otel.status_code") == Some("ERROR"), want_error, "{path}: {rec:?}");
        }
    }

    /// The cross-service promise, through the real OpenTelemetry layer: an
    /// inbound `traceparent` becomes the server span's parent, so a
    /// controller's trace continues here instead of a new root starting. And
    /// with `http-client`, the request this handler makes carries the same
    /// trace on to the next service.
    #[actix_web::test]
    async fn an_inbound_traceparent_is_adopted_and_passed_on() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};

        opentelemetry::global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test"))),
        );

        // What the next service would see: the handler calls it through `send`.
        #[cfg(feature = "http-client")]
        let (next, seen) = {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let next = format!("http://{}/next", l.local_addr().unwrap());
            let seen = tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n").await.unwrap();
                String::from_utf8_lossy(&buf[..n]).to_lowercase()
            });
            (next, seen)
        };
        #[cfg(not(feature = "http-client"))]
        let next = String::new();

        let app = test::init_service(App::new().wrap(actix_trace()).app_data(web::Data::new(next)).route(
            "/api/items/{id}",
            web::get().to(|_next: web::Data<String>| async move {
                #[cfg(feature = "http-client")]
                {
                    let _ = crate::http_client::send(reqwest::Client::new().get(_next.as_str())).await;
                }
                HttpResponse::Ok().finish()
            }),
        ))
        .await;
        let inbound = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let _ = test::call_service(
            &app,
            test::TestRequest::get().uri("/api/items/7").insert_header(("traceparent", inbound)).to_request(),
        )
        .await;

        let spans = exporter.get_finished_spans().unwrap();
        let server = spans.iter().find(|s| s.name == "GET /api/items/{id}").expect("server span exported");
        assert_eq!(server.span_context.trace_id().to_string(), "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(server.parent_span_id.to_string(), "b7ad6b7169203331", "the caller's span is the parent");

        #[cfg(feature = "http-client")]
        {
            let req = seen.await.unwrap();
            assert!(
                req.contains("traceparent: 00-0af7651916cd43dd8448eb211c80319c-"),
                "the outbound request must continue the same trace: {req}"
            );
            let client = spans.iter().find(|s| s.name.starts_with("GET 127.0.0.1")).expect("client span exported");
            assert_eq!(client.parent_span_id, server.span_context.span_id(), "client span is the server span's child");
        }
    }

    /// What a healthcheck does that is worth suppressing: a child span of its
    /// own and, with `http-client`, a backend call.
    async fn healthcheck(next: web::Data<String>) -> HttpResponse {
        let child = tracing::info_span!("healthcheck.child");
        let _ = &next;
        async {
            tracing::info!("checking");
            #[cfg(feature = "http-client")]
            {
                use crate::http_client::SendTraced as _;
                let _ = reqwest::Client::new().get(next.as_str()).send_traced().await;
            }
        }
        .instrument(child)
        .await;
        HttpResponse::Ok().finish()
    }

    /// The Docker healthcheck polls `/healthcheck` every few seconds. At
    /// `otel.level=info` nothing of it is exported — not its server span, not
    /// a child span, not its backend call's client span — and the
    /// `traceparent` it sends on says "not sampled", so the next service
    /// drops its side too. The request is still a request to the metrics.
    #[actix_web::test]
    async fn a_healthcheck_exports_nothing_at_info_but_is_still_counted() {
        let ex = crate::otel::test_export::install("info");
        #[cfg(feature = "http-client")]
        let (next, seen) = crate::otel::test_export::next_hop().await;
        #[cfg(not(feature = "http-client"))]
        let next = String::new();

        let app = test::init_service(
            App::new()
                .wrap(actix_trace())
                .app_data(web::Data::new(next))
                .route("/healthcheck", web::get().to(healthcheck))
                .route("/api/items/{id}", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let _ = test::call_service(&app, test::TestRequest::get().uri("/healthcheck").to_request()).await;
        let _ = test::call_service(&app, test::TestRequest::get().uri("/api/items/1").to_request()).await;

        let names: Vec<String> = ex.finished().iter().map(|s| s.name.to_string()).collect();
        assert_eq!(names, ["GET /api/items/{id}"], "only the ordinary request is exported");
        #[cfg(feature = "http-client")]
        {
            let req = seen.await.unwrap();
            let tp = req.lines().find(|l| l.starts_with("traceparent:")).expect("traceparent still sent");
            assert!(tp.trim_end().ends_with("-00"), "the next hop must be told not to sample: {tp}");
        }
        let p = ex.points();
        assert_eq!(
            crate::otel::metrics::tests::has(&p, "http.server.request.duration", ("http.route", "/healthcheck")),
            Some(1.0),
            "{p:?}"
        );
    }

    /// With `otel.level=debug` the healthcheck is an ordinary trace: its span,
    /// its child beneath it.
    #[actix_web::test]
    async fn a_healthcheck_is_exported_at_debug() {
        let ex = crate::otel::test_export::install("debug");
        #[cfg(feature = "http-client")]
        let (next, _seen) = crate::otel::test_export::next_hop().await;
        #[cfg(not(feature = "http-client"))]
        let next = String::new();
        let app = test::init_service(
            App::new()
                .wrap(actix_trace())
                .app_data(web::Data::new(next))
                .route("/healthcheck", web::to(healthcheck)),
        )
        .await;
        let _ = test::call_service(&app, test::TestRequest::post().uri("/healthcheck").to_request()).await;

        let spans = ex.finished();
        let server = spans.iter().find(|s| s.name == "POST /healthcheck").expect("healthcheck span exported");
        let child = spans.iter().find(|s| s.name == "healthcheck.child").expect("child exported");
        assert_eq!(child.parent_span_id, server.span_context.span_id());
        assert_eq!(child.span_context.trace_id(), server.span_context.trace_id());
    }

    /// Only the exact path: `/healthcheck/deep` and `/healthchecks` are
    /// ordinary routes.
    #[actix_web::test]
    async fn only_the_exact_healthcheck_path_is_quiet() {
        let ex = crate::otel::test_export::install("info");
        let app = test::init_service(
            App::new()
                .wrap(actix_trace())
                .route("/healthcheck/deep", web::get().to(HttpResponse::Ok))
                .route("/healthchecks", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let _ = test::call_service(&app, test::TestRequest::get().uri("/healthcheck/deep").to_request()).await;
        let _ = test::call_service(&app, test::TestRequest::get().uri("/healthchecks").to_request()).await;
        let mut names: Vec<String> = ex.finished().iter().map(|s| s.name.to_string()).collect();
        names.sort();
        assert_eq!(names, ["GET /healthcheck/deep", "GET /healthchecks"]);
    }
}
