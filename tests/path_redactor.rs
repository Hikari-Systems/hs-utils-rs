//! A service whose paths carry a credential (`/hooks/{token}/…`) installs a
//! redactor, and the concrete path the server span records goes through it.
//!
//! Its own test binary: the redactor is process-wide and set-once, so it must
//! not leak into the unit tests' spans.
#![cfg(feature = "otel-actix")]

use std::sync::{Arc, Mutex};

use actix_web::{test, web, App, HttpResponse};
use tracing_subscriber::layer::SubscriberExt;

type Fields = Arc<Mutex<Vec<(String, String)>>>;

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
    fn on_new_span(&self, a: &tracing::span::Attributes<'_>, _: &tracing::Id, _: tracing_subscriber::layer::Context<'_, S>) {
        a.record(&mut Grab(self.0.clone()));
    }
    fn on_record(&self, _: &tracing::Id, r: &tracing::span::Record<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        r.record(&mut Grab(self.0.clone()));
    }
}

/// The redactor a consumer would write: `/hooks/<token>/rest` → `/hooks/…/rest`.
fn redact_hook_token(path: &str) -> String {
    match path.strip_prefix("/hooks/").and_then(|r| r.split_once('/')) {
        Some((_, rest)) => format!("/hooks/…/{rest}"),
        None => path.to_string(),
    }
}

#[actix_web::test]
async fn the_concrete_path_goes_through_the_redactor() {
    assert!(hs_utils::otel::set_path_redactor(redact_hook_token));
    assert!(!hs_utils::otel::set_path_redactor(|p| p.to_string()), "a second redactor must not replace the first");

    let cap: Fields = Arc::new(Mutex::new(Vec::new()));
    let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(Capture(cap.clone())));
    let app = test::init_service(
        App::new()
            .wrap(hs_utils::otel::actix_trace())
            .route("/hooks/{token}/linear", web::post().to(HttpResponse::Ok)),
    )
    .await;
    let _ = test::call_service(&app, test::TestRequest::post().uri("/hooks/whk_live_SECRET/linear").to_request()).await;

    let rec = cap.lock().unwrap().clone();
    assert!(!rec.iter().any(|(_, v)| v.contains("whk_live_SECRET")), "hook token reached the span: {rec:?}");
    assert!(rec.iter().any(|(k, v)| k == "url.path" && v == "/hooks/…/linear"), "{rec:?}");
    assert!(rec.iter().any(|(k, v)| k == "otel.name" && v == "POST /hooks/{token}/linear"), "{rec:?}");
}
