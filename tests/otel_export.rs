//! End-to-end check that the OTLP exporter actually ships spans.
//!
//! This lives in `tests/` rather than beside the module because [`init`]
//! installs the *global* `tracing` subscriber, which can only happen once per
//! process — an integration test gets its own binary, so it cannot collide with
//! the unit tests.
//!
//! What it is really guarding is the dependency feature set in `Cargo.toml`.
//! Every plausible mistake there (no TLS backend, the async reqwest client on
//! the batch processor's non-Tokio thread, no rustls crypto provider) fails
//! *silently at runtime* — the service stays up and exports nothing. A
//! compile-only check would not notice any of them.
#![cfg(feature = "otel")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use hs_utils::otel::{self, OtelConfig};

/// Reads one HTTP request per connection and replies `200 OK`, sending each
/// request line plus headers back. Enough of a server for the exporters (one
/// connection each: the traces and the metrics exporter do not share a client).
fn serve(listener: TcpListener, tx: mpsc::Sender<String>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { return };
        if serve_one(stream, &tx).is_err() {
            return;
        }
    }
}

fn serve_one(mut stream: std::net::TcpStream, tx: &mpsc::Sender<String>) -> Result<(), mpsc::SendError<String>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until the headers are complete; we do not need the protobuf body,
    // only proof that a POST arrived with the right path and auth header.
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let head = String::from_utf8_lossy(&buf)
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_string();
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.flush();
    tx.send(head)
}

#[test]
fn exports_spans_over_otlp_http() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub collector");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || serve(listener, tx));

    let cfg = OtelConfig {
        enabled: true,
        endpoint: format!("http://127.0.0.1:{port}"),
        api_key: "test-key".to_string(),
        service_name: "otel-export-test".to_string(),
        environment: "test".to_string(),
        sample_ratio: 1.0,
        // Every key added since is defaulted, which is how a consumer's
        // literal must be written too (see CLAUDE.md, v0.37.0).
        ..Default::default()
    };

    let mut guard = otel::init("info", &cfg).expect("otel init");
    tracing::info_span!("unit-under-test").in_scope(|| {
        tracing::info!("inside the span");
    });
    // Flushes the batch queue synchronously, so by the time this returns the
    // export has either happened or failed.
    guard.shutdown();

    // Both exporters, in whichever order they flushed. Each one failing is
    // silent at runtime, so each is asserted on its own.
    let mut heads = Vec::new();
    while heads.len() < 2 {
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(h) => heads.push(h),
            Err(_) => break,
        }
    }
    let find = |path: &str| heads.iter().find(|h| h.starts_with(&format!("POST {path} "))).cloned();

    let traces = find("/v1/traces")
        .unwrap_or_else(|| panic!("no POST to /v1/traces — the span exporter shipped nothing; got {heads:#?}"));
    assert!(
        traces.to_ascii_lowercase().contains("x-honeycomb-team: test-key"),
        "ingest key was not sent as x-honeycomb-team:\n{traces}"
    );

    let metrics = find("/v1/metrics")
        .unwrap_or_else(|| panic!("no POST to /v1/metrics — the metric exporter shipped nothing; got {heads:#?}"));
    let lower = metrics.to_ascii_lowercase();
    assert!(lower.contains("x-honeycomb-team: test-key"), "metrics sent without the key:\n{metrics}");
    assert!(
        !lower.contains("x-honeycomb-dataset"),
        "native OTLP metrics route themselves; the dataset header is opt-in:\n{metrics}"
    );
}

/// The disabled path must not start any OTLP machinery, and must still install
/// a working subscriber. Runs in its own binary-free scope by virtue of being
/// the only other test here — it deliberately does *not* call `init`, which
/// would panic on the second global-subscriber install.
#[test]
fn disabled_config_defaults_to_off() {
    let cfg = OtelConfig::default();
    assert!(!cfg.enabled, "otel must be off unless explicitly enabled");
    assert_eq!(cfg.sample_ratio, 1.0);
    assert_eq!(cfg.endpoint, "https://api.honeycomb.io");
    // The v0.37.0 keys: each unset one behaves as before.
    assert!(cfg.level.is_empty(), "empty level means: export at the log level, as before");
    assert!(cfg.api_key_required, "an empty key must still disable export by default");
    assert!(cfg.metrics_dataset.is_empty());
}

/// The new keys arrive through the usual all-strings config tree.
#[test]
fn new_keys_deserialise_from_strings() {
    let cfg: OtelConfig = serde_json::from_value(serde_json::json!({
        "enabled": "true",
        "level": "info,sqlx::query=debug",
        "metricsEnabled": "false",
        "metricsIntervalSecs": "15",
        "processMetrics": "false",
        "apiKeyRequired": "false"
    }))
    .unwrap();
    assert_eq!(cfg.level, "info,sqlx::query=debug");
    assert!(!cfg.metrics_enabled && !cfg.process_metrics && !cfg.api_key_required);
    assert_eq!(cfg.metrics_interval_secs, 15);
}
