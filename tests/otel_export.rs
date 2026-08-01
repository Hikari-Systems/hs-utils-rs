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

/// Reads one HTTP request off `stream` and replies `200 OK`, returning the
/// request line plus headers. Enough of a server for the exporter to talk to.
fn serve_one(listener: TcpListener, tx: mpsc::Sender<String>) {
    let Ok((mut stream, _)) = listener.accept() else {
        return;
    };
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
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.flush();
    let _ = tx.send(head);
}

#[test]
fn exports_spans_over_otlp_http() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub collector");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || serve_one(listener, tx));

    let cfg = OtelConfig {
        enabled: true,
        endpoint: format!("http://127.0.0.1:{port}"),
        api_key: "test-key".to_string(),
        service_name: "otel-export-test".to_string(),
        environment: "test".to_string(),
        sample_ratio: 1.0,
    };

    let mut guard = otel::init("info", &cfg).expect("otel init");
    tracing::info_span!("unit-under-test").in_scope(|| {
        tracing::info!("inside the span");
    });
    // Flushes the batch queue synchronously, so by the time this returns the
    // export has either happened or failed.
    guard.shutdown();

    let head = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("collector received no OTLP request — the exporter shipped nothing");

    assert!(
        head.starts_with("POST /v1/traces "),
        "expected a POST to /v1/traces, got:\n{head}"
    );
    assert!(
        head.to_ascii_lowercase().contains("x-honeycomb-team: test-key"),
        "ingest key was not sent as x-honeycomb-team:\n{head}"
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
}
