//! Stdlib-only TCP healthcheck for use as a binary subcommand.
//!
//! Add to `main.rs` before the async runtime starts:
//!
//! ```rust,ignore
//! hs_utils::healthcheck::check_subcommand(
//!     config::load().map(|c| c.server.port).unwrap_or(3000),
//! );
//! ```
//!
//! `check_subcommand` is a no-op when `argv[1] != "healthcheck"`, so it is
//! safe to call unconditionally at the top of every `main`.
//!
//! **Dockerfile:**
//! ```dockerfile
//! HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
//!     CMD ["/app/server", "healthcheck"]
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Open a raw TCP connection to `host:port`, send a minimal HTTP/1.1 GET to
/// `/healthcheck`, and return `true` if the response starts with `HTTP/1.1 200`.
///
/// Uses only stdlib — no reqwest, no tokio, no extra dependencies.
/// Suitable for use before the async runtime is started.
pub fn run(host: &str, port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(format!("{host}:{port}")) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok();

    let req = "GET /healthcheck HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }

    response.starts_with("HTTP/1.1 200")
}

/// Handle the `healthcheck` CLI subcommand and exit if it is present.
///
/// Parses `argv[1..3]` as `[host] [port]`, using `default_port` when port is
/// absent.  Calls `std::process::exit(0)` on success, `exit(1)` on failure.
///
/// This function is a **no-op** when `argv[1] != "healthcheck"`, so it can be
/// called unconditionally at the top of every `main` before the async runtime
/// starts:
///
/// ```rust,ignore
/// hs_utils::healthcheck::check_subcommand(
///     config::load().map(|c| c.server.port).unwrap_or(3000),
/// );
/// ```
pub fn check_subcommand(default_port: u16) {
    if std::env::args().nth(1).as_deref() != Some("healthcheck") {
        return;
    }
    let host = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "localhost".to_string());
    let port = std::env::args()
        .nth(3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(default_port);
    std::process::exit(if run(&host, port) { 0 } else { 1 });
}
