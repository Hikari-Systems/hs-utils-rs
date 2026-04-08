//! Stdlib-only TCP healthcheck for use as a binary subcommand.
//!
//! Add to `main.rs` before the async runtime starts:
//!
//! ```rust,ignore
//! if std::env::args().nth(1).as_deref() == Some("healthcheck") {
//!     let host = std::env::args().nth(2).unwrap_or_else(|| "localhost".to_string());
//!     let default_port = config::load().map(|c| c.server.port).unwrap_or(3000);
//!     let port = std::env::args()
//!         .nth(3)
//!         .and_then(|s| s.parse::<u16>().ok())
//!         .unwrap_or(default_port);
//!     std::process::exit(if hs_utils::healthcheck::run(&host, port) { 0 } else { 1 });
//! }
//! ```
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
