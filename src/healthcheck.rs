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
//! By default the probe hits the cheap `/healthcheck` liveness endpoint. Pass
//! the optional `deps` token to additionally exercise the service's
//! dependencies (`/healthcheck?deps=true`) — only do this where the service
//! actually implements the `?deps=true` branch (e.g. a DB `SELECT 1`).
//!
//! **Dockerfile (liveness only):**
//! ```dockerfile
//! HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
//!     CMD ["/app/server", "healthcheck"]
//! ```
//!
//! **Dockerfile / compose (dependency-aware):**
//! ```dockerfile
//! HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
//!     CMD ["/app/server", "healthcheck", "deps"]
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Open a raw TCP connection to `host:port`, send a minimal HTTP/1.1 GET to
/// `/healthcheck` (or `/healthcheck?deps=true` when `deps` is set), and return
/// `true` if the response starts with `HTTP/1.1 200`.
///
/// Uses only stdlib — no reqwest, no tokio, no extra dependencies.
/// Suitable for use before the async runtime is started.
pub fn run(host: &str, port: u16, deps: bool) -> bool {
    let Ok(mut stream) = TcpStream::connect(format!("{host}:{port}")) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok();

    let path = if deps {
        "/healthcheck?deps=true"
    } else {
        "/healthcheck"
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
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
/// Accepts (after the `healthcheck` subcommand) an optional `[host] [port]` and
/// an optional `deps` / `--deps` token, in any order:
///
/// ```text
/// healthcheck                       # localhost:<default_port>, liveness only
/// healthcheck deps                  # localhost:<default_port>, ?deps=true
/// healthcheck myhost 3000           # myhost:3000, liveness only
/// healthcheck myhost 3000 deps      # myhost:3000, ?deps=true
/// ```
///
/// `default_port` is used when the port is absent. Calls
/// `std::process::exit(0)` on success, `exit(1)` on failure.
///
/// `deps` is **opt-in**: omit it and the probe stays a cheap liveness check.
/// Only request it where the service implements the `?deps=true` branch.
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
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("healthcheck") {
        return;
    }

    // The `deps` flag may appear anywhere after the subcommand; the remaining
    // positional args are `[host] [port]`.
    let mut deps = false;
    let mut positional: Vec<String> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "deps" | "--deps" => deps = true,
            _ => positional.push(arg),
        }
    }

    let host = positional
        .first()
        .cloned()
        .unwrap_or_else(|| "localhost".to_string());
    let port = positional
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(default_port);

    std::process::exit(if run(&host, port, deps) { 0 } else { 1 });
}
