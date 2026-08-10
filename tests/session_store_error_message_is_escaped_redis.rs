//! A hostile redis must not be able to forge log lines through the redis
//! session store's error text.
//!
//! Sibling of `session_store_sid_never_logged_redis.rs`, and its own binary for
//! the same reason: a global `tracing` subscriber can be installed once per
//! process, and that file's assertions require a capture in which
//! `connection failed` **never** appears — which is precisely the line this one
//! exists to drive. The two cannot share a capture.
//!
//! The threat is `RedisError`'s `Display`. Every reply the server sends comes
//! back through it verbatim: at the pinned redis 0.27.6 the RESP line parser is
//! `take_until_bytes(b"\r\n")` (`parser.rs:93`), so a **bare LF** inside a
//! `-ERR` reply is *not* a terminator — it survives into `ServerError::details`,
//! through `check_db_select` (`connection.rs:1079`) into
//! `ErrorRepr::WithDescriptionAndDetail`, and out of `Display` as a real
//! newline. Rendered with the `%` sigil (or interpolated into the message, which
//! is the same thing) the fmt layer emits those bytes raw and the reply becomes
//! an extra line in the container log, indistinguishable from one this service
//! wrote. Recorded as a bare `&str` the layer escapes it instead.
//!
//! **The vehicle is a `SELECT` failure, not a closed port**, and that is the
//! only part of this file with any subtlety. `conn()`'s two call sites are
//! reached by any connection failure, but a closed port yields an
//! `ErrorRepr::IoError` whose text this test cannot choose — the whole point is
//! server-controlled text. `connection_setup_pipeline` (`connection.rs:972`)
//! emits `SELECT` only when the db index is non-zero, so the URL carries `/3`
//! and the stub answers the pipelined handshake with a scripted `-ERR` for
//! `SELECT` and `+OK` for the two `CLIENT SETINFO`s that follow it. That is the
//! shortest path from "bytes a hostile redis chose" to "the two
//! `connection failed` lines".
//!
//! **Asserting that the error text is present proves nothing — it is present
//! either way.** The assertions that discriminate are the *line count* of the
//! rendered output and the *escaped* spelling of the newline (`\` followed by
//! `n`, two characters). Both are taken over rendered text rather than over
//! fields, because what a forged line lands in is the container log.
//!
//! **`log_safe` is a second property and it needs a second reply.** The escaping
//! comes from recording the value as a bare `&str`; all `log_safe`
//! (`web_login.rs:512`) adds on top is a 256-byte cap. So a run driven only by
//! the short reply above stays green when `log_safe` is dropped from both sites
//! — measured — while a hostile redis answering with a megabyte `-ERR` detail
//! writes a megabyte log line and nothing goes red. The second pair of
//! operations is therefore answered with a reply whose detail runs well past the
//! cap and ends in a canary, and the cap is what those assertions turn on: the
//! canary absent, the truncation marker present.
#![cfg(feature = "web-login-redis")]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hs_utils::web_login::{Session, WebSessionStore};
use hs_utils::web_login_redis::RedisSessionStore;
use tracing_subscriber::prelude::*;

/// A valid uuid, so nothing on the path short-circuits on the shape of the sid.
const SID: &str = "a7f3c1d9-4e62-4b8a-9d15-c0ffee5ed17e";

/// The `-ERR` reply to `SELECT`, carrying a **bare LF** and a payload shaped
/// like a `tracing` line. `err_parser` splits on the first space, so the code is
/// `ERR` and everything after it — newline included — is the detail.
const FORGED: &[u8] =
    b"-ERR select refused\n2026-08-06T00:00:00.000000Z  INFO forged: attacker controlled line\r\n";

/// The marker a forged line would start with, if one were forged.
const FORGED_LINE_START: &str = "2026-08-06T00:00:00.000000Z";

/// `log_safe`'s cap, i.e. `web_login::MAX_LOGGED_LEN`. Not importable — the
/// constant is private — so it is restated here and the reply below is sized
/// against it with room to spare rather than exactly.
const MAX_LOGGED_LEN: usize = 256;

/// The last thing an over-long reply says. It sits past the cap, so it appears
/// in the log only if nothing truncated the value.
const LONG_TAIL_CANARY: &str = "T4ILOFAV3RYLONGREPLY";

/// A `-ERR` whose detail runs well past `MAX_LOGGED_LEN`. Carries the same bare
/// LF as `FORGED`, so this pair asserts the escaping *and* the cap rather than
/// trading one for the other.
fn long_forged() -> Vec<u8> {
    let mut s = String::from("-ERR select refused verbosely\n2026-08-06T00:00:00.000000Z  INFO ");
    s.push_str(&"P".repeat(4 * MAX_LOGGED_LEN));
    s.push_str(LONG_TAIL_CANARY);
    s.push_str("\r\n");
    s.into_bytes()
}

/// The scripted handshake reply: `SELECT` fails with `err`, both
/// `CLIENT SETINFO`s succeed. Order matches `connection_setup_pipeline`, which
/// emits `SELECT` first and `check_connection_setup` reads by index.
fn handshake_reply(err: &[u8]) -> Vec<u8> {
    let mut v = err.to_vec();
    v.extend_from_slice(b"+OK\r\n+OK\r\n");
    v
}

/// `Arc<Mutex<Vec<u8>>>` is not itself a `MakeWriter`; see the sid siblings.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn rendered(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Read until the client's message looks complete, i.e. ends in CRLF. The three
/// handshake commands are pipelined into one write, so one read is enough.
fn read_a_message(sock: &mut TcpStream) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while Instant::now() < deadline {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.ends_with(b"\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
    }
    if std::env::var("STUB_TRACE").is_ok() {
        eprintln!("stub <- {:?}", String::from_utf8_lossy(&buf));
    }
    buf
}

/// Answer one handshake per entry in `replies`, each with the forged `SELECT`
/// failure it names. Every store operation opens a fresh connection, so the Nth
/// operation gets the Nth reply — which is how the short and the long reply are
/// driven from one subscriber.
fn spawn_stub(replies: Vec<Vec<u8>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for reply in replies {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
            read_a_message(&mut sock);
            let _ = sock.write_all(&handshake_reply(&reply));
            let _ = sock.flush();
            // Hold the socket open long enough for the client to consume the
            // reply; dropping it immediately surfaces as a connection reset,
            // whose text the server does not choose.
            std::thread::sleep(Duration::from_millis(150));
        }
    });
    port
}

#[tokio::test]
async fn a_hostile_redis_cannot_forge_a_log_line_through_a_connection_failure() {
    let capture = Capture::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(capture.clone())
                // ERROR-only, so the line count below is an oracle rather than a
                // hostage to whatever mio and hyper log at TRACE — measured, they
                // contribute ten lines to this run. It does not weaken the test:
                // both sites under test are `tracing::error!`, and a forged line
                // is raw bytes *inside* one of those events, so it is captured
                // regardless of the level it pretends to be.
                .with_filter(tracing_subscriber::filter::LevelFilter::ERROR),
        )
        .try_init()
        .expect("this binary installs exactly one subscriber");

    // Four connections: `load`'s `conn()` and `store`'s, twice over — once with
    // the short reply for the escaping, once with the over-long one for the cap.
    // `remove`'s connection failure is silent at this pin and belongs to
    // HIK-241, so it is not driven here — driving it would assert on a line that
    // does not exist yet.
    let port = spawn_stub(vec![
        FORGED.to_vec(),
        FORGED.to_vec(),
        long_forged(),
        long_forged(),
    ]);

    // `/3` is what makes the handshake emit `SELECT`; see the header.
    let store = RedisSessionStore::from_url(
        &format!("redis://127.0.0.1:{port}/3"),
        Duration::from_secs(3600),
    )
    .expect("a plain redis url parses; from_url performs no I/O");

    // Discarded on purpose: each of these is *expected* to fail, and what this
    // test reads is the rendered log line, not the error that came back.
    let _ = store.load(SID).await;
    let _ = store.store(SID, &Session::default()).await;
    // The same two operations again, answered with the over-long reply.
    let _ = store.load(SID).await;
    let _ = store.store(SID, &Session::default()).await;

    let rendered = capture.rendered();

    // FIRST, and fix-invariant: without this the run could prove nothing at all.
    // It is the vehicle control, NOT the property — the error text is present
    // whether it was escaped or not.
    for marker in [
        "web_login redis load: connection failed",
        "web_login redis store: connection failed",
    ] {
        assert!(
            rendered.contains(marker),
            "{marker:?} was never logged, so the stub never drove `conn()` to fail and \
             this run proves nothing.\n----- full captured output -----\n{rendered}"
        );
    }
    for text in ["select refused", "select refused verbosely"] {
        assert!(
            rendered.contains(text),
            "the server's own error text {text:?} never reached the log, so the vehicle did \
             not carry attacker-chosen bytes.\n----- full captured output -----\n{rendered}"
        );
    }

    // THE PROPERTY, oracle 1: the reply chose the bytes, it must not choose the
    // line count. Four operations, four lines.
    let lines: Vec<&str> = rendered.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        4,
        "a `-ERR` reply containing a newline forged {} log line(s) out of 4 operations.\n\
         ----- full captured output -----\n{rendered}",
        lines.len()
    );

    // THE PROPERTY, oracle 2: the newline is present as the two characters `\`
    // and `n`, i.e. the fmt layer escaped it. Written as a runtime `format!` of
    // the two chars rather than a `"\\n"` literal so it cannot be misread as an
    // actual newline by someone skimming.
    let escaped_newline = format!("{}{}", '\\', 'n');
    assert!(
        rendered.contains(&escaped_newline),
        "the newline in the server's reply was not escaped, so it was emitted raw.\n\
         ----- full captured output -----\n{rendered}"
    );

    // Belt and braces, and the one an operator would actually notice: no line
    // may *begin* with the reply's payload.
    assert!(
        !lines.iter().any(|l| l.starts_with(FORGED_LINE_START)),
        "a line in the log stream was written by the redis server, not by this service.\n\
         ----- full captured output -----\n{rendered}"
    );

    // THE SECOND PROPERTY: `log_safe`'s cap. Nothing above is sensitive to it —
    // drop `log_safe` from both sites and every assertion so far stays green,
    // because the escaping comes from the bare `&str`. What the cap stops is a
    // hostile redis choosing the *length* of our log line as well as its bytes.
    assert!(
        !rendered.contains(LONG_TAIL_CANARY),
        "the tail of a {}-byte reply reached the log, so the error text was not capped and a \
         hostile redis chooses how much it writes.\n----- full captured output -----\n{rendered}",
        long_forged().len()
    );
    assert!(
        rendered.contains('…'),
        "no truncation marker, so nothing was capped — check `log_safe` is still applied at \
         both `connection failed` sites.\n----- full captured output -----\n{rendered}"
    );
    // And the cap has to bind on the line that was over it, not merely somewhere
    // in the capture: without this a marker anywhere would satisfy the assertion
    // above. `MAX_LOGGED_LEN` bounds the field, and the rest of the line (the
    // timestamp, level and the other two fields) is fixed overhead of ~200 B.
    let longest = lines.iter().map(|l| l.len()).max().unwrap_or_default();
    assert!(
        longest < 2 * MAX_LOGGED_LEN,
        "the longest rendered line is {longest} B against a {MAX_LOGGED_LEN} B field cap, so \
         the reply's length still reached the log.\n----- full captured output -----\n{rendered}"
    );
}
