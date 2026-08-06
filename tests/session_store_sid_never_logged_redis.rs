//! The `hs_session` id must never reach the log stream from the redis session
//! store. The postgres sibling's header states the threat model and why this is
//! its own binary with its own global subscriber; read it first.
//!
//! **The driver is a scripted RESP stub, not a closed port, and that is the
//! whole point.** Pointing the store at a port nothing is listening on reaches
//! only the two `connection failed` sites, which carry no sid and are correct as
//! they are — a test that would prove nothing. A stub that completes the
//! handshake and *then* fails reaches the four sid-bearing sites instead:
//! `load` (backend error), `load` (malformed payload), `store` and `remove`.
//!
//! The handshake is short because the URL is deliberately plain. At the pinned
//! redis 0.27.6, `connection_setup_pipeline` (`connection.rs:972`) emits AUTH
//! only when a password is set, SELECT only when `db != 0`, and HELLO only for
//! RESP3 — so a bare `redis://127.0.0.1:port` sends exactly the two
//! `CLIENT SETINFO` commands, which are pipelined and whose two replies are read
//! together. Hence `+OK\r\n+OK\r\n`. If that ever stops being true this stub
//! will hang rather than lie, and `STUB_TRACE=1` prints the bytes it received so
//! the script can be corrected.
//!
//! One of the store's five `error!` sites — `store`'s `serialize failed` — is
//! not reachable offline (`serde_json` will not fail on a `Session`), and is
//! covered by `session_store_sid_source_lint.rs` only.
#![cfg(feature = "web-login-redis")]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hs_utils::web_login::{Session, WebSessionStore};
use hs_utils::web_login_redis::RedisSessionStore;
use tracing_subscriber::prelude::*;

/// See the postgres sibling: a valid uuid so the real path runs, distinctive so
/// the substring sweep means something.
const SID: &str = "a7f3c1d9-4e62-4b8a-9d15-c0ffee5ed17e";

/// Sweep width; see the postgres sibling for why it is 6 and not 8.
const WINDOW: usize = 6;

/// The two `CLIENT SETINFO` replies redis-rs reads before handing the caller a
/// connection.
const HANDSHAKE_REPLY: &[u8] = b"+OK\r\n+OK\r\n";

/// A backend failure that is *not* a connection failure, so it lands on the
/// sid-bearing branch rather than on `conn()`'s.
const BACKEND_ERROR: &[u8] = b"-ERR simulated backend failure\r\n";

/// A bulk string that is valid JSON but not a valid `Session` (`user_id` must be
/// a string), which is what `malformed payload` means. An unknown-key document
/// would NOT do: every field on `Session` is `#[serde(default)]` and unknown
/// keys are ignored, so `{"a":1}` deserialises happily.
const MALFORMED_PAYLOAD: &[u8] = b"$14\r\n{\"user_id\":42}\r\n";

/// `Arc<Mutex<Vec<u8>>>` is not itself a `MakeWriter`; see the postgres sibling.
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

/// Fail if any [`WINDOW`]-character window of the sentinel sid — hyphenated or
/// not, case-insensitively — appears in the rendered log. A short window because
/// a partial disclosure is a disclosure; see the postgres sibling.
fn assert_no_sid_fragment(rendered: &str) {
    let haystack = rendered.to_ascii_lowercase();
    let forms = [
        SID.to_ascii_lowercase(),
        SID.replace('-', "").to_ascii_lowercase(),
    ];
    for form in &forms {
        let chars: Vec<char> = form.chars().collect();
        for window in chars.windows(WINDOW) {
            let needle: String = window.iter().collect();
            if haystack.contains(&needle) {
                let line = rendered
                    .lines()
                    .find(|l| l.to_ascii_lowercase().contains(&needle))
                    .unwrap_or("<no single line matched — the leak spans lines>");
                panic!(
                    "the session id leaked into the log stream: the {WINDOW}-character window \
                     {needle:?} of the sentinel sid is present.\n\
                     offending line: {line}\n\
                     ----- full captured output -----\n{rendered}\
                     --------------------------------"
                );
            }
        }
    }
}

/// Read until `buf` holds a complete-looking client message, i.e. one ending in
/// CRLF. Framing-agnostic on purpose: the stub only has to know *when* to reply,
/// not how to parse RESP, and loopback may still split a write.
fn read_a_message(sock: &mut TcpStream, what: &str) -> Vec<u8> {
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
        eprintln!("stub <- {what}: {:?}", String::from_utf8_lossy(&buf));
    }
    buf
}

/// Serve one scripted reply per connection, in order. Every store operation
/// opens a fresh connection (`RedisSessionStore::conn` does so by design), so
/// the Nth connection is the Nth operation.
fn spawn_stub(script: Vec<&'static [u8]>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for reply in script {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
            read_a_message(&mut sock, "handshake");
            if sock.write_all(HANDSHAKE_REPLY).is_err() {
                continue;
            }
            read_a_message(&mut sock, "command");
            let _ = sock.write_all(reply);
            let _ = sock.flush();
            // Hold the socket open long enough for the client to consume the
            // reply; dropping it immediately can surface as a connection reset,
            // which lands on the wrong (sid-free) branch.
            std::thread::sleep(Duration::from_millis(150));
        }
    });
    port
}

#[tokio::test]
async fn the_redis_store_never_writes_the_session_id_to_the_log() {
    let capture = Capture::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(capture.clone()),
        )
        .try_init()
        .expect("this binary installs exactly one subscriber");

    // One connection per operation, in this order.
    let port = spawn_stub(vec![
        MALFORMED_PAYLOAD, // load  -> malformed payload
        BACKEND_ERROR,     // load  -> backend error
        BACKEND_ERROR,     // store -> backend error
        BACKEND_ERROR,     // remove -> backend error
    ]);

    let store = RedisSessionStore::from_url(
        &format!("redis://127.0.0.1:{port}"),
        Duration::from_secs(3600),
    )
    .expect("a plain redis url parses; from_url performs no I/O");

    store.load(SID).await;
    store.load(SID).await;
    store.store(SID, &Session::default()).await;
    store.remove(SID).await;

    let rendered = capture.rendered();

    // FIRST, and deliberately fix-invariant. A stub that never got as far as
    // answering a command would otherwise give a clean, and entirely vacuous,
    // pass on the sweep below. It also catches the failure mode this driver is
    // most likely to have: the handshake script being wrong, in which case the
    // store logs `connection failed` — a line with no sid on it.
    for marker in [
        "web_login redis load",
        "web_login redis store",
        "web_login redis remove",
    ] {
        assert!(
            rendered.contains(marker),
            "{marker:?} was never logged, so this run proves nothing about a leak.\n\
             ----- full captured output -----\n{rendered}"
        );
    }
    assert!(
        !rendered.contains("connection failed"),
        "the stub failed to complete the handshake, so these lines are the sid-free \
         connection branch and the sid-bearing ones were never reached.\n\
         ----- full captured output -----\n{rendered}"
    );

    assert_no_sid_fragment(&rendered);

    // The replacement contract. The `key` is NOT an acceptable stand-in for the
    // sid: `RedisSessionStore::key` is `"weblogin:sess:" + sid`, so logging it
    // discloses the whole credential behind fourteen fixed characters. The sweep
    // above already catches that, which is why the trap is worth naming here.
    assert!(
        rendered.contains("session.store=redis"),
        "the failure line must name the store it came from.\n{rendered}"
    );
    for op in ["session.op=load", "session.op=store", "session.op=remove"] {
        assert!(
            rendered.contains(op),
            "{op:?} missing — the operation must be a field, not prose.\n{rendered}"
        );
    }
    assert!(
        rendered.contains("error.message="),
        "dropping the sid must not drop the cause with it.\n{rendered}"
    );
    assert!(
        rendered.contains("malformed payload"),
        "the malformed-payload branch was never reached, so one of the four \
         sid-bearing sites is untested here.\n{rendered}"
    );
}
