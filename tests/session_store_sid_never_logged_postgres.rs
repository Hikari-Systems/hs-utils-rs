//! The `hs_session` id must never reach the log stream from the Postgres
//! session store.
//!
//! `hs_session` is an **unsigned bearer credential** — possession is
//! authentication — and these are the store's *error* paths, so they fire for
//! every in-flight authenticated request at once during a database outage.
//! Before HIK-236 each one interpolated the raw sid into its message, so an RDS
//! blip wrote every logged-in user's live session id into the container log.
//!
//! This lives in `tests/` and installs a **global** subscriber, for the reason
//! `tests/gate_span.rs` documents at length: `tracing`'s callsite interest cache
//! is process-global while `subscriber::set_default` is thread-local, so a leak
//! test sharing a binary with anything else that touches these callsites can
//! pass against broken code. Its own binary, its own subscriber, nothing else in
//! it.
//!
//! What is captured is the **rendered** output of the same fmt layer
//! `otel::init`'s disabled branch installs — not a field visitor. The property
//! under test is "what lands in the container log", and a visitor would miss a
//! leak arriving through the fmt layer's enclosing-span prefix rather than
//! through the event's own fields.
//!
//! Three of the store's five `error!` sites are reachable offline (`load`,
//! `store`, `remove` — all three of the query-failure paths). The other two
//! (`malformed payload`, which needs a real row, and `serialize failed`, which
//! `serde_json` will not do to a `Session`) are covered by
//! `session_store_sid_source_lint.rs` only. Do not read this file as covering
//! all five.
#![cfg(feature = "web-login-postgres")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hs_utils::web_login::{Session, WebSessionStore};
use hs_utils::web_login_postgres::PgSessionStore;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::prelude::*;

/// A valid uuid, so it drives the real code path, but a distinctive one so the
/// substring sweep below means something. Deliberately NOT a short label: a
/// short canary makes truncation undetectable, because every window long enough
/// to matter is the whole string.
const SID: &str = "a7f3c1d9-4e62-4b8a-9d15-c0ffee5ed17e";

/// Sweep width, in characters.
///
/// **Six, not eight (HIK-246).** The 8 it replaces was itself defeatable: a
/// 7-character correlator passed the sweep *and* the old source lint, which is
/// one of the four evasions that ticket measured. Six narrows that gap — but do
/// not let the number carry the argument. Any window can be undercut by one, and
/// the mechanism that actually stops a correlator is the identifier allow-list
/// in `session_store_sid_source_lint.rs`; this is a backstop that catches the
/// same thing in the **rendered output**, which no source scanner can see.
///
/// Not lower than 6: at 4 the hex alphabet starts colliding with unrelated text
/// in the captured stream, and a sweep that fails for a coincidence is a sweep
/// somebody deletes.
const WINDOW: usize = 6;

/// `Arc<Mutex<Vec<u8>>>` is not itself a `MakeWriter` (tracing-subscriber's
/// `Arc<W>` impl wants `&W: Write`, which `Mutex<Vec<u8>>` is not), so the
/// shared buffer needs this one-line newtype to be usable as one.
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
/// not, case-insensitively — appears anywhere in the rendered log.
///
/// **A window, not the whole value, because a partial disclosure is a
/// disclosure.** This is what makes "log the first few chars as a correlator"
/// *fail* rather than quietly pass. It cannot detect a hash, and does not claim
/// to: a digest shares no substring with its input.
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

#[tokio::test]
async fn the_postgres_store_never_writes_the_session_id_to_the_log() {
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

    // `connect_lazy` performs no I/O, so the pool builds against a port nothing
    // is listening on and every query then fails. The short `acquire_timeout` is
    // load-bearing: sqlx's default is 30s and it retries a refused connect for
    // the whole window, which would make this test a two-minute stall.
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(250))
        .connect_lazy("postgres://u:p@127.0.0.1:1/db")
        .expect("a lazy pool does not dial, so this cannot fail on connectivity");
    let store = PgSessionStore::from_pool(pool);

    // **Asserted, not discarded.** What this file goes on to read is the log line
    // each failure wrote, but the *return* is HIK-241's own subject and it is the
    // arm the fleet runs. Measured: replace these three error returns in
    // `web_login_postgres.rs` with `Ok(None)` / `Ok(())` and this binary stayed
    // green without them, so the header's "a failure is logged here **and
    // returned**" rested on nothing. Three lines rather than new harness — the
    // failing fixture is the lazy pool already in hand.
    assert!(
        store.load(SID).await.is_err(),
        "a query that could not be run must reach the caller: an unreadable row \
         and an absent one are different facts, and only the caller can price them"
    );
    assert!(
        store.store(SID, &Session::default()).await.is_err(),
        "a write that did not land must reach the caller — `callback` removes the \
         old row on the strength of this one"
    );
    assert!(
        store.remove(SID).await.is_err(),
        "a delete that did not land must reach the caller — logout answers \"you \
         are logged out\" on the strength of this one"
    );

    let rendered = capture.rendered();

    // FIRST, and deliberately fix-invariant: without it, a run in which the
    // store was never reached is indistinguishable from one that is clean, and
    // a test that passes because nothing was logged is a false green.
    for marker in [
        "web_login pg load",
        "web_login pg store",
        "web_login pg remove",
    ] {
        assert!(
            rendered.contains(marker),
            "{marker:?} was never logged, so this run proves nothing about a leak.\n\
             ----- full captured output -----\n{rendered}"
        );
    }

    assert_no_sid_fragment(&rendered);

    // The replacement contract. The sid is not swapped for a redacted stand-in —
    // it is gone — so what a reader gets instead is which store and which
    // operation failed, structured rather than embedded in prose.
    assert!(
        rendered.contains("session.store=postgres"),
        "the failure line must name the store it came from.\n{rendered}"
    );
    for op in ["session.op=load", "session.op=store", "session.op=remove"] {
        assert!(
            rendered.contains(op),
            "{op:?} missing — the operation must be a field, not prose.\n{rendered}"
        );
    }
    assert!(
        rendered.contains("session.table=web_sessions"),
        "the table is the other half of 'which store' when services share a database.\n{rendered}"
    );
    assert!(
        rendered.contains("error.message="),
        "dropping the sid must not drop the cause with it.\n{rendered}"
    );
}
