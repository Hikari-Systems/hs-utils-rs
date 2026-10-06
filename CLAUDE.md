# CLAUDE.md — hs-utils-rs

Guidance for AI assistants working on this codebase.

---

## What this crate is

`hs-utils` is the shared Rust utility crate for all Hikari Systems backend services. It is referenced via `git + tag` from each service's `Cargo.toml` — there is no workspace. Changes here affect every service that consumes it.

Data services currently using this crate:
- `user-data-service-rs`
- `conversation-data-service-rs`
- `oauth2-data-service-rs`
- `secret-service-rs`
- `task-queue-service-rs`
- `image-service-rs`

**Controllers, which the list above does not cover.** They are the consumers of
`web_login`, `session_store` and `controller` — the modules the data services do
not touch — so a breaking change there reaches these repos and no others. The
list was six data services and none of these when v0.32.0 broke all four:
- `botsafely-controller`
- `5drive-demo-controller`
- `slackbot-controller`
- `graph-d3-mcpui`

---

## Codebase map

```
src/
  lib.rs           — module declarations
  config.rs        — config loading helpers: prepare_config, apply_env_overrides,
                     deep_merge, resolve_secrets, normalize_to_strings,
                     and all deser_*_or_str deserializers
  db.rs            — DbConfig, DbSslConfig structs + build_pool()
  healthcheck.rs   — run() and check_subcommand()
  logging.rs       — init()
  middleware.rs    — timing(), ApiKey middleware, forwarded_for(), ForwardedInfo
  server.rs        — run() wrapping HttpServer
```

---

## Design principles

**Invisible by default.** Features like secret resolution (`[SECRET]:/path`) and type normalisation are baked into `prepare_config` so service code never needs to call them explicitly. If you add a new config source (e.g. AWS Parameter Store), add it inside `prepare_config`, not as a new function services must call.

**Extend, don't duplicate.** If a service needs a variant of an existing function, add the variant here rather than implementing it locally. The goal is zero duplicated infrastructure code across services.

**No breaking changes without a plan.** Every repo listed above consumes this crate. Removing or renaming public items requires updating each affected consumer in the same PR/session. Adding new public items is always safe.

There is no CHANGELOG in this repo, so "the plan" cannot live in one. It goes in the section below — a short note per breaking release naming the signatures and, more importantly, naming the ones the compiler will **not** make a consumer look at. That distinction is what a bumper needs and cannot get from `cargo build`.

---

## Migrating consumers

### v0.32.1 — the post-login redirect is sanitised (HIK-272)

No API change — nothing is added, removed or re-typed, so this is a patch and a consumer bump is a one-line tag change. What changes is **behaviour**, at two points a consumer never calls directly: `gate` sanitises the request target before storing it as the `state → destination` map, and `callback` sanitises again before emitting the `Location`. Both were previously verbatim, which made the completed-login redirect an open redirect against a victim who is *necessarily* authenticated by the time it fires.

**The guard is unconditional.** There is no config key and no feature flag for it, deliberately: either would be a switch that turns an open-redirect guard off. It cannot be opted out of, so read the set below rather than planning around it.

**It does NOT supersede a consumer's own redirect guard, and deleting one as redundant would reopen a fixed bug.** This guard covers two inputs and only those: the request target `gate` stores, and the row `callback` reads back. `botsafely-controller`'s `routes::auth::origin_relative_dest` covers a different input — the caller-supplied `dest_uri` query parameter on `/api/auth` and `/api/logout`, which never passes through either of this crate's two sites. The rule is the same rule; the inputs are disjoint, so both are needed. That local copy is HIK-242 and it stays.

**A refused destination becomes `/`, never a 4xx.** At the callback a 4xx would throw away an authentication that already succeeded — the code is spent and the session rotated — and at the gate it would let this library refuse a page of yours it merely failed to parse.

**The accepted set moved in BOTH directions, so "it only got stricter" is false** and a consumer reasoning from that will mispredict it:

| request target / stored destination | before | now |
|---|---|---|
| `/dash?tab=runs`, `/api/auth`, `/`, `/x?a=b#f` | forwarded | **unchanged, byte for byte** |
| `/../../etc/passwd` | forwarded verbatim | **rewritten** to `/etc/passwd` |
| `*` | forwarded verbatim | **rewritten** to `/*` |
| `//evil.example.com/x`, `/\evil.example.com/x` | forwarded — off-origin | **`/`** |
| `///evil.example.com/x`, `//\evil.example.com/x` | forwarded | **`/`** |
| `/..//x`, `/.//x`, `/a/..//x` and the rest of the dot-segment family | forwarded | **`/`** |
| a target containing CR or LF | a 303 with **no `Location` header at all** — `see_other` silently drops a header value it cannot build | **`/`** |

The rewrites are harmless — a browser resolves dot segments the same way and the origin is unchanged — but they are not what the old code did.

**One live consumer shape is affected.** `botsafely-controller`'s UI sends `${window.location.pathname}${search}`, so a user who landed on `https://app.example.com//dashboard` sends a `pathname` beginning with a doubled slash. That is genuinely protocol-relative and nothing at this layer can tell it from an attack, so it now lands on `/` after login instead of being forwarded. Correct, but a real request shape rather than a hypothetical one — expect it in a support ticket rather than in a pen test.

**Telemetry a consumer may want to alert on.** One `warn!` per refusal, message `web_login: post-login redirect destination refused`, carrying `auth.redirect.outcome`, `auth.redirect.reason` (`missing` | `control_character` | `unparseable` | `not_origin_relative` | `escapes_root`), `auth.redirect.site` (`gate` | `callback`), `auth.redirect.dest` and, at the callback only, `user.id`. Nothing at all on the accept path. `auth.redirect.refused` and `auth.redirect.reason` are also recorded on the existing `auth.gate` / `auth.login` spans; at `log.level: debug` those render in the span's brace prefix, so `auth.redirect.reason` appears on the line twice. `user.id` renders twice on the callback line for the same reason — `callback` records it on the `auth.login` span before it reaches the redirect — which is pre-existing behaviour for that handler's other `warn!`s, not new here.

**`auth.redirect.dest` diverges from this crate's own redaction policy, and an operator alerting on it should know before switching it on.** It carries the destination **raw and pre-sanitisation, query string included**, capped at 256 bytes — while `otel::redact_query` in this same crate deliberately records which query parameters were *present* and never their values, because spans land in a third-party store with long retention. So a refused destination that happens to be an absolute return URL carrying a token gets that token's first 256 bytes onto a log line. The divergence is narrow and deliberate: only refusals are logged, and a refusal that named nothing would be undiagnosable. It is a trade, not an oversight.

`escapes_root` is a misnomer and is kept only because `botsafely-controller` already publishes that vocabulary: it never fires for an input that escapes the root, and what it fires for in practice is the protocol-relative form the reconstruction can manufacture out of a dot-segment input. (It also catches a cannot-be-a-base URL whose origin aliases the sentinel, which nothing reaches from either call site.)

**Also in v0.32.1: `JwtClaims::scopes()` reads Hydra's `scp`.** Ory Hydra puts a JWT access token's scopes in `scp` (an array), and `scopes()` read only the RFC 9068 `scope` string, so `AuthExtension.scopes` was empty for every Hydra token. It now merges `scope` with `scp` (array or string), without duplicates. Nothing failed open on the old behaviour (an empty list grants nothing), but an MCP server that gates tools on `mcp:read` / `mcp:write` saw none, as woodhouse-controller did. No signature change; a server that ignores scopes is unaffected. HIK-274 (the sid-disclosure lint now scans `src/web_login*`) is in this release too and changes no runtime behaviour.

### v0.32.0 — `WebSessionStore` is fallible (HIK-241)

All three trait methods changed. Any type implementing `WebSessionStore` outside this crate must change with them:

```rust
async fn load(&self, sid: &str)                     -> anyhow::Result<Option<Session>>;  // was Option<Session>
async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()>;               // was ()
async fn remove(&self, sid: &str)                   -> anyhow::Result<()>;               // was ()
```

`WebLogin::end_session` follows: `Option<String>` → `anyhow::Result<Option<String>>`.

**`load` announces itself; `remove` does not, and that asymmetry is the whole point of this note.** A `store.load(&sid).await?` inside an `Option`-returning function stops compiling, so every call site is a build error you cannot miss. A bare `store.remove(&sid).await;` statement still compiles — it is only `unused_must_use`, a **warning**, and none of the four controller repos sets `deny(warnings)` or a `RUSTFLAGS` that would promote it. So after the bump a logout can keep answering "you are logged out" on a delete that failed, in a build whose only complaint is a line in a log nobody reads. That is the defect this release exists to remove, surviving into the first consumer that pins the fix.

Grep each consumer for `.remove(` and `.store(` on a session store and rule on every hit. `botsafely-controller/src/routes/auth.rs` is the known one: it hand-rolls logout rather than calling `end_session`, so it owns the verdict itself.

Posture to copy when deciding what an error costs, taken from this crate's own call sites: fail **open** where an unreadable row and an absent row deserve the same answer; fail **loud** where a write is what makes the next request work. The rule is generative and that is the point — the parenthetical list that used to sit here was the same three-site enumeration the `WebSessionStore` doc comment had just replaced for being short by `end_session`, reproduced two files away where nothing would catch it going stale again. For which sites take which, read the trait, not this. Do not read "the gate fails open" as "an outage keeps the site serving" — see `web_login::gate`.

---

## Module details

### `config.rs`

**Standard service `load()` pattern:**
```rust
prepare_config(&mut root);      // [SECRET]: resolution + normalise to strings
apply_env_overrides(&mut root); // KEY__subkey=val env var overrides
serde_json::from_value(root)
```

`prepare_config` calls `resolve_secrets` then `normalize_to_strings` internally. Services that use a `/sandbox/config.json` overlay call `deep_merge` before `prepare_config`:
```rust
if let Ok(overlay_text) = std::fs::read_to_string(&overlay_path) {
    if let Ok(overlay) = serde_json::from_str::<Value>(&overlay_text) {
        deep_merge(&mut root, overlay);
    }
}
prepare_config(&mut root);
apply_env_overrides(&mut root);
```

**Deserializers** are named `deser_{type}_or_str` and `deser_opt_{type}_or_str`. They accept both native JSON types and their string equivalents. All are used with `#[serde(deserialize_with = "...")]`. Do not use plain `serde(rename)` + string fields for numeric/bool config values — use the typed deserializers so structs carry the right Rust types.

**`normalize_to_strings`** converts all bool/number leaves to `Value::String` before deserialisation. This is why `deser_*_or_str` always encounters strings at runtime even if the JSON file had native types — the deserializers handle both because services may bypass normalisation in tests.

### `db.rs`

`DbConfig` and `DbSslConfig` both derive `Default` (needed for services that use `#[serde(default)]` on their `AppConfig.db` field, e.g. image-service where the db section is optional).

`build_pool` defaults: `minpool=0`, `maxpool=3`. SSL defaults: if `ssl` is absent or `enabled` is absent/false, `PgSslMode::Prefer` is used (not `Disable`) — this allows unencrypted connections to local dev databases while not failing if the server offers TLS.

Port is stored as `String` in `DbConfig` because `prepare_config` normalises everything to strings. `build_pool` parses it at runtime and defaults to `5432` if empty.

### `healthcheck.rs`

`run()` uses only stdlib — no tokio, no reqwest. This is intentional: it must work before the async runtime is started. Do not add async variants here; use a dedicated health endpoint in the service if you need async checks.

`check_subcommand` calls `process::exit` directly. This is correct and intentional — it must terminate the process without starting the server.

### `server.rs`

`server::run` mirrors `HttpServer::new`'s generic bounds exactly. The function is intentionally thin — its value is as a hook point for future cross-cutting concerns (SNS lifecycle notifications, graceful shutdown handling), not as an abstraction over actix-web.

The bounds require `actix-service` and `actix-http` as direct dependencies because `IntoServiceFactory` and the raw `Request` type are not re-exported through `actix_web::dev` in actix-web 4.

### `middleware.rs`

`ApiKey` uses `EitherBody<B>` to return a `401` response without changing the response body type. The `forward_ready!` macro from actix-web delegates `poll_ready` to the inner service.

`forwarded_for` clones `connection_info()` before accessing headers to avoid a temporary lifetime issue with `req.connection_info().scheme()`.

---

## Versioning workflow

1. Implement and `cargo build` locally
2. Bump `version` in `Cargo.toml`
3. `git commit`, `git tag vX.Y.Z`, `git push origin main`, `git push origin vX.Y.Z`
4. Update `tag = "vX.Y.Z"` in each service's `Cargo.toml`
5. Run `cargo build` in each service to refresh `Cargo.lock`
6. Commit and push each service

**Never use a path dependency** (`path = "../hs-utils-rs"`) in a service. Always use `git + tag`. This ensures the service's `Cargo.lock` pins to a specific commit and Docker builds are reproducible.

**Never update a service's tag before pushing it to GitHub.** `cargo build` fetches from the remote; if the tag doesn't exist yet, the build fails.

---

## Common gotchas

- Adding a new public function is a minor version bump (0.2.x). Removing or changing a public function is a breaking change — coordinate with every consumer listed at the top of this file, and leave a note under "Migrating consumers".
- `normalize_to_strings` converts numbers to strings, so `DbConfig.port` is always a string at deserialisation time. Don't add `port: u16` fields to `DbConfig` — keep them as `String` and parse in `build_pool`.
- The `[SECRET]:` prefix must appear in the raw config JSON (before `prepare_config` runs). A secret reference injected via an env var override will not be resolved because `apply_env_overrides` runs after `prepare_config`.
- `tracing::warn!` in `resolve_secrets` does not require the tracing subscriber to be initialised — messages before `logging::init` are silently dropped, which is correct behaviour.
