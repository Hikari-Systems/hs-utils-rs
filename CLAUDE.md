# CLAUDE.md — hs-utils-rs

Guidance for AI assistants working on this codebase.

---

## What this crate is

`hs-utils` is a shared Rust utility crate for backend services: config loading, database pools, HTTP server
startup, logging, healthchecks, actix-web middleware, and (behind features) browser login, session stores,
locks, pub/sub and an MCP resource server. Consumers reference it via `git + tag` from their own `Cargo.toml`;
there is no workspace. Changes here affect every consumer.

Two broad kinds of consumer:
- **Data services** use `config`, `db`, `healthcheck`, `logging`, `middleware` and `server`.
- **Controllers** additionally use `web_login`, `session_store` and `controller`, so a breaking change in those
  modules reaches only them.

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
  session_store.rs — build_session_store(): the session store, plus locks() / event_bus() on its database
  lock.rs          — LockManager / LockGuard: named locks (Postgres advisory, or in-process)
```

---

## Design principles

**Invisible by default.** Features like secret resolution (`[SECRET]:/path`) and type normalisation are baked into `prepare_config` so service code never needs to call them explicitly. If you add a new config source (e.g. AWS Parameter Store), add it inside `prepare_config`, not as a new function services must call.

**Extend, don't duplicate.** If a service needs a variant of an existing function, add the variant here rather than implementing it locally. The goal is zero duplicated infrastructure code across services.

**No breaking changes without a plan.** Removing or renaming public items requires updating each affected consumer. Adding new public items is always safe.

There is no CHANGELOG in this repo, so "the plan" goes in the section below — a short note per breaking release naming the signatures and, more importantly, naming the ones the compiler will **not** make a consumer look at. That distinction is what a bumper needs and cannot get from `cargo build`.

---

## Migrating consumers

### v0.36.0 — jsonwebtoken 10, rmcp 2

**Breaking** for a consumer that names rmcp itself: move its own `rmcp` requirement to `2.1`. `model::Content` is now
`ContentBlock` (`RawContent` and `.raw` are gone; use `as_text()`), `Annotated` and `RawResource` are gone (`Resource::new`),
and `ProgressNotificationParam` is built with `new` / `with_total` / `with_message`.

### v0.35.0 — `session.requiredAtBoot`: a session store that isn't essential at boot

**Not breaking** for a consumer of `build_session_store`: unset means `true`, which is what it already did. New:
`session.requiredAtBoot` (`session__requiredAtBoot`) and `db::build_lazy_pool`.

- `true` or unset: a Postgres store that can't connect is a startup error.
- `false`, for a service whose login isn't essential: it starts regardless, connects on demand, and creates its table
  in the background, retrying (backing off to once a minute) until the table is usable; a pre-provisioned one it can
  read counts. It never falls back to memory, so session requests fail until then. With no Postgres configured it
  never connects or retries. A changed password still needs a restart: the pool holds what it was given.

**The compiler will not tell you this:** a consumer with its own hand-rolled web session store builder ignores the key
and may still swallow a connection failure into `None`. Move it to `build_session_store`. Moving makes a failed
connection stop that service, so set `session__requiredAtBoot: "false"` if its login isn't essential. Locks and event
buses from a `false` store share the lazy pool, so they too fail until the database answers.

### v0.34.0 — the session pool is private; `SessionSetup::locks()` and `::event_bus()` instead

**Breaking:** `SessionSetup::pg_pool` is gone. Nothing outside this crate gets the session store's pool or redis
connection any more; it gets what is built on them, on the store's own backend:

- `setup.locks() -> Option<lock::LockManager>` (feature `lock`): named locks for short critical sections.
  `manager.acquire(name, wait).await -> Result<LockGuard, LockError>` (`Busy` after `wait`), then
  `guard.release().await`; dropping a guard releases too.
  - `lock-postgres`, Postgres store: session-level advisory locks (`pg_try_advisory_lock`, key
    `hashtextextended('hs_utils.lock:' || name, 0)`) on a connection held for the guard's life. A dropped
    guard closes its connection, so the server frees the lock; so does a dead replica's.
  - `lock-redis`, redis store: `SET hs_utils:lock:<name> <token> NX PX <lease>`, released only while the key
    still holds the guard's token. A **lease**: a dead holder frees it after `with_lease` (default 60 s), and a
    holder stalled past it loses it while still running, so size the lease above the longest section.
  - Memory store: in-process (`is_shared() == false`).
  - Any store whose backend feature is off: `None`, never a local lock posing as shared.
- `setup.event_bus::<E>(channel, capacity) -> Option<Arc<dyn pubsub::EventBus<E>>>` (feature `pubsub`):
  a `PgEventBus` (`LISTEN/NOTIFY`) for Postgres, a `RedisEventBus` (`PUBLISH/SUBSCRIBE`, feature
  `pubsub-redis`) for redis, an `InMemoryEventBus` for memory, else `None`. Call it once per channel (each call
  spawns that channel's listener task).

New features: `lock`, `lock-postgres` (implies `web-login-postgres`), `lock-redis` (implies `web-login-redis`),
`pubsub-redis` (implies `pubsub` and `web-login-redis`). `pubsub` itself is unchanged.

The compiler finds every consumer that read `pg_pool`. A consumer that needs the bus calls `setup.event_bus(…)`
where it used to pass the pool to `PgEventBus::new` — the same bus, on the same pool. `RedisSessionStore` now
resolves a Sentinel master with `Sentinel::async_master_for` per operation (what `SentinelClient` did internally),
so the lock and bus can share its connection; no behaviour change.

### v0.33.0 — a resource (and `aud`) per path for MCP servers with sub-resources

New, nothing changed: `apply_mcp_auth`, `auth_middleware` and `JwtVerifier::verify` answer exactly as before (a
golden test pins their 401 and metadata). A server with resources under its URL (e.g. `/mcp/o/{orgId}`) calls
`apply_mcp_auth_with(cfg, stores, resolver, accept)` instead and layers `auth_middleware_per_resource` with the
returned `ResourceAuthState`. `accept(rest)` decides which `{path}/{rest}` exist (raw path, never percent-decoded);
it drives both the 404s and `/.well-known/oauth-protected-resource{path}/{rest}`. Per path, the token's `aud` must
contain that resource byte for byte and no other value equal to `expected_audience` or under it at a `/`, so a token
with two of the server's audiences is refused everywhere. Nothing is normalised: Hydra copies `..`, `%2e%2e`, a
trailing `/`, `?` and `#` into `aud` verbatim. The middleware must see the full path (layer it outside any `nest`),
and the resource it verified is in the `VerifiedResource` extension.

### v0.32.4 — `web_login::account_redirect` for an app's "My account" link

New, nothing changed: `account_redirect(settings_url, headers, dest)` answers an app's `GET /api/account?dest_uri=`
with a 303 to the login host's settings page carrying `return_to=<app origin><sanitised dest>`. `dest` goes through
`safe_dest` (refusals log with `auth.redirect.site=account` and fall to `/`). An empty `settings_url` is a 404, a
non-URL a 500. Wire it to an `auth.accountSettingsUrl` config value and link the app's user menu to
`/api/account?dest_uri=<current path>`.

### v0.32.3 — the authorize URL carries the return page (`hs_return_to`)

`web_login`'s gate adds `hs_return_to=<this app's origin><the sanitised page>` to the IdP authorize URL. The IdP
ignores it; a login UI may read it off Hydra's login request to offer a "Back to <app>" link, but should only do so
when its origin matches one of the client's registered redirect URIs. It is the value already stored for the
callback (`safe_dest`), so nothing unsanitised leaves the app. No signature change: bump the tag.

### v0.32.2 — the advertised resource metadata URL is path-inserted

A 401's `WWW-Authenticate` now names the path-inserted metadata URL, as RFC 9728 §3.1 says
(`https://h/.well-known/oauth-protected-resource/mcp`, from `metadata::prm_url`), rather than one under the
resource path (which sat behind the auth layer itself). `metadata::router` also serves that path when the
resource's path is not `/mcp`. No signature change: bump the tag.

### v0.32.1 — the post-login redirect is sanitised

No API change: a consumer bump is a one-line tag change. `gate` sanitises the request target before storing it as
the `state → destination` map, and `callback` sanitises again before emitting the `Location`. The guard is
unconditional (no config key or feature flag turns it off). A refused destination becomes `/`, never a 4xx.

It covers only those two inputs. A consumer that accepts its own caller-supplied destination (e.g. a `dest_uri`
query parameter on its own login/logout routes) still needs its own origin-relative check; don't delete one as
redundant.

| request target / stored destination | now |
|---|---|
| `/dash?tab=runs`, `/api/auth`, `/`, `/x?a=b#f` | unchanged |
| `/../../etc/passwd` | rewritten to `/etc/passwd` |
| `*` | rewritten to `/*` |
| `//evil.example.com/x`, `/\evil.example.com/x`, `///…`, `//\…` | `/` |
| `/..//x`, `/.//x`, `/a/..//x` and similar dot-segment forms | `/` |
| a target containing CR or LF | `/` |

Telemetry: one `warn!` per refusal, `web_login: post-login redirect destination refused`, with
`auth.redirect.outcome`, `auth.redirect.reason` (`missing` | `control_character` | `unparseable` |
`not_origin_relative` | `escapes_root`), `auth.redirect.site` (`gate` | `callback`), `auth.redirect.dest` (raw,
capped at 256 bytes — note it can include query values, unlike `otel::redact_query`) and, at the callback,
`user.id`.

Also: `JwtClaims::scopes()` now merges RFC 9068 `scope` with Hydra's `scp` (array or string), without duplicates.

### v0.32.0 — `WebSessionStore` is fallible

All three trait methods changed. Any type implementing `WebSessionStore` outside this crate must change with them:

```rust
async fn load(&self, sid: &str)                     -> anyhow::Result<Option<Session>>;  // was Option<Session>
async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()>;               // was ()
async fn remove(&self, sid: &str)                   -> anyhow::Result<()>;               // was ()
```

`WebLogin::end_session` follows: `Option<String>` → `anyhow::Result<Option<String>>`.

**`load` announces itself; `remove` does not.** A `store.load(&sid).await?` inside an `Option`-returning function
stops compiling. A bare `store.remove(&sid).await;` still compiles — it is only an `unused_must_use` warning — so a
logout can keep answering "you are logged out" on a delete that failed. Grep each consumer for `.remove(` and
`.store(` on a session store and rule on every hit, especially hand-rolled logout handlers.

Posture: fail **open** where an unreadable row and an absent row deserve the same answer; fail **loud** where a write
is what makes the next request work. For which sites take which, read the trait docs.

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

`DbConfig` and `DbSslConfig` both derive `Default` (needed for services that use `#[serde(default)]` on their `AppConfig.db` field, where the db section is optional).

`build_pool` defaults: `minpool=0`, `maxpool=3`. SSL defaults: if `ssl` is absent or `enabled` is absent/false, `PgSslMode::Prefer` is used (not `Disable`) — this allows unencrypted connections to local dev databases while not failing if the server offers TLS.

Port is stored as `String` in `DbConfig` because `prepare_config` normalises everything to strings. `build_pool` parses it at runtime and defaults to `5432` if empty.

### `healthcheck.rs`

`run()` uses only stdlib — no tokio, no reqwest. This is intentional: it must work before the async runtime is started. Do not add async variants here; use a dedicated health endpoint in the service if you need async checks.

`check_subcommand` calls `process::exit` directly. This is correct and intentional — it must terminate the process without starting the server.

### `server.rs`

`server::run` mirrors `HttpServer::new`'s generic bounds exactly. The function is intentionally thin — its value is as a hook point for future cross-cutting concerns (lifecycle notifications, graceful shutdown handling), not as an abstraction over actix-web.

The bounds require `actix-service` and `actix-http` as direct dependencies because `IntoServiceFactory` and the raw `Request` type are not re-exported through `actix_web::dev` in actix-web 4.

### `middleware.rs`

`ApiKey` uses `EitherBody<B>` to return a `401` response without changing the response body type. The `forward_ready!` macro from actix-web delegates `poll_ready` to the inner service.

`forwarded_for` clones `connection_info()` before accessing headers to avoid a temporary lifetime issue with `req.connection_info().scheme()`.

---

## Versioning workflow

1. Implement and `cargo build` locally
2. Bump `version` in `Cargo.toml`
3. `git commit`, `git tag vX.Y.Z`, push the branch and the tag
4. Update `tag = "vX.Y.Z"` in each consumer's `Cargo.toml`
5. Run `cargo build` in each consumer to refresh `Cargo.lock`

**Never use a path dependency** (`path = "../hs-utils-rs"`) in a consumer. Always use `git + tag`. This ensures the consumer's `Cargo.lock` pins to a specific commit and Docker builds are reproducible.

**Never update a consumer's tag before pushing it to GitHub.** `cargo build` fetches from the remote; if the tag doesn't exist yet, the build fails.

---

## Common gotchas

- Adding a new public function is a minor version bump. Removing or changing a public function is a breaking change — leave a note under "Migrating consumers".
- `normalize_to_strings` converts numbers to strings, so `DbConfig.port` is always a string at deserialisation time. Don't add `port: u16` fields to `DbConfig` — keep them as `String` and parse in `build_pool`.
- The `[SECRET]:` prefix must appear in the raw config JSON (before `prepare_config` runs). A secret reference injected via an env var override will not be resolved because `apply_env_overrides` runs after `prepare_config`.
- `tracing::warn!` in `resolve_secrets` does not require the tracing subscriber to be initialised — messages before `logging::init` are silently dropped, which is correct behaviour.
