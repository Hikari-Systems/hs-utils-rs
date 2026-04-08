# hs-utils-rs

Shared Rust utilities for all Hikari Systems backend services. Provides a consistent foundation for config loading, database connectivity, HTTP server startup, logging, healthchecks, and actix-web middleware so that service `main.rs` files stay small and cross-cutting concerns can be improved in one place.

## Usage

Add to `Cargo.toml`:

```toml
hs-utils = { git = "https://github.com/Hikari-Systems/hs-utils-rs", tag = "v0.2.2" }
```

Always pin to a tag. Never use a path dependency or `branch = "main"` in production services.

---

## Modules

### `hs_utils::config`

Config loading helpers. The standard pattern for every service `load()` function:

```rust
use hs_utils::config::{apply_env_overrides, prepare_config};

pub fn load() -> anyhow::Result<AppConfig> {
    let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.json".to_string());
    let mut root: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;

    // optional: deep_merge for /sandbox overlay
    // if let Ok(overlay) = std::fs::read_to_string("/sandbox/config.json") { ... }

    prepare_config(&mut root);       // resolve [SECRET]: files + normalise types
    apply_env_overrides(&mut root);  // KEY__subkey=val env var overrides
    Ok(serde_json::from_value(root)?)
}
```

**Config priority (lowest → highest):**
1. `config.json` (or `$CONFIG_PATH`)
2. `/sandbox/config.json` overlay merged with `deep_merge` (services that use this opt in explicitly)
3. Env vars: `KEY__subkey=val` (exact camelCase, `__` separator)

**Secret file indirection:**

Any config value starting with `[SECRET]:` is replaced with the contents of the file at the given path. This is handled automatically inside `prepare_config` — no explicit call needed:

```json
{ "db": { "password": "[SECRET]:/run/secrets/db_password" } }
```

**Deserialiser attributes:**

Fields whose JSON representation may be a string use `#[serde(deserialize_with = "...")]`:

```rust
#[serde(deserialize_with = "hs_utils::config::deser_u16_or_str")]
pub port: u16,

#[serde(deserialize_with = "hs_utils::config::deser_opt_bool_or_str")]
pub enabled: Option<bool>,
```

Available deserializers: `deser_bool_or_str`, `deser_opt_bool_or_str`, `deser_u8_or_str`, `deser_u16_or_str`, `deser_u32_or_str`, `deser_opt_u32_or_str`, `deser_i32_or_str`, `deser_opt_i32_or_str`, `deser_i64_or_str`, `deser_opt_i64_or_str`, `deser_f64_or_str`, `deser_opt_f64_or_str`.

> **Do not use the `config` crate.** It lowercases all JSON keys, silently breaking camelCase fields like `caCertFile`, `bucketName`, `secretSalt`.

---

### `hs_utils::db`

Shared PostgreSQL config struct and pool builder.

Embed `DbConfig` directly in your service's `AppConfig`:

```rust
use hs_utils::db::DbConfig;

#[derive(Debug, serde::Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub db: DbConfig,
}
```

Build the pool in `main.rs`:

```rust
let pool = hs_utils::db::build_pool(&cfg.db).await?;
```

**`DbConfig` fields:**

| Field | Type | Notes |
|---|---|---|
| `host` | `String` | |
| `port` | `String` | Parsed at runtime; tolerates `"5432"` or `5432` in JSON |
| `database` | `String` | |
| `username` | `String` | |
| `password` | `String` | Can be a `[SECRET]:/path` reference |
| `ssl` | `Option<DbSslConfig>` | |
| `minpool` | `Option<u32>` | Default 0 |
| `maxpool` | `Option<u32>` | Default 3 |

**`DbSslConfig` fields:** `enabled: Option<bool>`, `verify: Option<bool>`, `ca_cert_file: Option<String>`.

**SSL mode selection:**
- `enabled=true, verify=true` → `VerifyFull`
- `enabled=true, verify=false` → `Require`
- absent / `enabled=false` → `Prefer`

---

### `hs_utils::healthcheck`

Stdlib-only TCP healthcheck — no async, no reqwest, no extra dependencies. Safe to call before the Tokio runtime starts.

**`check_subcommand(default_port)`** — call unconditionally at the top of every `main`. No-op unless `argv[1] == "healthcheck"`. Parses optional `argv[2]` (host) and `argv[3]` (port), runs the check, and calls `process::exit(0/1)`:

```rust
#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    hs_utils::healthcheck::check_subcommand(
        config::load().map(|c| c.server.port).unwrap_or(3000),
    );
    // ...
}
```

**Dockerfile:**

```dockerfile
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/app/server", "healthcheck"]
```

**`run(host, port) -> bool`** — the underlying check if you need it directly.

---

### `hs_utils::logging`

Initialise `tracing_subscriber` with a level filter string. Call once after config is loaded:

```rust
hs_utils::logging::init(&cfg.log.level);
```

Accepts any valid `EnvFilter` string (e.g. `"info"`, `"debug"`, `"warn,sqlx=error"`). Falls back to `"info"` if the string cannot be parsed.

---

### `hs_utils::middleware`

**`timing()`** — returns an actix-web `Logger` middleware that logs each request as `METHOD /path → STATUS (Xms)`:

```rust
App::new()
    .wrap(hs_utils::middleware::timing())
```

**`ApiKey(key)`** — validates the `X-Api-Key` request header. Empty key allows all requests with a warning (for unconfigured deployments). Wrong key returns `401 Unauthorized`:

```rust
let api_key = cfg.server.api_key.clone().unwrap_or_default();
App::new()
    .wrap(hs_utils::middleware::ApiKey(api_key))
```

**`forwarded_for(req, x_prefix)`** — extracts `X-Forwarded-Proto`, `X-Forwarded-Port`, and `X-Forwarded-Host` headers (with an optional prefix) and returns a `ForwardedInfo { base_url, full_url }`. Falls back to the request's own protocol/host when headers are absent.

---

### `hs_utils::server`

Wraps `HttpServer::new(...).bind(...).run()` in a single call. All cross-cutting startup/shutdown hooks (SNS lifecycle notifications, etc.) live here — services get them for free when the crate is updated.

```rust
hs_utils::server::run(port, move || {
    App::new()
        .app_data(state.clone())
        .route("/healthcheck", web::get().to(|| async { "OK" }))
        .configure(routes::configure)
})
.await
```

The factory closure is identical to what you'd pass to `HttpServer::new`. The function logs `"Listening on port {port}"` before starting and returns when the server shuts down.

---

## Adding a new version

```bash
# 1. Make changes and verify they build
cargo build

# 2. Bump version in Cargo.toml
# version = "0.2.3"

# 3. Commit, push, tag
git add -A
git commit -m "feat: ..."
git tag v0.2.3
git push origin main
git push origin v0.2.3

# 4. Update each service's Cargo.toml tag and run cargo build to refresh Cargo.lock
```

Never update a service to point at a new tag before the tag exists on GitHub — `cargo build` will fail.
