//! Config loading helpers shared across all hs Rust services.
//!
//! # Loading pattern
//!
//! Each service defines its own `AppConfig` struct and a `load()` function that
//! calls the helpers here:
//!
//! ```rust,ignore
//! pub fn load() -> anyhow::Result<AppConfig> {
//!     let text = std::fs::read_to_string("config.json")?;
//!     let mut root: serde_json::Value = serde_json::from_str(&text)?;
//!     // optional: hs_utils::config::deep_merge(&mut root, overlay);
//!     hs_utils::config::prepare_config(&mut root);
//!     hs_utils::config::apply_env_overrides(&mut root);
//!     Ok(serde_json::from_value(root)?)
//! }
//! ```
//!
//! # Secret file indirection
//!
//! Config values that start with `[SECRET]:` are treated as file paths and are
//! resolved automatically by `prepare_config`.  No explicit call is needed —
//! secrets are invisible to service code:
//!
//! ```json
//! { "db": { "password": "[SECRET]:/run/secrets/db_password" } }
//! ```
//!
//! # Deserializer attributes
//!
//! Add `#[serde(deserialize_with = "hs_utils::config::deser_<type>")]` to
//! struct fields whose JSON representation may be a string.  The deserializers
//! accept both the native JSON type and its string encoding so that
//! `"port": 3000` and `"port": "3000"` are both valid in config.json.

use serde::Deserialize;
use serde_json::Value;

/// A downstream data-service client target: `{ url, apiKey }`.
///
/// The canonical shape every hs service uses to point at a sibling
/// microservice (image-service, payment-data-service, auction-data-service, …).
/// Lives here (not behind a feature) so any consumer — controller toolkit,
/// consent bridge, avatar hook, or a plain service — can reuse one type instead
/// of redeclaring `{ url, apiKey }`. `controller::config::ServiceConfig` is a
/// backward-compatible alias of this.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataServiceConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub api_key: String,
}

// ── Value tree helpers ───────────────────────────────────────────────────────

/// Recursively converts all non-null leaf values in a `serde_json::Value`
/// tree to `Value::String`.
///
/// After this pass `true` and `"true"` are both represented as `"true"`,
/// and `3000` and `"3000"` are both `"3000"`.  This makes config.json files
/// and env-var overrides (which are always strings) uniform before
/// deserialization, so the service structs are not sensitive to whether the
/// config file author wrote `true` or `"true"`.
pub fn normalize_to_strings(v: &mut Value) {
    match v {
        Value::Object(map) => map.values_mut().for_each(normalize_to_strings),
        Value::Array(arr) => arr.iter_mut().for_each(normalize_to_strings),
        Value::Bool(b) => *v = Value::String(b.to_string()),
        Value::Number(n) => *v = Value::String(n.to_string()),
        _ => {} // strings and null unchanged
    }
}

/// Finalise a raw config `Value` tree for deserialisation in one call.
///
/// Performs (in order):
/// 1. `resolve_secrets` — replaces `[SECRET]:/path` strings with file contents
/// 2. `normalize_to_strings` — converts booleans and numbers to strings so
///    that `true` and `"true"` are equivalent
///
/// Call this **last**, after the full layering/override chain has selected each
/// value: base config → `/sandbox` overlay → `apply_env_overrides`. Secret
/// resolution must come *after* env overrides so that a `[SECRET]:` indirection
/// supplied via an environment variable is resolved on the final winning value
/// (matching the TypeScript `hs.utils` loader, which resolves `[SECRET]:` lazily
/// at read time). Calling it *before* `apply_env_overrides` leaves any
/// env-provided secret stored verbatim and never resolved.  `[SECRET]:`
/// resolution is intentionally invisible to the calling code.
pub fn prepare_config(v: &mut Value) {
    resolve_secrets(v);
    normalize_to_strings(v);
}

/// Walk env vars and apply them as overrides into `root`.  `__` is used as a
/// path separator so nested keys can be addressed, e.g. `db__host=postgres` or
/// `s3__bucketName=my-bucket`; a key with no `__` overrides a top-level config
/// key (e.g. `port=8080`). Key segments must match the JSON key names exactly
/// (case-sensitive camelCase).
///
/// Every env var is applied — there is no namespace filter — so the process
/// environment (`PATH`, `HOME`, …) is layered onto the config as string keys.
/// Deserialisation into the service's `AppConfig` ignores any keys the struct
/// does not declare, so unrelated env vars are harmless.
///
/// New values are inserted verbatim as strings; `[SECRET]:/path` indirections
/// are NOT resolved here. Env overrides are part of the *layering/override* step
/// (they win over config files), and `[SECRET]:` resolution happens afterwards on
/// the final selected value — see [`prepare_config`], which must run *after* this.
/// This is why a secret supplied via an environment variable (e.g.
/// `db__host=[SECRET]:/run/secrets/db-hostname`, the standard container
/// deployment pattern) resolves the same as one written in config.json.
pub fn apply_env_overrides(root: &mut Value) {
    for (key, value) in std::env::vars() {
        let parts: Vec<&str> = key.split("__").collect();
        set_nested(root, &parts, &value);
    }
}

/// Recursively merge `overlay` into `base`.  Object keys are merged; all
/// other value types (strings, numbers, booleans, arrays) are replaced by the
/// overlay value.  Used when layering a `/sandbox/config.json` on top of the
/// baked-in `config.json`.
pub fn deep_merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                deep_merge(base_map.entry(k).or_insert(Value::Null), v);
            }
        }
        (base, overlay) => *base = overlay,
    }
}

/// Recursively walk a `Value` tree and replace any string that starts with
/// `[SECRET]:` with the contents of the file at the given path.
///
/// Trailing newlines are stripped from the file contents so that secrets
/// produced by tools like `echo "value" > /run/secrets/foo` work correctly.
///
/// Should be called **before** `normalize_to_strings` — file contents are
/// already strings and will pass through unchanged.
///
/// A warning is logged (not an error) if a secret file cannot be read, so
/// that misconfiguration is visible at startup without crashing prematurely.
pub fn resolve_secrets(v: &mut Value) {
    const PREFIX: &str = "[SECRET]:";
    match v {
        Value::Object(map) => map.values_mut().for_each(resolve_secrets),
        Value::Array(arr) => arr.iter_mut().for_each(resolve_secrets),
        Value::String(s) if s.starts_with(PREFIX) => {
            let path = s[PREFIX.len()..].trim();
            match std::fs::read_to_string(path) {
                Ok(content) => *v = Value::String(content.trim_end_matches('\n').to_string()),
                Err(e) => tracing::warn!("Failed to read secret file '{path}': {e}"),
            }
        }
        _ => {}
    }
}

fn set_nested(node: &mut Value, path: &[&str], val: &str) {
    let Value::Object(map) = node else { return };
    let key = path[0];
    if path.len() == 1 {
        map.insert(key.to_string(), Value::String(val.to_string()));
    } else {
        let child = map
            .entry(key.to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        set_nested(child, &path[1..], val);
    }
}

// ── Layered loader ───────────────────────────────────────────────────────────

/// Container-standard layered config load.
///
/// 1. Reads the **base** config — `/app/config.json` (the image-baked default)
///    when it exists, falling back to `config.json` in the cwd for local dev
///    and tests.
/// 2. If `${CONFIG_PATH:-/sandbox}/config.json` exists, **deep-merges** it OVER
///    the base — the per-environment overlay mounted at `/sandbox`. `CONFIG_PATH`
///    selects the overlay *directory* and defaults to `/sandbox`.
/// 3. Applies `__`-flattened env overrides (`apply_env_overrides`), THEN resolves
///    `[SECRET]:` indirections + stringifies scalars on the final values
///    (`prepare_config`) — secret resolution comes after the override chain.
///
/// Returns the merged `Value`; the caller does `serde_json::from_value`. This is
/// the loader hs Rust services should call — no service hand-rolls config-file
/// reading or overlay merging.
pub fn load_layered_value() -> anyhow::Result<Value> {
    let base_path = if std::path::Path::new("/app/config.json").exists() {
        "/app/config.json".to_string()
    } else {
        "config.json".to_string()
    };
    let sandbox_dir = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "/sandbox".to_string());
    load_layered_from(&base_path, &sandbox_dir)
}

/// Testable core of [`load_layered_value`]: read `base_path`, deep-merge
/// `{sandbox_dir}/config.json` over it (when present), then prepare + apply env.
pub fn load_layered_from(base_path: &str, sandbox_dir: &str) -> anyhow::Result<Value> {
    use anyhow::Context as _;

    let text = std::fs::read_to_string(base_path)
        .with_context(|| format!("read base config '{base_path}'"))?;
    let mut root: Value =
        serde_json::from_str(&text).with_context(|| format!("parse base config '{base_path}'"))?;

    let overlay_path = format!("{}/config.json", sandbox_dir.trim_end_matches('/'));
    match std::fs::read_to_string(&overlay_path) {
        Ok(otext) => {
            let overlay: Value = serde_json::from_str(&otext)
                .with_context(|| format!("parse overlay config '{overlay_path}'"))?;
            deep_merge(&mut root, overlay);
            tracing::info!("config: merged overlay '{overlay_path}' over '{base_path}'");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("config: no overlay at '{overlay_path}'; using '{base_path}' only");
        }
        Err(e) => {
            return Err(e).with_context(|| format!("read overlay config '{overlay_path}'"));
        }
    }

    // Order matters: layer/override first (overlay then env), THEN resolve
    // `[SECRET]:` + normalise on the final selected values. Resolving before the
    // env override would leave any env-supplied `[SECRET]:` indirection verbatim.
    apply_env_overrides(&mut root);
    prepare_config(&mut root);
    Ok(root)
}

// ── Deserializers ────────────────────────────────────────────────────────────
//
// Each function accepts both the native JSON type and its string encoding.
// Use with `#[serde(deserialize_with = "hs_utils::config::deser_<type>")]`.

macro_rules! bool_visitor {
    ($name:ident, $ret:ty, $wrap:expr) => {
        struct $name;
        impl<'de> serde::de::Visitor<'de> for $name {
            type Value = $ret;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "bool or bool-like string (true/false/1/0/yes/no)")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<$ret, E> {
                Ok($wrap(v))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$ret, E> {
                Ok($wrap(matches!(
                    v.to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes"
                )))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<$ret, E> {
                Ok($wrap(v != 0))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<$ret, E> {
                Ok($wrap(v != 0))
            }
        }
    };
}

macro_rules! int_visitor {
    ($name:ident, $ret:ty, $inner:ty, $wrap:expr, $from_u64:expr, $from_i64:expr) => {
        struct $name;
        impl<'de> serde::de::Visitor<'de> for $name {
            type Value = $ret;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, concat!(stringify!($inner), " or numeric string"))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<$ret, E> {
                $from_u64(v).map($wrap).map_err(E::custom)
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<$ret, E> {
                $from_i64(v).map($wrap).map_err(E::custom)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$ret, E> {
                v.parse::<$inner>().map($wrap).map_err(E::custom)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<$ret, E> {
                // only reached for Option variants
                Ok($wrap(Default::default()))
            }
        }
    };
}

// ── bool ─────────────────────────────────────────────────────────────────────

pub fn deser_bool_or_str<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bool_visitor!(V, bool, |v| v);
    d.deserialize_any(V)
}

pub fn deser_opt_bool_or_str<'de, D>(d: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Option<bool>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "bool, bool-like string, or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Option<bool>, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Option<bool>, E> {
            Ok(None)
        }
        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<bool>, D2::Error> {
            deser_bool_or_str(d).map(Some)
        }
        fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Option<bool>, E> {
            Ok(Some(v))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<bool>, E> {
            Ok(Some(matches!(
                v.to_ascii_lowercase().as_str(),
                "true" | "1" | "yes"
            )))
        }
    }
    d.deserialize_any(V)
}

// ── u8 ───────────────────────────────────────────────────────────────────────

pub fn deser_u8_or_str<'de, D>(d: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    int_visitor!(V, u8, u8, |v| v, |v: u64| u8::try_from(v), |v: i64| u8::try_from(v));
    d.deserialize_any(V)
}

// ── u16 ──────────────────────────────────────────────────────────────────────

pub fn deser_u16_or_str<'de, D>(d: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    int_visitor!(V, u16, u16, |v| v, |v: u64| u16::try_from(v), |v: i64| u16::try_from(v));
    d.deserialize_any(V)
}

// ── u32 ──────────────────────────────────────────────────────────────────────

pub fn deser_u32_or_str<'de, D>(d: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    int_visitor!(V, u32, u32, |v| v, |v: u64| u32::try_from(v), |v: i64| u32::try_from(v));
    d.deserialize_any(V)
}

pub fn deser_opt_u32_or_str<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Option<u32>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "u32, numeric string, or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Option<u32>, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Option<u32>, E> {
            Ok(None)
        }
        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<u32>, D2::Error> {
            deser_u32_or_str(d).map(Some)
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Option<u32>, E> {
            u32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Option<u32>, E> {
            u32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<u32>, E> {
            v.parse::<u32>().map(Some).map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

// ── i32 ──────────────────────────────────────────────────────────────────────

pub fn deser_i32_or_str<'de, D>(d: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    int_visitor!(V, i32, i32, |v| v, |v: u64| i32::try_from(v), |v: i64| i32::try_from(v));
    d.deserialize_any(V)
}

pub fn deser_opt_i32_or_str<'de, D>(d: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Option<i32>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "i32, numeric string, or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Option<i32>, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Option<i32>, E> {
            Ok(None)
        }
        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<i32>, D2::Error> {
            deser_i32_or_str(d).map(Some)
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Option<i32>, E> {
            i32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Option<i32>, E> {
            i32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<i32>, E> {
            v.parse::<i32>().map(Some).map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

// ── i64 ──────────────────────────────────────────────────────────────────────

pub fn deser_i64_or_str<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = i64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "i64 or numeric string")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<i64, E> {
            i64::try_from(v).map_err(E::custom)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<i64, E> {
            Ok(v)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<i64, E> {
            v.parse::<i64>().map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

pub fn deser_opt_i64_or_str<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Option<i64>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "i64, numeric string, or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Option<i64>, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Option<i64>, E> {
            Ok(None)
        }
        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<i64>, D2::Error> {
            deser_i64_or_str(d).map(Some)
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Option<i64>, E> {
            i64::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Option<i64>, E> {
            Ok(Some(v))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<i64>, E> {
            v.parse::<i64>().map(Some).map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

// ── f64 ──────────────────────────────────────────────────────────────────────

pub fn deser_f64_or_str<'de, D>(d: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = f64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "f64 or numeric string")
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<f64, E> {
            Ok(v)
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<f64, E> {
            Ok(v as f64)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<f64, E> {
            Ok(v as f64)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<f64, E> {
            v.parse::<f64>().map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

pub fn deser_opt_f64_or_str<'de, D>(d: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Option<f64>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "f64, numeric string, or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Option<f64>, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Option<f64>, E> {
            Ok(None)
        }
        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<f64>, D2::Error> {
            deser_f64_or_str(d).map(Some)
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Option<f64>, E> {
            Ok(Some(v))
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Option<f64>, E> {
            Ok(Some(v as f64))
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Option<f64>, E> {
            Ok(Some(v as f64))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<f64>, E> {
            v.parse::<f64>().map(Some).map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

#[cfg(test)]
mod layered_tests {
    use super::*;

    #[test]
    fn overlay_deep_merges_over_base() {
        // Unique temp dirs (no Date/rand needed — use the test thread id space).
        let root = std::env::temp_dir().join(format!("hsutils_layered_{}", std::process::id()));
        let base_dir = root.join("app");
        let sandbox_dir = root.join("sandbox");
        std::fs::create_dir_all(&base_dir).unwrap();
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let base_path = base_dir.join("config.json");
        std::fs::write(
            &base_path,
            r#"{ "server": { "port": 3000 }, "falkordb": { "host": "baked", "graphName": "g" } }"#,
        )
        .unwrap();
        // Overlay changes host + adds a key; leaves graphName + port untouched.
        std::fs::write(
            sandbox_dir.join("config.json"),
            r#"{ "falkordb": { "host": "from-sandbox" }, "log": { "level": "debug" } }"#,
        )
        .unwrap();

        let v = load_layered_from(
            base_path.to_str().unwrap(),
            sandbox_dir.to_str().unwrap(),
        )
        .unwrap();

        // overlay wins; sibling base keys preserved; new overlay key present.
        assert_eq!(v["falkordb"]["host"], Value::String("from-sandbox".into()));
        assert_eq!(v["falkordb"]["graphName"], Value::String("g".into()));
        assert_eq!(v["log"]["level"], Value::String("debug".into()));
        // prepare_config stringified the scalar.
        assert_eq!(v["server"]["port"], Value::String("3000".into()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_overlay_uses_base_only() {
        let root = std::env::temp_dir().join(format!("hsutils_base_{}", std::process::id()));
        let base_dir = root.join("app");
        std::fs::create_dir_all(&base_dir).unwrap();
        let base_path = base_dir.join("config.json");
        std::fs::write(&base_path, r#"{ "falkordb": { "host": "baked" } }"#).unwrap();

        let v = load_layered_from(
            base_path.to_str().unwrap(),
            root.join("does-not-exist").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(v["falkordb"]["host"], Value::String("baked".into()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression: a `[SECRET]:/path` supplied via an environment variable must
    /// be resolved to the file's contents — the standard container deployment
    /// pattern (`session__db__host=[SECRET]:/run/secrets/db-hostname`). This only
    /// works because `apply_env_overrides` runs *before* secret resolution; if
    /// secrets were resolved first (the old order), the env value would be stored
    /// verbatim and the service would treat the literal `[SECRET]:…` as a host.
    #[test]
    fn env_provided_secret_is_resolved() {
        let root = std::env::temp_dir().join(format!("hsutils_envsecret_{}", std::process::id()));
        let base_dir = root.join("app");
        std::fs::create_dir_all(&base_dir).unwrap();
        let base_path = base_dir.join("config.json");
        // Base leaves host empty; the deploy supplies it via env as a secret ref.
        std::fs::write(&base_path, r#"{ "session": { "db": { "host": "" } } }"#).unwrap();

        let secret_file = root.join("db-hostname");
        std::fs::write(&secret_file, "pg.internal.example.com\n").unwrap();

        let key = "session__db__host";
        std::env::set_var(key, format!("[SECRET]:{}", secret_file.display()));

        let v = load_layered_from(
            base_path.to_str().unwrap(),
            root.join("does-not-exist").to_str().unwrap(),
        )
        .unwrap();

        std::env::remove_var(key);
        let _ = std::fs::remove_dir_all(&root);

        // Resolved to file contents (trailing newline stripped), NOT the literal.
        assert_eq!(
            v["session"]["db"]["host"],
            Value::String("pg.internal.example.com".into()),
        );
    }
}
