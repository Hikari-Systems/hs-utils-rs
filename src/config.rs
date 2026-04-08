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
//!     hs_utils::config::normalize_to_strings(&mut root);
//!     hs_utils::config::apply_env_overrides(&mut root);
//!     Ok(serde_json::from_value(root)?)
//! }
//! ```
//!
//! # Secret file indirection
//!
//! Config values that start with `[SECRET]:` are treated as file paths.
//! Call `resolve_secrets(&mut root)` after merging sources to replace them
//! with the file's contents.  This mirrors the TS `hs.utils` behaviour and
//! lets secrets be injected as mounted files rather than env vars:
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

use serde_json::Value;

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

/// Walk env vars and apply any that use `__` as a path separator as overrides
/// into `root`.  Key segments must match the JSON key names exactly
/// (case-sensitive camelCase), e.g. `db__host=postgres` or
/// `s3__bucketName=my-bucket`.
///
/// Should be called *after* `normalize_to_strings` so all existing values are
/// already strings; new values are inserted as strings directly.
pub fn apply_env_overrides(root: &mut Value) {
    for (key, value) in std::env::vars() {
        let parts: Vec<&str> = key.split("__").collect();
        if parts.len() < 2 {
            continue;
        }
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
