//! Framework-free DCR forwarding logic.
//!
//! Takes the raw request body bytes, parses as JSON, deduplicates and merges
//! the configured `allowed_audiences` into the registration's `audience` array,
//! forwards to upstream Hydra `/oauth2/register`, and returns a wire-level
//! response (status + content-type + bytes) for the framework adapter to
//! render.

use serde_json::{json, Value};

use super::config::HydraDcrProxyConfig;

/// Wire-level response returned by `forward_register`. Framework adapters
/// (actix, axum) translate this into their respective response types.
pub struct DcrResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl DcrResponse {
    fn error(status: u16, error: &str, description: Option<&str>) -> Self {
        let body = match description {
            Some(d) => json!({ "error": error, "error_description": d }),
            None => json!({ "error": error }),
        };
        Self {
            status,
            content_type: Some("application/json".to_string()),
            body: body.to_string().into_bytes(),
        }
    }
}

/// Forward an RFC 7591 client registration to the upstream authorization
/// server, injecting the configured audience allowlist.
///
/// Mirrors `hs.utils/lib/mcp-auth/hydraDcrProxy.ts`.
pub async fn forward_register(cfg: &HydraDcrProxyConfig, body: &[u8]) -> DcrResponse {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return DcrResponse::error(
                400,
                "invalid_client_metadata",
                Some("Request body must be a JSON object."),
            );
        }
    };

    let mut obj = match parsed {
        Value::Object(m) => m,
        _ => {
            return DcrResponse::error(
                400,
                "invalid_client_metadata",
                Some("Request body must be a JSON object."),
            );
        }
    };

    let incoming_audience: Vec<String> = obj
        .remove("audience")
        .and_then(|v| match v {
            Value::Array(arr) => Some(arr),
            _ => None,
        })
        .map(|arr| {
            arr.into_iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let mut audience: Vec<String> =
        Vec::with_capacity(incoming_audience.len() + cfg.allowed_audiences.len());
    for a in incoming_audience
        .into_iter()
        .chain(cfg.allowed_audiences.iter().cloned())
    {
        if !audience.contains(&a) {
            audience.push(a);
        }
    }

    obj.insert(
        "audience".to_string(),
        Value::Array(audience.into_iter().map(Value::String).collect()),
    );

    // Mark proxied MCP clients consent-exempt (gated by config; on by
    // default). The consent bridge (hs-login-controller) auto-accepts when
    // the client carries this flag; Hydra may strip it on the public
    // registration endpoint, in which case the bridge's audience-based
    // fallback still skips the consent page.
    if cfg.skip_consent {
        obj.insert("skip_consent".to_string(), Value::Bool(true));
    }

    let merged_body = match serde_json::to_vec(&Value::Object(obj)) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("DCR proxy serialise merged body failed: {e}");
            return DcrResponse::error(500, "internal_error", None);
        }
    };

    let upstream_resp = match cfg
        .client
        .post(&cfg.upstream)
        .header("content-type", "application/json")
        .body(merged_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                "DCR proxy upstream fetch to {} failed: {e}",
                cfg.upstream
            );
            return DcrResponse::error(
                502,
                "upstream_unavailable",
                Some("Failed to reach upstream authorization server."),
            );
        }
    };

    let status = upstream_resp.status().as_u16();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let bytes = match upstream_resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            tracing::error!("DCR proxy reading upstream body failed: {e}");
            return DcrResponse::error(
                502,
                "upstream_unavailable",
                Some("Failed to read upstream response."),
            );
        }
    };

    DcrResponse {
        status,
        content_type,
        body: bytes,
    }
}
