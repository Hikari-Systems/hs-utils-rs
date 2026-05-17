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

    // NOTE: `skip_consent` is intentionally NOT injected into the public
    // registration body. It is an Ory privileged client field; Hydra v2
    // (≥ v26) rejects the *entire* `/oauth2/register` request with
    // `invalid_request` when it is present (it does not silently strip it).
    // Consent exemption is instead applied after creation via the admin API
    // (`mark_skip_consent` below). This deliberately diverges from
    // hs.utils/lib/mcp-auth/hydraDcrProxy.ts, which still injects it and is
    // affected by the same Hydra rejection.

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

    // Finalise consent exemption out-of-band. The public DCR response is
    // returned to the caller verbatim regardless of the outcome here: the
    // client is already registered and functional, and the consent bridge
    // has an audience-based fallback, so a failed admin PATCH must not turn
    // a successful registration into an error.
    if cfg.skip_consent && (200..300).contains(&status) {
        match serde_json::from_slice::<Value>(&bytes)
            .ok()
            .as_ref()
            .and_then(|v| v.get("client_id"))
            .and_then(Value::as_str)
        {
            Some(client_id) => mark_skip_consent(cfg, client_id).await,
            None => tracing::warn!(
                "DCR proxy: registration succeeded but response had no \
                 client_id; skipping skip_consent admin patch"
            ),
        }
    }

    DcrResponse {
        status,
        content_type,
        body: bytes,
    }
}

/// Mark a freshly registered client consent-exempt via Hydra's admin API
/// (`PATCH /admin/clients/{id}`, RFC 6902 JSON Patch). Best-effort: failures
/// are logged, never propagated — the consent bridge's audience-based
/// fallback still skips the consent page if this does not land.
async fn mark_skip_consent(cfg: &HydraDcrProxyConfig, client_id: &str) {
    let Some(admin) = cfg.admin_url.as_deref() else {
        tracing::warn!(
            "DCR proxy: skip_consent requested but no admin_url configured; \
             relying on the consent bridge audience-based fallback for {client_id}"
        );
        return;
    };

    let url = format!("{admin}/admin/clients/{client_id}");
    let patch = json!([{ "op": "replace", "path": "/skip_consent", "value": true }]);

    match cfg
        .client
        .patch(&url)
        .header("content-type", "application/json")
        .body(patch.to_string())
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            tracing::info!("DCR proxy: marked client {client_id} consent-exempt");
        }
        Ok(r) => {
            let st = r.status();
            let detail = r.text().await.unwrap_or_default();
            tracing::warn!(
                "DCR proxy: skip_consent patch for {client_id} returned {st}: {detail}"
            );
        }
        Err(e) => tracing::warn!(
            "DCR proxy: skip_consent patch for {client_id} failed: {e}"
        ),
    }
}
