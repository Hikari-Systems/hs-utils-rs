//! Kratos post-flow webhook: ingest a provider avatar into image-service (axum).
//!
//! On registration Kratos POSTs the new identity here (authenticated by a shared
//! `X-Webhook-Key`). The OIDC mapper has already written the raw provider avatar
//! URL into `traits.picture`; this hook downloads it, stores it in image-service,
//! and patches `traits.pictureId` with the returned image-service id (which the
//! consent bridge then surfaces as the `{ns}pictureId` claim).
//!
//! Fire-and-forget: every path returns 200 with a discriminator field, so a
//! picture failure never blocks the user's auth flow.
//!
//! Reusable, self-contained axum port of the hand-rolled hook in
//! `hs-login-controller` (actix). Mount on a PUBLIC path — it is called
//! server-to-server by Kratos, before any session cookie exists.
//!
//! Route: `POST /api/hooks/post-flow`

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use reqwest::{multipart, Client};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use crate::config::DataServiceConfig;

/// Post-flow hook configuration.
#[derive(Clone, Debug)]
pub struct AvatarHookConfig {
    /// Shared secret matched against the Kratos web_hook `api_key` header. An
    /// empty value disables auth (accepts any caller) — dev only.
    pub webhook_key: String,
    /// image-service client target (`{ url, apiKey }`).
    pub image_service: DataServiceConfig,
    /// Kratos admin API base, e.g. `http://kratos:4434`.
    pub kratos_admin_url: String,
    /// image-service scaling-set type for avatars (e.g. `userIcon`).
    pub image_type: String,
}

/// Cheap-to-clone hook handle (shared config + pooled HTTP client).
#[derive(Clone)]
pub struct AvatarHook {
    cfg: Arc<AvatarHookConfig>,
    http: Client,
}

impl AvatarHook {
    pub fn new(cfg: AvatarHookConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            http: Client::new(),
        }
    }

    /// Router serving `POST /api/hooks/post-flow`. Mount on a PUBLIC path — it
    /// is called by Kratos server-to-server, authed by the shared webhook key.
    pub fn router(self) -> Router {
        Router::new()
            .route("/api/hooks/post-flow", post(post_flow))
            .with_state(self)
    }

    fn kratos_admin(&self, path: &str) -> String {
        format!("{}{path}", self.cfg.kratos_admin_url.trim_end_matches('/'))
    }

    async fn get_identity(&self, id: &str) -> Result<Value> {
        let resp = self
            .http
            .get(self.kratos_admin(&format!("/admin/identities/{}", urlenc(id))))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("Kratos getIdentity failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Kratos getIdentity {id}: {status}: {}", trunc(&text)));
        }
        resp.json().await.context("Kratos identity decode")
    }

    /// PUT the identity back with `new_traits`, preserving
    /// `schema_id`/`state`/`metadata_public`/`metadata_admin`.
    async fn put_traits(&self, id: &str, identity: &Value, new_traits: Value) -> Result<()> {
        let mut body = serde_json::Map::new();
        if let Some(v) = identity.get("schema_id") {
            body.insert("schema_id".into(), v.clone());
        }
        body.insert(
            "state".into(),
            identity
                .get("state")
                .cloned()
                .unwrap_or_else(|| Value::String("active".into())),
        );
        body.insert("traits".into(), new_traits);
        if let Some(v) = identity.get("metadata_public") {
            body.insert("metadata_public".into(), v.clone());
        }
        if let Some(v) = identity.get("metadata_admin") {
            body.insert("metadata_admin".into(), v.clone());
        }

        let resp = self
            .http
            .put(self.kratos_admin(&format!("/admin/identities/{}", urlenc(id))))
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&Value::Object(body))
            .send()
            .await
            .context("Kratos updateIdentity failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Kratos updateIdentity {id}: {status}: {}", trunc(&text)));
        }
        Ok(())
    }

    /// Download an external image URL and forward its bytes to image-service,
    /// returning the new image id.
    async fn download_and_store(&self, image_url: &str) -> Result<String> {
        let resp = self
            .http
            .get(image_url)
            .send()
            .await
            .context("avatar download failed")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "avatar download HTTP {} from {image_url}",
                resp.status()
            ));
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // Derive a file extension from the content-type ("image/png" → "png"),
        // falling back to the URL path suffix, then "png".
        let extension = content_type
            .as_deref()
            .and_then(|ct| ct.split(';').next())
            .map(str::trim)
            .and_then(|s| s.split('/').next_back())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                let path = reqwest::Url::parse(image_url).ok()?.path().to_string();
                path.rsplit_once('.').map(|(_, ext)| ext.to_string())
            })
            .unwrap_or_else(|| "png".to_string());
        let bytes = resp
            .bytes()
            .await
            .context("avatar body read failed")?
            .to_vec();
        let mime = content_type.unwrap_or_else(|| format!("image/{extension}"));

        let url = format!(
            "{}/api/image/{}?forceImmediateResize=true",
            self.cfg.image_service.url.trim_end_matches('/'),
            urlenc(&self.cfg.image_type),
        );
        let part = multipart::Part::bytes(bytes)
            .file_name(format!("avatar.{extension}"))
            .mime_str(&mime)
            .context("invalid avatar content-type")?;
        let form = multipart::Form::new().part("image", part);
        let mut req = self.http.post(&url).multipart(form);
        if !self.cfg.image_service.api_key.is_empty() {
            req = req.header("X-Api-Key", &self.cfg.image_service.api_key);
        }
        let resp = req.send().await.context("image-service upload failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("image-service upload HTTP {status}: {}", trunc(&text)));
        }
        let rec: ImageRecord = resp.json().await.context("image-service upload decode")?;
        Ok(rec.id)
    }
}

#[derive(Deserialize)]
struct ImageRecord {
    id: String,
}

#[derive(Deserialize, Default)]
struct WebhookBody {
    #[serde(default)]
    identity_id: Option<String>,
    #[serde(default)]
    identity: Option<NestedIdentity>,
}

#[derive(Deserialize, Default)]
struct NestedIdentity {
    #[serde(default)]
    id: Option<String>,
}

async fn post_flow(
    State(hook): State<AvatarHook>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Auth: constant-time compare of the shared webhook key.
    let sent = headers
        .get("X-Webhook-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct_eq(sent.as_bytes(), hook.cfg.webhook_key.as_bytes()) {
        warn!("post-flow: bad webhook key");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }

    let parsed: WebhookBody = serde_json::from_value(body).unwrap_or_default();
    let Some(identity_id) = parsed
        .identity_id
        .or_else(|| parsed.identity.and_then(|i| i.id))
    else {
        warn!("post-flow: no identity id in payload");
        return ok(json!({ "ok": true, "skipped": "no_identity_id" }));
    };

    let identity = match hook.get_identity(&identity_id).await {
        Ok(i) => i,
        Err(e) => {
            error!("post-flow: getIdentity failed identityId={identity_id}: {e:#}");
            return ok(json!({ "ok": true, "error": "lookup_failed" }));
        }
    };
    let traits = identity
        .get("traits")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    // Already ingested — idempotent.
    if traits
        .get("pictureId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .is_some()
    {
        info!("post-flow: pictureId already set, skipping identityId={identity_id}");
        return ok(json!({ "ok": true, "skipped": "already_uploaded" }));
    }

    let Some(picture) = traits
        .get("picture")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        info!("post-flow: no picture trait, skipping identityId={identity_id}");
        return ok(json!({ "ok": true, "skipped": "no_picture" }));
    };

    // Sentinel `image-service://<uuid>`: the id is already known — adopt it and
    // clear the URL. Otherwise download the URL and store it.
    let sentinel = sentinel_id(picture);
    let image_id = match &sentinel {
        Some(id) => id.clone(),
        None => match hook.download_and_store(picture).await {
            Ok(id) => id,
            Err(e) => {
                error!("post-flow: upload failed (swallowed) identityId={identity_id}: {e:#}");
                return ok(json!({ "ok": true, "error": "upload_failed" }));
            }
        },
    };

    let mut new_traits = traits.clone();
    if let Value::Object(map) = &mut new_traits {
        map.insert("pictureId".into(), Value::String(image_id.clone()));
        if sentinel.is_some() {
            map.insert("picture".into(), Value::String(String::new()));
        }
    }
    if let Err(e) = hook.put_traits(&identity_id, &identity, new_traits).await {
        error!("post-flow: identity patch failed identityId={identity_id}: {e:#}");
        return ok(json!({ "ok": true, "error": "patch_failed" }));
    }

    let action = if sentinel.is_some() { "sentinel" } else { "uploaded" };
    info!("post-flow: {action} avatar identityId={identity_id} imageId={image_id}");
    ok(json!({ "ok": true, "action": action, "imageId": image_id }))
}

fn ok(v: Value) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

/// Recognise the `image-service://<36-char-uuid>` sentinel and return the id.
fn sentinel_id(picture: &str) -> Option<String> {
    let rest = picture.strip_prefix("image-service://")?;
    if rest.len() == 36 && rest.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        Some(rest.to_string())
    } else {
        None
    }
}

/// Constant-time byte comparison (avoids leaking the key length/content via
/// timing). Returns false on length mismatch.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn trunc(s: &str) -> String {
    s.chars().take(200).collect()
}

/// Percent-encode a path segment (mirrors `encodeURIComponent`).
fn urlenc(s: &str) -> String {
    const KEEP: &[u8] = b"-_.!~*'()";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || KEEP.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_matches_uuid_only() {
        assert_eq!(
            sentinel_id("image-service://2fa8add8-5621-4912-8078-f6d32cb00180").as_deref(),
            Some("2fa8add8-5621-4912-8078-f6d32cb00180")
        );
        assert!(sentinel_id("https://lh3.googleusercontent.com/a/xyz").is_none());
        assert!(sentinel_id("image-service://not-a-uuid").is_none());
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreu"));
        assert!(!ct_eq(b"secret", b"sec"));
        assert!(ct_eq(b"", b""));
    }
}
