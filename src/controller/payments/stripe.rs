//! Stripe REST client — covers only the operations the controllers use.
//! Hand-rolled over reqwest (form-encoded requests, JSON responses) to avoid the
//! heavy `async-stripe` dependency. Reads `secret_key` from `CoreConfig.stripe`.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::controller::services::CoreServices;

const API_BASE: &str = "https://api.stripe.com/v1";

/// Default webhook timestamp tolerance (seconds), matching the Stripe SDK.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

/// Verify a Stripe webhook signature and parse the event JSON (port of
/// `stripe.webhooks.constructEvent`). `payload` is the raw request body.
pub fn construct_event(payload: &[u8], sig_header: &str, secret: &str) -> Result<serde_json::Value> {
    // Header form: `t=<ts>,v1=<sig>,v1=<sig2>,...`
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<String> = Vec::new();
    for part in sig_header.split(',') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        match k.trim() {
            "t" => timestamp = v.trim().parse().ok(),
            "v1" => signatures.push(v.trim().to_string()),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or_else(|| anyhow!("no timestamp in signature header"))?;
    if signatures.is_empty() {
        bail!("no v1 signature in header");
    }

    let signed_payload = {
        let mut v = format!("{timestamp}.").into_bytes();
        v.extend_from_slice(payload);
        v
    };
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| anyhow!("hmac key: {e}"))?;
    mac.update(&signed_payload);
    let expected = hex::encode(mac.finalize().into_bytes());

    let matched = signatures
        .iter()
        .any(|sig| constant_time_eq(sig.as_bytes(), expected.as_bytes()));
    if !matched {
        bail!("no signatures found matching the expected signature for payload");
    }

    // Timestamp tolerance (best-effort; skipped if the clock can't be read).
    if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        let now = now.as_secs() as i64;
        if (now - timestamp).abs() > WEBHOOK_TOLERANCE_SECS {
            bail!("timestamp outside the tolerance zone");
        }
    }

    Ok(serde_json::from_slice(payload)?)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn secret(core: &CoreServices) -> &str {
    &core.cfg.stripe.secret_key
}

#[derive(Debug, Deserialize)]
pub struct StripeRecurring {
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub interval_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct StripePrice {
    #[serde(default)]
    pub unit_amount: Option<i64>,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub recurring: Option<StripeRecurring>,
}

#[derive(Debug, Deserialize)]
pub struct StripePriceRef {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubItem {
    pub price: StripePriceRef,
}

#[derive(Debug, Default, Deserialize)]
pub struct StripeSubItems {
    #[serde(default)]
    pub data: Vec<StripeSubItem>,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    #[serde(default)]
    pub status: String,
    /// Customer id (string when not expanded).
    #[serde(default)]
    pub customer: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub items: StripeSubItems,
    #[serde(default)]
    pub trial_end: Option<i64>,
    #[serde(default)]
    pub current_period_end: Option<i64>,
    /// String id when not expanded, object when expanded — keep it raw and pull
    /// `client_secret` out where the expanded form is requested.
    #[serde(default)]
    pub pending_setup_intent: Option<serde_json::Value>,
}

impl StripeSubscription {
    /// `pending_setup_intent.client_secret` when the field was expanded.
    pub fn pending_setup_intent_client_secret(&self) -> Option<String> {
        self.pending_setup_intent
            .as_ref()
            .and_then(|v| v.get("client_secret"))
            .and_then(|c| c.as_str())
            .map(str::to_string)
    }
}

#[derive(Debug, Deserialize)]
struct StripeList<T> {
    #[serde(default = "Vec::new")]
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct IdOnly {
    id: String,
}

#[derive(Debug, Deserialize)]
struct UrlOnly {
    url: String,
}

async fn err_for(resp: reqwest::Response, op: &str) -> anyhow::Error {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    anyhow!("stripe {op}: {status}: {text}")
}

pub async fn retrieve_price(core: &CoreServices, price_id: &str) -> Result<StripePrice> {
    let resp = core
        .http
        .get(format!("{API_BASE}/prices/{price_id}"))
        .bearer_auth(secret(core))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "prices.retrieve").await);
    }
    Ok(resp.json().await?)
}

pub async fn retrieve_subscription(core: &CoreServices, id: &str) -> Result<StripeSubscription> {
    let resp = core
        .http
        .get(format!("{API_BASE}/subscriptions/{id}"))
        .bearer_auth(secret(core))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "subscriptions.retrieve").await);
    }
    Ok(resp.json().await?)
}

/// Retrieve a subscription as a raw JSON value (webhook navigation across API
/// versions).
pub async fn retrieve_subscription_value(
    core: &CoreServices,
    id: &str,
) -> Result<serde_json::Value> {
    let resp = core
        .http
        .get(format!("{API_BASE}/subscriptions/{id}"))
        .bearer_auth(secret(core))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "subscriptions.retrieve").await);
    }
    Ok(resp.json().await?)
}

/// List subscription ids for a customer with the given status.
pub async fn list_subscriptions(
    core: &CoreServices,
    customer: &str,
    status: &str,
) -> Result<Vec<String>> {
    let resp = core
        .http
        .get(format!("{API_BASE}/subscriptions"))
        .query(&[("customer", customer), ("status", status)])
        .bearer_auth(secret(core))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "subscriptions.list").await);
    }
    let list: StripeList<IdOnly> = resp.json().await?;
    Ok(list.data.into_iter().map(|s| s.id).collect())
}

pub async fn cancel_subscription(core: &CoreServices, id: &str) -> Result<()> {
    let resp = core
        .http
        .delete(format!("{API_BASE}/subscriptions/{id}"))
        .bearer_auth(secret(core))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "subscriptions.cancel").await);
    }
    Ok(())
}

pub async fn create_customer(core: &CoreServices, user_id: &str) -> Result<String> {
    let form = [("metadata[userId]", user_id)];
    let resp = core
        .http
        .post(format!("{API_BASE}/customers"))
        .bearer_auth(secret(core))
        .form(&form)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "customers.create").await);
    }
    let c: IdOnly = resp.json().await?;
    Ok(c.id)
}

/// Create a 7-day-trial incomplete subscription, expanding the pending setup
/// intent (port of the `createSubscriptionIntent` Stripe call).
pub async fn create_subscription_with_trial(
    core: &CoreServices,
    customer: &str,
    price_id: &str,
    user_id: &str,
    dest_uri: &str,
    plan: &str,
) -> Result<StripeSubscription> {
    let form: Vec<(String, String)> = vec![
        ("customer".into(), customer.into()),
        ("items[0][price]".into(), price_id.into()),
        ("payment_behavior".into(), "default_incomplete".into()),
        ("trial_period_days".into(), "7".into()),
        ("expand[0]".into(), "pending_setup_intent".into()),
        ("metadata[user_id]".into(), user_id.into()),
        ("metadata[dest_uri]".into(), dest_uri.into()),
        ("metadata[plan]".into(), plan.into()),
    ];
    let resp = core
        .http
        .post(format!("{API_BASE}/subscriptions"))
        .bearer_auth(secret(core))
        .form(&form)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "subscriptions.create").await);
    }
    Ok(resp.json().await?)
}

pub async fn create_billing_portal_session(
    core: &CoreServices,
    customer: &str,
    return_url: Option<&str>,
) -> Result<String> {
    let mut form: Vec<(String, String)> = vec![("customer".into(), customer.into())];
    if let Some(url) = return_url {
        form.push(("return_url".into(), url.into()));
    }
    let resp = core
        .http
        .post(format!("{API_BASE}/billing_portal/sessions"))
        .bearer_auth(secret(core))
        .form(&form)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "billingPortal.sessions.create").await);
    }
    let s: UrlOnly = resp.json().await?;
    Ok(s.url)
}
