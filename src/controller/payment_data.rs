//! payment-data-service client + payment logic, shared across controllers.
//! Reads its config from [`CoreConfig`] (SKU, free-access allowlist, grace
//! window) and talks to the service over the shared HTTP client in
//! [`CoreServices`]. Lives in the base `controller` feature (no Stripe) so the
//! shared `User.subscription` resolver can use it without the payments feature.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use super::config::CoreConfig;
use super::dates::{iso_utc, parse_dt};
use super::services::CoreServices;

/// One user payment-state row from the payment-data-service.
#[derive(Debug, Clone, Default)]
pub struct UserPaymentState {
    pub id: Option<String>,
    pub user_id: String,
    pub sku: String,
    pub provider_product_id: Option<String>,
    pub provider_price_id: Option<String>,
    pub paid_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub plan: Option<String>,
    pub refunded_at: Option<DateTime<Utc>>,
}

fn base(core: &CoreServices) -> &str {
    &core.cfg.payment_data_service.url
}
fn api_key(core: &CoreServices) -> &str {
    &core.cfg.payment_data_service.api_key
}

// ── Pure logic ──────────────────────────────────────────────────────────────

/// Map a Stripe price id to a plan name (`annual`/`monthly`), defaulting to
/// `monthly` with a warning for unknown ids.
pub fn plan_from_price_id(cfg: &CoreConfig, price_id: &str) -> String {
    let monthly = cfg.stripe.price_id.get("monthly").map(String::as_str);
    let annual = cfg.stripe.price_id.get("annual").map(String::as_str);
    if Some(price_id) == annual {
        return "annual".to_string();
    }
    if Some(price_id) == monthly {
        return "monthly".to_string();
    }
    tracing::warn!("Unknown priceId {price_id} — defaulting plan to 'monthly'");
    "monthly".to_string()
}

/// Lowercased/trimmed free-access email set from `freeAccessEmails` CSV.
pub fn free_access_set(cfg: &CoreConfig) -> HashSet<String> {
    cfg.free_access_emails
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty())
        .collect()
}

/// True when `email` is in the free-access allowlist (case-insensitive).
pub fn has_free_access(cfg: &CoreConfig, email: Option<&str>) -> bool {
    match email {
        Some(e) if !e.is_empty() => free_access_set(cfg).contains(&e.to_lowercase()),
        _ => false,
    }
}

/// Find the active subscription: paid in the past, not yet expired (plus
/// `cfg.subscription_grace_days` of grace), and not refunded.
pub fn find_active_subscription(
    cfg: &CoreConfig,
    states: &[UserPaymentState],
) -> Option<UserPaymentState> {
    let now = Utc::now();
    let grace = Duration::days(cfg.subscription_grace_days.max(0));
    states
        .iter()
        .find(|s| match (s.paid_at, s.expires_at) {
            (Some(paid), Some(expires)) => {
                paid < now && (expires + grace) > now && s.refunded_at.is_none()
            }
            _ => false,
        })
        .cloned()
}

/// Enforce the payment requirement, erroring with `Payment required` when there
/// is no active subscription and no free access.
pub async fn is_payment_active(
    core: &CoreServices,
    user_id: &str,
    email: Option<&str>,
) -> Result<()> {
    if has_free_access(&core.cfg, email) {
        return Ok(());
    }
    let states = get_payment_states_by_user_id_and_sku(core, user_id, &core.cfg.sku).await?;
    if find_active_subscription(&core.cfg, &states).is_none() {
        return Err(anyhow!("Payment required"));
    }
    Ok(())
}

// ── HTTP ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPaymentState {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    sku: String,
    #[serde(default)]
    provider_product_id: Option<String>,
    #[serde(default)]
    provider_price_id: Option<String>,
    #[serde(default)]
    paid_at: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    refunded_at: Option<String>,
}

fn parse_row(raw: RawPaymentState) -> UserPaymentState {
    UserPaymentState {
        id: raw.id,
        user_id: raw.user_id,
        sku: raw.sku,
        provider_product_id: raw.provider_product_id,
        provider_price_id: raw.provider_price_id,
        paid_at: parse_dt(raw.paid_at.as_deref()),
        expires_at: parse_dt(raw.expires_at.as_deref()),
        customer_id: raw.customer_id,
        plan: raw.plan,
        refunded_at: parse_dt(raw.refunded_at.as_deref()),
    }
}

pub async fn get_payment_states_by_user_id_and_sku(
    core: &CoreServices,
    user_id: &str,
    sku: &str,
) -> Result<Vec<UserPaymentState>> {
    let url = format!(
        "{}/api/userPaymentState/byUserIdAndSku/{}/{}",
        base(core),
        urlenc(user_id),
        urlenc(sku),
    );
    let resp = core
        .http
        .get(&url)
        .header("X-API-Key", api_key(core))
        .header("Content-type", "application/json")
        .send()
        .await?;
    if resp.status().as_u16() == 204 {
        return Ok(Vec::new());
    }
    if !resp.status().is_success() {
        return Err(anyhow!("Error getting payment states: {}", resp.status()));
    }
    let raws: Vec<RawPaymentState> = resp.json().await?;
    Ok(raws.into_iter().map(parse_row).collect())
}

#[allow(clippy::too_many_arguments)]
pub async fn add_user_payment_state(
    core: &CoreServices,
    user_id: &str,
    sku: &str,
    provider_product_id: &str,
    provider_price_id: &str,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    customer_id: &str,
    plan: &str,
) -> Result<UserPaymentState> {
    let body = json!({
        "userId": user_id, "sku": sku,
        "providerProductId": provider_product_id, "providerPriceId": provider_price_id,
        "paidAt": iso_utc(&started_at), "expiresAt": iso_utc(&ended_at),
        "customerId": customer_id, "plan": plan,
    });
    let resp = core
        .http
        .post(format!("{}/api/userPaymentState", base(core)))
        .header("X-API-Key", api_key(core))
        .header("Content-type", "application/json")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Error adding user payment state: {}", resp.status()));
    }
    // The endpoint returns either the row or an array of rows; accept either.
    let v: Value = resp.json().await?;
    let row = match v {
        Value::Array(mut arr) if !arr.is_empty() => arr.remove(0),
        other => other,
    };
    Ok(parse_row(serde_json::from_value(row)?))
}

#[allow(clippy::too_many_arguments)]
pub async fn update_user_payment_state(
    core: &CoreServices,
    id: &str,
    user_id: &str,
    sku: &str,
    provider_product_id: &str,
    provider_price_id: &str,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    customer_id: &str,
    plan: &str,
    refunded_at: Option<DateTime<Utc>>,
) -> Result<UserPaymentState> {
    let body = json!({
        "userId": user_id, "sku": sku,
        "providerProductId": provider_product_id, "providerPriceId": provider_price_id,
        "paidAt": iso_utc(&started_at), "expiresAt": iso_utc(&ended_at),
        "customerId": customer_id, "plan": plan,
        "refundedAt": refunded_at.map(|d| iso_utc(&d)),
    });
    let resp = core
        .http
        .put(format!("{}/api/userPaymentState/{}", base(core), urlenc(id)))
        .header("X-API-Key", api_key(core))
        .header("Content-type", "application/json")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Error updating user payment state: {}", resp.status()));
    }
    Ok(parse_row(resp.json().await?))
}

/// POST a Stripe webhook event for idempotent storage.
pub async fn add_payment_event(
    core: &CoreServices,
    provider_event_id: &str,
    event_data: &Value,
) -> Result<Value> {
    let body = json!({
        "providerEventId": provider_event_id,
        "eventData": serde_json::to_string(event_data)?,
    });
    let resp = core
        .http
        .post(format!("{}/api/paymentEvent", base(core)))
        .header("X-API-Key", api_key(core))
        .header("Content-type", "application/json")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Error adding payment event: {}", resp.status()));
    }
    Ok(resp.json().await?)
}

/// Percent-encode a path segment (mirrors `encodeURIComponent`).
pub fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*'
            | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(monthly: &str, annual: &str, free: &str, grace: i64) -> CoreConfig {
        let mut cfg = CoreConfig {
            free_access_emails: (!free.is_empty()).then(|| free.to_string()),
            subscription_grace_days: grace,
            ..Default::default()
        };
        cfg.stripe.price_id.insert("monthly".into(), monthly.into());
        cfg.stripe.price_id.insert("annual".into(), annual.into());
        cfg
    }

    #[test]
    fn plan_mapping() {
        let cfg = cfg_with("price_m", "price_a", "", 0);
        assert_eq!(plan_from_price_id(&cfg, "price_a"), "annual");
        assert_eq!(plan_from_price_id(&cfg, "price_m"), "monthly");
        assert_eq!(plan_from_price_id(&cfg, "price_unknown"), "monthly");
    }

    #[test]
    fn free_access_matches_case_insensitively() {
        let cfg = cfg_with("m", "a", "Foo@Bar.com, baz@qux.io", 0);
        assert!(has_free_access(&cfg, Some("foo@bar.com")));
        assert!(has_free_access(&cfg, Some("BAZ@QUX.IO")));
        assert!(!has_free_access(&cfg, Some("nope@x.com")));
        assert!(!has_free_access(&cfg, None));
        assert!(!has_free_access(&cfg, Some("")));
    }

    #[test]
    fn active_subscription_no_grace() {
        let cfg = cfg_with("m", "a", "", 0);
        let now = Utc::now();
        let mk = |paid_days: i64, exp_days: i64, refunded: bool| UserPaymentState {
            paid_at: Some(now - Duration::days(paid_days)),
            expires_at: Some(now + Duration::days(exp_days)),
            refunded_at: refunded.then_some(now),
            ..Default::default()
        };
        assert!(find_active_subscription(&cfg, &[mk(30, 5, false)]).is_some());
        assert!(find_active_subscription(&cfg, &[mk(30, -1, false)]).is_none());
        assert!(find_active_subscription(&cfg, &[mk(30, 5, true)]).is_none());
        assert!(find_active_subscription(&cfg, &[mk(-1, 5, false)]).is_none());
    }

    #[test]
    fn active_subscription_with_grace() {
        let cfg = cfg_with("m", "a", "", 7);
        let now = Utc::now();
        let mk = |paid_days: i64, exp_days: i64, refunded: bool| UserPaymentState {
            paid_at: Some(now - Duration::days(paid_days)),
            expires_at: Some(now + Duration::days(exp_days)),
            refunded_at: refunded.then_some(now),
            ..Default::default()
        };
        // within 7-day grace
        assert!(find_active_subscription(&cfg, &[mk(30, -3, false)]).is_some());
        // beyond grace
        assert!(find_active_subscription(&cfg, &[mk(30, -10, false)]).is_none());
    }
}
