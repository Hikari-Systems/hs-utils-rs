//! Stripe REST client — covers only the operations the controllers use.
//! Hand-rolled over reqwest (form-encoded requests, JSON responses) to avoid the
//! heavy `async-stripe` dependency. Reads `secret_key` from `CoreConfig.stripe`.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::controller::services::CoreServices;
use crate::http_client::SendTraced as _;

const API_BASE: &str = "https://api.stripe.com/v1";

/// Default webhook timestamp tolerance (seconds), matching the Stripe SDK.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

/// Verify a Stripe webhook signature and parse the event JSON (port of
/// `stripe.webhooks.constructEvent`). `payload` is the raw request body.
pub fn construct_event(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
) -> Result<serde_json::Value> {
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
        .send_traced()
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
        .send_traced()
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
        .send_traced()
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
        .send_traced()
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
        .send_traced()
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
        .send_traced()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "customers.create").await);
    }
    let c: IdOnly = resp.json().await?;
    Ok(c.id)
}

/// Create a 7-day-trial incomplete subscription, expanding the pending setup
/// intent (port of the `createSubscriptionIntent` Stripe call). No automatic
/// tax: see [`create_subscription`].
pub async fn create_subscription_with_trial(
    core: &CoreServices,
    customer: &str,
    price_id: &str,
    user_id: &str,
    dest_uri: &str,
    plan: &str,
) -> Result<StripeSubscription> {
    create_subscription(
        core,
        &NewSubscription {
            customer,
            price_id,
            user_id,
            dest_uri,
            plan,
            trial_days: 7,
            automatic_tax: false,
        },
    )
    .await
}

/// What [`create_subscription`] starts.
pub struct NewSubscription<'a> {
    pub customer: &'a str,
    pub price_id: &'a str,
    pub user_id: &'a str,
    pub dest_uri: &'a str,
    pub plan: &'a str,
    /// 0 for none: the first period is then paid now, through a payment intent
    /// on the latest invoice (not expanded here).
    pub trial_days: u32,
    /// `automatic_tax[enabled]`: the customer needs a tax-valid address first
    /// ([`update_customer_address`]).
    pub automatic_tax: bool,
}

impl NewSubscription<'_> {
    fn form(&self) -> Vec<(String, String)> {
        let mut form: Vec<(String, String)> = vec![
            ("customer".into(), self.customer.into()),
            ("items[0][price]".into(), self.price_id.into()),
            ("payment_behavior".into(), "default_incomplete".into()),
            ("expand[0]".into(), "pending_setup_intent".into()),
            ("metadata[user_id]".into(), self.user_id.into()),
            ("metadata[dest_uri]".into(), self.dest_uri.into()),
            ("metadata[plan]".into(), self.plan.into()),
        ];
        if self.trial_days > 0 {
            form.push(("trial_period_days".into(), self.trial_days.to_string()));
        }
        if self.automatic_tax {
            form.push(("automatic_tax[enabled]".into(), "true".into()));
        }
        form
    }
}

/// Create an incomplete subscription, expanding the pending setup intent.
pub async fn create_subscription(
    core: &CoreServices,
    n: &NewSubscription<'_>,
) -> Result<StripeSubscription> {
    let resp = core
        .http
        .post(format!("{API_BASE}/subscriptions"))
        .bearer_auth(secret(core))
        .form(&n.form())
        .send_traced()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "subscriptions.create").await);
    }
    Ok(resp.json().await?)
}

/// A billing address, as Stripe's Address Element gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BillingAddress {
    pub name: Option<String>,
    pub line1: String,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    /// ISO 3166-1 alpha-2, e.g. `GB`.
    pub country: String,
}

impl BillingAddress {
    /// Trimmed, empty parts dropped, the country upper-cased; refused (with a
    /// message fit for the person) when the country isn't a two-letter code,
    /// there's no first line, or a part is over 200 characters.
    pub fn tidied(&self) -> std::result::Result<Self, String> {
        let tidy = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let out = Self {
            name: tidy(&self.name),
            line1: self.line1.trim().to_string(),
            line2: tidy(&self.line2),
            city: tidy(&self.city),
            state: tidy(&self.state),
            postal_code: tidy(&self.postal_code),
            country: self.country.trim().to_ascii_uppercase(),
        };
        if out.country.len() != 2 || !out.country.chars().all(|c| c.is_ascii_uppercase()) {
            return Err("the country must be a two-letter code (e.g. GB)".into());
        }
        if out.line1.is_empty() {
            return Err("the address needs a first line".into());
        }
        let parts = [
            out.name.as_deref(),
            Some(out.line1.as_str()),
            out.line2.as_deref(),
            out.city.as_deref(),
            out.state.as_deref(),
            out.postal_code.as_deref(),
        ];
        if parts.into_iter().flatten().any(|p| p.chars().count() > 200) {
            return Err("an address field is too long".into());
        }
        Ok(out)
    }

    /// The customers.update form fields; empty optional parts are cleared.
    fn form(&self) -> Vec<(String, String)> {
        let opt = |v: &Option<String>| v.as_deref().map(str::trim).unwrap_or("").to_string();
        let mut f = vec![
            ("address[line1]".to_string(), self.line1.trim().to_string()),
            ("address[line2]".to_string(), opt(&self.line2)),
            ("address[city]".to_string(), opt(&self.city)),
            ("address[state]".to_string(), opt(&self.state)),
            ("address[postal_code]".to_string(), opt(&self.postal_code)),
            (
                "address[country]".to_string(),
                self.country.trim().to_string(),
            ),
        ];
        if let Some(n) = self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            f.push(("name".into(), n.into()));
        }
        f
    }
}

/// Stripe's error code for an address it can't work out tax for.
pub const TAX_LOCATION_INVALID: &str = "customer_tax_location_invalid";

/// Save the customer's billing address. With `validate_for_tax`, Stripe
/// refuses an address it can't work out tax for: the error's text then
/// contains [`TAX_LOCATION_INVALID`].
pub async fn update_customer_address(
    core: &CoreServices,
    customer: &str,
    address: &BillingAddress,
    validate_for_tax: bool,
) -> Result<()> {
    let mut form = address.form();
    if validate_for_tax {
        form.push(("tax[validate_location]".into(), "immediately".into()));
    }
    let resp = core
        .http
        .post(format!("{API_BASE}/customers/{customer}"))
        .bearer_auth(secret(core))
        .form(&form)
        .send_traced()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "customers.update").await);
    }
    Ok(())
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
        .send_traced()
        .await?;
    if !resp.status().is_success() {
        return Err(err_for(resp, "billingPortal.sessions.create").await);
    }
    let s: UrlOnly = resp.json().await?;
    Ok(s.url)
}

#[cfg(test)]
mod tax_tests {
    use super::*;

    #[test]
    fn subscriptions_ask_for_tax_only_when_told() {
        let mut n = NewSubscription {
            customer: "cus_1",
            price_id: "price_1",
            user_id: "u",
            dest_uri: "",
            plan: "monthly",
            trial_days: 7,
            automatic_tax: false,
        };
        let has = |f: &[(String, String)], k: &str| f.iter().any(|(fk, _)| fk == k);
        assert!(!has(&n.form(), "automatic_tax[enabled]"));
        assert!(has(&n.form(), "trial_period_days"));
        n.automatic_tax = true;
        n.trial_days = 0;
        assert!(has(&n.form(), "automatic_tax[enabled]"));
        assert!(!has(&n.form(), "trial_period_days"));
    }

    #[test]
    fn addresses_are_tidied_and_checked() {
        let a = BillingAddress {
            name: Some("  ".into()),
            line1: " 1 High St ".into(),
            line2: Some("".into()),
            city: Some(" London".into()),
            state: None,
            postal_code: Some("SW1A 1AA".into()),
            country: "gb".into(),
        };
        let t = a.tidied().unwrap();
        assert_eq!(t.name, None);
        assert_eq!(t.line1, "1 High St");
        assert_eq!(t.line2, None);
        assert_eq!(t.city.as_deref(), Some("London"));
        assert_eq!(t.country, "GB");
        assert!(BillingAddress {
            country: "GBR".into(),
            ..t.clone()
        }
        .tidied()
        .is_err());
        assert!(BillingAddress {
            line1: " ".into(),
            ..t.clone()
        }
        .tidied()
        .is_err());
        assert!(BillingAddress {
            city: Some("x".repeat(201)),
            ..t
        }
        .tidied()
        .is_err());
    }

    #[test]
    fn address_form_clears_missing_parts() {
        let a = BillingAddress {
            line1: "1 High St".into(),
            country: "GB".into(),
            ..Default::default()
        };
        let f = a.form();
        assert!(f.contains(&("address[line2]".into(), String::new())));
        assert!(!f.iter().any(|(k, _)| k == "name"));
    }
}
