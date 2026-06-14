//! Core configuration the controller toolkit reads. Controllers keep their own
//! `AppConfig` (loaded from `config.json` as before) and build a [`CoreConfig`]
//! from it — the toolkit never owns config loading. The struct types here
//! (`KratosConfig`/`ServiceConfig`/`StripeConfig`) are deliberately
//! shape-compatible with the per-controller copies so a controller can either
//! reuse them directly in its `AppConfig` or map its own structs across.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

/// Default OIDC claims namespace (matches the controllers' historical fallback).
pub const DEFAULT_CLAIMS_NAMESPACE: &str = "https://hikari-systems.com/";

/// Kratos admin API target.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KratosConfig {
    #[serde(default)]
    pub admin_url: Option<String>,
}

/// A downstream microservice client target (`{ url, apiKey }`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub api_key: String,
}

/// Stripe payments configuration (the payments superset). 5drive does not use
/// this — its Stripe usage (bids) is app-specific and stays in the controller.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeConfig {
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub publishable_key: String,
    #[serde(default)]
    pub webhook_secret: String,
    #[serde(default)]
    pub sku: Option<String>,
    #[serde(default)]
    pub product_id: Option<String>,
    /// Map of plan name → Stripe price id (e.g. `{ monthly, annual }`).
    #[serde(default)]
    pub price_id: BTreeMap<String, String>,
}

/// The configuration the toolkit's shared resolvers, clients and helpers read.
/// A controller constructs this from its own parsed config and hands an
/// `Arc<CoreConfig>` to [`super::CoreServices`].
///
/// Scalar knobs capture the per-controller divergences so the GraphQL surface is
/// a single superset configured by data: `sku`, `free_access_emails` and
/// `subscription_grace_days`. Subscription dates are always emitted as ISO — no
/// format knob.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreConfig {
    #[serde(default)]
    pub kratos: KratosConfig,
    /// Resolved OIDC claims namespace (controller applies its default before
    /// constructing; empty falls back to [`DEFAULT_CLAIMS_NAMESPACE`]).
    #[serde(default)]
    pub claims_namespace: String,
    #[serde(default)]
    pub stripe: StripeConfig,
    #[serde(default, rename = "payment-data-service")]
    pub payment_data_service: ServiceConfig,
    #[serde(default, rename = "image-service")]
    pub image_service: ServiceConfig,
    /// Product SKU used for payment-state lookups (e.g. `lloquent`/`botsafely`),
    /// already resolved by the controller (its per-app default applied).
    #[serde(default)]
    pub sku: String,
    /// Comma-separated allowlist of emails granted access without payment.
    #[serde(default)]
    pub free_access_emails: Option<String>,
    /// Days of grace added past `expires_at` when judging an active
    /// subscription (slackbot: 0, botsafely: 7).
    #[serde(default)]
    pub subscription_grace_days: i64,
}

impl CoreConfig {
    /// Resolved claims namespace, defaulting to [`DEFAULT_CLAIMS_NAMESPACE`].
    pub fn claims_namespace(&self) -> &str {
        let ns = self.claims_namespace.trim();
        if ns.is_empty() {
            DEFAULT_CLAIMS_NAMESPACE
        } else {
            ns
        }
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}
