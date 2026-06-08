//! Shared async-graphql output types: `Image`, `User`, `Subscription`, `Plan`,
//! and the subscription/payment SimpleObjects. Unified on the superset — `User`
//! always exposes `isMe` and `subscription` (the latter resolves `None` when no
//! payment-data-service is configured). Subscription dates are ISO.

use async_graphql::{Context, Enum, Object, SimpleObject, ID};
use serde_json::Value;

use super::context::{core_parts, gql_err};
use crate::controller::dates::iso_utc;
use crate::controller::payment_data::{self, UserPaymentState};
use crate::controller::services::CoreServices;

// ── Image ─────────────────────────────────────────────────────────────────

/// An image referenced by image-service id. URL fields resolve signed URLs via
/// the image-service in [`CoreServices`].
pub struct Image(pub String);

/// Resolve a signed URL for an image at the given size. `None` on any error
/// (mirrors the controllers' `getUrlByImageId`, which swallows failures).
async fn image_url(core: &CoreServices, image_id: &str, size: &str) -> Option<String> {
    let base = &core.cfg.image_service.url;
    if base.is_empty() {
        return None;
    }
    let url = format!("{base}/api/image/s/{image_id}/{size}");
    let resp = core
        .http
        .get(&url)
        .header("X-Api-Key", &core.cfg.image_service.api_key)
        .send()
        .await
        .ok()?;
    let json: Value = resp.json().await.ok()?;
    json.get("url").and_then(Value::as_str).map(str::to_string)
}

#[Object]
impl Image {
    async fn id(&self) -> ID {
        ID(self.0.clone())
    }
    async fn small_url(&self, ctx: &Context<'_>) -> Option<String> {
        let (core, _) = core_parts(ctx).ok()?;
        image_url(core, &self.0, "small").await
    }
    async fn large_url(&self, ctx: &Context<'_>) -> Option<String> {
        let (core, _) = core_parts(ctx).ok()?;
        image_url(core, &self.0, "large").await
    }
}

// ── Plan / Subscription ─────────────────────────────────────────────────────

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(rename_items = "lowercase")]
pub enum Plan {
    Monthly,
    Annual,
}

#[derive(Clone, Default)]
pub struct SubscriptionSrc {
    pub plan: Option<String>,
    pub paid_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl SubscriptionSrc {
    pub fn from_payment_state(s: &UserPaymentState) -> Self {
        Self {
            plan: s.plan.clone(),
            paid_at: s.paid_at,
            expires_at: s.expires_at,
        }
    }
}

#[Object(name = "Subscription")]
impl SubscriptionSrc {
    async fn plan(&self) -> Option<Plan> {
        match self.plan.as_deref() {
            Some("annual") => Some(Plan::Annual),
            Some("monthly") => Some(Plan::Monthly),
            _ => None,
        }
    }
    async fn from(&self) -> Option<String> {
        self.paid_at.as_ref().map(iso_utc)
    }
    async fn to(&self) -> Option<String> {
        self.expires_at.as_ref().map(iso_utc)
    }
}

#[derive(SimpleObject)]
pub struct SubscriptionPlan {
    pub price_id: Option<String>,
    pub plan: Option<String>,
    pub unit_amount: Option<i32>,
    pub currency: Option<String>,
    pub interval: Option<String>,
    pub interval_count: Option<i32>,
    pub monthly_equivalent_amount: Option<i32>,
}

#[derive(SimpleObject)]
pub struct SubscriptionConfig {
    pub publishable_key: String,
    pub plans: Vec<SubscriptionPlan>,
}

#[derive(SimpleObject)]
pub struct SubscriptionIntent {
    pub client_secret: Option<String>,
    pub subscription_id: Option<String>,
}

#[derive(SimpleObject)]
pub struct CustomerPortalSession {
    pub url: Option<String>,
}

// ── User ────────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct UserSrc {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture_image_service_id: Option<String>,
}

#[Object(name = "User")]
impl UserSrc {
    async fn id(&self) -> Option<ID> {
        (!self.id.is_empty()).then(|| ID(self.id.clone()))
    }
    async fn email(&self) -> Option<String> {
        self.email.clone()
    }
    async fn name(&self) -> Option<String> {
        self.name.clone()
    }
    async fn picture(&self) -> Option<Image> {
        self.picture_image_service_id.clone().map(Image)
    }
    async fn is_me(&self, ctx: &Context<'_>) -> bool {
        core_parts(ctx)
            .ok()
            .and_then(|(_, gctx)| gctx.user_id.clone())
            .map(|uid| uid == self.id)
            .unwrap_or(false)
    }
    /// Active subscription for this user. `None` when no payment-data-service is
    /// configured (controllers without payments) or there is no active sub.
    async fn subscription(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Option<SubscriptionSrc>> {
        let (core, _) = core_parts(ctx)?;
        if core.cfg.payment_data_service.url.is_empty() {
            return Ok(None);
        }
        let states =
            payment_data::get_payment_states_by_user_id_and_sku(core, &self.id, &core.cfg.sku)
                .await
                .map_err(gql_err)?;
        Ok(payment_data::find_active_subscription(&core.cfg, &states)
            .map(|s| SubscriptionSrc::from_payment_state(&s)))
    }
}
