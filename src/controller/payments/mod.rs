//! Payments resolver fragments (`checkPaidState`, `listSubscriptionPlans`,
//! `createSubscriptionIntent`, `activateTrialSubscription`,
//! `createCustomerPortalSession`) and the Stripe client. Gated behind the
//! `controller-payments` feature; controllers without payments (e.g. 5drive)
//! simply do not merge these fragments.

pub mod stripe;

use async_graphql::{Context, Object};
use chrono::{TimeZone, Utc};

use super::graphql::context::{core_parts, gql_err};
use super::graphql::types::{
    CustomerPortalSession, Plan, SubscriptionConfig, SubscriptionIntent, SubscriptionPlan,
    SubscriptionSrc,
};
use super::payment_data;

fn err(msg: impl Into<String>) -> async_graphql::Error {
    async_graphql::Error::new(msg.into())
}

#[derive(Default)]
pub struct PaymentsQuery;

#[Object]
impl PaymentsQuery {
    async fn check_paid_state(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<bool>> {
        let (core, gctx) = core_parts(ctx)?;
        let user_id = gctx.require_user_id()?;
        let states =
            payment_data::get_payment_states_by_user_id_and_sku(core, user_id, &core.cfg.sku)
                .await
                .map_err(gql_err)?;
        let active = payment_data::find_active_subscription(&core.cfg, &states).is_some();
        Ok(Some(active))
    }

    async fn list_subscription_plans(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<SubscriptionConfig> {
        let (core, _) = core_parts(ctx)?;
        let publishable_key = core.cfg.stripe.publishable_key.clone();
        let configured: Vec<(String, String)> = core
            .cfg
            .stripe
            .price_id
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if configured.is_empty() {
            tracing::warn!("No subscription plans configured under stripe:priceId.*");
            return Ok(SubscriptionConfig {
                publishable_key,
                plans: Vec::new(),
            });
        }
        let mut plans = Vec::new();
        for (id, price_id) in configured {
            let price = stripe::retrieve_price(core, &price_id).await.map_err(gql_err)?;
            let unit_amount = price.unit_amount.unwrap_or(0);
            let interval = price
                .recurring
                .as_ref()
                .and_then(|r| r.interval.clone())
                .unwrap_or_else(|| "month".into());
            let interval_count = price.recurring.as_ref().and_then(|r| r.interval_count).unwrap_or(1);
            let months_in_period = if interval == "year" {
                12 * interval_count
            } else {
                interval_count
            };
            let monthly_equivalent = if months_in_period != 0 {
                (unit_amount as f64 / months_in_period as f64).round() as i64
            } else {
                unit_amount
            };
            plans.push(SubscriptionPlan {
                price_id: Some(price_id),
                plan: Some(id),
                unit_amount: Some(unit_amount as i32),
                currency: Some(price.currency),
                interval: Some(interval),
                interval_count: Some(interval_count as i32),
                monthly_equivalent_amount: Some(monthly_equivalent as i32),
            });
        }
        Ok(SubscriptionConfig {
            publishable_key,
            plans,
        })
    }
}

#[derive(Default)]
pub struct PaymentsMutation;

#[Object]
impl PaymentsMutation {
    async fn create_subscription_intent(
        &self,
        ctx: &Context<'_>,
        dest_uri: Option<String>,
        plan: Plan,
    ) -> async_graphql::Result<Option<SubscriptionIntent>> {
        let (core, gctx) = core_parts(ctx)?;
        let user_id = gctx.require_user_id()?;
        let plan_str = match plan {
            Plan::Annual => "annual",
            Plan::Monthly => "monthly",
        };
        let price_id = core
            .cfg
            .stripe
            .price_id
            .get(plan_str)
            .cloned()
            .ok_or_else(|| err(format!("No price configured for plan {plan_str}")))?;

        let states =
            payment_data::get_payment_states_by_user_id_and_sku(core, user_id, &core.cfg.sku)
                .await
                .map_err(gql_err)?;
        let customer_id = match states.first().and_then(|s| s.customer_id.clone()) {
            Some(c) => c,
            None => stripe::create_customer(core, user_id).await.map_err(gql_err)?,
        };

        for sub_id in stripe::list_subscriptions(core, &customer_id, "incomplete")
            .await
            .map_err(gql_err)?
        {
            stripe::cancel_subscription(core, &sub_id).await.map_err(gql_err)?;
        }

        let subscription = stripe::create_subscription_with_trial(
            core,
            &customer_id,
            &price_id,
            user_id,
            dest_uri.as_deref().unwrap_or(""),
            plan_str,
        )
        .await
        .map_err(gql_err)?;
        let client_secret = subscription.pending_setup_intent_client_secret().ok_or_else(|| {
            err("No pending setup intent on subscription — trial may not be configured correctly")
        })?;
        Ok(Some(SubscriptionIntent {
            client_secret: Some(client_secret),
            subscription_id: Some(subscription.id),
        }))
    }

    async fn activate_trial_subscription(
        &self,
        ctx: &Context<'_>,
        subscription_id: String,
    ) -> async_graphql::Result<Option<SubscriptionSrc>> {
        let (core, gctx) = core_parts(ctx)?;
        let user_id = gctx.require_user_id()?;
        let sub = stripe::retrieve_subscription(core, &subscription_id).await.map_err(gql_err)?;
        if sub.metadata.get("user_id").map(String::as_str) != Some(user_id) {
            return Err(err("Subscription does not belong to this user"));
        }
        if sub.status != "trialing" && sub.status != "active" {
            return Err(err(format!("Cannot activate subscription with status: {}", sub.status)));
        }
        let customer_id = sub.customer.clone();
        let price_id = sub.items.data.first().map(|i| i.price.id.clone()).unwrap_or_default();
        let plan = payment_data::plan_from_price_id(&core.cfg, &price_id);
        let paid_at = Utc::now();
        let expires_secs = sub.trial_end.or(sub.current_period_end).unwrap_or(0);
        let expires_at = Utc.timestamp_opt(expires_secs, 0).single().unwrap_or(paid_at);
        let product_id = core.cfg.stripe.product_id.clone().unwrap_or_default();

        let existing =
            payment_data::get_payment_states_by_user_id_and_sku(core, user_id, &core.cfg.sku)
                .await
                .map_err(gql_err)?;
        if let Some(id) = existing.first().and_then(|s| s.id.clone()) {
            payment_data::update_user_payment_state(
                core, &id, user_id, &core.cfg.sku, &product_id, &price_id, paid_at, expires_at,
                &customer_id, &plan, None,
            )
            .await
            .map_err(gql_err)?;
        } else {
            payment_data::add_user_payment_state(
                core, user_id, &core.cfg.sku, &product_id, &price_id, paid_at, expires_at,
                &customer_id, &plan,
            )
            .await
            .map_err(gql_err)?;
        }
        Ok(Some(SubscriptionSrc {
            plan: Some(plan),
            paid_at: Some(paid_at),
            expires_at: Some(expires_at),
        }))
    }

    async fn create_customer_portal_session(
        &self,
        ctx: &Context<'_>,
        dest_uri: Option<String>,
    ) -> async_graphql::Result<Option<CustomerPortalSession>> {
        let (core, gctx) = core_parts(ctx)?;
        let user_id = gctx.require_user_id()?;
        let states =
            payment_data::get_payment_states_by_user_id_and_sku(core, user_id, &core.cfg.sku)
                .await
                .map_err(gql_err)?;
        let sub = payment_data::find_active_subscription(&core.cfg, &states)
            .ok_or_else(|| err("No active subscription found"))?;
        let customer_id = sub.customer_id.unwrap_or_default();
        let url = stripe::create_billing_portal_session(core, &customer_id, dest_uri.as_deref())
            .await
            .map_err(gql_err)?;
        Ok(Some(CustomerPortalSession { url: Some(url) }))
    }
}
