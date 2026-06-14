//! Composable GraphQL controller toolkit.
//!
//! A set of building blocks shared across the Hikari controller binaries
//! (slackbot / botsafely / 5drive). The library owns no `AppState` and no schema
//! — each controller keeps its own state, schema assembly and handlers, and
//! pulls these elements in:
//!
//! - [`CoreConfig`] / [`CoreServices`] — the shared config + services bundle the
//!   controller inserts into its async-graphql schema `.data()` alongside its own
//!   `AppState`. Shared fragments read `ctx.data::<CoreServices>()`.
//! - [`graphql`] — the per-request [`graphql::GqlContext`], shared output types
//!   (`User`/`Subscription`/`Image`/…), and mergeable resolver fragments
//!   (`IdentityQuery`, `TermsQuery`, `TermsMutation`). Compose via
//!   `#[derive(MergedObject)]`.
//! - [`terms`] — terms login-hydration + session-profile refresh. Call
//!   [`terms::ensure_terms_hydrated`] from the controller's GraphQL handler.
//! - [`kratos_admin`] — Kratos admin client (profile lookup, terms read,
//!   `metadata_public` writer).
//! - [`payment_data`] — payment-data-service client + subscription logic.
//! - [`payments`] (feature `controller-payments`) — Stripe client + payment
//!   resolver fragments (`PaymentsQuery`/`PaymentsMutation`).

pub mod config;
pub mod dates;
pub mod graphql;
pub mod kratos_admin;
pub mod payment_data;
pub mod services;
pub mod terms;

#[cfg(feature = "controller-payments")]
pub mod payments;

pub use config::{CoreConfig, KratosConfig, ServiceConfig, StripeConfig, DEFAULT_CLAIMS_NAMESPACE};
pub use graphql::{
    core_parts, gql_err, GqlContext, IdentityQuery, TermsMutation, TermsQuery, UserSrc,
};
pub use kratos_admin::{KratosAdmin, OwnerProfile};
pub use services::CoreServices;
