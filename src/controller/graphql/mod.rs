//! Shared GraphQL building blocks: the per-request [`GqlContext`], shared output
//! types, and mergeable resolver fragments (`IdentityQuery`, `TermsQuery`,
//! `TermsMutation`). Controllers compose these into their own roots with
//! `#[derive(MergedObject)]` and build/serve the schema themselves.

pub mod context;
pub mod identity;
pub mod terms;
pub mod types;

pub use context::{core_parts, gql_err, GqlContext};
pub use identity::IdentityQuery;
pub use terms::{TermsMutation, TermsQuery};
pub use types::{
    CustomerPortalSession, Image, Plan, SubscriptionConfig, SubscriptionIntent, SubscriptionPlan,
    SubscriptionSrc, UserSrc,
};
