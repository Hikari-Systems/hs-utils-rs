//! The per-request GraphQL context shared across controllers, plus helpers for
//! shared resolver fragments to pull `(CoreServices, GqlContext)` out of an
//! async-graphql context.

use async_graphql::Context;
use serde_json::Value;

use crate::controller::services::CoreServices;

/// Per-request context the controller builds from the logged-in user + request
/// headers and injects via `schema.execute(req.data(gctx))`. App resolvers and
/// shared fragments both read this same type.
#[derive(Clone, Default)]
pub struct GqlContext {
    pub user_id: Option<String>,
    pub profile: Option<Value>,
    pub access_token: Option<String>,
    /// Forwarded base/full URL, populated from proxy headers.
    pub base_url: Option<String>,
    pub full_url: Option<String>,
    /// Session id (cookie value), used by terms acceptance to refresh the cached
    /// session profile in place.
    pub session_id: Option<String>,
}

impl GqlContext {
    /// Logged-in user id or a GraphQL error.
    pub fn require_user_id(&self) -> async_graphql::Result<&str> {
        self.user_id
            .as_deref()
            .ok_or_else(|| async_graphql::Error::new("User not logged in"))
    }

    pub fn email(&self) -> Option<&str> {
        self.profile
            .as_ref()
            .and_then(|p| p.get("email"))
            .and_then(Value::as_str)
    }

    pub fn profile_str(&self, key: &str) -> Option<String> {
        self.profile
            .as_ref()
            .and_then(|p| p.get(key))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    /// Image-service UUID for the user's avatar — the live session key is
    /// `picture` (hs-utils `OauthProfile.picture`), with fallbacks to the legacy
    /// field and raw namespaced claim.
    pub fn picture_image_service_id(&self, claims_namespace: &str) -> Option<String> {
        self.profile_str("picture")
            .or_else(|| self.profile_str("pictureImageServiceId"))
            .or_else(|| self.profile_str(&format!("{claims_namespace}pictureId")))
            .or_else(|| self.profile_str("pictureId"))
    }
}

/// Pull `(&CoreServices, &GqlContext)` out of a shared resolver context.
pub fn core_parts<'a>(
    ctx: &'a Context<'_>,
) -> async_graphql::Result<(&'a CoreServices, &'a GqlContext)> {
    let core = ctx.data::<CoreServices>()?;
    let gctx = ctx.data::<GqlContext>()?;
    Ok((core, gctx))
}

/// Convert an `anyhow::Error` into a GraphQL error, preserving the message.
pub fn gql_err(e: anyhow::Error) -> async_graphql::Error {
    async_graphql::Error::new(format!("{e}"))
}
