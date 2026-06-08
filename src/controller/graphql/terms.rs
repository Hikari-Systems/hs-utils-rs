//! Terms query + mutation fragments: `checkTermsAccepted` and `acceptTerms`.
//! Merge into a controller's roots via `#[derive(MergedObject)]`. Pair with
//! [`crate::controller::terms::ensure_terms_hydrated`] in the controller's
//! GraphQL handler so a fresh session reads the persisted version.

use async_graphql::{Context, Object};
use serde_json::json;

use super::context::{core_parts, gql_err};
use crate::controller::dates::now_iso;
use crate::controller::terms::refresh_session_profile;

#[derive(Default)]
pub struct TermsQuery;

#[Object]
impl TermsQuery {
    async fn check_terms_accepted(
        &self,
        ctx: &Context<'_>,
        min_version: String,
    ) -> async_graphql::Result<Option<bool>> {
        let (_, gctx) = core_parts(ctx)?;
        gctx.require_user_id()?;
        if min_version.trim().is_empty() {
            return Err(async_graphql::Error::new("Min version is required"));
        }
        let accepted = gctx.profile_str("termsVersion");
        Ok(Some(accepted.map(|v| v >= min_version).unwrap_or(false)))
    }
}

#[derive(Default)]
pub struct TermsMutation;

#[Object]
impl TermsMutation {
    async fn accept_terms(
        &self,
        ctx: &Context<'_>,
        version: String,
    ) -> async_graphql::Result<bool> {
        let (core, gctx) = core_parts(ctx)?;
        let user_id = gctx.require_user_id()?.to_string();
        if version.trim().is_empty() {
            return Err(async_graphql::Error::new("Version is required"));
        }
        if gctx.profile_str("termsVersion").as_deref() == Some(version.as_str()) {
            return Ok(true);
        }
        let accepted_at = now_iso();
        core.kratos
            .update_metadata_public(
                &user_id,
                json!({ "terms": { "version": version, "accepted_at": accepted_at } }),
            )
            .await
            .map_err(gql_err)?;
        // Refresh the cached session profile so the next request sees the new
        // termsVersion without re-login.
        refresh_session_profile(
            core,
            gctx.session_id.as_deref(),
            json!({ "termsVersion": version, "termsAcceptedAt": accepted_at }),
        )
        .await;
        Ok(true)
    }
}
