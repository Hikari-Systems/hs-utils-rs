//! Identity query fragment: `loggedInUser`. Merge into a controller's QueryRoot
//! via `#[derive(MergedObject)]`.

use async_graphql::{Context, Object};

use super::context::core_parts;
use super::types::UserSrc;

#[derive(Default)]
pub struct IdentityQuery;

#[Object]
impl IdentityQuery {
    async fn logged_in_user(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<UserSrc>> {
        let (core, gctx) = core_parts(ctx)?;
        let Some(user_id) = gctx.user_id.clone() else {
            return Ok(None);
        };
        // Resolve the profile LIVE from Kratos — the same source every other
        // user resolves through (`lookup_by_sub`) — so name/email/pictureId
        // reflect the current identity, not the values frozen into the session
        // token at login (which lag avatar ingest and profile edits). Fall back
        // to the session profile when the Kratos admin API is unconfigured.
        if let Some(p) = core.kratos.lookup_by_sub(&user_id).await {
            return Ok(Some(UserSrc {
                id: p.id,
                email: p.email,
                name: p.name,
                picture_image_service_id: p.picture_image_service_id,
            }));
        }
        Ok(Some(UserSrc {
            id: user_id,
            email: gctx.profile_str("email"),
            name: gctx.profile_str("name"),
            picture_image_service_id: gctx
                .picture_image_service_id(core.cfg.claims_namespace()),
        }))
    }
}
