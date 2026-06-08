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
        Ok(Some(UserSrc {
            id: user_id,
            email: gctx.profile_str("email"),
            name: gctx.profile_str("name"),
            picture_image_service_id: gctx
                .picture_image_service_id(core.cfg.claims_namespace()),
        }))
    }
}
