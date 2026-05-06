//! Claim-based user resolver: from a verified JWT, derive the local user.
//!
//! Mirrors `userResolver.ts:createClaimsUserResolver` line-for-line:
//!   1. Read `sub` off the verified JWT payload.
//!   2. Cache by `sub` with a 5-minute TTL.
//!   3. Build an `OauthProfile` from namespaced custom claims.
//!   4. Look up the user in user-data-service by email, or create one.
//!   5. Upsert the OAuth profile against the resolved `userId`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use moka::future::Cache;
use serde_json::Value;
use uuid::Uuid;

use super::claims::{build_profile, OauthProfile};
use super::user_data_service_client::UserDataServiceClient;

const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const CACHE_MAX_ENTRIES: u64 = 10_000;

#[derive(Debug, Clone)]
pub struct ResolvedUser {
    pub user_id: Uuid,
    pub profile: OauthProfile,
}

pub struct ClaimsUserResolver {
    client: Arc<UserDataServiceClient>,
    namespace: String,
    cache: Cache<String, ResolvedUser>,
}

impl ClaimsUserResolver {
    pub fn new(client: Arc<UserDataServiceClient>, namespace: impl Into<String>) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            cache: Cache::builder()
                .time_to_live(CACHE_TTL)
                .max_capacity(CACHE_MAX_ENTRIES)
                .build(),
        }
    }

    /// Resolve a verified JWT payload to a local user, creating the user
    /// row and OAuth profile on first sight. Returns `None` if `sub` is
    /// absent (this should never happen for a well-formed JWT).
    pub async fn resolve(&self, payload: &Value) -> Option<ResolvedUser> {
        let sub = payload.get("sub").and_then(Value::as_str)?;
        if sub.is_empty() {
            return None;
        }

        if let Some(cached) = self.cache.get(sub).await {
            return Some(cached);
        }

        let profile = build_profile(payload, sub, &self.namespace);

        let resolved = match self.upsert_local_user(&profile).await {
            Ok(user_id) => user_id,
            Err(err) => {
                tracing::error!("User resolution failed for sub={sub}: {err:#}");
                return None;
            }
        };

        let profile_json = match serde_json::to_string(&profile) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!("Profile JSON serialise failed for sub={sub}: {err:#}");
                return None;
            }
        };

        if let Err(err) = self
            .client
            .upsert_oauth_profile(sub, resolved, &profile_json)
            .await
        {
            tracing::error!("upsert_oauth_profile failed for sub={sub}: {err:#}");
            // Don't fail resolution if the profile-row write fails — the
            // user record exists; matches TS behaviour where the upsert is
            // fire-and-forget for caching purposes.
        }

        let result = ResolvedUser {
            user_id: resolved,
            profile,
        };
        self.cache.insert(sub.to_string(), result.clone()).await;
        Some(result)
    }

    async fn upsert_local_user(&self, profile: &OauthProfile) -> Result<Uuid> {
        // Mirrors `upsertLocalUser` in userResolver.ts.
        match profile.email.as_deref() {
            None | Some("") => {
                if let Some(saved) = self.client.get_oauth_profile_by_sub(&profile.sub).await? {
                    return Ok(saved.user_id);
                }
                let created = self
                    .client
                    .create_user("", profile.name.as_deref())
                    .await?;
                Ok(created.id)
            }
            Some(email) => {
                if let Some(existing) = self.client.get_user_by_email(email).await? {
                    return Ok(existing.id);
                }
                let created = self
                    .client
                    .create_user(email, profile.name.as_deref())
                    .await?;
                Ok(created.id)
            }
        }
    }
}
