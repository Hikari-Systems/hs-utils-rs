//! HTTP client for `user-data-service`. Mirrors the four call sites the
//! TypeScript `userResolver` uses: `getUserByEmail`, `createUser`,
//! `getOauthProfileBySub`, `upsertOauthProfile`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthProfileRow {
    pub sub: String,
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpsertOauthProfileRequest<'a> {
    sub: &'a str,
    user_id: Uuid,
    /// JSON-encoded profile string (matches the TS `upsertOauthProfile(sub, userId, JSON.stringify(profile))` signature).
    profile_json: &'a str,
}

/// Thin HTTP client for the user-data-service routes used by claim-based
/// user resolution.
#[derive(Clone)]
pub struct UserDataServiceClient {
    base_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl UserDataServiceClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self::with_client(base_url, api_key, reqwest::Client::new())
    }

    pub fn with_client(
        base_url: impl Into<String>,
        api_key: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            api_key,
            client,
        }
    }

    fn req(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(key) if !key.is_empty() => builder.header("X-Api-Key", key),
            _ => builder,
        }
    }

    /// `GET /api/user/byEmail?email=…` — returns `Some(user)` on 200,
    /// `None` on 204.
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<UserResponse>> {
        let url = format!("{}/api/user/byEmail", self.base_url);
        let resp = self
            .req(self.client.get(&url).query(&[("email", email)]))
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status().as_u16() == 204 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(anyhow!(
                "user-data-service GET byEmail returned {}",
                resp.status()
            ));
        }
        Ok(Some(resp.json().await.context("parse User response")?))
    }

    /// `POST /api/user` — returns the created user.
    pub async fn create_user(&self, email: &str, name: Option<&str>) -> Result<UserResponse> {
        let url = format!("{}/api/user", self.base_url);
        let body = CreateUserRequest { email, name };
        let resp = self
            .req(self.client.post(&url).json(&body))
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "user-data-service POST /api/user returned {}",
                resp.status()
            ));
        }
        resp.json().await.context("parse created User")
    }

    /// `GET /api/oauthProfile/bySub?sub=…` — returns `Some(profile)` on 200,
    /// `None` on 204.
    pub async fn get_oauth_profile_by_sub(&self, sub: &str) -> Result<Option<OauthProfileRow>> {
        let url = format!("{}/api/oauthProfile/bySub", self.base_url);
        let resp = self
            .req(self.client.get(&url).query(&[("sub", sub)]))
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status().as_u16() == 204 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(anyhow!(
                "user-data-service GET oauthProfile/bySub returned {}",
                resp.status()
            ));
        }
        Ok(Some(
            resp.json().await.context("parse OauthProfile response")?,
        ))
    }

    /// `PUT /api/oauthProfile` — upsert the OAuth profile by `sub`.
    pub async fn upsert_oauth_profile(
        &self,
        sub: &str,
        user_id: Uuid,
        profile_json: &str,
    ) -> Result<()> {
        let url = format!("{}/api/oauthProfile", self.base_url);
        let body = UpsertOauthProfileRequest {
            sub,
            user_id,
            profile_json,
        };
        let resp = self
            .req(self.client.put(&url).json(&body))
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "user-data-service PUT /api/oauthProfile returned {}",
                resp.status()
            ));
        }
        Ok(())
    }
}
