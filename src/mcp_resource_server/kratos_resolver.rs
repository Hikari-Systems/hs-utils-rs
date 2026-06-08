//! Kratos-backed MCP user resolver.
//!
//! Mirrors the TypeScript `@hikari-systems/hs.utils`
//! `lib/mcp-auth/kratosResolver.ts:createKratosUserResolver` line-for-line:
//!   1. Read `sub` off the verified JWT payload (non-empty string) — else
//!      skip resolution.
//!   2. 5-minute TTL cache keyed by `sub`.
//!   3. Primary path: namespaced Kratos claims injected by the Hydra
//!      consent app (`${ns}email` / `${ns}name` / `${ns}pictureId`).
//!   4. Fallback path (on by default): if the claim-derived profile has no
//!      email/name/picture, `GET {kratosAdminUrl}/admin/identities/{sub}`
//!      and fill from the identity traits.
//!   5. `user_id == sub` (the Kratos identity id is the internal user id).
//!      No user-data-service upsert.
//!
//! This is the *only* user-resolution path in the Rust resource server;
//! the legacy user-data-service-backed resolver was removed (parity with
//! the TS `bioalphaengine-mcp` under Hydra+Kratos).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::Deserialize;
use serde_json::Value;

use super::claims::{read_kratos_claims, OauthProfile};

const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const CACHE_MAX_ENTRIES: u64 = 10_000;

/// Resolved user: the Kratos identity id (`sub`) and the derived profile.
/// Mirrors the TS `McpResolvedUser { userId: string, profile }`.
#[derive(Debug, Clone)]
pub struct ResolvedUser {
    pub user_id: String,
    pub profile: OauthProfile,
}

/// Minimal subset of a Kratos admin identity we need to fill a profile.
#[derive(Debug, Clone, Deserialize)]
pub struct KratosIdentity {
    #[allow(dead_code)]
    pub id: String,
    #[serde(default)]
    pub traits: Option<KratosTraits>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KratosTraits {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
    #[serde(default, rename = "pictureId")]
    pub picture_id: Option<String>,
}

/// Seam over the Kratos admin identity lookup so the resolver is unit
/// testable without a live Kratos (production impl is reqwest-backed).
pub trait KratosIdentityFetcher: Send + Sync {
    fn fetch<'a>(
        &'a self,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<KratosIdentity>> + Send + 'a>>;
}

/// Production fetcher: `GET {admin_url}/admin/identities/{sub}`.
#[derive(Clone)]
pub struct ReqwestKratosFetcher {
    admin_url: String,
    client: reqwest::Client,
}

impl ReqwestKratosFetcher {
    pub fn new(admin_url: impl Into<String>) -> Self {
        Self::with_client(admin_url, reqwest::Client::new())
    }

    pub fn with_client(admin_url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            admin_url: admin_url.into().trim_end_matches('/').to_string(),
            client,
        }
    }

    /// `GET {admin_url}/admin/identities/{id}` returning the raw identity JSON.
    /// `None` on 404 or any error. Unlike [`KratosIdentityFetcher::fetch`], this
    /// keeps the full document (`schema_id`, `state`, `metadata_public`,
    /// `metadata_admin`, `traits`) so callers that need to read or round-trip the
    /// whole identity (e.g. a `metadata_public` writer) can do so without a
    /// second GET. Reuses this fetcher's client + admin URL + path encoding.
    pub async fn fetch_raw(&self, id: &str) -> Option<serde_json::Value> {
        let url = format!("{}/admin/identities/{}", self.admin_url, encode_segment(id));
        let resp = match self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::error!("Kratos identity lookup {id} failed: {err}");
                return None;
            }
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return None;
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                "Kratos identity lookup {id} → {status}: {}",
                body.chars().take(200).collect::<String>()
            );
            return None;
        }
        match resp.json::<serde_json::Value>().await {
            Ok(v) => Some(v),
            Err(err) => {
                tracing::error!("Kratos identity {id} body parse failed: {err}");
                None
            }
        }
    }
}

// Percent-encode a path segment (mirrors TS `encodeURIComponent`). Kratos
// identity ids are UUIDs in practice, but stay faithful to the reference.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl KratosIdentityFetcher for ReqwestKratosFetcher {
    fn fetch<'a>(
        &'a self,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<KratosIdentity>> + Send + 'a>> {
        Box::pin(async move {
            let url = format!(
                "{}/admin/identities/{}",
                self.admin_url,
                encode_segment(id)
            );
            let resp = match self
                .client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    tracing::error!("Kratos identity lookup {id} failed: {err}");
                    return None;
                }
            };
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return None;
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    "Kratos identity lookup {id} → {status}: {}",
                    body.chars().take(200).collect::<String>()
                );
                return None;
            }
            match resp.json::<KratosIdentity>().await {
                Ok(identity) => Some(identity),
                Err(err) => {
                    tracing::error!("Kratos identity {id} body parse failed: {err}");
                    None
                }
            }
        })
    }
}

/// MCP user resolver that derives the user from the verified JWT against
/// Ory Kratos. Construct once at startup; clone is cheap (all `Arc`s).
pub struct KratosUserResolver {
    fetcher: Arc<dyn KratosIdentityFetcher>,
    namespace: String,
    fallback: bool,
    cache: Cache<String, ResolvedUser>,
}

impl KratosUserResolver {
    /// Production constructor: reqwest-backed Kratos admin fetcher.
    /// `admin_url` is the Kratos *admin* API base (e.g.
    /// `http://kratos:4434`). `fallback` mirrors the TS
    /// `fallbackToKratosAdmin` (default `true`).
    pub fn new(
        admin_url: impl Into<String>,
        namespace: impl Into<String>,
        fallback: bool,
    ) -> Self {
        Self::with_fetcher(
            Arc::new(ReqwestKratosFetcher::new(admin_url)),
            namespace,
            fallback,
        )
    }

    /// Construct with an explicit identity fetcher (test seam).
    pub fn with_fetcher(
        fetcher: Arc<dyn KratosIdentityFetcher>,
        namespace: impl Into<String>,
        fallback: bool,
    ) -> Self {
        Self {
            fetcher,
            namespace: namespace.into(),
            fallback,
            cache: Cache::builder()
                .time_to_live(CACHE_TTL)
                .max_capacity(CACHE_MAX_ENTRIES)
                .build(),
        }
    }

    /// Resolve a verified JWT payload to `{ user_id, profile }`. Returns
    /// `None` only when `sub` is absent/empty (never for a well-formed
    /// JWT). Mirrors `kratosResolver.ts` `resolve`.
    pub async fn resolve(&self, payload: &Value) -> Option<ResolvedUser> {
        let sub = payload.get("sub").and_then(Value::as_str)?;
        if sub.is_empty() {
            tracing::warn!("JWT missing sub; skipping user resolution");
            return None;
        }

        if let Some(cached) = self.cache.get(sub).await {
            return Some(cached);
        }

        let kc = read_kratos_claims(payload, &self.namespace);
        let mut profile = OauthProfile {
            sub: sub.to_string(),
            email: kc.email,
            name: kc.name,
            picture: kc.picture_image_service_id,
            email_verified: None,
        };

        let needs_fallback = self.fallback
            && profile.email.is_none()
            && profile.name.is_none()
            && profile.picture.is_none();
        if needs_fallback {
            if let Some(identity) = self.fetcher.fetch(sub).await {
                let t = identity.traits.unwrap_or_default();
                profile.email = t.email.or(profile.email);
                profile.name = t.name.or(profile.name);
                profile.picture = t.picture_id.or(t.picture).or(profile.picture);
            }
        }

        let result = ResolvedUser {
            user_id: sub.to_string(),
            profile,
        };
        self.cache.insert(sub.to_string(), result.clone()).await;
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NS: &str = "https://hikari-systems.com/";

    struct StubFetcher {
        identity: Option<KratosIdentity>,
        calls: AtomicUsize,
    }
    impl StubFetcher {
        fn new(identity: Option<KratosIdentity>) -> Arc<Self> {
            Arc::new(Self {
                identity,
                calls: AtomicUsize::new(0),
            })
        }
    }
    impl KratosIdentityFetcher for StubFetcher {
        fn fetch<'a>(
            &'a self,
            _id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<KratosIdentity>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let id = self.identity.clone();
            Box::pin(async move { id })
        }
    }

    fn resolver(fetcher: Arc<dyn KratosIdentityFetcher>, fallback: bool) -> KratosUserResolver {
        KratosUserResolver::with_fetcher(fetcher, NS, fallback)
    }

    #[tokio::test]
    async fn missing_sub_returns_none() {
        let r = resolver(StubFetcher::new(None), true);
        assert!(r.resolve(&json!({})).await.is_none());
    }

    #[tokio::test]
    async fn empty_sub_returns_none() {
        let r = resolver(StubFetcher::new(None), true);
        assert!(r.resolve(&json!({ "sub": "" })).await.is_none());
    }

    #[tokio::test]
    async fn profile_from_claims_no_fallback_call() {
        let fetcher = StubFetcher::new(None);
        let r = resolver(fetcher.clone(), true);
        let payload = json!({
            "sub": "id-123",
            "https://hikari-systems.com/email": "a@b.com",
            "https://hikari-systems.com/name": "Ada",
            "https://hikari-systems.com/pictureId": "pic-uuid",
        });
        let u = r.resolve(&payload).await.unwrap();
        assert_eq!(u.user_id, "id-123");
        assert_eq!(u.profile.sub, "id-123");
        assert_eq!(u.profile.email.as_deref(), Some("a@b.com"));
        assert_eq!(u.profile.name.as_deref(), Some("Ada"));
        assert_eq!(u.profile.picture.as_deref(), Some("pic-uuid"));
        assert!(u.profile.email_verified.is_none());
        // Claims present → no Kratos admin fallback.
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fallback_fills_from_traits_when_claims_empty() {
        let identity = KratosIdentity {
            id: "id-9".into(),
            traits: Some(KratosTraits {
                email: Some("k@kratos".into()),
                name: Some("Grace".into()),
                picture: None,
                picture_id: Some("pid-9".into()),
            }),
        };
        let fetcher = StubFetcher::new(Some(identity));
        let r = resolver(fetcher.clone(), true);
        let u = r.resolve(&json!({ "sub": "id-9" })).await.unwrap();
        assert_eq!(u.user_id, "id-9");
        assert_eq!(u.profile.email.as_deref(), Some("k@kratos"));
        assert_eq!(u.profile.name.as_deref(), Some("Grace"));
        // picture_id wins over picture.
        assert_eq!(u.profile.picture.as_deref(), Some("pid-9"));
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fallback_404_yields_sub_only_profile() {
        // Fetcher returns None (mirrors a 404). Profile keeps just the sub.
        let fetcher = StubFetcher::new(None);
        let r = resolver(fetcher.clone(), true);
        let u = r.resolve(&json!({ "sub": "id-x" })).await.unwrap();
        assert_eq!(u.user_id, "id-x");
        assert_eq!(u.profile.sub, "id-x");
        assert!(u.profile.email.is_none());
        assert!(u.profile.name.is_none());
        assert!(u.profile.picture.is_none());
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fallback_disabled_skips_admin_lookup() {
        let fetcher = StubFetcher::new(None);
        let r = resolver(fetcher.clone(), false);
        r.resolve(&json!({ "sub": "id-2" })).await.unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn second_call_is_cache_hit() {
        let fetcher = StubFetcher::new(None);
        let r = resolver(fetcher.clone(), true);
        let p = json!({ "sub": "id-cache" });
        r.resolve(&p).await.unwrap();
        r.resolve(&p).await.unwrap();
        // Fallback fetch only happened on the first (uncached) resolve.
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }
}
