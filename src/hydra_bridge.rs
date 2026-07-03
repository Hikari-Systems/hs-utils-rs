//! Ory Hydra login/consent/logout **provider** bridge (axum).
//!
//! A login SPA drives Hydra's login/consent/logout challenges through these
//! endpoints; this bridge resolves the logged-in identity from Kratos and
//! accepts (or rejects) the challenge via Hydra's admin API, injecting the
//! namespaced + scope-mapped OIDC claims into the issued tokens.
//!
//! This is the reusable, axum port of the hand-rolled bridge in
//! `hs-login-controller` (actix). Mount it on a PUBLIC path — these routes are
//! called mid-login, before a session cookie exists, so they must NOT sit
//! behind the login gate.
//!
//! Routes (full paths, to match the `/api/oauth/*` SPA contract):
//! - `GET  /api/oauth/login?challenge=`      — fetch/accept the Hydra login request
//! - `POST /api/oauth/login/accept`          — accept login for the current session
//! - `GET  /api/oauth/consent?challenge=`    — introspect (or auto-skip) consent
//! - `POST /api/oauth/consent`               — accept/deny consent (`action`)
//! - `POST /api/oauth/logout/accept`         — accept the Hydra logout request

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tracing::warn;

/// Bridge configuration. All URLs are service-internal (Hydra/Kratos admin +
/// Kratos public); `accounts_host`/`auth_host` are the public auth hosts used
/// to build the re-authentication redirect when there is no Kratos session.
#[derive(Clone, Debug)]
pub struct HydraBridgeConfig {
    pub hydra_admin_url: String,
    pub kratos_public_url: String,
    pub kratos_admin_url: String,
    pub accounts_host: String,
    pub auth_host: String,
    pub claims_namespace: String,
}

/// Cheap-to-clone bridge handle (shared config + pooled HTTP client).
#[derive(Clone)]
pub struct HydraBridge {
    cfg: Arc<HydraBridgeConfig>,
    http: Client,
}

impl HydraBridge {
    pub fn new(cfg: HydraBridgeConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            http: Client::new(),
        }
    }

    /// Router serving `/api/oauth/{login,consent,logout}`. Mount on a PUBLIC
    /// path (merge into the top-level app, NOT behind the login gate) — these
    /// endpoints are hit mid-login before a session exists.
    pub fn router(self) -> Router {
        Router::new()
            .route("/api/oauth/login", get(get_login))
            .route("/api/oauth/login/accept", post(post_login_accept))
            .route(
                "/api/oauth/consent",
                get(get_consent).post(post_consent),
            )
            .route("/api/oauth/logout/accept", post(post_logout_accept))
            .with_state(self)
    }

    fn hydra(&self, path: &str) -> String {
        format!("{}{path}", self.cfg.hydra_admin_url.trim_end_matches('/'))
    }

    fn kratos_public(&self, path: &str) -> String {
        format!("{}{path}", self.cfg.kratos_public_url.trim_end_matches('/'))
    }

    fn kratos_admin(&self, path: &str) -> String {
        format!("{}{path}", self.cfg.kratos_admin_url.trim_end_matches('/'))
    }

    // ── Hydra v2 admin API ──────────────────────────────────────────────────

    async fn get_login_request(&self, challenge: &str) -> Result<LoginRequest> {
        let resp = self
            .http
            .get(self.hydra("/admin/oauth2/auth/requests/login"))
            .query(&[("login_challenge", challenge)])
            .send()
            .await
            .context("Hydra getOAuth2LoginRequest failed")?;
        ensure_ok(resp.status(), "getOAuth2LoginRequest")?;
        resp.json().await.context("Hydra login request decode")
    }

    async fn accept_login_request(
        &self,
        challenge: &str,
        body: &AcceptLoginBody<'_>,
    ) -> Result<RedirectTo> {
        let resp = self
            .http
            .put(self.hydra("/admin/oauth2/auth/requests/login/accept"))
            .query(&[("login_challenge", challenge)])
            .json(body)
            .send()
            .await
            .context("Hydra acceptOAuth2LoginRequest failed")?;
        ensure_ok(resp.status(), "acceptOAuth2LoginRequest")?;
        resp.json().await.context("Hydra accept-login decode")
    }

    async fn get_consent_request(&self, challenge: &str) -> Result<ConsentRequest> {
        let resp = self
            .http
            .get(self.hydra("/admin/oauth2/auth/requests/consent"))
            .query(&[("consent_challenge", challenge)])
            .send()
            .await
            .context("Hydra getOAuth2ConsentRequest failed")?;
        ensure_ok(resp.status(), "getOAuth2ConsentRequest")?;
        resp.json().await.context("Hydra consent request decode")
    }

    async fn accept_consent_request(
        &self,
        challenge: &str,
        body: &AcceptConsentBody,
    ) -> Result<RedirectTo> {
        let resp = self
            .http
            .put(self.hydra("/admin/oauth2/auth/requests/consent/accept"))
            .query(&[("consent_challenge", challenge)])
            .json(body)
            .send()
            .await
            .context("Hydra acceptOAuth2ConsentRequest failed")?;
        ensure_ok(resp.status(), "acceptOAuth2ConsentRequest")?;
        resp.json().await.context("Hydra accept-consent decode")
    }

    async fn reject_consent_request(
        &self,
        challenge: &str,
        body: &RejectBody,
    ) -> Result<RedirectTo> {
        let resp = self
            .http
            .put(self.hydra("/admin/oauth2/auth/requests/consent/reject"))
            .query(&[("consent_challenge", challenge)])
            .json(body)
            .send()
            .await
            .context("Hydra rejectOAuth2ConsentRequest failed")?;
        ensure_ok(resp.status(), "rejectOAuth2ConsentRequest")?;
        resp.json().await.context("Hydra reject-consent decode")
    }

    async fn accept_logout_request(&self, challenge: &str) -> Result<RedirectTo> {
        let resp = self
            .http
            .put(self.hydra("/admin/oauth2/auth/requests/logout/accept"))
            .query(&[("logout_challenge", challenge)])
            .send()
            .await
            .context("Hydra acceptOAuth2LogoutRequest failed")?;
        ensure_ok(resp.status(), "acceptOAuth2LogoutRequest")?;
        resp.json().await.context("Hydra accept-logout decode")
    }

    // ── Kratos ──────────────────────────────────────────────────────────────

    /// Validate a Kratos session by forwarding the raw `Cookie` header to
    /// `/sessions/whoami`. Returns `None` on any failure (no session, network
    /// error, malformed body) — the caller falls back to the re-auth path.
    async fn whoami(&self, cookie: Option<&str>) -> Option<Session> {
        let cookie = cookie?;
        if cookie.is_empty() {
            return None;
        }
        let resp = self
            .http
            .get(self.kratos_public("/sessions/whoami"))
            .header("cookie", cookie)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<Session>().await.ok()
    }

    async fn get_identity(&self, id: &str) -> Result<Identity> {
        let resp = self
            .http
            .get(self.kratos_admin(&format!("/admin/identities/{id}")))
            .send()
            .await
            .context("Kratos getIdentity failed")?;
        ensure_ok(resp.status(), "getIdentity")?;
        resp.json().await.context("Kratos identity decode")
    }
}

// ── Route handlers ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ChallengeQuery {
    #[serde(default)]
    challenge: String,
}

#[derive(Deserialize)]
struct ChallengeBody {
    #[serde(default)]
    challenge: String,
}

#[derive(Deserialize)]
struct ConsentBody {
    #[serde(default)]
    challenge: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    remember: bool,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

fn cookie_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("cookie").and_then(|v| v.to_str().ok())
}

async fn get_login(
    State(b): State<HydraBridge>,
    headers: HeaderMap,
    Query(q): Query<ChallengeQuery>,
) -> Response {
    if q.challenge.is_empty() {
        return err(StatusCode::BAD_REQUEST, "missing challenge");
    }

    let login_request = match b.get_login_request(&q.challenge).await {
        Ok(r) => r,
        Err(e) => {
            warn!("get_login: hydra get failed: {e:#}");
            return internal_err(&e);
        }
    };

    if login_request.skip {
        return match b
            .accept_login_request(
                &q.challenge,
                &AcceptLoginBody {
                    subject: &login_request.subject,
                    remember: false,
                    remember_for: 0,
                },
            )
            .await
        {
            Ok(accept) => Json(accept).into_response(),
            Err(e) => {
                warn!("get_login (skip): hydra accept failed: {e:#}");
                internal_err(&e)
            }
        };
    }

    let session = b.whoami(cookie_header(&headers)).await;
    let identity_id = session
        .as_ref()
        .and_then(|s| s.identity.as_ref().map(|i| i.id.clone()));

    let Some(identity_id) = identity_id else {
        let return_to = format!(
            "{}/oauth/login?login_challenge={}",
            b.cfg.auth_host, q.challenge
        );
        return Json(json!({
            "requireAuth": true,
            "returnTo": return_to,
            "accountsLoginUrl": format!("{}/login", b.cfg.accounts_host),
        }))
        .into_response();
    };

    match b
        .accept_login_request(
            &q.challenge,
            &AcceptLoginBody {
                subject: &identity_id,
                remember: true,
                remember_for: 3600,
            },
        )
        .await
    {
        Ok(accept) => Json(accept).into_response(),
        Err(e) => {
            warn!("get_login (session): hydra accept failed: {e:#}");
            internal_err(&e)
        }
    }
}

async fn post_login_accept(
    State(b): State<HydraBridge>,
    headers: HeaderMap,
    Json(body): Json<ChallengeBody>,
) -> Response {
    if body.challenge.is_empty() {
        return err(StatusCode::BAD_REQUEST, "missing challenge");
    }

    let identity_id = match b
        .whoami(cookie_header(&headers))
        .await
        .and_then(|s| s.identity.map(|i| i.id))
    {
        Some(id) => id,
        None => return err(StatusCode::UNAUTHORIZED, "no kratos session"),
    };

    match b
        .accept_login_request(
            &body.challenge,
            &AcceptLoginBody {
                subject: &identity_id,
                remember: true,
                remember_for: 3600,
            },
        )
        .await
    {
        Ok(accept) => Json(accept).into_response(),
        Err(e) => {
            warn!("post_login_accept: hydra accept failed: {e:#}");
            internal_err(&e)
        }
    }
}

async fn get_consent(
    State(b): State<HydraBridge>,
    Query(q): Query<ChallengeQuery>,
) -> Response {
    if q.challenge.is_empty() {
        return err(StatusCode::BAD_REQUEST, "missing challenge");
    }

    let consent = match b.get_consent_request(&q.challenge).await {
        Ok(r) => r,
        Err(e) => {
            warn!("get_consent: hydra get failed: {e:#}");
            return internal_err(&e);
        }
    };

    let Some(subject) = consent.subject.as_deref() else {
        return err(StatusCode::BAD_REQUEST, "consent request has no subject");
    };

    let identity = match b.get_identity(subject).await {
        Ok(i) => i,
        Err(e) => {
            warn!("get_consent: kratos getIdentity failed: {e:#}");
            return internal_err(&e);
        }
    };

    let grant_scope = consent.requested_scope.clone();
    let grant_audience = consent.requested_access_token_audience.clone();
    let skip_consent = consent
        .client
        .get("skip_consent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if consent.skip || skip_consent {
        let claims = build_claims(
            &identity.traits,
            identity.metadata_public.as_ref(),
            &b.cfg.claims_namespace,
            &grant_scope,
        );
        let accept_body = AcceptConsentBody {
            grant_scope,
            grant_access_token_audience: grant_audience,
            session: AcceptConsentSession {
                access_token: claims.clone(),
                id_token: claims,
            },
            remember: true,
            remember_for: 3600,
        };
        return match b.accept_consent_request(&q.challenge, &accept_body).await {
            Ok(accept) => Json(accept).into_response(),
            Err(e) => {
                warn!("get_consent (skip): hydra accept failed: {e:#}");
                internal_err(&e)
            }
        };
    }

    Json(json!({
        "challenge": q.challenge,
        "client": consent.client,
        "requested_scope": grant_scope,
        "requested_access_token_audience": grant_audience,
        "identity": { "id": identity.id, "traits": identity.traits },
        "skip": false,
    }))
    .into_response()
}

async fn post_consent(
    State(b): State<HydraBridge>,
    Json(body): Json<ConsentBody>,
) -> Response {
    if body.challenge.is_empty() {
        return err(StatusCode::BAD_REQUEST, "missing challenge");
    }

    let consent = match b.get_consent_request(&body.challenge).await {
        Ok(r) => r,
        Err(e) => {
            warn!("post_consent: hydra get failed: {e:#}");
            return internal_err(&e);
        }
    };

    if body.action == "deny" {
        return match b
            .reject_consent_request(
                &body.challenge,
                &RejectBody {
                    error: "access_denied",
                    error_description: "user rejected consent",
                },
            )
            .await
        {
            Ok(reject) => Json(reject).into_response(),
            Err(e) => {
                warn!("post_consent (deny): hydra reject failed: {e:#}");
                internal_err(&e)
            }
        };
    }

    let Some(subject) = consent.subject.as_deref() else {
        return err(StatusCode::BAD_REQUEST, "consent request has no subject");
    };

    let identity = match b.get_identity(subject).await {
        Ok(i) => i,
        Err(e) => {
            warn!("post_consent: kratos getIdentity failed: {e:#}");
            return internal_err(&e);
        }
    };

    let grant_scope = body
        .scopes
        .clone()
        .unwrap_or_else(|| consent.requested_scope.clone());
    let grant_audience = consent.requested_access_token_audience.clone();

    let claims = build_claims(
        &identity.traits,
        identity.metadata_public.as_ref(),
        &b.cfg.claims_namespace,
        &grant_scope,
    );

    let accept_body = AcceptConsentBody {
        grant_scope,
        grant_access_token_audience: grant_audience,
        session: AcceptConsentSession {
            access_token: claims.clone(),
            id_token: claims,
        },
        remember: body.remember,
        remember_for: 3600,
    };

    match b.accept_consent_request(&body.challenge, &accept_body).await {
        Ok(accept) => Json(accept).into_response(),
        Err(e) => {
            warn!("post_consent: hydra accept failed: {e:#}");
            internal_err(&e)
        }
    }
}

async fn post_logout_accept(
    State(b): State<HydraBridge>,
    Json(body): Json<ChallengeBody>,
) -> Response {
    if body.challenge.is_empty() {
        return err(StatusCode::BAD_REQUEST, "missing challenge");
    }
    match b.accept_logout_request(&body.challenge).await {
        Ok(accept) => Json(accept).into_response(),
        Err(e) => {
            warn!("post_logout_accept: hydra accept failed: {e:#}");
            internal_err(&e)
        }
    }
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn internal_err(e: &anyhow::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(default)]
    skip: bool,
    #[serde(default)]
    subject: String,
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    #[serde(default)]
    skip: bool,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    client: Value,
    #[serde(default)]
    requested_scope: Vec<String>,
    #[serde(default)]
    requested_access_token_audience: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RedirectTo {
    redirect_to: String,
}

#[derive(Debug, Serialize)]
struct AcceptLoginBody<'a> {
    subject: &'a str,
    remember: bool,
    remember_for: i64,
}

#[derive(Debug, Serialize)]
struct AcceptConsentSession {
    access_token: Value,
    id_token: Value,
}

#[derive(Debug, Serialize)]
struct AcceptConsentBody {
    grant_scope: Vec<String>,
    grant_access_token_audience: Vec<String>,
    session: AcceptConsentSession,
    remember: bool,
    remember_for: i64,
}

#[derive(Debug, Serialize)]
struct RejectBody {
    error: &'static str,
    error_description: &'static str,
}

#[derive(Debug, Deserialize)]
struct Session {
    #[serde(default)]
    identity: Option<Identity>,
}

#[derive(Debug, Deserialize, Clone)]
struct Identity {
    id: String,
    #[serde(default = "Value::default")]
    traits: Value,
    #[serde(default)]
    metadata_public: Option<Value>,
}

/// Build the claims object inserted into the Hydra access/id token session.
///
/// Namespaced claims (always): `{ns}email`, `{ns}name`, `{ns}pictureId`,
/// `{ns}terms`. Standard OIDC claims gated on granted scope: `email` scope →
/// `email`; `profile` scope → `name`. `picture` is intentionally excluded.
fn build_claims(
    traits: &Value,
    metadata_public: Option<&Value>,
    namespace: &str,
    granted_scopes: &[String],
) -> Value {
    let mut out = Map::new();

    out.insert(format!("{namespace}email"), trait_str(traits, "email"));
    out.insert(format!("{namespace}name"), trait_str(traits, "name"));
    out.insert(
        format!("{namespace}pictureId"),
        trait_str(traits, "pictureId"),
    );
    out.insert(
        format!("{namespace}terms"),
        metadata_public
            .and_then(|m| m.get("terms").cloned())
            .unwrap_or(Value::Null),
    );

    let has_scope = |s: &str| granted_scopes.iter().any(|x| x == s);
    if has_scope("email") {
        let email = trait_str(traits, "email");
        if !email.is_null() {
            out.insert("email".to_string(), email);
        }
    }
    if has_scope("profile") {
        let name = trait_str(traits, "name");
        if !name.is_null() {
            out.insert("name".to_string(), name);
        }
    }

    Value::Object(out)
}

fn trait_str(traits: &Value, key: &str) -> Value {
    match traits.get(key) {
        Some(Value::String(s)) => Value::String(s.clone()),
        _ => Value::Null,
    }
}

fn ensure_ok(status: reqwest::StatusCode, op: &str) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("{op}: upstream returned {status}"))
    }
}
