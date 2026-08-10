//! Browser (Authorization-Code) OAuth2 login with a cookie session, backed by
//! Ory Kratos for user data.
//!
//! Rust port of `@hikari-systems/hs.utils` `lib/oauth2.ts` +
//! `lib/oauth2-kratos.ts` (`authorizeKratosMiddleware`). The flow:
//!   1. An un-authenticated request to a protected route is redirected to the
//!      provider's `authorize` endpoint (`response_type=code`), with a random
//!      `state` → original URL stored in the session.
//!   2. The provider redirects back to `{callback_uri}` with `code`+`state`.
//!      [`callback`] exchanges the code for tokens
//!      ([`do_token_exchange`]), fetches userinfo
//!      ([`get_oauth_profile_by_token`]), resolves `{ sub, profile }` from
//!      Kratos via the reused [`KratosUserResolver`], stores `session.user`,
//!      and redirects to the original URL.
//!   3. Subsequent requests carry the session cookie and pass straight through.
//!
//! Kratos is the source of truth (no user-data-service rows): the Kratos
//! identity id (= `sub`) is the canonical user id.
//!
//! Unlike the TS `pathConfigs` regex whitelist, the gate is *layered only on
//! the protected routes* (idiomatic axum) — public routes simply aren't
//! wrapped. Mount [`WebLogin::callback_router`] (public) and apply
//! [`WebLogin::gate_state`] + [`gate`] via `from_fn_with_state` to the routes
//! you want behind login.
//!
//! # Session storage
//!
//! Both the OAuth `state → original-URL` map and the post-login session are
//! held in a [`WebSessionStore`], keyed by the `hs_session` cookie. The
//! default ([`InMemorySessionStore`]) keeps them in this process's memory —
//! correct for a single replica, but it breaks behind a load balancer: the
//! `gate` that starts the flow and the `callback` that finishes it can land on
//! different replicas, so the callback finds "no stored state" and 400s. For a
//! multi-replica deployment construct [`WebLogin::with_store`] with a shared
//! store (see the `web-login-redis` feature's `RedisSessionStore`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::Instrument as _;

use crate::mcp_resource_server::kratos_resolver::KratosUserResolver;

/// Default session TTL (24h) used by [`WebLogin::new`]'s in-memory store.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Token endpoint response (RFC 6749). Mirrors the TS `TokenResponse`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// Configuration mirroring the TS `oauth2:*` config keys.
#[derive(Debug, Clone)]
pub struct WebLoginConfig {
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub profile_url: String,
    pub scopes: String,
    /// Path the provider redirects back to. Default `/oauth2/callback`.
    pub callback_uri: String,
    /// Session cookie name. Default `hs_session`.
    pub cookie_name: String,
}

impl WebLoginConfig {
    /// Construct with the standard defaults (`callback_uri=/oauth2/callback`,
    /// `cookie_name=hs_session`). The browser-facing origin (for `redirect_uri`
    /// and the cookie `Secure` attribute) is derived per-request from the
    /// trusted edge's `X-Forwarded-*` headers — never hard-coded here.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        profile_url: impl Into<String>,
        scopes: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            profile_url: profile_url.into(),
            scopes: scopes.into(),
            callback_uri: "/oauth2/callback".to_string(),
            cookie_name: "hs_session".to_string(),
        }
    }
}

/// One server-side session, keyed by the `sid` cookie. Mirrors the express
/// `req.session` used by the TS middleware. Serializable so it can live in a
/// shared store (e.g. redis) and be restored on any replica.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    profile: Option<Value>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    /// OIDC id_token captured at login, for RP-initiated logout (`id_token_hint`).
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    /// `state` → original URL, set at redirect time, consumed at callback.
    #[serde(default)]
    redirects: HashMap<String, String>,
}

/// Pluggable backing store for [`Session`]s, keyed by the `sid` cookie.
///
/// `Ok(None)` from [`load`](WebSessionStore::load) means the session is absent;
/// an `Err` means the backend could not be asked, which is a different thing and
/// the caller decides what it costs. Implementations are responsible for expiry
/// (TTL).
///
/// **The error is opaque.** Every implementation logs its own cause first, with
/// HIK-236's fields (`session.store` / `session.op` / `error.message`), so a
/// caller is not expected to inspect the value — its whole question is the
/// boolean "did that land?". That is also why this is `anyhow::Result` and not a
/// typed enum: an enum nobody matches on looks like a guarantee it is not making,
/// which is the shape this signature exists to remove.
///
/// **Returning `()` was not "best effort", it was a claim nobody could check.**
/// `callback` rotates the session id by storing the new row and then removing the
/// old one, and it did both regardless of whether the first succeeded — so a
/// store failure between them handed the browser a cookie naming a row that was
/// never written, logging the user out at the moment they logged in and bouncing
/// them back to the IdP.
///
/// Fail-open is still right where the answer to an unreadable row is the same as
/// the answer to an absent one, and wrong where a write is what makes the next
/// request work. **In this file the first group is every read except
/// `callback`'s two** — the gate's, `access_token`'s, `id_token`'s and
/// `end_session`'s, the last so that a lost `id_token_hint` cannot stop the
/// destroy beneath it from being attempted. Stated as the rule rather than as a
/// count, because a list of sites goes stale on the next one added and this
/// enumeration was already short by `end_session` once. (`access_token`'s two
/// write-backs are non-fatal for the mirror-image reason, given at the site:
/// nothing's next request depends on them.)
///
/// Read that narrowly: it is a statement about individual call sites, **not** a
/// promise that a store outage keeps a service serving. The gate's read failing
/// open only reaches the branch below it, and on the browser tier that branch
/// writes, fatally. The posture is per call site, and each one says which it
/// took and why.
#[async_trait]
pub trait WebSessionStore: Send + Sync {
    async fn load(&self, sid: &str) -> anyhow::Result<Option<Session>>;
    async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()>;
    async fn remove(&self, sid: &str) -> anyhow::Result<()>;
}

/// In-process [`WebSessionStore`] (a `HashMap` with lazy TTL eviction). The
/// default; fine for a single replica. NOT shared across replicas — see the
/// module docs.
pub struct InMemorySessionStore {
    map: Mutex<HashMap<String, (Session, Instant)>>,
    ttl: Duration,
}

impl InMemorySessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            ttl,
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_SESSION_TTL_SECS))
    }
}

/// Infallible in practice — a `HashMap` behind a `Mutex` has nothing to fail —
/// so every method answers `Ok`. The signature is the trait's, which exists for
/// the stores that reach the network.
#[async_trait]
impl WebSessionStore for InMemorySessionStore {
    async fn load(&self, sid: &str) -> anyhow::Result<Option<Session>> {
        let mut map = self.map.lock().unwrap();
        Ok(match map.get(sid) {
            Some((s, exp)) if *exp > Instant::now() => Some(s.clone()),
            Some(_) => {
                map.remove(sid);
                None
            }
            None => None,
        })
    }

    async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()> {
        self.map
            .lock()
            .unwrap()
            .insert(sid.to_string(), (session.clone(), Instant::now() + self.ttl));
        Ok(())
    }

    async fn remove(&self, sid: &str) -> anyhow::Result<()> {
        self.map.lock().unwrap().remove(sid);
        Ok(())
    }
}

/// The logged-in user, inserted into request extensions by [`gate`] so
/// downstream handlers can read who is authenticated.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub user_id: String,
    pub profile: Option<Value>,
}

/// Browser-login service. Clone is cheap (all `Arc`s + a `reqwest::Client`).
#[derive(Clone)]
pub struct WebLogin {
    cfg: Arc<WebLoginConfig>,
    store: Arc<dyn WebSessionStore>,
    resolver: Arc<KratosUserResolver>,
    http: reqwest::Client,
}

/// State for the [`gate`] middleware (carries the per-route `fail_fast` flag).
#[derive(Clone)]
pub struct GateState {
    wl: WebLogin,
    fail_fast: bool,
}

impl WebLogin {
    /// Construct with the default in-process [`InMemorySessionStore`]. Use
    /// [`WebLogin::with_store`] for a shared store across replicas.
    pub fn new(cfg: WebLoginConfig, resolver: Arc<KratosUserResolver>) -> Self {
        Self::with_store(
            cfg,
            resolver,
            Arc::new(InMemorySessionStore::default()),
        )
    }

    /// Construct with a caller-supplied [`WebSessionStore`] (e.g. a shared
    /// redis-backed store for a multi-replica deployment).
    pub fn with_store(
        cfg: WebLoginConfig,
        resolver: Arc<KratosUserResolver>,
        store: Arc<dyn WebSessionStore>,
    ) -> Self {
        Self {
            cfg: Arc::new(cfg),
            store,
            resolver,
            http: reqwest::Client::new(),
        }
    }

    /// Router serving the OAuth callback (`GET {callback_uri}`). Mount this on
    /// a public path — it must NOT be behind the gate.
    pub fn callback_router(&self) -> Router {
        Router::new()
            .route(&self.cfg.callback_uri, get(callback))
            .with_state(self.clone())
    }

    /// State to hand to `axum::middleware::from_fn_with_state(.., gate)` when
    /// wrapping protected routes. `fail_fast`: `true` → 401 when not logged in
    /// (for APIs); `false` → 302 redirect to the provider (for browser pages).
    pub fn gate_state(&self, fail_fast: bool) -> GateState {
        GateState {
            wl: self.clone(),
            fail_fast,
        }
    }

    /// The OAuth `redirect_uri`, derived from the request's browser-facing
    /// origin via [`forwarded_for`] (proto/host from the trusted edge's
    /// `X-Forwarded-*` headers — the TS `forwardedFor` behaviour). The app never
    /// hard-codes a public URL; the edge (LB/WAF) is the source of truth.
    fn redirect_uri(&self, headers: &HeaderMap) -> String {
        let base = forwarded_for(headers, "", "").base_url;
        format!("{base}{}", self.cfg.callback_uri)
    }

    fn authorize_url(&self, state_key: &str, headers: &HeaderMap) -> String {
        let redirect_uri = self.redirect_uri(headers);
        reqwest::Url::parse_with_params(
            &self.cfg.authorize_url,
            &[
                ("response_type", "code"),
                ("client_id", self.cfg.client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("state", state_key),
                ("scope", self.cfg.scopes.as_str()),
            ],
        )
        .map(|u| u.to_string())
        .unwrap_or_else(|_| self.cfg.authorize_url.clone())
    }

    /// Current valid access token for a session, refreshing if expired (mirrors
    /// the TS `getAccessToken`). For consumers that need to call downstream
    /// APIs on the user's behalf; not needed for page-access checks.
    pub async fn access_token(&self, sid: &str) -> Option<String> {
        // Fail open, deliberately: this answers "what token may I use for this
        // request?", and a store that cannot be read has no token to offer — the
        // same answer as a session that does not exist. Erroring here would turn
        // a store blip into a failure of every downstream call a consumer makes.
        let mut sess = self.store.load(sid).await.ok().flatten()?;
        let expired = sess.expires_at.map(|e| e <= now_secs()).unwrap_or(false);
        if let Some(tok) = sess.access_token.clone() {
            if !expired {
                return Some(tok);
            }
        }
        if let Some(rt) = sess.refresh_token.clone() {
            if let Ok(t) = do_token_refresh(&self.http, &self.cfg, &rt).await {
                sess.access_token = Some(t.access_token.clone());
                sess.refresh_token = t.refresh_token.clone();
                sess.expires_at = t.expires_in.map(|e| now_secs() + e);
                // Non-fatal: the token in hand is valid for this request whether
                // or not it was persisted. A failed write costs the *next*
                // request one more refresh, which is what a refresh token is
                // for. The store has already logged the cause.
                let _ = self.store.store(sid, &sess).await;
                return Some(t.access_token);
            }
        }
        sess.access_token = None;
        sess.refresh_token = None;
        sess.expires_at = None;
        // Non-fatal for the same reason in the other direction: this write only
        // clears tokens that are already known to be stale, and the caller is
        // told `None` whether or not it landed.
        let _ = self.store.store(sid, &sess).await;
        None
    }

    /// The OIDC `id_token` captured at login, for RP-initiated logout
    /// (`id_token_hint`). Returns `None` when there is no session or it predates
    /// id_token capture.
    pub async fn id_token(&self, sid: &str) -> Option<String> {
        // Fail open: the id_token is a *hint* on the logout redirect. A store
        // that cannot be read costs the IdP the hint, and nothing else.
        self.store.load(sid).await.ok().flatten()?.id_token
    }

    /// End the session: read the `id_token` (for `id_token_hint`), remove the
    /// session from the store, and return the id_token. Use this for logout —
    /// destroy the local session, then redirect to the IdP's RP-initiated logout
    /// endpoint with the returned hint.
    ///
    /// **The `remove` propagates.** Logging out is the one operation whose whole
    /// purpose is the write: a caller that answers "you are logged out" while the
    /// row is still live has told the user something false about a credential
    /// that still works. What to do about it is the caller's to decide — it is
    /// the one holding the response — so the error travels rather than being
    /// swallowed here.
    pub async fn end_session(&self, sid: &str) -> anyhow::Result<Option<String>> {
        // Fail open on the *read* only: the hint is a nicety, and failing to
        // fetch it must not stop the destroy below from being attempted.
        let id_token = self
            .store
            .load(sid)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.id_token);
        self.store.remove(sid).await?;
        Ok(id_token)
    }

    /// A `Set-Cookie` value that clears the session cookie, for a consumer that
    /// destroys a session itself rather than through [`end_session`].
    ///
    /// It exists because building it correctly needs two things that are private
    /// to this module: the configured cookie name, and the `Secure` decision,
    /// which is derived from the trusted edge's `X-Forwarded-Proto` exactly as
    /// [`WebLogin::redirect_uri`] is. A consumer outside the crate cannot reach
    /// either, so every one of them was on course to hard-code `hs_session` and
    /// guess at `Secure` — and a clearing cookie whose attributes do not match
    /// the one that was set does not replace it, it sits beside it.
    pub fn clear_cookie_header(&self, headers: &HeaderMap) -> HeaderValue {
        build_clear_cookie(&self.cfg, request_is_https(headers))
    }
}

// ─── HTTP primitives (ported 1:1 from oauth2.ts) ───────────────────────────

/// RFC 6749 §4.1.3 authorization-code token exchange (form-urlencoded POST).
pub async fn do_token_exchange(
    http: &reqwest::Client,
    cfg: &WebLoginConfig,
    code: &str,
    redirect_uri: &str,
) -> anyhow::Result<TokenResponse> {
    let resp = http
        .post(&cfg.token_url)
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
            ("code", code),
        ])
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json::<TokenResponse>().await?)
}

/// RFC 6749 §6 refresh-token grant (form-urlencoded POST).
pub async fn do_token_refresh(
    http: &reqwest::Client,
    cfg: &WebLoginConfig,
    refresh_token: &str,
) -> anyhow::Result<TokenResponse> {
    let resp = http
        .post(&cfg.token_url)
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json::<TokenResponse>().await?)
}

/// Fetch the userinfo / profile for an access token (`GET profile_url` with a
/// Bearer header). Returns the raw JSON so the Kratos resolver can read the
/// namespaced claims off it.
pub async fn get_oauth_profile_by_token(
    http: &reqwest::Client,
    profile_url: &str,
    access_token: &str,
) -> anyhow::Result<Value> {
    let resp = http
        .get(profile_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json::<Value>().await?)
}

// ─── Forwarded request origin (port of TS `forwardedFor`) ──────────────────

/// Browser-facing origin derived from a request, for building absolute URLs
/// (redirect_uri, post_logout_redirect_uri, …) without a hard-coded public URL.
#[derive(Debug, Clone)]
pub struct ForwardedInfo {
    /// e.g. `https://app.example.com`
    pub base_url: String,
    /// `base_url` + the supplied path-and-query.
    pub full_url: String,
}

/// Port of the TS `forwardedFor(req)`: derive the origin from
/// `X-[prefix]Forwarded-Proto/Port/Host` (falling back to the `Host` header and
/// `http`), suppressing the port for the protocol default. `path_and_query` is
/// appended to form `full_url`. Pass `x_prefix = ""` for the standard headers.
pub fn forwarded_for(headers: &HeaderMap, path_and_query: &str, x_prefix: &str) -> ForwardedInfo {
    let get = |suffix: &str| -> Option<String> {
        let key = format!("x-{x_prefix}forwarded-{suffix}");
        headers.get(&key).and_then(|v| v.to_str().ok()).map(str::to_string)
    };

    let protocol = get("proto").unwrap_or_else(|| "http".to_string());
    let default_port = if protocol == "https" { "443" } else { "80" };
    let port = get("port").unwrap_or_else(|| default_port.to_string());
    let host = get("host")
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()).map(str::to_string))
        .unwrap_or_default();

    let is_standard =
        (protocol == "https" && port == "443") || (protocol == "http" && port == "80");
    let port_suffix = if is_standard { String::new() } else { format!(":{port}") };

    let base_url = format!("{protocol}://{host}{port_suffix}");
    let full_url = format!("{base_url}{path_and_query}");
    ForwardedInfo { base_url, full_url }
}

// ─── Cookie + response helpers ─────────────────────────────────────────────

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Whether the browser-facing request reached the trusted edge over HTTPS, per
/// `X-Forwarded-Proto` (same source as [`WebLogin::redirect_uri`]). Drives the
/// `Secure` cookie attribute, so HTTPS deployments get it automatically and
/// plain-HTTP local dev does not — without any configured public URL.
fn request_is_https(headers: &HeaderMap) -> bool {
    forwarded_for(headers, "", "").base_url.starts_with("https://")
}

fn build_set_cookie(cfg: &WebLoginConfig, sid: &str, secure: bool) -> HeaderValue {
    let mut s = format!("{}={}; HttpOnly; SameSite=Lax; Path=/", cfg.cookie_name, sid);
    if secure {
        s.push_str("; Secure");
    }
    HeaderValue::from_str(&s).expect("cookie header value")
}

/// The counterpart to [`build_set_cookie`]: same name, same `Path`, same
/// `SameSite`, same `Secure`, with an empty value and `Max-Age=0` so it is
/// dropped immediately.
///
/// Of those, `Path` is the one that has to match: a browser's cookie store keys
/// on name/domain/path (RFC 6265 §5.3), so a differing `Path` adds a second
/// cookie rather than replacing the first. `Secure` and `HttpOnly` are **not**
/// part of that key — an earlier version of this comment said they were —
/// they are mirrored so the clearing cookie cannot end up more permissive than
/// the one it replaces.
fn build_clear_cookie(cfg: &WebLoginConfig, secure: bool) -> HeaderValue {
    let mut s = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        cfg.cookie_name
    );
    if secure {
        s.push_str("; Secure");
    }
    HeaderValue::from_str(&s).expect("cookie header value")
}

fn see_other(location: &str, set_cookie: Option<HeaderValue>) -> Response {
    let mut resp = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .body(Body::empty())
        .expect("response");
    if let Ok(loc) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    if let Some(c) = set_cookie {
        resp.headers_mut().insert(header::SET_COOKIE, c);
    }
    resp
}

fn bad_request(msg: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, msg).into_response()
}

/// What a login step answers when it could not reach the session store.
///
/// **"Try logging in again", never "refresh this page".** One constant serves
/// four sites and has to be safe at the worst of them: the two in `callback`
/// that answer *after* the token exchange, where the authorization `code` still
/// in the URL bar has been spent and a refresh fails at the token endpoint. It
/// is merely unnecessary at the other two — the gate's 503 carries no `code` at
/// all, and `callback`'s pre-exchange 503 carries an unspent one — so nothing is
/// lost by giving the same advice everywhere.
const STORE_UNAVAILABLE_BODY: &str =
    "login is temporarily unavailable, please try logging in again";

/// Terminal refusal for a login step whose write did not land.
///
/// **503, not 500**: a dependency being transiently unavailable is not a bug in
/// handling the request, and 503 is what a load balancer and an alert read as
/// "retry". Not 400 either — the surrounding handler already answers 400 for
/// token-exchange and userinfo failures, which are our dependencies too, but
/// consistency with a wrong status is not a reason to add a third instance of
/// it.
///
/// **And not a redirect, in either direction — that is the load-bearing part.**
/// Sending the browser back to the IdP means persisting a fresh `state` in the
/// store that is down, so the next callback answers "no state found"; sending it
/// on to its destination with no cookie means the gate bounces it straight back.
/// Either way it is the login loop this ticket exists to remove, so failing
/// loudly has to mean a terminal status. No `Set-Cookie` and no `Location`:
/// nothing was written, so there is nothing for a cookie to name.
fn store_unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, STORE_UNAVAILABLE_BODY).into_response()
}

/// Max length for an attacker-supplied value recorded on a log line.
const MAX_LOGGED_LEN: usize = 256;

/// Bound an untrusted value before it is logged.
///
/// Callers must additionally record the result as a `&str` (`field = log_safe(x)
/// .as_str()`) and **never** with the `%` sigil: `%` formats via `Display`,
/// which the fmt layer emits unescaped, so a value containing CRLF injects
/// whole forged lines into the log stream. Recorded as a `&str` the formatter
/// escapes it, and this caps the length so it cannot flood the stream either —
/// the same reasoning that bounds `url.query` and `user_agent.original` in
/// `crate::otel`, which these fields would otherwise sidestep.
///
/// `pub(crate)` so the shared session stores bound *their* downstream error text
/// with this helper rather than a copy of it — sqlx and redis `Display` output
/// is downstream-derived and can carry a newline just as a query parameter can.
pub(crate) fn log_safe(s: &str) -> String {
    if s.len() <= MAX_LOGGED_LEN {
        return s.to_string();
    }
    let mut end = MAX_LOGGED_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

// ─── Callback handler + gate middleware ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// The provider's redirect back to us: exchange the `code`, resolve the user,
/// rotate the session id onto the finished session.
///
/// Emits one `auth.login` span — one per login, not one per store call —
/// carrying the verdict **and its reason** (`auth.login.outcome`), plus `user.id`
/// once there is one. This handler had no span at all, and it is the one place a
/// login can fail eight different ways that all read as "400" from outside. The
/// `code` and the `state` are never recorded on it: the first is a one-time
/// credential, the second is attacker-chosen.
///
/// `session.op` (HIK-236's vocabulary) rides along on the `store_unavailable`
/// outcome, because this handler reaches the store three times and the outcome
/// alone cannot tell a read outage from a write one — different halves of the
/// store and, on the two arms, different code paths.
///
/// **`skip_all` is load-bearing, not tidiness.** Without it `#[instrument]`
/// records every argument by `Debug`: `headers` carries `cookie:
/// hs_session=<the bearer credential>` and `q` carries the one-time `code`.
/// `WebLogin` is not `Debug`, so `skip(wl)` compiles — and compiles *because*
/// the other two are being recorded. `tests/login_span.rs` is what fails when
/// someone writes it.
#[tracing::instrument(
    name = "auth.login",
    skip_all,
    fields(
        auth.login.outcome = tracing::field::Empty,
        session.op = tracing::field::Empty,
        user.id = tracing::field::Empty,
    )
)]
async fn callback(
    State(wl): State<WebLogin>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let span = tracing::Span::current();
    if let Some(err) = q.error.as_deref() {
        // Already a `&str`, so the formatter escapes it — but it is still an
        // unbounded attacker-supplied query parameter, so it is capped too.
        span.record("auth.login.outcome", "provider_error");
        tracing::warn!(error = log_safe(err).as_str(), "web_login: provider returned error");
        return bad_request("login error");
    }
    let (Some(code), Some(state_key)) = (q.code, q.state) else {
        span.record("auth.login.outcome", "missing_code_or_state");
        return bad_request("missing code/state");
    };
    let Some(sid) = read_cookie(&headers, &wl.cfg.cookie_name) else {
        span.record("auth.login.outcome", "no_session_cookie");
        return bad_request("no session cookie");
    };

    // **Two loads, and the second one is not redundant — see the rotation
    // below.** This one answers "is this `state` one we issued, and where was
    // the browser going?".
    let loaded = match wl.store.load(&sid).await {
        Ok(s) => s,
        Err(e) => {
            // **The one `load` in this crate that does not fail open.**
            // Degrading to `None` lands on the "no state found" branch below,
            // which is the verdict for a caller who invented a `state` — so an
            // outage of ours answered 400 and sent whoever investigated it
            // hunting the IdP. Same misdiagnosis as the rotation defect, in the
            // same handler.
            span.record("auth.login.outcome", "store_unavailable");
            span.record("session.op", "load");
            tracing::warn!(
                session.op = %"load",
                auth.login.outcome = %"store_unavailable",
                error.message = log_safe(&format!("{e:#}")).as_str(),
                "web_login: session store unavailable, login refused"
            );
            return store_unavailable();
        }
    };
    // Copied, not consumed: the row is re-read after the token exchange, and
    // *that* copy is the one this flow's entry is removed from. The session read
    // here is kept only as the fallback for a row that is gone by then.
    let found = loaded.and_then(|s| s.redirects.get(&state_key).cloned().map(|orig| (s, orig)));
    let Some((prior, orig)) = found else {
        // Recorded as `&str`, NOT `%state_key`. The `%` sigil formats via
        // Display, which the fmt layer passes through unescaped — so a
        // `state` containing CRLF lets an unauthenticated caller inject
        // whole forged lines into the log stream, indistinguishable from
        // real ones. As a `&str` the formatter escapes it. Bounded too:
        // this value is attacker-chosen and otherwise unlimited, which
        // sidesteps the caps applied to `url.query` and the user agent.
        span.record("auth.login.outcome", "no_state_found");
        tracing::warn!(state = log_safe(&state_key).as_str(), "web_login: no stored state");
        return bad_request("no state found");
    };

    let token = match do_token_exchange(&wl.http, &wl.cfg, &code, &wl.redirect_uri(&headers)).await {
        Ok(t) if !t.access_token.is_empty() => t,
        Ok(_) => {
            span.record("auth.login.outcome", "no_access_token");
            return bad_request("no access token in response");
        }
        Err(e) => {
            span.record("auth.login.outcome", "token_exchange_failed");
            tracing::warn!(error = log_safe(&e.to_string()).as_str(), "web_login: token exchange failed");
            return bad_request("token exchange failed");
        }
    };
    let userinfo = match get_oauth_profile_by_token(&wl.http, &wl.cfg.profile_url, &token.access_token)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            span.record("auth.login.outcome", "profile_fetch_failed");
            tracing::warn!(error = log_safe(&e.to_string()).as_str(), "web_login: userinfo fetch failed");
            return bad_request("profile fetch failed");
        }
    };
    let Some(resolved) = wl.resolver.resolve(&userinfo).await else {
        span.record("auth.login.outcome", "user_unresolved");
        return bad_request("could not resolve user");
    };
    span.record("user.id", resolved.user_id.as_str());

    // Rotate the session id across the privilege change. This handler is where
    // an anonymous row acquires a user's tokens, so keeping the id hands the
    // finished session to anyone who already knew it — and the pre-login id is
    // knowable by design: `gate` mints one for *any* anonymous caller and sets
    // it as a cookie. Plant that value in a victim's browser, wait for them to
    // log in, and the row it names is now theirs. Rotating here is what makes
    // "a caller cannot influence the authenticated sid" actually true; the
    // lazy-mint rule in `decide` is the same claim for the other direction.
    //
    // Store the new row before dropping the old one, so a failure between the
    // two leaves the browser's current cookie still working rather than logging
    // the user out. Leftover `redirects` move across: a second tab mid-flow will
    // arrive here carrying the rotated cookie and must still find its own state.
    //
    // **That sentence was true of a crash and false of a store failure, which is
    // the mode it names.** `store` reported nothing, so this ran the whole
    // rotation regardless: the new row was never written, the old one was
    // removed anyway, and the browser was sent away with a cookie naming a
    // session that does not exist — logged out at the instant it logged in, and
    // bounced back to the IdP by the gate, which reads as the IdP looping. The
    // fallible signature is what makes the paragraph above true for the first
    // time.
    let new_sid = uuid::Uuid::new_v4().to_string();
    // **Re-read, rather than writing back the snapshot taken at the top of this
    // handler.** The gap between the two reads is two IdP round trips wide, and
    // a second tab that begins its own login inside it inserts a `state` into
    // this very row. Writing the older copy and then removing the row would
    // delete that entry, and tab 2's callback would come back "no state found" —
    // a login broken by ordinary concurrency, no store failure required.
    let mut sess = match wl.store.load(&sid).await {
        Ok(Some(fresh)) => fresh,
        // The row is gone between the two reads: its TTL lapsed, or another tab
        // logged out, or another tab's callback rotated and removed it. There is
        // nothing *fresh* to read — so the copy taken at the top of this
        // handler, the only surviving evidence of what the row held, is what
        // gets written, `redirects` and all. A second tab whose `state` was
        // already on that copy still finds it under the rotated id; what is lost
        // is only whatever reached the row after that first read.
        //
        // **It also RESURRECTS, and losing data is the half a reader guesses.**
        // `sess.redirects.remove` below drops *this* callback's own `state` and
        // nothing else, so every other entry on the snapshot is written into the
        // authenticated row — and a snapshot cannot say whether one of them has
        // since been **consumed** by another tab that finished first. Measured
        // on this arm's own fixture with the two tabs' roles swapped — seeded
        // `{st-1: /tab-one, st-2: /tab-two}`, re-read blanked, `state=st-2`
        // instead of `st-1`: the rotated row comes back
        // `redirects = {"st-1": "/tab-one"}`, and if tab 1 got there first that
        // `st-1` names a state which by then exists nowhere else — its row was
        // removed and the entry dropped from tab 1's own rotation
        // (`a_state_stored_while_the_token_exchange_was_in_flight_survives_the_rotation`
        // asserts both). It then lives for the row's TTL. New with the fix: at
        // `c46e50c` this was `load(&sid).await.unwrap_or_default()` over an
        // `Option<Session>`, so a vanished row produced `Session::default()` and
        // the whole snapshot went.
        //
        // Accepted rather than fixed. Nothing in `prior` distinguishes pending
        // from consumed, so the choice is between resurrecting some spent
        // entries and dropping every live one — and a resurrected entry only
        // maps a `state` to a destination: redeeming it still needs a fresh
        // single-use `code` from the IdP, which is the IdP's to refuse.
        //
        // Spelled as a branch and not `unwrap_or_default()`, because that
        // spelling swallowed the `Err` below too, which is how a store blip came
        // to silently drop a second tab's `redirects`. Pinned by
        // `a_row_that_vanished_between_the_two_reads_carries_the_first_read_across`.
        Ok(None) => prior,
        Err(e) => {
            // Fatal, for the same reason the write below is: the next two
            // statements write a new row and delete this one, and a re-read that
            // failed cannot say what is being deleted. Consistent with the first
            // `load` — and nothing has been written yet, so the old row and its
            // `state -> orig` entry survive and a retry works.
            span.record("auth.login.outcome", "store_unavailable");
            span.record("session.op", "load");
            tracing::warn!(
                session.op = %"load",
                auth.login.outcome = %"store_unavailable",
                user.id = resolved.user_id.as_str(),
                error.message = log_safe(&format!("{e:#}")).as_str(),
                "web_login: session store unavailable, login refused"
            );
            return store_unavailable();
        }
    };
    sess.redirects.remove(&state_key);
    sess.user_id = Some(resolved.user_id.clone());
    sess.profile = serde_json::to_value(&resolved.profile).ok();
    sess.access_token = Some(token.access_token);
    sess.refresh_token = token.refresh_token;
    sess.id_token = token.id_token;
    sess.expires_at = token.expires_in.map(|e| now_secs() + e);
    if let Err(e) = wl.store.store(&new_sid, &sess).await {
        // Fatal. The old row and its `state -> orig` entry are untouched, so a
        // retry works the moment the store recovers.
        //
        // `user.id` is on this line on purpose. It is in hand at no cost, and
        // this crate's only other span (`auth.gate`) does not cover `callback`.
        //
        // **Say what that buys, exactly: a store that started failing, not one
        // that is down.** The identity exists here only because the first `load`
        // succeeded and the token exchange and Kratos then answered. In a total
        // outage that first read is what fails, the handler returns there, and
        // the process never learns who the caller was — so those refusals are
        // anonymous and carry no `user.id` at all. "Which users
        // could not log in during the blip" is answerable for the branches past
        // the identity and for nothing else.
        //
        // Recorded as a bare `&str`: it is downstream-derived (Kratos' `sub`),
        // and `%` emits bytes raw.
        span.record("auth.login.outcome", "store_unavailable");
        span.record("session.op", "store");
        tracing::warn!(
            session.op = %"store",
            auth.login.outcome = %"store_unavailable",
            user.id = resolved.user_id.as_str(),
            error.message = log_safe(&format!("{e:#}")).as_str(),
            "web_login: session store unavailable, login refused"
        );
        return store_unavailable();
    }
    // Non-fatal: the rotation landed, so this caller *is* logged in, and
    // refusing the login over a tidy-up delete would throw away an
    // authentication that succeeded.
    //
    // What is left behind when it fails is a superseded row that lives until the
    // store reclaims it — `DEFAULT_SESSION_TTL_SECS`, 24 h, unless the
    // deployment built its store with another. It is **not** necessarily
    // anonymous: `redirects` move across the rotation (above), so a second tab's
    // callback arrives holding the *authenticated* row this handler just wrote,
    // and rotates that. If its delete is the one that fails, the leftover
    // carries `user_id`, the access token and the refresh token, and the cookie
    // naming it is one the browser was given. Nothing here bounds that; the TTL
    // does.
    //
    // **A failed delete is not the only producer, and this paragraph read as
    // though it were.** Two callbacks racing on one cookie leave the same row
    // behind with every store call succeeding: tab 1 rotates and removes the
    // shared row while tab 2 is at the token endpoint, tab 2's re-read then
    // finds nothing (the `Ok(None)` arm above), so it writes its own rotated row
    // and its `remove` deletes a row that is already gone — nobody removes tab
    // 1's, and the browser's cookie now names tab 2's. Driven, not reasoned:
    // `two_callbacks_racing_on_one_cookie_orphan_a_row_with_no_store_failure`.
    // Pre-existing, and not this ticket's to fix.
    //
    // Hence a line of its own: `error!` inside the store names the operation but
    // not whose rotation it was, and `user.id` is in hand two statements up.
    if let Err(e) = wl.store.remove(&sid).await {
        tracing::warn!(
            session.op = %"remove",
            user.id = resolved.user_id.as_str(),
            error.message = log_safe(&format!("{e:#}")).as_str(),
            "web_login: rotated session stored, but the superseded row could not be removed"
        );
    }
    span.record("auth.login.outcome", "success");
    tracing::debug!(user = %resolved.user_id, "web_login: login complete, redirecting to {orig}");
    see_other(
        &orig,
        Some(build_set_cookie(&wl.cfg, &new_sid, request_is_https(&headers))),
    )
}

/// Middleware (use with `from_fn_with_state(web_login.gate_state(fail_fast), gate)`)
/// that requires a logged-in cookie session. Logged in → continue (with
/// [`CurrentUser`] in request extensions); else 401 (`fail_fast`) or a 302 to
/// the provider's authorize endpoint.
///
/// The session id is minted **lazily**, on the one branch that needs it. Only a
/// request that already offers a cookie can be authenticated (its `load` is what
/// finds the user), and a refusal needs no session at all — so anything else
/// would be an unauthenticated write into a store the whole fleet shares. See
/// the branch comments.
///
/// Emits one `auth.gate` span per gated request, as a child of the caller's
/// `http.server` span so it inherits parent-based sampling. It spans the gate's
/// **decision only** and closes before the request goes downstream: held open
/// across `next.run` it would time the whole request instead of the gate,
/// reparent every span a gated handler emits under the auth middleware, and
/// stamp `user.id` onto every log event inside every gated handler. The
/// session id is **never** recorded on it, whole or hashed: the `hs_session`
/// value *is* the bearer credential — it is unsigned, and a consumer logs a user
/// in by inserting a row keyed on it — so presence and minting are booleans.
///
/// `user.id` is the current OTel semantic-convention slot for an end user's
/// identifier. The older `enduser.*` attributes are **deprecated** — do not
/// "correct" this back to `enduser.id`.
///
/// `auth.gate.session.load_failed` is a **span field and deliberately not a log
/// line**: this path is anonymously reachable at whatever rate a caller chooses,
/// and it exists because the read below fails open, so on the api tier an outage
/// refuses with `outcome=refused_401 session.present=true` — byte-identical to
/// an expired session, and a different incident.
pub async fn gate(State(g): State<GateState>, req: Request, next: Next) -> Response {
    let span = tracing::info_span!(
        "auth.gate",
        auth.gate.fail_fast = g.fail_fast,
        auth.gate.outcome = tracing::field::Empty,
        auth.gate.session.present = tracing::field::Empty,
        auth.gate.session.minted = tracing::field::Empty,
        auth.gate.session.load_failed = tracing::field::Empty,
        session.op = tracing::field::Empty,
        user.id = tracing::field::Empty,
    );
    // The request's parts, not the request itself: `Body` is not `Sync`, so
    // holding a `&Request` across an await would make this middleware's future
    // non-`Send` and axum would not accept it.
    match decide(&g, req.headers(), req.uri()).instrument(span).await {
        GateDecision::Pass(user) => {
            let mut req = req;
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        GateDecision::Respond(resp) => resp,
    }
}

/// What [`gate`] resolved. Settled *before* the request is handed downstream, so
/// the `auth.gate` span can close around the decision and nothing else.
enum GateDecision {
    /// Logged in — put this in the request extensions and continue.
    Pass(CurrentUser),
    /// Terminal: the 401, or the redirect that begins the login flow.
    Respond(Response),
}

async fn decide(g: &GateState, headers: &HeaderMap, uri: &Uri) -> GateDecision {
    let wl = &g.wl;
    let span = tracing::Span::current();

    let cookie_sid = read_cookie(headers, &wl.cfg.cookie_name);
    span.record("auth.gate.session.present", cookie_sid.is_some());

    // No cookie ⇒ nothing to load ⇒ the request cannot be authenticated. Asking
    // the store anyway would be a guaranteed miss on a made-up id.
    //
    // The whole session is kept rather than just the user it resolves to: the
    // redirect branch needs to know whether the store *recognised* this cookie,
    // and reuses the row it already has instead of reading it a second time.
    //
    // **Fail open, and here that is the right posture rather than a leftover.**
    // This read decides "is this caller logged in?", and an unreadable session
    // is indistinguishable from an absent one from the caller's side — the
    // branches below already handle absent, so degrading to `None` costs a
    // logged-in caller a fresh login rather than an error page.
    //
    // **It does not follow that a store outage keeps the site serving**, and an
    // earlier version of this comment said so. Failing open here only reaches
    // the *next* branch; on the browser tier that branch mints a session and
    // writes it, and that write is fatal, so a store that is down answers 503 on
    // every gated page. Only the api tier's 401 (below) returns before any
    // write. Both halves are pinned by
    // `a_store_outage_is_a_401_on_the_api_tier_and_a_503_on_the_browser_tier`.
    let loaded = match &cookie_sid {
        Some(sid) => match wl.store.load(sid).await {
            Ok(s) => s,
            Err(_) => {
                // Recorded on the span and **not** as a log line: this path is
                // anonymously reachable at caller-chosen rate, and the store has
                // already emitted its own `error!` for the cause.
                span.record("auth.gate.session.load_failed", true);
                None
            }
        },
        None => None,
    };

    if let Some(user_id) = loaded.as_ref().and_then(|s| s.user_id.clone()) {
        span.record("auth.gate.outcome", "authenticated");
        span.record("auth.gate.session.minted", false);
        span.record("user.id", user_id.as_str());
        let profile = loaded.and_then(|s| s.profile);
        return GateDecision::Pass(CurrentUser { user_id, profile });
    }

    if g.fail_fast {
        // Refusing costs nothing: no id minted, no row written, and no
        // `Set-Cookie`. Nothing reads that cookie, and with the write gone it
        // would name a row that does not exist. Before this, an anonymous
        // caller wrote one empty session row per 401 into shared storage —
        // unauthenticated write amplification at request rate.
        span.record("auth.gate.outcome", "refused_401");
        span.record("auth.gate.session.minted", false);
        return GateDecision::Respond((StatusCode::UNAUTHORIZED, "not logged in").into_response());
    }

    // Begin the authorization-code dance: stash state → original URL. This is
    // the only branch that needs a session id, so it is the one that mints it —
    // and the only one that writes.
    //
    // Which id it writes under is the security-relevant part. Only a cookie the
    // store actually recognises may be kept; anything else is replaced with a
    // fresh uuid. Reusing an unrecognised value would take caller-supplied input
    // straight to a primary key in storage the whole fleet shares — letting an
    // anonymous caller both choose that key and fix a session id ahead of a
    // victim's login. Its other half is the rotation in `callback`: one stops a
    // chosen id from ever being written, the other stops a *minted* id from
    // surviving into the authenticated session.
    let (sid, mut sess, minted) = match (cookie_sid, loaded) {
        // A session the store knows, still anonymous because the dance is in
        // flight. Keep the id and add to the row — this is the row the redirect
        // branch itself just created, and a second tab arrives holding it. It is
        // also already loaded, so the reuse costs no second read.
        (Some(sid), Some(sess)) => (sid, sess, false),
        _ => (uuid::Uuid::new_v4().to_string(), Session::default(), true),
    };
    let set_cookie = minted.then(|| build_set_cookie(&wl.cfg, &sid, request_is_https(headers)));

    let orig = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let state_key = uuid::Uuid::new_v4().to_string();
    sess.redirects.insert(state_key.clone(), orig);
    if let Err(e) = wl.store.store(&sid, &sess).await {
        // **Fatal, unlike the `load` above, and the difference is what the write
        // is for.** `callback` reads this `state` back out of the store, so a
        // redirect carrying one that was never persisted is *guaranteed* to come
        // back "no state found" — a round trip spent reaching a failure already
        // known here, with the IdP taking the blame for it. No `Location` and no
        // `Set-Cookie`: there is no row for either to name.
        //
        // A `let _ =` here instead would be the "a Result nobody branches on"
        // outcome the fallible signature exists to remove.
        span.record("auth.gate.outcome", "store_unavailable");
        span.record("auth.gate.session.minted", minted);
        span.record("session.op", "store");
        tracing::warn!(
            session.op = %"store",
            auth.gate.outcome = %"store_unavailable",
            auth.gate.session.minted = minted,
            error.message = log_safe(&format!("{e:#}")).as_str(),
            "web_login: session store unavailable, login refused"
        );
        return GateDecision::Respond(store_unavailable());
    }
    span.record("auth.gate.outcome", "redirect_to_login");
    span.record("auth.gate.session.minted", minted);
    GateDecision::Respond(see_other(&wl.authorize_url(&state_key, headers), set_cookie))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    fn cfg() -> WebLoginConfig {
        WebLoginConfig::new(
            "client-abc",
            "secret-xyz",
            "https://auth.example.com/oauth2/auth",
            "https://auth.example.com/oauth2/token",
            "https://auth.example.com/userinfo",
            "openid profile email",
        )
    }

    /// Standard forwarded headers from an HTTPS edge (proto + host), as the LB
    /// supplies them. `redirect_uri` / cookie `Secure` derive from these.
    fn https_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        h.insert("x-forwarded-host", "app.example.com".parse().unwrap());
        h
    }

    fn wl() -> WebLogin {
        let resolver = Arc::new(KratosUserResolver::new(
            "http://kratos:4434",
            "https://hikari-systems.com/",
            true,
        ));
        WebLogin::new(cfg(), resolver)
    }

    #[test]
    fn session_round_trips_id_token() {
        let sess = Session {
            user_id: Some("u1".into()),
            id_token: Some("eyJhbGc.payload.sig".into()),
            ..Default::default()
        };
        let json = serde_json::to_value(&sess).unwrap();
        assert_eq!(json["id_token"], "eyJhbGc.payload.sig");
        let back: Session = serde_json::from_value(json).unwrap();
        assert_eq!(back.id_token.as_deref(), Some("eyJhbGc.payload.sig"));
    }

    #[tokio::test]
    async fn end_session_returns_id_token_and_clears() {
        let wl = wl();
        let sess = Session {
            id_token: Some("tok-123".into()),
            ..Default::default()
        };
        wl.store.store("sid-1", &sess).await.unwrap();
        assert_eq!(wl.id_token("sid-1").await.as_deref(), Some("tok-123"));
        assert_eq!(
            wl.end_session("sid-1").await.unwrap().as_deref(),
            Some("tok-123")
        );
        // session is gone now
        assert!(wl.id_token("sid-1").await.is_none());
    }

    #[test]
    fn redirect_uri_is_derived_from_the_request() {
        let wl = wl();
        // Plain Host header (local dev) → http origin.
        let mut h = HeaderMap::new();
        h.insert("host", "localhost:3000".parse().unwrap());
        assert_eq!(wl.redirect_uri(&h), "http://localhost:3000/oauth2/callback");
        // Forwarded proto/host from the edge win.
        assert_eq!(
            wl.redirect_uri(&https_headers()),
            "https://app.example.com/oauth2/callback"
        );
    }

    #[test]
    fn forwarded_for_suppresses_standard_ports() {
        let mut h = HeaderMap::new();
        h.insert("host", "localhost:3000".parse().unwrap());
        assert_eq!(forwarded_for(&h, "/p?q=1", "").base_url, "http://localhost:3000");
        assert_eq!(forwarded_for(&h, "/p?q=1", "").full_url, "http://localhost:3000/p?q=1");
        let mut h2 = HeaderMap::new();
        h2.insert("x-forwarded-proto", "https".parse().unwrap());
        h2.insert("x-forwarded-host", "api.example.com".parse().unwrap());
        assert_eq!(forwarded_for(&h2, "", "").base_url, "https://api.example.com");
    }

    #[test]
    fn authorize_url_has_oauth_params() {
        let u = wl().authorize_url("state-123", &https_headers());
        let parsed = reqwest::Url::parse(&u).unwrap();
        let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("response_type").unwrap(), "code");
        assert_eq!(q.get("client_id").unwrap(), "client-abc");
        assert_eq!(q.get("state").unwrap(), "state-123");
        assert_eq!(q.get("scope").unwrap(), "openid profile email");
        assert_eq!(
            q.get("redirect_uri").unwrap(),
            "https://app.example.com/oauth2/callback"
        );
        assert!(parsed.as_str().starts_with("https://auth.example.com/oauth2/auth?"));
    }

    #[test]
    fn set_cookie_has_security_attrs() {
        // Secure derives from the request: HTTPS edge ⇒ Secure, plain HTTP ⇒ not.
        let secure = build_set_cookie(&cfg(), "sid-1", true);
        let s = secure.to_str().unwrap();
        assert!(s.starts_with("hs_session=sid-1"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("Secure"));

        let insecure = build_set_cookie(&cfg(), "sid-1", false);
        assert!(!insecure.to_str().unwrap().contains("Secure"));
    }

    /// A clearing cookie only replaces the one that was set when the browser
    /// sees the same name, `Path`, `SameSite` and `Secure` — otherwise it lands
    /// *beside* it and the session cookie survives the logout. So this is
    /// asserted against [`build_set_cookie`]'s own output, not against a list.
    #[test]
    fn the_clearing_cookie_matches_the_one_it_replaces() {
        for secure in [true, false] {
            let set = build_set_cookie(&cfg(), "sid-1", secure);
            let clear = build_clear_cookie(&cfg(), secure);
            let (set, clear) = (set.to_str().unwrap(), clear.to_str().unwrap());

            for attr in ["hs_session=", "HttpOnly", "SameSite=Lax", "Path=/"] {
                assert!(set.contains(attr), "{set:?} is missing {attr}");
                assert!(clear.contains(attr), "{clear:?} is missing {attr}");
            }
            assert_eq!(
                set.contains("; Secure"),
                clear.contains("; Secure"),
                "Secure must match, or the browser keeps the original cookie"
            );
            assert!(
                clear.contains("hs_session=;"),
                "the value must be emptied: {clear:?}"
            );
            assert!(
                clear.contains("Max-Age=0"),
                "and expired immediately: {clear:?}"
            );
        }
    }

    /// `clear_cookie_header` takes `Secure` from the same place `redirect_uri`
    /// does — the trusted edge's `X-Forwarded-Proto`. That is the half a
    /// consumer outside this crate cannot reach, and would therefore guess at.
    #[test]
    fn the_clearing_cookie_takes_secure_from_the_edge() {
        let wl = wl();
        assert!(wl
            .clear_cookie_header(&https_headers())
            .to_str()
            .unwrap()
            .contains("Secure"));

        let mut plain = HeaderMap::new();
        plain.insert("host", "localhost:3000".parse().unwrap());
        assert!(!wl
            .clear_cookie_header(&plain)
            .to_str()
            .unwrap()
            .contains("Secure"));
    }

    #[test]
    fn request_is_https_tracks_forwarded_proto() {
        assert!(request_is_https(&https_headers()));
        let mut h = HeaderMap::new();
        h.insert("host", "localhost:3000".parse().unwrap());
        assert!(!request_is_https(&h));
    }

    #[test]
    fn read_cookie_picks_the_named_value() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; hs_session=abc123; x=2"),
        );
        assert_eq!(read_cookie(&h, "hs_session").as_deref(), Some("abc123"));
        // a name that is only a prefix of a different cookie must not match
        assert_eq!(read_cookie(&h, "hs_sess"), None);
        assert_eq!(read_cookie(&h, "missing"), None);
    }

    // ─── gate() end to end ─────────────────────────────────────────────────
    //
    // Everything above this line exercises a helper. Nothing drove `gate`
    // itself, which is how it came to write a session row on every anonymous
    // request for as long as it did — the tests below drive the real middleware
    // through a real `Router`.

    /// A [`WebSessionStore`] that counts calls, so a test can assert a request
    /// wrote *nothing*. It delegates to the real in-memory store, so behaviour
    /// under test is the shipped behaviour.
    struct CountingStore {
        inner: InMemorySessionStore,
        stores: AtomicUsize,
        loads: AtomicUsize,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                inner: InMemorySessionStore::default(),
                stores: AtomicUsize::new(0),
                loads: AtomicUsize::new(0),
            }
        }
        fn stores(&self) -> usize {
            self.stores.load(Ordering::SeqCst)
        }
        fn loads(&self) -> usize {
            self.loads.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl WebSessionStore for CountingStore {
        async fn load(&self, sid: &str) -> anyhow::Result<Option<Session>> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.load(sid).await
        }
        async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()> {
            self.stores.fetch_add(1, Ordering::SeqCst);
            self.inner.store(sid, session).await
        }
        async fn remove(&self, sid: &str) -> anyhow::Result<()> {
            self.inner.remove(sid).await
        }
    }

    /// A router behind the real [`gate`] middleware: `/api/graphql` for the
    /// api-gated tier, `/dash` for the browser-gated one.
    fn gated_app(store: Arc<CountingStore>, fail_fast: bool) -> Router {
        let resolver = Arc::new(KratosUserResolver::new(
            "http://kratos:4434",
            "https://hikari-systems.com/",
            true,
        ));
        let wl = WebLogin::with_store(cfg(), resolver, store);
        Router::new()
            .route("/api/graphql", axum::routing::post(|| async { "ok" }))
            .route("/dash", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                wl.gate_state(fail_fast),
                gate,
            ))
    }

    /// Refusing an anonymous request must cost nothing: no session id minted, no
    /// row written, and no `Set-Cookie` — with the write gone that cookie would
    /// name a row that does not exist, and nothing reads it.
    ///
    /// The request deliberately sends **no `Cookie` header at all**. That is
    /// load-bearing, not incidental — see
    /// `an_unknown_cookie_is_refused_without_a_write` below.
    #[tokio::test]
    async fn a_refused_anonymous_request_creates_no_session() {
        let store = Arc::new(CountingStore::new());
        let resp = gated_app(store.clone(), true)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/graphql")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            store.stores(),
            0,
            "a refused anonymous request must not write a session row"
        );
        assert!(
            resp.headers().get(header::SET_COOKIE).is_none(),
            "a 401 must not hand out a cookie naming a session that was never stored"
        );
    }

    /// **Not a regression test, and deliberately so.** It is green on both sides
    /// of the HIK-179 fix; it exists to document the trap that hid the defect.
    ///
    /// `gate` wrote a row only when the cookie was *absent*, so a probe that
    /// sends a fresh random cookie value each time never triggers it. Measured
    /// against a live stack: 25 requests each with a different `hs_session` gave
    /// a delta of **0** rows, while 25 with no header at all gave **25**. The
    /// ticket's own verification steps proposed the former and would have
    /// produced a false green.
    ///
    /// Do not fold this and `a_refused_anonymous_request_creates_no_session`
    /// into one test: the difference between them *is* the defect.
    #[tokio::test]
    async fn an_unknown_cookie_is_refused_without_a_write() {
        let store = Arc::new(CountingStore::new());
        let resp = gated_app(store.clone(), true)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/graphql")
                    .header(header::COOKIE, "hs_session=6f1c4e0a-not-a-real-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            store.stores(),
            0,
            "an unrecognised cookie must not be stored"
        );
        assert_eq!(
            store.loads(),
            1,
            "the offered cookie must actually be looked up, not assumed unknown"
        );
    }

    /// The redirect branch is the *only* one that needs a session id, so it is
    /// the one that mints it — and it must still create the row, because the
    /// callback reads the `state → original URL` map back out of it. Its store
    /// is `load(..).unwrap_or_default()`, which with no row yields a default
    /// session, takes the state insert and writes it. Break that composition and
    /// every login 400s at the callback with "no state found".
    #[tokio::test]
    async fn the_browser_gate_still_stores_the_oauth_state() {
        let store = Arc::new(CountingStore::new());
        let resp = gated_app(store.clone(), false)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/dash?tab=runs")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .expect("Location")
            .to_str()
            .unwrap()
            .to_string();
        assert!(loc.starts_with("https://auth.example.com/oauth2/auth?"));
        let parsed = reqwest::Url::parse(&loc).unwrap();
        let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let state_key = q.get("state").expect("state parameter").clone();

        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("the browser gate mints a sid, so it must set the cookie")
            .to_str()
            .unwrap()
            .to_string();
        let sid = cookie
            .strip_prefix("hs_session=")
            .expect("cookie names the session")
            .split(';')
            .next()
            .unwrap()
            .to_string();

        assert_eq!(store.stores(), 1, "exactly one write: the state map");
        let sess = store
            .inner
            .load(&sid)
            .await
            .unwrap()
            .expect("the redirect branch created the row");
        assert_eq!(
            sess.redirects.get(&state_key).map(String::as_str),
            Some("/dash?tab=runs"),
            "the state must map back to the original path AND query"
        );
    }

    /// The other half of that composition: the redirect branch is a
    /// read-modify-**write**, and the read half only bites when there is
    /// something to lose. The test above starts from an empty store with no
    /// cookie, so its `load` returns `None` — under which replacing the load
    /// with a bare `Session::default()` is indistinguishable from correct code,
    /// and the whole suite stays green.
    ///
    /// This is an ordinary production state, not a contrived one: a browser
    /// holding an `hs_session` for a session that is not yet logged in is
    /// exactly what the redirect branch itself just created. A second tab, a
    /// refresh, or a retried login arrives here with that cookie, and its row
    /// already carries the first flow's `state -> url`. Clobber it and the first
    /// tab's callback 400s with "no state found" — the failure this branch
    /// exists to avoid.
    #[tokio::test]
    async fn a_second_login_flow_keeps_the_first_flows_state() {
        let store = Arc::new(CountingStore::new());
        let mut midflow = Session::default();
        midflow
            .redirects
            .insert("state-tab-1".into(), "/dash?tab=one".into());
        store.inner.store("sid-midflow", &midflow).await.unwrap();

        let resp = gated_app(store.clone(), false)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/dash?tab=two")
                    .header(header::COOKIE, "hs_session=sid-midflow")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(
            resp.headers().get(header::SET_COOKIE).is_none(),
            "the cookie was already good, so nothing is minted and nothing is re-issued"
        );
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .expect("Location")
            .to_str()
            .unwrap()
            .to_string();
        let parsed = reqwest::Url::parse(&loc).unwrap();
        let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let state_key = q.get("state").expect("state parameter").clone();

        assert_eq!(store.stores(), 1, "exactly one write");
        assert_eq!(
            store.loads(),
            1,
            "and exactly one read: the redirect branch reuses the session it \
             already loaded to answer 'is this cookie known', rather than \
             fetching the same row twice"
        );
        let sess = store
            .inner
            .load("sid-midflow")
            .await
            .unwrap()
            .expect("the existing row is updated, not replaced");
        assert_eq!(
            sess.redirects.get("state-tab-1").map(String::as_str),
            Some("/dash?tab=one"),
            "the first flow's state must survive the second redirect"
        );
        assert_eq!(
            sess.redirects.get(&state_key).map(String::as_str),
            Some("/dash?tab=two"),
            "and the second flow's state is added alongside it"
        );
        assert_eq!(sess.redirects.len(), 2);
    }

    /// A caller-supplied session id must never become the key a row is written
    /// under. The redirect branch is the one that writes, and it used to reuse
    /// whatever `hs_session` value arrived — so an anonymous caller picked the
    /// primary key in storage the whole fleet shares (the write amplification
    /// the 401 fix closed only for the api tier), and could fix a session id
    /// ahead of a victim's login.
    ///
    /// Only an id the store already knows may be kept — that case is
    /// `a_second_login_flow_keeps_the_first_flows_state` above, and the two
    /// together are the whole rule. Anything else is replaced, which is why the
    /// response must also carry the freshly minted cookie.
    #[tokio::test]
    async fn an_unknown_cookie_is_never_reused_as_the_session_key() {
        let store = Arc::new(CountingStore::new());
        let resp = gated_app(store.clone(), false)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/dash")
                    .header(header::COOKIE, "hs_session=attacker-chosen-sid")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(
            store
                .inner
                .load("attacker-chosen-sid")
                .await
                .unwrap()
                .is_none(),
            "a caller-supplied session id must never become a stored key"
        );
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("an unrecognised cookie must be replaced with a minted sid")
            .to_str()
            .unwrap()
            .to_string();
        let sid = cookie
            .strip_prefix("hs_session=")
            .expect("cookie names the session")
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert_ne!(sid, "attacker-chosen-sid");
        uuid::Uuid::parse_str(&sid).expect("the replacement is a server-generated uuid");
        assert!(
            store.inner.load(&sid).await.unwrap().is_some(),
            "the state is stored under the minted id instead"
        );
    }

    /// A throwaway provider serving the only two endpoints [`callback`] calls:
    /// the token endpoint and userinfo. stdlib sockets, no new dependency —
    /// `callback` reaches the network, which is why it had no test at all, and
    /// the session-id rotation below is not observable without driving it end to
    /// end. Answers `Connection: close` so each request gets its own accept.
    fn oauth_provider_stub() -> String {
        oauth_provider_stub_with(None)
    }

    /// Handshake for holding the token exchange open, so a test can act inside
    /// the window it leaves. The stub announces on `arrived` that it has read a
    /// `/token` request and then blocks on `release` before answering.
    ///
    /// A handshake and not a sleep: the window this opens is the whole point of
    /// `a_state_stored_while_the_token_exchange_was_in_flight_survives_the_rotation`,
    /// and a timed one turns that test into a race whose green means "the timer
    /// was long enough today". `arrived` is a tokio channel because the test
    /// awaits it on a current-thread runtime; `release` is a std one because the
    /// stub's own OS thread blocks on it.
    struct TokenGate {
        arrived: tokio::sync::mpsc::UnboundedSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    fn oauth_provider_stub_with(gate: Option<TokenGate>) -> String {
        use std::io::{BufRead, BufReader, Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                // Drain headers, then the body, so the client sees a clean
                // exchange rather than a reset mid-POST.
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                if len > 0 {
                    let mut body = vec![0u8; len];
                    let _ = reader.read_exact(&mut body);
                }

                let json = if path.starts_with("/token") {
                    if let Some(g) = gate.as_ref() {
                        let _ = g.arrived.send(());
                        let _ = g.release.recv();
                    }
                    // The `refresh_token` is here so the leftover-row tests can
                    // assert it rather than describe it: it is the part of an
                    // orphaned session that outlives the access token's hour,
                    // and a doc comment naming it while nothing drove it is the
                    // claim-without-evidence this ticket keeps failing on.
                    r#"{"access_token":"at-1","refresh_token":"rt-1","token_type":"bearer","expires_in":3600,"id_token":"idt-1"}"#
                } else {
                    r#"{"sub":"kratos-identity-9"}"#
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = stream.flush();
            }
        });
        base
    }

    /// Logging in must rotate the session id. The pre-login id was handed to (or
    /// arrived from) an unauthenticated browser, and this handler is where the
    /// row it names acquires the user's tokens — so without rotation anyone
    /// holding that id holds the session the moment the victim logs in. Getting
    /// hold of one is not the hard part: `gate` mints and sets a sid for any
    /// anonymous caller. Planting it in the victim's browser is the whole attack.
    ///
    /// Rotation carries the remaining `redirects` across, so a second tab still
    /// mid-flow finds its state under the new id instead of 400-ing.
    #[tokio::test]
    async fn logging_in_rotates_the_session_id() {
        let base = oauth_provider_stub();
        let mut c = cfg();
        c.token_url = format!("{base}/token");
        c.profile_url = format!("{base}/userinfo");

        let store = Arc::new(CountingStore::new());
        let mut seeded = Session::default();
        seeded.redirects.insert("st-1".into(), "/dash?tab=runs".into());
        seeded.redirects.insert("st-2".into(), "/other".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();

        // `fallback: false` keeps the resolver off the network entirely: with no
        // fallback it never fetches, so the unroutable admin URL is never used.
        let resolver = Arc::new(KratosUserResolver::new(
            "http://kratos.invalid:4434",
            "https://hikari-systems.com/",
            false,
        ));
        let resp = WebLogin::with_store(c, resolver, store.clone())
            .callback_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/callback?code=auth-code&state=st-1")
                    .header(header::COOKIE, "hs_session=pre-login-sid")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/dash?tab=runs"
        );

        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("a rotated id is useless unless the browser is told about it")
            .to_str()
            .unwrap()
            .to_string();
        let new_sid = cookie
            .strip_prefix("hs_session=")
            .expect("cookie names the session")
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert_ne!(new_sid, "pre-login-sid");
        assert!(cookie.contains("Secure"), "the edge was HTTPS");

        assert!(
            store.inner.load("pre-login-sid").await.unwrap().is_none(),
            "the pre-login id must not survive the privilege change"
        );
        let sess = store
            .inner
            .load(&new_sid)
            .await
            .unwrap()
            .expect("the session moved to the rotated id");
        assert_eq!(sess.user_id.as_deref(), Some("kratos-identity-9"));
        assert_eq!(sess.access_token.as_deref(), Some("at-1"));
        assert!(
            !sess.redirects.contains_key("st-1"),
            "the consumed state is dropped"
        );
        assert_eq!(
            sess.redirects.get("st-2").map(String::as_str),
            Some("/other"),
            "a second flow still in flight must move across with it"
        );
    }

    // ─── A store that is down (HIK-241) ────────────────────────────────────

    /// A [`WebSessionStore`] whose three methods fail **independently**, and
    /// which delegates to the real in-memory store whenever it is not failing.
    ///
    /// The independence is the design of these tests, not a convenience. Fail
    /// `remove` as well as `store` in
    /// `a_rotation_that_could_not_be_stored_keeps_the_old_session` and its
    /// oracle — "the superseded row is still there" — goes **green against the
    /// unfixed code**: the row survives because the DELETE never landed, not
    /// because the handler declined to issue one. Only a real `remove` under a
    /// failing `store` tells those two apart.
    ///
    /// **`load` also misbehaves by call number, and that is what reaches
    /// `callback`'s second read.** `fail_load` is a latch with no counter, so it
    /// fails the *first* `load` and the handler answers 503 before the token
    /// exchange — the re-read after it is unreachable under that fixture, which
    /// is why two of its three arms were asserted by nothing. The two `*_nth`
    /// fields name a 1-based call index instead; `0`, the default, matches no
    /// call, so the two tests that set `fail_load` —
    /// `a_store_outage_is_a_401_on_the_api_tier_and_a_503_on_the_browser_tier`
    /// and `a_store_outage_at_the_callback_is_not_reported_as_a_bogus_state` —
    /// keep exactly the behaviour they were written against. Named rather than
    /// counted, per this file's own habit: a numeral here read neither the
    /// latch's setters nor the tests built on `FailingStore`, and matched
    /// nothing. The count is per store rather than per request: a test driving
    /// two callbacks through one store is counting both.
    struct FailingStore {
        inner: InMemorySessionStore,
        fail_load: AtomicBool,
        fail_store: AtomicBool,
        fail_remove: AtomicBool,
        /// Every `load`, whatever it went on to answer.
        load_calls: AtomicUsize,
        /// 1-based index of the `load` that returns `Err`; `0` never matches.
        fail_load_nth: AtomicUsize,
        /// 1-based index of the `load` that returns `Ok(None)` — the row is gone
        /// rather than unreadable. `0` never matches.
        blank_load_nth: AtomicUsize,
        /// Every call, whether or not it was allowed to write.
        store_attempts: AtomicUsize,
        /// Only the calls that actually reached the inner map.
        store_writes: AtomicUsize,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: InMemorySessionStore::default(),
                fail_load: AtomicBool::new(false),
                fail_store: AtomicBool::new(false),
                fail_remove: AtomicBool::new(false),
                load_calls: AtomicUsize::new(0),
                fail_load_nth: AtomicUsize::new(0),
                blank_load_nth: AtomicUsize::new(0),
                store_attempts: AtomicUsize::new(0),
                store_writes: AtomicUsize::new(0),
            }
        }
        fn fail(&self, which: &AtomicBool) {
            which.store(true, Ordering::SeqCst);
        }
        fn fail_load_on_call(&self, nth: usize) {
            self.fail_load_nth.store(nth, Ordering::SeqCst);
        }
        fn blank_load_on_call(&self, nth: usize) {
            self.blank_load_nth.store(nth, Ordering::SeqCst);
        }
        fn store_attempts(&self) -> usize {
            self.store_attempts.load(Ordering::SeqCst)
        }
        fn store_writes(&self) -> usize {
            self.store_writes.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl WebSessionStore for FailingStore {
        async fn load(&self, sid: &str) -> anyhow::Result<Option<Session>> {
            let nth = self.load_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_load.load(Ordering::SeqCst)
                || nth == self.fail_load_nth.load(Ordering::SeqCst)
            {
                anyhow::bail!("session store load failed (test)");
            }
            if nth == self.blank_load_nth.load(Ordering::SeqCst) {
                return Ok(None);
            }
            self.inner.load(sid).await
        }
        async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()> {
            self.store_attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail_store.load(Ordering::SeqCst) {
                anyhow::bail!("session store write failed (test)");
            }
            self.store_writes.fetch_add(1, Ordering::SeqCst);
            self.inner.store(sid, session).await
        }
        async fn remove(&self, sid: &str) -> anyhow::Result<()> {
            if self.fail_remove.load(Ordering::SeqCst) {
                anyhow::bail!("session store delete failed (test)");
            }
            self.inner.remove(sid).await
        }
    }

    /// `callback` wired to the stub provider and a caller-supplied store, with
    /// the Kratos resolver kept off the network (`fallback: false` never
    /// fetches, so the unroutable admin URL is never dialled).
    fn callback_app(store: Arc<FailingStore>) -> Router {
        callback_app_at(store, oauth_provider_stub())
    }

    fn callback_app_at(store: Arc<FailingStore>, base: String) -> Router {
        let mut c = cfg();
        c.token_url = format!("{base}/token");
        c.profile_url = format!("{base}/userinfo");
        let resolver = Arc::new(KratosUserResolver::new(
            "http://kratos.invalid:4434",
            "https://hikari-systems.com/",
            false,
        ));
        WebLogin::with_store(c, resolver, store).callback_router()
    }

    /// The provider's redirect back to us, carrying the pre-login cookie.
    fn callback_request() -> Request {
        callback_request_with("pre-login-sid", "st-1")
    }

    fn callback_request_with(sid: &str, state: &str) -> Request {
        Request::builder()
            .method("GET")
            .uri(format!("/oauth2/callback?code=auth-code&state={state}"))
            .header(header::COOKIE, format!("hs_session={sid}"))
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "app.example.com")
            .body(Body::empty())
            .unwrap()
    }

    /// The `hs_session` value a `Set-Cookie` names.
    fn cookie_sid(resp: &Response) -> String {
        resp.headers()
            .get(header::SET_COOKIE)
            .expect("a rotated id is useless unless the browser is told about it")
            .to_str()
            .unwrap()
            .strip_prefix("hs_session=")
            .expect("cookie names the session")
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn body_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    /// A rotation whose new row could not be written must not drop the old one.
    ///
    /// `store` is best-effort and reports nothing, so `callback` ran the whole
    /// rotation regardless: the new row was never written, the old row was
    /// removed anyway, and the browser was handed a cookie naming a session that
    /// does not exist — logged out at the moment it just logged in, then bounced
    /// back to the IdP by the gate.
    ///
    /// **The four assertions do not carry equal weight**, and the next reader
    /// should not assume they do:
    ///
    /// | # | assertion | against the unfixed code |
    /// |---|-----------|--------------------------|
    /// | 1 | the old row still exists | **RED — this is the oracle** |
    /// | 2 | no new row: one write attempted, zero succeeded | GREEN — non-discriminating by construction; it is here to stop a "fix" that writes twice |
    /// | 3 | no `Set-Cookie` | RED |
    /// | 4 | 503 + the fixed body | RED, but weakest — a "fix" that 503s *and still removes the row* passes 4 and fails 1 |
    #[tokio::test]
    async fn a_rotation_that_could_not_be_stored_keeps_the_old_session() {
        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded
            .redirects
            .insert("st-1".into(), "/dash?tab=runs".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();
        store.fail(&store.fail_store);

        let resp = callback_app(store.clone())
            .oneshot(callback_request())
            .await
            .unwrap();
        let status = resp.status();
        let set_cookie = resp.headers().get(header::SET_COOKIE).cloned();

        // 1 — the oracle.
        assert!(
            store.inner.load("pre-login-sid").await.unwrap().is_some(),
            "the row the browser's cookie still names must survive a rotation \
             that could not be written"
        );
        // 2 — green either way; it fails a fix that retries or double-writes.
        assert_eq!(store.store_attempts(), 1, "exactly one write attempted");
        assert_eq!(store.store_writes(), 0, "and none of them landed");
        // 3
        assert!(
            set_cookie.is_none(),
            "no cookie may be issued for a row that was not written"
        );
        // 4
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_text(resp).await,
            "login is temporarily unavailable, please try logging in again",
            "the OAuth code was spent by the token exchange, so refreshing this \
             URL fails at the token endpoint — the body must say to log in again"
        );
    }

    /// The other half of the truth table: a rotation that *was* written must
    /// still succeed when only the tidy-up delete fails. Refusing the login
    /// there would throw away an authentication that had already completed.
    ///
    /// It says nothing about what the leftover row *is*; that is the test below,
    /// and the two disagreed for a review round.
    #[tokio::test]
    async fn a_rotation_whose_tidy_up_delete_failed_is_still_a_login() {
        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded
            .redirects
            .insert("st-1".into(), "/dash?tab=runs".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();
        store.fail(&store.fail_remove);

        let resp = callback_app(store.clone())
            .oneshot(callback_request())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/dash?tab=runs"
        );
        let new_sid = cookie_sid(&resp);
        assert_eq!(
            store
                .inner
                .load(&new_sid)
                .await
                .unwrap()
                .expect("the rotated row was written")
                .user_id
                .as_deref(),
            Some("kratos-identity-9")
        );
        assert!(
            store.inner.load("pre-login-sid").await.unwrap().is_some(),
            "the delete failed, so the old row is still there"
        );
    }

    /// **The row a failed tidy-up leaves behind can be an authenticated
    /// session.** The comment on that `remove` used to say the opposite — that
    /// the leftover is anonymous, so it authenticates nobody — and that claim
    /// was the whole justification for the delete being silent as well as
    /// non-fatal.
    ///
    /// It is false on the multi-tab path this module documents as ordinary, and
    /// this test drives that path rather than describing it: two tabs each start
    /// a login against one row, and the *second* callback is the one whose
    /// delete fails. By then the row it is rotating is the row the first
    /// callback wrote — `user_id`, access token, refresh token and the second
    /// tab's still-pending `state`, all on it.
    ///
    /// The refresh token is the part that outlives the obvious reasoning: the
    /// leftover can mint fresh access tokens long after the one on it expires,
    /// for as long as the store keeps the row — `DEFAULT_SESSION_TTL_SECS`,
    /// 24 h, which is what `PgSessionStore::from_pool` builds with. It is
    /// asserted below rather than merely said: the stub issues one, so a
    /// rotation that dropped it would be red here.
    ///
    /// Seeding a hand-built authenticated row would assert the same thing more
    /// cheaply and prove less — the question is whether *this code* produces
    /// one, and it does.
    #[tokio::test]
    async fn the_row_a_failed_tidy_up_leaves_behind_can_be_an_authenticated_session() {
        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded.redirects.insert("st-1".into(), "/tab-one".into());
        seeded.redirects.insert("st-2".into(), "/tab-two".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();
        let app = callback_app(store.clone());

        // Tab 1 finishes its login. Its rotation succeeds outright, and carries
        // tab 2's pending `state` onto the new, now authenticated, row.
        let first = app
            .clone()
            .oneshot(callback_request_with("pre-login-sid", "st-1"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::SEE_OTHER);
        let sid_after_tab_one = cookie_sid(&first);

        // Tab 2 comes back carrying the rotated cookie — the browser has one
        // cookie jar, so this is what a real second tab sends. This time the
        // tidy-up delete is the one that fails.
        store.fail(&store.fail_remove);
        let second = app
            .oneshot(callback_request_with(&sid_after_tab_one, "st-2"))
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::SEE_OTHER,
            "the second tab logged in too — only its tidy-up failed"
        );
        assert_ne!(cookie_sid(&second), sid_after_tab_one, "and it rotated");

        let leftover = store
            .inner
            .load(&sid_after_tab_one)
            .await
            .unwrap()
            .expect("the delete failed, so the superseded row is still there");
        assert_eq!(
            leftover.user_id.as_deref(),
            Some("kratos-identity-9"),
            "the superseded row is NOT anonymous: it is a live authenticated \
             session under a cookie value the browser was given"
        );
        assert_eq!(leftover.access_token.as_deref(), Some("at-1"));
        assert_eq!(
            leftover.refresh_token.as_deref(),
            Some("rt-1"),
            "and the refresh token is on it, which is what makes the leftover \
             outlive the access token's expiry"
        );
    }

    /// **A failed delete is not the only way to leave one behind.** Two
    /// callbacks racing on one cookie produce the same authenticated leftover
    /// with every store call succeeding, which is what the comment on that
    /// `remove` would otherwise read as ruling out.
    ///
    /// Tab 2 reads the shared row, then goes to the token endpoint. Tab 1
    /// finishes inside that window: it rotates and *removes* the shared row.
    /// Tab 2's re-read therefore finds nothing, so it writes its own rotated row
    /// from the copy it read at the top, and its `remove` deletes a row that is
    /// already gone. Nobody removes tab 1's row, and the browser's cookie now
    /// names tab 2's — so tab 1's session is orphaned with its tokens intact
    /// until the TTL reclaims it.
    ///
    /// Two provider stubs over one store, because the gated stub serves its
    /// connections on a single thread: tab 1 cannot reach a token endpoint that
    /// tab 2 is blocking. A handshake rather than a timer, for the reason
    /// [`TokenGate`] gives.
    ///
    /// Pre-existing behaviour, and deliberately not fixed here — it is driven so
    /// the sentence describing it is falsifiable.
    #[tokio::test]
    async fn two_callbacks_racing_on_one_cookie_orphan_a_row_with_no_store_failure() {
        let (arrived_tx, mut arrived_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let gated = oauth_provider_stub_with(Some(TokenGate {
            arrived: arrived_tx,
            release: release_rx,
        }));

        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded.redirects.insert("st-1".into(), "/tab-one".into());
        seeded.redirects.insert("st-2".into(), "/tab-two".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();

        let tab_two = callback_app_at(store.clone(), gated);
        let tab_one = callback_app_at(store.clone(), oauth_provider_stub());

        let two = tokio::spawn(async move {
            tab_two
                .oneshot(callback_request_with("pre-login-sid", "st-2"))
                .await
                .unwrap()
        });
        arrived_rx
            .recv()
            .await
            .expect("tab 2 has read the row and is at the token endpoint");

        let one = tab_one
            .oneshot(callback_request_with("pre-login-sid", "st-1"))
            .await
            .unwrap();
        assert_eq!(one.status(), StatusCode::SEE_OTHER);
        let sid_one = cookie_sid(&one);
        assert!(
            store.inner.load("pre-login-sid").await.unwrap().is_none(),
            "tab 1's rotation removed the shared row — that is the precondition \
             for tab 2's re-read finding nothing"
        );

        release_tx.send(()).expect("let tab 2's exchange answer");
        let two = two.await.unwrap();
        assert_eq!(two.status(), StatusCode::SEE_OTHER);
        let sid_two = cookie_sid(&two);
        assert_ne!(
            sid_two, sid_one,
            "the browser's cookie now names tab 2's row"
        );

        // No fixture failure is configured, and this is what says so: every
        // write that was attempted landed. Without it the leftover could be read
        // as a store blip after all.
        assert_eq!(
            store.store_attempts(),
            store.store_writes(),
            "no store call failed — the leftover is ordinary concurrency"
        );

        let orphan = store
            .inner
            .load(&sid_one)
            .await
            .unwrap()
            .expect("nothing removed tab 1's rotated row");
        assert_eq!(orphan.user_id.as_deref(), Some("kratos-identity-9"));
        assert_eq!(orphan.access_token.as_deref(), Some("at-1"));
        assert_eq!(orphan.refresh_token.as_deref(), Some("rt-1"));
    }

    /// A `state` written while the token exchange was in flight must survive the
    /// rotation.
    ///
    /// The window is two IdP round trips wide and a second tab lands in it
    /// routinely: its gate inserts a `state` into the row this callback is about
    /// to rotate. Collapse `callback`'s two loads into one and the row written
    /// under the new id is a snapshot taken *before* that insert, while
    /// `remove(&sid)` deletes the row that held it — so tab 2 comes back to
    /// `400 no state found`. No store failure required; ordinary concurrency is
    /// enough, which is why this is a regression test and not a hardening one.
    ///
    /// The window is opened by a handshake with the provider stub rather than by
    /// a timer, so the interleaving is the same on every run and on a loaded
    /// machine.
    #[tokio::test]
    async fn a_state_stored_while_the_token_exchange_was_in_flight_survives_the_rotation() {
        let (arrived_tx, mut arrived_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let base = oauth_provider_stub_with(Some(TokenGate {
            arrived: arrived_tx,
            release: release_rx,
        }));

        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded.redirects.insert("st-1".into(), "/tab-one".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();

        let app = callback_app_at(store.clone(), base);
        let call = tokio::spawn(async move { app.oneshot(callback_request()).await.unwrap() });

        // Tab 2's gate, mid-exchange: read the row, add its state, write it back.
        arrived_rx.recv().await.expect("the token exchange started");
        let mut mid = store
            .inner
            .load("pre-login-sid")
            .await
            .unwrap()
            .expect("tab 1's row");
        mid.redirects.insert("st-2".into(), "/tab-two".into());
        store.inner.store("pre-login-sid", &mid).await.unwrap();
        release_tx.send(()).expect("let the exchange answer");

        let resp = call.await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let new_sid = cookie_sid(&resp);

        // Without this the assertion below could be satisfied by a rotation that
        // never removed anything, which is a different bug passing this test.
        assert!(
            store.inner.load("pre-login-sid").await.unwrap().is_none(),
            "the rotation still drops the old row"
        );
        let sess = store
            .inner
            .load(&new_sid)
            .await
            .unwrap()
            .expect("the rotated row");
        assert_eq!(
            sess.redirects.get("st-2").map(String::as_str),
            Some("/tab-two"),
            "a login started while this one was at the token endpoint must not \
             be deleted by this one's rotation"
        );
        assert!(!sess.redirects.contains_key("st-1"), "st-1 was consumed");
    }

    /// The re-read's `Err` arm: a rotation whose second `load` could not be made
    /// leaves the old row alone, so the retry the 503 asks for works.
    ///
    /// **`fail_load` cannot reach this branch**, which is why it went untested
    /// through two review rounds: that latch has no call counter, so it fails
    /// the read at the top of the handler and returns before the token exchange.
    /// `fail_load_on_call(2)` is the whole difference.
    ///
    /// The oracle is the surviving row, not the status. Collapse the three arms
    /// to `wl.store.load(&sid).await.unwrap_or_default().unwrap_or(prior)` — the
    /// spelling this branch exists to refuse — and the handler swallows the
    /// error, rotates on the stale copy and deletes the row the browser is still
    /// holding a cookie for.
    #[tokio::test]
    async fn a_re_read_that_could_not_be_made_leaves_the_old_row_for_the_retry() {
        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded
            .redirects
            .insert("st-1".into(), "/dash?tab=runs".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();
        store.fail_load_on_call(2);

        let resp = callback_app(store.clone())
            .oneshot(callback_request())
            .await
            .unwrap();
        let status = resp.status();
        let set_cookie = resp.headers().get(header::SET_COOKIE).cloned();

        // 1 — the oracle. A re-read that failed cannot say what is being
        // deleted, and nothing has been written yet, so both must be intact.
        let old = store
            .inner
            .load("pre-login-sid")
            .await
            .unwrap()
            .expect("the row the browser's cookie still names must survive");
        assert_eq!(
            old.redirects.get("st-1").map(String::as_str),
            Some("/dash?tab=runs"),
            "a retry needs the `state -> orig` entry, not just the row"
        );
        // 2 — and the rotation really did stop before writing, rather than
        // writing a row and then refusing.
        assert_eq!(store.store_attempts(), 0);
        assert_eq!(store.store_writes(), 0);
        // 3
        assert!(
            set_cookie.is_none(),
            "no cookie may be issued for a rotation that did not happen"
        );
        // 4
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The re-read's `Ok(None)` arm: the row is *gone* rather than unreadable —
    /// its TTL lapsed, or another tab's callback removed it — and the copy read
    /// at the top of the handler is what gets written, `redirects` included.
    ///
    /// So a second tab whose `state` was already on that copy still finds it
    /// under the rotated id. `Ok(None) => Session::default()` is the mutation
    /// this discriminates against, and it is the natural "there is nothing to
    /// carry across" reading of the branch.
    ///
    /// It does **not** discriminate against `unwrap_or_default().unwrap_or(prior)`,
    /// and no test can: on this arm that spelling computes the same value. What
    /// it gets wrong is the `Err` arm, which the test above owns.
    #[tokio::test]
    async fn a_row_that_vanished_between_the_two_reads_carries_the_first_read_across() {
        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded.redirects.insert("st-1".into(), "/tab-one".into());
        seeded.redirects.insert("st-2".into(), "/tab-two".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();
        store.blank_load_on_call(2);

        let resp = callback_app(store.clone())
            .oneshot(callback_request())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let new_sid = cookie_sid(&resp);

        let sess = store
            .inner
            .load(&new_sid)
            .await
            .unwrap()
            .expect("the rotated row was written");
        assert_eq!(
            sess.redirects.get("st-2").map(String::as_str),
            Some("/tab-two"),
            "the only evidence of what the row held is the first read, so a \
             second tab's pending state has to come across from there"
        );
        assert!(
            !sess.redirects.contains_key("st-1"),
            "the consumed state is still dropped"
        );
        assert_eq!(
            sess.user_id.as_deref(),
            Some("kratos-identity-9"),
            "and it is a login, not a half-written row"
        );
    }

    /// What a store outage actually costs, per tier — the sentence this crate's
    /// doc comments keep getting wrong, which is why both store headers now
    /// point a reader here instead of restating it. (No count: the previous one
    /// was stale within the round that wrote it, and this is the doc comment
    /// those headers send you to.)
    ///
    /// The gate's `load` fails open, which is easy to read as "an outage
    /// degrades to logging in again, never an error page". It does not: failing
    /// open only reaches the *next* branch. On the api tier that branch is the
    /// 401 and returns before any write, so the fail-open really is the whole
    /// story. On the browser tier it mints a session and writes it, and that
    /// write is fatal — so every gated page is a 503 for as long as the store is
    /// down. Worth knowing before someone plans a maintenance window on the
    /// strength of the prose.
    #[tokio::test]
    async fn a_store_outage_is_a_401_on_the_api_tier_and_a_503_on_the_browser_tier() {
        let tier = |fail_fast: bool| async move {
            let store = Arc::new(FailingStore::new());
            store.fail(&store.fail_load);
            store.fail(&store.fail_store);
            let resolver = Arc::new(KratosUserResolver::new(
                "http://kratos:4434",
                "https://hikari-systems.com/",
                true,
            ));
            let wl = WebLogin::with_store(cfg(), resolver, store.clone());
            let app = Router::new().route("/dash", get(|| async { "ok" })).layer(
                axum::middleware::from_fn_with_state(wl.gate_state(fail_fast), gate),
            );
            app.oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/dash")
                    // A cookie, so the failing `load` is actually reached — the
                    // gate does not ask the store about a request with none.
                    .header(header::COOKIE, "hs_session=some-live-session")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        assert_eq!(
            tier(true).await.status(),
            StatusCode::UNAUTHORIZED,
            "the api tier returns before the write, so the fail-open read is the \
             whole story there"
        );
        assert_eq!(
            tier(false).await.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the browser tier writes a state before redirecting, and that write \
             is fatal — an outage is a 503 per gated page, not a login bounce"
        );
    }

    /// The gate's own write is fatal too. A `state` that was never persisted
    /// guarantees the round trip comes back "no state found", so sending the
    /// browser to the IdP anyway buys a slower failure and blames the IdP for
    /// it.
    ///
    /// Asserts on the **absence of a `Location`** as well as the status: a 303
    /// carrying the authorize URL is exactly what the unfixed code answers.
    #[tokio::test]
    async fn the_gate_refuses_to_start_a_login_it_could_not_store() {
        let store = Arc::new(FailingStore::new());
        store.fail(&store.fail_store);

        let resolver = Arc::new(KratosUserResolver::new(
            "http://kratos:4434",
            "https://hikari-systems.com/",
            true,
        ));
        let wl = WebLogin::with_store(cfg(), resolver, store.clone());
        let app = Router::new().route("/dash", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(wl.gate_state(false), gate),
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/dash")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            resp.headers().get(header::LOCATION).is_none(),
            "a redirect to the IdP with an unstored state is a login loop"
        );
        assert!(
            resp.headers().get(header::SET_COOKIE).is_none(),
            "no cookie for a row that was not written"
        );
        assert_eq!(store.store_writes(), 0);
    }

    /// Logging out is the one operation whose whole purpose is the write, so a
    /// destroy that did not happen must reach the caller — it is the one holding
    /// the response, and answering "you are logged out" while the row is still
    /// live is a false statement about a credential that still works.
    ///
    /// The `id_token` read stays fail-open, which is why this seeds one and
    /// leaves `fail_load` off: the hint is a nicety, and losing it must not stop
    /// the destroy from being attempted.
    #[tokio::test]
    async fn a_logout_whose_delete_failed_is_reported_to_the_caller() {
        let store = Arc::new(FailingStore::new());
        let resolver = Arc::new(KratosUserResolver::new(
            "http://kratos:4434",
            "https://hikari-systems.com/",
            true,
        ));
        let wl = WebLogin::with_store(cfg(), resolver, store.clone());
        let sess = Session {
            id_token: Some("tok-123".into()),
            ..Default::default()
        };
        store.inner.store("sid-1", &sess).await.unwrap();

        assert_eq!(
            wl.end_session("sid-1").await.unwrap().as_deref(),
            Some("tok-123"),
            "the healthy path is unchanged"
        );

        store.inner.store("sid-2", &sess).await.unwrap();
        store.fail(&store.fail_remove);
        assert!(
            wl.end_session("sid-2").await.is_err(),
            "a session that is still live must not be reported as destroyed"
        );
        assert!(
            store.inner.load("sid-2").await.unwrap().is_some(),
            "and it really is still live — otherwise this asserts nothing"
        );
    }

    /// A store outage at `callback`'s read must not read as a bogus `state`.
    ///
    /// `load` failed open into `None`, which lands on the same branch as a
    /// caller who invented a `state` — so an outage answered `400 no state
    /// found` and sent whoever investigated it hunting the IdP for our own
    /// dependency being down. Same misdiagnosis as the headline defect, in the
    /// same handler.
    #[tokio::test]
    async fn a_store_outage_at_the_callback_is_not_reported_as_a_bogus_state() {
        let store = Arc::new(FailingStore::new());
        let mut seeded = Session::default();
        seeded
            .redirects
            .insert("st-1".into(), "/dash?tab=runs".into());
        store.inner.store("pre-login-sid", &seeded).await.unwrap();
        store.fail(&store.fail_load);

        let resp = callback_app(store.clone())
            .oneshot(callback_request())
            .await
            .unwrap();

        let status = resp.status();
        assert_eq!(
            body_text(resp).await,
            "login is temporarily unavailable, please try logging in again"
        );
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// An already-logged-in request passes through untouched: the store is read
    /// once to resolve the user and never written, and no cookie is re-issued.
    #[tokio::test]
    async fn an_authenticated_request_passes_without_a_write() {
        let store = Arc::new(CountingStore::new());
        let sess = Session {
            user_id: Some("kratos-identity-1".into()),
            ..Default::default()
        };
        // Seeded through `inner` so the counters start at zero.
        store.inner.store("sid-live", &sess).await.unwrap();

        let resp = gated_app(store.clone(), true)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/graphql")
                    .header(header::COOKIE, "hs_session=sid-live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.stores(), 0, "authenticating a request must not write");
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn in_memory_store_roundtrip_and_expiry() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        assert!(store.load("sid").await.unwrap().is_none());
        let mut s = Session {
            user_id: Some("u1".into()),
            ..Default::default()
        };
        s.redirects.insert("st".into(), "/orig".into());
        store.store("sid", &s).await.unwrap();
        let got = store.load("sid").await.unwrap().expect("present");
        assert_eq!(got.user_id.as_deref(), Some("u1"));
        assert_eq!(got.redirects.get("st").map(String::as_str), Some("/orig"));
        store.remove("sid").await.unwrap();
        assert!(store.load("sid").await.unwrap().is_none());

        // already-expired entry is evicted on load
        let expired = InMemorySessionStore::new(Duration::from_secs(0));
        expired.store("sid", &Session::default()).await.unwrap();
        assert!(expired.load("sid").await.unwrap().is_none());
    }
}
