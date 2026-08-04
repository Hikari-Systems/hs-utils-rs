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
/// Reads return `None` when the session is absent (or on a backend failure —
/// stores should fail open so an outage degrades to "log in again" rather than
/// erroring every request). Writes are best-effort. Implementations are
/// responsible for expiry (TTL).
#[async_trait]
pub trait WebSessionStore: Send + Sync {
    async fn load(&self, sid: &str) -> Option<Session>;
    async fn store(&self, sid: &str, session: &Session);
    async fn remove(&self, sid: &str);
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

#[async_trait]
impl WebSessionStore for InMemorySessionStore {
    async fn load(&self, sid: &str) -> Option<Session> {
        let mut map = self.map.lock().unwrap();
        match map.get(sid) {
            Some((s, exp)) if *exp > Instant::now() => Some(s.clone()),
            Some(_) => {
                map.remove(sid);
                None
            }
            None => None,
        }
    }

    async fn store(&self, sid: &str, session: &Session) {
        self.map
            .lock()
            .unwrap()
            .insert(sid.to_string(), (session.clone(), Instant::now() + self.ttl));
    }

    async fn remove(&self, sid: &str) {
        self.map.lock().unwrap().remove(sid);
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
        let mut sess = self.store.load(sid).await?;
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
                self.store.store(sid, &sess).await;
                return Some(t.access_token);
            }
        }
        sess.access_token = None;
        sess.refresh_token = None;
        sess.expires_at = None;
        self.store.store(sid, &sess).await;
        None
    }

    /// The OIDC `id_token` captured at login, for RP-initiated logout
    /// (`id_token_hint`). Returns `None` when there is no session or it predates
    /// id_token capture.
    pub async fn id_token(&self, sid: &str) -> Option<String> {
        self.store.load(sid).await?.id_token
    }

    /// End the session: read the `id_token` (for `id_token_hint`), remove the
    /// session from the store, and return the id_token. Use this for logout —
    /// destroy the local session, then redirect to the IdP's RP-initiated logout
    /// endpoint with the returned hint.
    pub async fn end_session(&self, sid: &str) -> Option<String> {
        let id_token = self.store.load(sid).await.and_then(|s| s.id_token);
        self.store.remove(sid).await;
        id_token
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
fn log_safe(s: &str) -> String {
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

async fn callback(
    State(wl): State<WebLogin>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if let Some(err) = q.error.as_deref() {
        // Already a `&str`, so the formatter escapes it — but it is still an
        // unbounded attacker-supplied query parameter, so it is capped too.
        tracing::warn!(error = log_safe(err).as_str(), "web_login: provider returned error");
        return bad_request("login error");
    }
    let (Some(code), Some(state_key)) = (q.code, q.state) else {
        return bad_request("missing code/state");
    };
    let Some(sid) = read_cookie(&headers, &wl.cfg.cookie_name) else {
        return bad_request("no session cookie");
    };
    let orig = wl
        .store
        .load(&sid)
        .await
        .and_then(|s| s.redirects.get(&state_key).cloned());
    let Some(orig) = orig else {
        // Recorded as `&str`, NOT `%state_key`. The `%` sigil formats via
        // Display, which the fmt layer passes through unescaped — so a
        // `state` containing CRLF lets an unauthenticated caller inject
        // whole forged lines into the log stream, indistinguishable from
        // real ones. As a `&str` the formatter escapes it. Bounded too:
        // this value is attacker-chosen and otherwise unlimited, which
        // sidesteps the caps applied to `url.query` and the user agent.
        tracing::warn!(state = log_safe(&state_key).as_str(), "web_login: no stored state");
        return bad_request("no state found");
    };

    let token = match do_token_exchange(&wl.http, &wl.cfg, &code, &wl.redirect_uri(&headers)).await {
        Ok(t) if !t.access_token.is_empty() => t,
        Ok(_) => return bad_request("no access token in response"),
        Err(e) => {
            tracing::warn!(error = log_safe(&e.to_string()).as_str(), "web_login: token exchange failed");
            return bad_request("token exchange failed");
        }
    };
    let userinfo = match get_oauth_profile_by_token(&wl.http, &wl.cfg.profile_url, &token.access_token)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = log_safe(&e.to_string()).as_str(), "web_login: userinfo fetch failed");
            return bad_request("profile fetch failed");
        }
    };
    let Some(resolved) = wl.resolver.resolve(&userinfo).await else {
        return bad_request("could not resolve user");
    };

    {
        let mut sess = wl.store.load(&sid).await.unwrap_or_default();
        sess.redirects.remove(&state_key);
        sess.user_id = Some(resolved.user_id.clone());
        sess.profile = serde_json::to_value(&resolved.profile).ok();
        sess.access_token = Some(token.access_token);
        sess.refresh_token = token.refresh_token;
        sess.id_token = token.id_token;
        sess.expires_at = token.expires_in.map(|e| now_secs() + e);
        wl.store.store(&sid, &sess).await;
    }
    tracing::debug!(user = %resolved.user_id, "web_login: login complete, redirecting to {orig}");
    see_other(&orig, None)
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
pub async fn gate(State(g): State<GateState>, req: Request, next: Next) -> Response {
    let span = tracing::info_span!(
        "auth.gate",
        auth.gate.fail_fast = g.fail_fast,
        auth.gate.outcome = tracing::field::Empty,
        auth.gate.session.present = tracing::field::Empty,
        auth.gate.session.minted = tracing::field::Empty,
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
    let user = match &cookie_sid {
        Some(sid) => wl
            .store
            .load(sid)
            .await
            .and_then(|s| s.user_id.clone().map(|uid| (uid, s.profile.clone()))),
        None => None,
    };

    if let Some((user_id, profile)) = user {
        span.record("auth.gate.outcome", "authenticated");
        span.record("auth.gate.session.minted", false);
        span.record("user.id", user_id.as_str());
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
    // and the only one that writes. The `load(..).unwrap_or_default()` below is
    // what makes the lazy mint safe: with no row it yields a default session,
    // takes the state insert and stores it, creating the row here instead. Break
    // that and the callback finds no state and every login 400s.
    let minted = cookie_sid.is_none();
    let sid = cookie_sid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let set_cookie = minted.then(|| build_set_cookie(&wl.cfg, &sid, request_is_https(headers)));

    let orig = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let state_key = uuid::Uuid::new_v4().to_string();
    {
        let mut sess = wl.store.load(&sid).await.unwrap_or_default();
        sess.redirects.insert(state_key.clone(), orig);
        wl.store.store(&sid, &sess).await;
    }
    span.record("auth.gate.outcome", "redirect_to_login");
    span.record("auth.gate.session.minted", minted);
    GateDecision::Respond(see_other(&wl.authorize_url(&state_key, headers), set_cookie))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        wl.store.store("sid-1", &sess).await;
        assert_eq!(wl.id_token("sid-1").await.as_deref(), Some("tok-123"));
        assert_eq!(wl.end_session("sid-1").await.as_deref(), Some("tok-123"));
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
        async fn load(&self, sid: &str) -> Option<Session> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.load(sid).await
        }
        async fn store(&self, sid: &str, session: &Session) {
            self.stores.fetch_add(1, Ordering::SeqCst);
            self.inner.store(sid, session).await
        }
        async fn remove(&self, sid: &str) {
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
        store.inner.store("sid-midflow", &midflow).await;

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
        let sess = store
            .inner
            .load("sid-midflow")
            .await
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
        store.inner.store("sid-live", &sess).await;

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
        assert!(store.load("sid").await.is_none());
        let mut s = Session {
            user_id: Some("u1".into()),
            ..Default::default()
        };
        s.redirects.insert("st".into(), "/orig".into());
        store.store("sid", &s).await;
        let got = store.load("sid").await.expect("present");
        assert_eq!(got.user_id.as_deref(), Some("u1"));
        assert_eq!(got.redirects.get("st").map(String::as_str), Some("/orig"));
        store.remove("sid").await;
        assert!(store.load("sid").await.is_none());

        // already-expired entry is evicted on load
        let expired = InMemorySessionStore::new(Duration::from_secs(0));
        expired.store("sid", &Session::default()).await;
        assert!(expired.load("sid").await.is_none());
    }
}
