//! Browser (Authorization-Code) OAuth2 login with a cookie session, backed by
//! Ory Kratos for user data.
//!
//! Rust port of `@hikari-systems/hs.utils` `lib/oauth2.ts` +
//! `lib/oauth2-kratos.ts` (`authorizeKratosMiddleware`). The flow:
//!   1. An un-authenticated request to a protected route is redirected to the
//!      provider's `authorize` endpoint (`response_type=code`), with a random
//!      `state` → original URL stored in the cookie session.
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::Value;

use crate::mcp_resource_server::kratos_resolver::KratosUserResolver;

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
    /// Public base URL of this server (e.g. `https://app.example.com`), used to
    /// build the `redirect_uri`. No trailing slash required.
    pub public_base: String,
    /// Session cookie name. Default `hs_session`.
    pub cookie_name: String,
    /// Set the `Secure` cookie attribute (enable behind HTTPS).
    pub cookie_secure: bool,
}

impl WebLoginConfig {
    /// Construct with the standard defaults (`callback_uri=/oauth2/callback`,
    /// `cookie_name=hs_session`, `cookie_secure=false`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        profile_url: impl Into<String>,
        scopes: impl Into<String>,
        public_base: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            profile_url: profile_url.into(),
            scopes: scopes.into(),
            callback_uri: "/oauth2/callback".to_string(),
            public_base: public_base.into(),
            cookie_name: "hs_session".to_string(),
            cookie_secure: false,
        }
    }
}

/// One server-side session, keyed by the `sid` cookie. Mirrors the express
/// `req.session` used by the TS middleware.
#[derive(Debug, Clone, Default)]
struct Session {
    user_id: Option<String>,
    profile: Option<Value>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
    /// `state` → original URL, set at redirect time, consumed at callback.
    redirects: HashMap<String, String>,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

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
    sessions: Sessions,
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
    pub fn new(cfg: WebLoginConfig, resolver: Arc<KratosUserResolver>) -> Self {
        Self {
            cfg: Arc::new(cfg),
            sessions: Arc::new(Mutex::new(HashMap::new())),
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

    fn redirect_uri(&self) -> String {
        format!(
            "{}{}",
            self.cfg.public_base.trim_end_matches('/'),
            self.cfg.callback_uri
        )
    }

    fn authorize_url(&self, state_key: &str) -> String {
        let redirect_uri = self.redirect_uri();
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
        let (tok, refresh, exp) = {
            let store = self.sessions.lock().unwrap();
            let u = store.get(sid)?;
            (u.access_token.clone(), u.refresh_token.clone(), u.expires_at)
        };
        let expired = exp.map(|e| e <= now_secs()).unwrap_or(false);
        if tok.is_some() && !expired {
            return tok;
        }
        if let Some(rt) = refresh {
            if let Ok(t) = do_token_refresh(&self.http, &self.cfg, &rt).await {
                let mut store = self.sessions.lock().unwrap();
                if let Some(u) = store.get_mut(sid) {
                    u.access_token = Some(t.access_token.clone());
                    u.refresh_token = t.refresh_token.clone();
                    u.expires_at = t.expires_in.map(|e| now_secs() + e);
                }
                return Some(t.access_token);
            }
        }
        let mut store = self.sessions.lock().unwrap();
        if let Some(u) = store.get_mut(sid) {
            u.access_token = None;
            u.refresh_token = None;
            u.expires_at = None;
        }
        None
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

fn build_set_cookie(cfg: &WebLoginConfig, sid: &str) -> HeaderValue {
    let mut s = format!("{}={}; HttpOnly; SameSite=Lax; Path=/", cfg.cookie_name, sid);
    if cfg.cookie_secure {
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
        tracing::warn!(error = err, "web_login: provider returned error");
        return bad_request("login error");
    }
    let (Some(code), Some(state_key)) = (q.code, q.state) else {
        return bad_request("missing code/state");
    };
    let Some(sid) = read_cookie(&headers, &wl.cfg.cookie_name) else {
        return bad_request("no session cookie");
    };
    let orig = {
        let store = wl.sessions.lock().unwrap();
        store
            .get(&sid)
            .and_then(|s| s.redirects.get(&state_key).cloned())
    };
    let Some(orig) = orig else {
        tracing::warn!(state = %state_key, "web_login: no stored state");
        return bad_request("no state found");
    };

    let token = match do_token_exchange(&wl.http, &wl.cfg, &code, &wl.redirect_uri()).await {
        Ok(t) if !t.access_token.is_empty() => t,
        Ok(_) => return bad_request("no access token in response"),
        Err(e) => {
            tracing::warn!(error = %e, "web_login: token exchange failed");
            return bad_request("token exchange failed");
        }
    };
    let userinfo = match get_oauth_profile_by_token(&wl.http, &wl.cfg.profile_url, &token.access_token)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "web_login: userinfo fetch failed");
            return bad_request("profile fetch failed");
        }
    };
    let Some(resolved) = wl.resolver.resolve(&userinfo).await else {
        return bad_request("could not resolve user");
    };

    {
        let mut store = wl.sessions.lock().unwrap();
        let sess = store.entry(sid).or_default();
        sess.redirects.remove(&state_key);
        sess.user_id = Some(resolved.user_id.clone());
        sess.profile = serde_json::to_value(&resolved.profile).ok();
        sess.access_token = Some(token.access_token);
        sess.refresh_token = token.refresh_token;
        sess.expires_at = token.expires_in.map(|e| now_secs() + e);
    }
    tracing::debug!(user = %resolved.user_id, "web_login: login complete, redirecting to {orig}");
    see_other(&orig, None)
}

/// Middleware (use with `from_fn_with_state(web_login.gate_state(fail_fast), gate)`)
/// that requires a logged-in cookie session. Logged in → continue (with
/// [`CurrentUser`] in request extensions); else 401 (`fail_fast`) or a 302 to
/// the provider's authorize endpoint.
pub async fn gate(State(g): State<GateState>, req: Request, next: Next) -> Response {
    let wl = &g.wl;

    // Resolve (or mint) the session id from the cookie.
    let (sid, set_cookie) = match read_cookie(req.headers(), &wl.cfg.cookie_name) {
        Some(s) => (s, None),
        None => {
            let s = uuid::Uuid::new_v4().to_string();
            wl.sessions.lock().unwrap().entry(s.clone()).or_default();
            let cookie = build_set_cookie(&wl.cfg, &s);
            (s, Some(cookie))
        }
    };

    let user = {
        let store = wl.sessions.lock().unwrap();
        store
            .get(&sid)
            .and_then(|s| s.user_id.clone().map(|uid| (uid, s.profile.clone())))
    };

    if let Some((user_id, profile)) = user {
        let mut req = req;
        req.extensions_mut().insert(CurrentUser { user_id, profile });
        let mut resp = next.run(req).await;
        if let Some(c) = set_cookie {
            resp.headers_mut().insert(header::SET_COOKIE, c);
        }
        return resp;
    }

    if g.fail_fast {
        let mut resp = (StatusCode::UNAUTHORIZED, "not logged in").into_response();
        if let Some(c) = set_cookie {
            resp.headers_mut().insert(header::SET_COOKIE, c);
        }
        return resp;
    }

    // Begin the authorization-code dance: stash state → original URL.
    let orig = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let state_key = uuid::Uuid::new_v4().to_string();
    {
        let mut store = wl.sessions.lock().unwrap();
        store
            .entry(sid)
            .or_default()
            .redirects
            .insert(state_key.clone(), orig);
    }
    see_other(&wl.authorize_url(&state_key), set_cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> WebLoginConfig {
        let mut c = WebLoginConfig::new(
            "client-abc",
            "secret-xyz",
            "https://auth.example.com/oauth2/auth",
            "https://auth.example.com/oauth2/token",
            "https://auth.example.com/userinfo",
            "openid profile email",
            "https://app.example.com/",
        );
        c.cookie_secure = true;
        c
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
    fn redirect_uri_trims_trailing_slash() {
        assert_eq!(
            wl().redirect_uri(),
            "https://app.example.com/oauth2/callback"
        );
    }

    #[test]
    fn authorize_url_has_oauth_params() {
        let u = wl().authorize_url("state-123");
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
        let c = build_set_cookie(&cfg(), "sid-1");
        let s = c.to_str().unwrap();
        assert!(s.starts_with("hs_session=sid-1"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("Secure"));
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
}
