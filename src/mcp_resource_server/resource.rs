//! Several protected resources behind one server: a resource, and so a
//! required `aud`, per request path.
//!
//! [`super::middleware::auth_middleware`] checks one static audience for
//! every path. A server that issues per-path resources (woodhouse's
//! `/mcp` and `/mcp/o/{orgId}`) layers [`auth_middleware_per_resource`]
//! instead: it maps the path to its resource, 404s a path with none,
//! verifies the token with [`JwtVerifier::verify_for_resource`] (exact
//! `aud`, and no second audience of this server), and answers 401 naming
//! that path's resource and metadata URL. On success the request carries
//! the usual [`AuthExtension`] plus a [`VerifiedResource`].
//!
//! [`JwtVerifier::verify_for_resource`]: super::jwt::JwtVerifier::verify_for_resource
//! [`AuthExtension`]: super::middleware::AuthExtension

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use super::metadata::{split_resource, SubResourceValidator};
use super::middleware::{extension_for, extract_bearer, unauthorized_for, AuthState};

/// Maps a request path, as the middleware sees it, to the resource it
/// belongs to, or `None` (404). The resource is both the RFC 9728
/// `resource` and the `aud` a token must carry, byte for byte.
pub type ResourceFor = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The resource a request was verified for, inserted next to the
/// `AuthExtension` by [`auth_middleware_per_resource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedResource(pub String);

/// State for [`auth_middleware_per_resource`]: the usual [`AuthState`] and
/// the path-to-resource map. Cheap to clone.
#[derive(Clone)]
pub struct ResourceAuthState {
    auth: AuthState,
    resource_for: ResourceFor,
}

impl ResourceAuthState {
    /// `auth.auth_cfg.expected_audience` is the server's base audience: any
    /// `aud` value equal to it or under it at a `/` counts as one of this
    /// server's, and a token may carry exactly one, the path's resource.
    pub fn new(auth: AuthState, resource_for: ResourceFor) -> Self {
        Self { auth, resource_for }
    }

    pub fn auth(&self) -> &AuthState {
        &self.auth
    }

    /// The resource for `path`, as the middleware would require it.
    pub fn resource_for(&self, path: &str) -> Option<String> {
        (self.resource_for)(path)
    }
}

/// The usual [`ResourceFor`]: the resource's own path (from
/// `resource_server_url`) is the resource itself, and `{path}/{rest}` is
/// `<resource_server_url>/{rest}` when `accept(rest)`. Anything else,
/// including a trailing `/`, is `None`. The path is compared raw, so the
/// middleware must sit where it sees the full path (outside a `nest`).
pub fn sub_resource_mapper(resource_server_url: &str, accept: SubResourceValidator) -> ResourceFor {
    let base = resource_server_url.trim_end_matches('/').to_string();
    let (_, path) = split_resource(&base);
    let own = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    let prefix = format!("{path}/");
    Arc::new(move |p: &str| {
        if p == own {
            return Some(base.clone());
        }
        let rest = p.strip_prefix(prefix.as_str())?;
        (!rest.is_empty() && accept(rest)).then(|| format!("{base}/{rest}"))
    })
}

/// True for a UUID in its canonical form only: lowercase hex, hyphenated
/// 8-4-4-4-12. Uppercase, braced, `urn:uuid:` and unhyphenated forms are
/// refused, so one id has one resource URL.
pub fn is_canonical_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

/// Axum middleware fn. Wire with
/// `axum::middleware::from_fn_with_state(state, auth_middleware_per_resource)`.
pub async fn auth_middleware_per_resource(
    State(state): State<ResourceAuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(resource) = state.resource_for(request.uri().path()) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response();
    };

    let token = match extract_bearer(&request) {
        Some(t) => t,
        None => return unauthorized_for(&resource, "missing Bearer token"),
    };

    let auth = &state.auth;
    let claims = match auth
        .verifier
        .verify_for_resource(&token, &resource, &auth.auth_cfg.expected_audience)
        .await
    {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!("JWT verification failed for {resource}: {err:#}");
            return unauthorized_for(&resource, "invalid_token");
        }
    };

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let extension = extension_for(auth, &claims, method, path).await;
    request.extensions_mut().insert(extension);
    request.extensions_mut().insert(VerifiedResource(resource));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        http::{header, StatusCode},
        middleware::from_fn_with_state,
        response::Response,
        routing::any,
        Router,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::mcp_resource_server::apply::{apply_mcp_auth, apply_mcp_auth_with, McpAuthStores};
    use crate::mcp_resource_server::config::McpAuthConfig;
    use crate::mcp_resource_server::kratos_resolver::KratosUserResolver;
    use crate::mcp_resource_server::middleware::{auth_middleware, AuthExtension};
    use crate::mcp_resource_server::stores::JsonWebKeySet;

    const ISS: &str = "https://sso.example.test";
    const BASE: &str = "https://wh.example.test/mcp";
    const ORG_A: &str = "0b6f3c1e-2a4d-4e8f-9b1a-5c7d9e0f1a2b";
    const ORG_B: &str = "7d1e2f3a-4b5c-4d6e-8f70-81a2b3c4d5e6";
    const PRM: &str = "https://wh.example.test/.well-known/oauth-protected-resource/mcp";

    /// A test-only RSA key (PKCS#1 DER), made for these tests and used
    /// nowhere else. `N` is its modulus, base64url.
    const KEY_DER: &[u8] = include_bytes!("testdata/rsa_test_key.der");
    const N: &str = "oI_ZTxc45TLhTT2vxRPs-CLdbKLOiqg4Ykbq6pMZpYHpYWrNEpkA0wPQNnzDXv0CVFpwpOjqhZjcY_ZH5ARsORdeLpuyyaHviHrL_GSb-T0FKkaNv4tJ1kKcHJO5wMZ6O5qDdA2QJ5SCtXiLSSAocNa-kJKA2if9bV-Q2nZhgS7Regm9SUHkH97sfPazPDGqUuZaAph8FN92WjpoviornpWDbaN9WO-cMNwrB6r1JjFTvUYTw9CYQ7he7r8HNfApnTstPb2YurG0RJoG4DKYn1M7xIXX8ycD0XqKtATetMWmqBPIkV1B52kpclpgWaxu2FF3r7ESWoL2_EGvSwtPxw";

    fn org(id: &str) -> String {
        format!("{BASE}/o/{id}")
    }

    fn token(aud: Value) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("k1".into());
        let claims = json!({
            "sub": "4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
            "iss": ISS,
            "aud": aud,
            "exp": now + 300,
            "iat": now,
            "scp": ["mcp:read"],
            "client_id": "c1",
        });
        encode(&header, &claims, &EncodingKey::from_rsa_der(KEY_DER)).unwrap()
    }

    fn cfg() -> Arc<McpAuthConfig> {
        let cfg: McpAuthConfig = serde_json::from_value(json!({
            "resourceServerUrl": BASE,
            "expectedAudience": BASE,
            "supportedScopes": "mcp:read,mcp:write",
            "enableDcr": "false",
        }))
        .unwrap();
        Arc::new(cfg.with_runtime(Some(ISS.into()), None, None, None, None))
    }

    async fn stores() -> McpAuthStores {
        let stores = McpAuthStores::in_memory();
        let jwk =
            json!({ "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": N, "e": "AQAB" });
        stores
            .jwks
            .set(
                ISS,
                &format!("{ISS}/jwks"),
                JsonWebKeySet { keys: vec![jwk] },
            )
            .await;
        stores
    }

    fn resolver() -> Arc<KratosUserResolver> {
        Arc::new(KratosUserResolver::new(
            "http://127.0.0.1:9",
            "https://hikari-systems.com/",
            false,
        ))
    }

    /// woodhouse's shape: `/mcp` and `/mcp/o/<canonical uuid>`.
    fn woodhouse_accept() -> SubResourceValidator {
        Arc::new(|rest: &str| rest.strip_prefix("o/").is_some_and(is_canonical_uuid))
    }

    async fn echo(req: Request) -> String {
        let resource = req
            .extensions()
            .get::<VerifiedResource>()
            .map(|r| r.0.clone());
        let ext = req.extensions().get::<AuthExtension>().cloned();
        json!({
            "resource": resource,
            "sub": ext.as_ref().and_then(|e| e.sub.clone()),
            "scopes": ext.map(|e| e.scopes),
        })
        .to_string()
    }

    async fn per_resource_app() -> Router {
        let (public, state) =
            apply_mcp_auth_with(cfg(), stores().await, resolver(), woodhouse_accept());
        let mcp = Router::new()
            .route("/mcp", any(echo))
            .route("/mcp/{*rest}", any(echo))
            .route_layer(from_fn_with_state(state, auth_middleware_per_resource));
        public.merge(mcp)
    }

    async fn legacy_app() -> Router {
        let (public, state) = apply_mcp_auth(cfg(), stores().await, resolver());
        let mcp = Router::new()
            .route("/mcp", any(echo))
            .route_layer(from_fn_with_state(state, auth_middleware));
        public.merge(mcp)
    }

    async fn call(app: &Router, path: &str, bearer: Option<&str>) -> Response {
        let mut req = Request::builder().uri(path);
        if let Some(t) = bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        app.clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body(resp: Response) -> Value {
        serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    fn www_authenticate(resp: &Response) -> &str {
        resp.headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap()
    }

    // --- the path map -------------------------------------------------

    #[test]
    fn canonical_uuid_only() {
        assert!(is_canonical_uuid(ORG_A));
        assert!(!is_canonical_uuid(&ORG_A.to_uppercase()));
        assert!(!is_canonical_uuid(&ORG_A.replace('-', "")));
        assert!(!is_canonical_uuid(&format!("{{{ORG_A}}}")));
        assert!(!is_canonical_uuid(&format!("{ORG_A}0")));
        assert!(!is_canonical_uuid("0b6f3c1e-2a4d-4e8f-9b1a-5c7d9e0f1a2g"));
    }

    #[test]
    fn the_mapper_is_exact() {
        let map = sub_resource_mapper(BASE, woodhouse_accept());
        assert_eq!(map("/mcp").as_deref(), Some(BASE));
        assert_eq!(map(&format!("/mcp/o/{ORG_A}")), Some(org(ORG_A)));
        for p in [
            "/mcp/".to_string(),
            "/mcpx".to_string(),
            "/mcp/o".to_string(),
            "/mcp/o/".to_string(),
            format!("/mcp/o/{ORG_A}/"),
            format!("/mcp/o/{}", ORG_A.to_uppercase()),
            format!("/mcp/o/{ORG_A}/x"),
            "/mcp/../admin".to_string(),
            "/mcp/o/%2e%2e".to_string(),
            format!("/mcp/o/%30{}", &ORG_A[1..]),
            "/other".to_string(),
        ] {
            assert_eq!(map(&p), None, "{p}");
        }
    }

    // --- the per-resource middleware ------------------------------------

    #[tokio::test]
    async fn exact_tokens_are_accepted_at_their_own_path() {
        let app = per_resource_app().await;
        let resp = call(&app, "/mcp", Some(&token(json!(BASE)))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body(resp).await;
        assert_eq!(b["resource"], BASE);
        assert_eq!(b["scopes"], json!(["mcp:read"]));

        let path = format!("/mcp/o/{ORG_A}");
        let resp = call(&app, &path, Some(&token(json!([org(ORG_A)])))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body(resp).await["resource"], org(ORG_A));

        // Another server's audience alongside is ignored.
        let resp = call(
            &app,
            &path,
            Some(&token(json!([org(ORG_A), "https://bae.example.test/mcp"]))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tokens_never_cross_paths() {
        let app = per_resource_app().await;
        let at_a = format!("/mcp/o/{ORG_A}");
        let at_b = format!("/mcp/o/{ORG_B}");
        for (path, aud) in [
            (at_a.as_str(), json!(BASE)),       // base token at an org path
            ("/mcp", json!(org(ORG_A))),        // org token at the base
            (at_b.as_str(), json!(org(ORG_A))), // org A's token at org B's path
        ] {
            let resp = call(&app, path, Some(&token(aud.clone()))).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{aud} at {path}");
        }
    }

    #[tokio::test]
    async fn two_woodhouse_audiences_are_refused_everywhere() {
        let app = per_resource_app().await;
        let paths = [
            "/mcp".to_string(),
            format!("/mcp/o/{ORG_A}"),
            format!("/mcp/o/{ORG_B}"),
        ];
        for aud in [json!([BASE, org(ORG_A)]), json!([org(ORG_A), org(ORG_B)])] {
            let t = token(aud.clone());
            for path in &paths {
                let resp = call(&app, path, Some(&t)).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{aud} at {path}");
            }
        }
    }

    #[tokio::test]
    async fn near_miss_audiences_are_refused() {
        let app = per_resource_app().await;
        let at_a = format!("/mcp/o/{ORG_A}");
        for (path, aud) in [
            ("/mcp", format!("{BASE}/")),
            ("/mcp", format!("{BASE}/../admin")),
            ("/mcp", format!("{BASE}/%2e%2e")),
            ("/mcp", format!("{BASE}?x")),
            ("/mcp", format!("{BASE}#f")),
            ("/mcp", format!("{BASE}x")),
            (at_a.as_str(), format!("{}/", org(ORG_A))),
            (at_a.as_str(), format!("{BASE}/o/{}", ORG_A.to_uppercase())),
            (at_a.as_str(), format!("{}?x", org(ORG_A))),
            (at_a.as_str(), format!("{}#f", org(ORG_A))),
        ] {
            let resp = call(&app, path, Some(&token(json!(aud)))).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{aud} at {path}");
        }
    }

    #[tokio::test]
    async fn paths_with_no_resource_are_404_before_auth() {
        let app = per_resource_app().await;
        let t = token(json!(BASE));
        for path in [
            "/mcp/".to_string(),
            "/mcpx".to_string(),
            format!("/mcp/o/{ORG_A}/"),
            format!("/mcp/o/{}", ORG_A.to_uppercase()),
            "/mcp/o/%2e%2e".to_string(),
            "/mcp/../admin".to_string(),
        ] {
            for bearer in [None, Some(t.as_str())] {
                let resp = call(&app, &path, bearer).await;
                assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
            }
        }
    }

    #[tokio::test]
    async fn the_401_names_each_paths_resource_and_metadata() {
        let app = per_resource_app().await;
        let resp = call(&app, "/mcp", None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&resp),
            format!("Bearer realm=\"{BASE}\", error=\"missing Bearer token\", resource_metadata=\"{PRM}\"")
        );

        let resp = call(&app, &format!("/mcp/o/{ORG_A}"), Some(&token(json!(BASE)))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&resp),
            format!(
                "Bearer realm=\"{}\", error=\"invalid_token\", resource_metadata=\"{PRM}/o/{ORG_A}\"",
                org(ORG_A)
            )
        );
        assert_eq!(body(resp).await, json!({ "error": "invalid_token" }));
    }

    #[tokio::test]
    async fn metadata_per_path() {
        let app = per_resource_app().await;
        let resp = call(&app, "/.well-known/oauth-protected-resource/mcp", None).await;
        assert_eq!(body(resp).await["resource"], BASE);

        let resp = call(
            &app,
            &format!("/.well-known/oauth-protected-resource/mcp/o/{ORG_A}"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["cache-control"], "public, max-age=300");
        assert_eq!(
            body(resp).await,
            json!({
                "resource": org(ORG_A),
                "authorization_servers": [ISS],
                "scopes_supported": ["mcp:read", "mcp:write"],
                "bearer_methods_supported": ["header"],
            })
        );

        for rest in [
            format!("o/{ORG_A}/"),
            format!("o/{}", ORG_A.to_uppercase()),
            "o/%2e%2e".to_string(),
            format!("o/%30{}", &ORG_A[1..]),
            "x".to_string(),
        ] {
            let resp = call(
                &app,
                &format!("/.well-known/oauth-protected-resource/mcp/{rest}"),
                None,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{rest}");
        }
    }

    // --- the old API, unchanged ----------------------------------------

    /// `apply_mcp_auth` + `auth_middleware` answer exactly as in v0.32.4:
    /// the 401, the metadata, no sub-resource route, and the audience check
    /// by containment of `expected_audience`.
    #[tokio::test]
    async fn apply_mcp_auth_is_unchanged() {
        let app = legacy_app().await;

        let resp = call(&app, "/mcp", None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&resp),
            "Bearer realm=\"https://wh.example.test/mcp\", error=\"missing Bearer token\", \
             resource_metadata=\"https://wh.example.test/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(body(resp).await, json!({ "error": "missing Bearer token" }));

        let resp = call(&app, "/mcp", Some("not-a-jwt")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate(&resp),
            "Bearer realm=\"https://wh.example.test/mcp\", error=\"invalid_token\", \
             resource_metadata=\"https://wh.example.test/.well-known/oauth-protected-resource/mcp\""
        );

        let prm = json!({
            "resource": "https://wh.example.test/mcp",
            "authorization_servers": ["https://sso.example.test"],
            "scopes_supported": ["mcp:read", "mcp:write"],
            "bearer_methods_supported": ["header"],
        });
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let resp = call(&app, path, None).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.headers()["cache-control"], "public, max-age=300");
            assert_eq!(body(resp).await, prm, "{path}");
        }
        let resp = call(
            &app,
            &format!("/.well-known/oauth-protected-resource/mcp/o/{ORG_A}"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Containment, as before: one static audience, other values ignored.
        for aud in [
            json!(BASE),
            json!([BASE, org(ORG_A)]),
            json!(["https://bae.example.test/mcp", BASE]),
        ] {
            let resp = call(&app, "/mcp", Some(&token(aud.clone()))).await;
            assert_eq!(resp.status(), StatusCode::OK, "{aud}");
            let b = body(resp).await;
            assert_eq!(
                b["resource"],
                Value::Null,
                "no VerifiedResource from the old middleware"
            );
            assert_eq!(b["sub"], "4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f");
        }
        let resp = call(&app, "/mcp", Some(&token(json!(org(ORG_A))))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_still_reports_the_first_aud() {
        let (_, state) = apply_mcp_auth(cfg(), stores().await, resolver());
        let claims = state
            .verifier
            .verify(&token(json!(["https://bae.example.test/mcp", BASE])))
            .await
            .unwrap();
        assert_eq!(claims.aud, "https://bae.example.test/mcp");
        let claims = state
            .verifier
            .verify_for_resource(
                &token(json!(["https://bae.example.test/mcp", BASE])),
                BASE,
                BASE,
            )
            .await
            .unwrap();
        assert_eq!(claims.aud, BASE);
    }
}
