//! Terms-acceptance login hydration + session-profile refresh.
//!
//! Login resolves the session profile from the OAuth `OauthProfile`, which has
//! no terms field — so without hydration a fresh session always reads
//! `checkTermsAccepted == false` until the user re-accepts. The controller calls
//! [`ensure_terms_hydrated`] once per authenticated request (it self-skips after
//! the first) to pull `metadata_public.terms.version` from Kratos into the
//! cached profile. [`refresh_session_profile`] is the shared write-back used by
//! both hydration and the `acceptTerms` mutation.

use serde_json::{json, Value};

use super::graphql::context::GqlContext;
use super::services::CoreServices;

/// Hydrate `termsVersion` into the session profile from Kratos
/// (`metadata_public.terms.version`) on the first authenticated request of a
/// session. Idempotent per session: once the `termsVersion` key is present (a
/// real value or `null` for a user who has not accepted) the Kratos round-trip
/// is skipped. Patches both the persisted session (so later requests are cache
/// hits) and the in-memory `gctx` (so the current request sees the value).
pub async fn ensure_terms_hydrated(core: &CoreServices, gctx: &mut GqlContext) {
    // Already resolved this session (key present, possibly null) — nothing to do.
    if gctx
        .profile
        .as_ref()
        .is_some_and(|p| p.get("termsVersion").is_some())
    {
        return;
    }
    let Some(user_id) = gctx.user_id.clone() else {
        return;
    };

    let version = core.kratos.terms_version(&user_id).await;
    let value = match version {
        Some(v) => Value::String(v),
        None => Value::Null,
    };

    // Persist into the session store so subsequent requests skip the lookup.
    refresh_session_profile(
        core,
        gctx.session_id.as_deref(),
        json!({ "termsVersion": value }),
    )
    .await;

    // Patch the in-memory profile so the current request sees it immediately.
    match gctx.profile.as_mut() {
        Some(Value::Object(map)) => {
            map.insert("termsVersion".into(), value);
        }
        _ => {
            gctx.profile = Some(json!({ "termsVersion": value }));
        }
    }
}

/// Shallow-merge `patch` into the cached session's `profile` and store it back.
/// No-op when there is no session store or session id. Round-trips the session
/// through JSON (its fields are private to `web_login`).
pub async fn refresh_session_profile(core: &CoreServices, session_id: Option<&str>, patch: Value) {
    let (Some(store), Some(sid)) = (core.session_store.as_ref(), session_id) else {
        return;
    };
    let Some(session) = store.load(sid).await else {
        return;
    };
    let Ok(mut session_val) = serde_json::to_value(&session) else {
        return;
    };
    let mut profile = session_val
        .get("profile")
        .filter(|p| p.is_object())
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    if let (Value::Object(dst), Value::Object(src)) = (&mut profile, &patch) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    if let Value::Object(map) = &mut session_val {
        map.insert("profile".into(), profile);
    }
    if let Ok(updated) = serde_json::from_value::<crate::web_login::Session>(session_val) {
        store.store(sid, &updated).await;
    }
}
