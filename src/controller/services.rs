//! [`CoreServices`] — the bundle of shared services a controller inserts into
//! its async-graphql schema's data alongside its own `AppState`. Shared resolver
//! fragments read `ctx.data::<CoreServices>()`; the controller's app resolvers
//! keep reading `ctx.data::<AppState>()`. The two have distinct types so they
//! coexist in the schema's global data.

use std::sync::Arc;

use crate::web_login::WebSessionStore;

use super::config::CoreConfig;
use super::kratos_admin::KratosAdmin;

/// Shared services for the controller toolkit. Clone is cheap (all `Arc`s + a
/// pooled `reqwest::Client`).
#[derive(Clone)]
pub struct CoreServices {
    /// Shared HTTP client for downstream calls (Kratos, Stripe, image-service,
    /// payment-data-service).
    pub http: reqwest::Client,
    pub cfg: Arc<CoreConfig>,
    pub kratos: Arc<KratosAdmin>,
    /// Session store, used by terms login-hydration to refresh the cached
    /// session profile in place. `None` when the controller runs without a
    /// shared session store.
    pub session_store: Option<Arc<dyn WebSessionStore>>,
    /// Session cookie name (used when reading/refreshing the session).
    pub cookie_name: String,
}

impl CoreServices {
    /// Build from a shared HTTP client + core config + optional session store.
    /// Constructs the Kratos admin client from `cfg.kratos.admin_url`.
    pub fn new(
        http: reqwest::Client,
        cfg: Arc<CoreConfig>,
        session_store: Option<Arc<dyn WebSessionStore>>,
        cookie_name: impl Into<String>,
    ) -> Self {
        let admin_url = cfg.kratos.admin_url.clone().unwrap_or_default();
        let kratos = Arc::new(KratosAdmin::new(admin_url, http.clone()));
        Self {
            http,
            cfg,
            kratos,
            session_store,
            cookie_name: cookie_name.into(),
        }
    }
}
