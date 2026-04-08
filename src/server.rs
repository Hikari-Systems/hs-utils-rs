//! Shared HTTP server startup for all hs actix-web services.
//!
//! Wraps `HttpServer::new(...).bind(...).run()` in a single call so that
//! cross-cutting startup/shutdown hooks (e.g. SNS lifecycle notifications)
//! can be added in one place without touching each service.
//!
//! # Usage
//!
//! ```rust,ignore
//! hs_utils::server::run(cfg.server.port, move || {
//!     App::new()
//!         .app_data(state.clone())
//!         .route("/healthcheck", web::get().to(|| async { "OK" }))
//!         .configure(routes::configure)
//! })
//! .await?;
//! ```

use actix_service::IntoServiceFactory;
use actix_web::HttpServer;
use anyhow::Result;

/// Bind and run an actix-web server on `0.0.0.0:port`.
///
/// `factory` is the same closure you would pass to `HttpServer::new` — it is
/// called once per worker thread to construct the `App`.
///
/// The function logs `"Listening on port {port}"` before starting and returns
/// when the server shuts down.  Any SNS startup / shutdown notifications added
/// in future will fire inside this function, keeping all services' `main.rs`
/// unchanged.
pub async fn run<F, I, S, B>(port: u16, factory: F) -> Result<()>
where
    F: Fn() -> I + Send + Clone + 'static,
    I: IntoServiceFactory<S, actix_http::Request>,
    S: actix_web::dev::ServiceFactory<
            actix_http::Request,
            Config = actix_web::dev::AppConfig,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
            InitError = (),
        > + 'static,
    B: actix_web::body::MessageBody + 'static,
{
    tracing::info!("Listening on port {port}");
    HttpServer::new(factory)
        .bind(("0.0.0.0", port))?
        .run()
        .await?;
    Ok(())
}
