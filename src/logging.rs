/// Initialise tracing-subscriber with the given level filter string
/// (e.g. `"info"`, `"debug"`, `"warn,sqlx=error"`).
/// Falls back to `"info"` if the string is not a valid filter expression.
pub fn init(level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
