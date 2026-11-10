//! One span per GraphQL operation, named after the operation.
//!
//! ```rust,ignore
//! Schema::build(Query::default(), Mutation::default(), EmptySubscription)
//!     .extension(hs_utils::controller::graphql::OtelExtension)
//!     .finish()
//! ```
//!
//! Every HTTP request to `/graphql` is `POST /graphql` to the server span, so
//! without this a trace cannot say which query was slow. The span sits inside
//! the server span and around every resolver, so resolver work (its data
//! service calls, its queries) nests under the operation that asked for it.
//!
//! **Not** async-graphql's own `Tracing` extension: that opens a span per
//! field resolved, so the span count grows with the size of the response — a
//! list of 500 items is 500+ spans — for little more than this tells you.

use std::sync::Arc;

use async_graphql::extensions::{Extension, ExtensionContext, ExtensionFactory, NextExecute};
use async_graphql::Response;
use tracing::Instrument;

/// Add with `.extension(OtelExtension)` on the schema builder.
#[derive(Debug, Clone, Copy, Default)]
pub struct OtelExtension;

impl ExtensionFactory for OtelExtension {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(OtelExtension)
    }
}

/// What a span may be named after. The operation name is the CLIENT's choice,
/// so anything that is not a plain GraphQL name of reasonable length is not
/// used (it would be attacker-chosen text in the span name).
fn operation_label(name: Option<&str>) -> &str {
    match name {
        Some(n)
            if !n.is_empty()
                && n.len() <= 64
                && n.chars().next().is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
                && n.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) =>
        {
            n
        }
        _ => "<anonymous>",
    }
}

#[async_graphql::async_trait::async_trait]
impl Extension for OtelExtension {
    async fn execute(&self, ctx: &ExtensionContext<'_>, operation_name: Option<&str>, next: NextExecute<'_>) -> Response {
        let label = operation_label(operation_name);
        let span = tracing::info_span!(
            "graphql",
            otel.name = %format!("graphql {label}"),
            graphql.operation.name = %label,
            graphql.errors = tracing::field::Empty,
        );
        let response = next.run(ctx, operation_name).instrument(span.clone()).await;
        // Errors are recorded, not made the span's status: most are the
        // caller's (auth, not found), and a resolver that hit a real failure
        // has its own errored span beneath this one. A query that fails to
        // parse or validate never reaches this stage, so it has no operation
        // span — only the server span, which says `200` (GraphQL errors ride
        // in a successful response).
        if !response.errors.is_empty() {
            span.record("graphql.errors", response.errors.len());
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};

    struct Query;
    #[Object]
    impl Query {
        async fn ping(&self) -> &str {
            "pong"
        }
        async fn fail(&self) -> async_graphql::Result<bool> {
            Err("no such order".into())
        }
    }

    #[test]
    fn only_plain_names_label_the_span() {
        assert_eq!(operation_label(Some("ListOrders")), "ListOrders");
        assert_eq!(operation_label(Some("_private2")), "_private2");
        assert_eq!(operation_label(None), "<anonymous>");
        assert_eq!(operation_label(Some("drop table; --")), "<anonymous>");
        assert_eq!(operation_label(Some(&"a".repeat(65))), "<anonymous>");
        assert_eq!(operation_label(Some("9lives")), "<anonymous>");
    }

    #[tokio::test]
    async fn an_operation_gets_a_named_span_with_its_error_count() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        let schema = Schema::build(Query, EmptyMutation, EmptySubscription).extension(OtelExtension).finish();

        let ok = schema.execute("query Ping { ping }").await;
        assert!(ok.errors.is_empty());
        let bad = schema.execute("query Broken { fail }").await;
        assert!(!bad.errors.is_empty());

        let rec = cap.lock().unwrap().clone();
        assert!(rec.iter().any(|(k, v)| k == "otel.name" && v == "graphql Ping"), "{rec:?}");
        assert!(rec.iter().any(|(k, v)| k == "graphql.errors" && v == "1"), "{rec:?}");
    }
}
