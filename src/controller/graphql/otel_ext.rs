//! One span per GraphQL operation: [`OtelExtension`], also available without
//! `controller` as `hs_utils::otel::OtelExtension` (feature `otel-graphql`,
//! which `otel-axum` turns on). The same type under both paths.

pub use crate::graphql_otel::OtelExtension;
