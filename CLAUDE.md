# CLAUDE.md — hs-utils-rs

Guidance for AI assistants working on this codebase.

---

## What this crate is

`hs-utils` is a shared Rust utility crate for backend services: config loading, database pools, HTTP server
startup, logging, healthchecks, actix-web middleware, and (behind features) browser login, session stores,
locks, pub/sub and an MCP resource server. Consumers reference it via `git + tag` from their own `Cargo.toml`;
there is no workspace. Changes here affect every consumer.

Two broad kinds of consumer:
- **Data services** use `config`, `db`, `healthcheck`, `logging`, `middleware` and `server`.
- **Controllers** additionally use `web_login`, `session_store` and `controller`, so a breaking change in those
  modules reaches only them.

---

## Codebase map

```
src/
  lib.rs           — module declarations
  config.rs        — config loading helpers: prepare_config, apply_env_overrides,
                     deep_merge, resolve_secrets, normalize_to_strings,
                     and all deser_*_or_str deserializers
  db.rs            — DbConfig, DbSslConfig structs + build_pool()
  healthcheck.rs   — run() and check_subcommand()
  logging.rs       — init()
  middleware.rs    — timing(), ApiKey middleware, forwarded_for(), ForwardedInfo
  server.rs        — run() wrapping HttpServer
  session_store.rs — build_session_store(): the session store, plus locks() / event_bus() on its database
  lock.rs          — LockManager / LockGuard: named locks (Postgres advisory, or in-process)
  genai.rs         — GenAiCall (span + log line per GenAI call: tokens, cost, TTFT, throughput,
                     model, provider, task); the metrics layer turns it into gen_ai.client.* metrics
  telemetry.rs     — always on: client_span / record_outcome / record_error, query redaction, and the
                     metrics facade (count, up_down, register_gauges) the feature-gated modules call
  http_client.rs   — send() / SendTraced / TraceOptions: reqwest 0.12 in a client span (a level, a
                     recorded path), + traceparent with `otel`
  graphql_otel.rs  — OtelExtension (async-graphql), re-exported by `otel` (otel-graphql) and `controller`
  otel/            — feature `otel`: init() (traces + metrics + per-layer filters, QuietLayer), propagation;
    metrics.rs       instruments, the gauge CATALOG, and the span → metrics layer
    procfs.rs        /proc/self and cgroup v2 readers (CPU, memory, I/O, PSI pressure)
    http_span.rs     the server span both framework layers build
    axum_layer.rs    axum_trace_layer()  (otel-axum)
    actix_layer.rs   actix_trace()       (otel-actix)
```

---

## Design principles

**Invisible by default.** Features like secret resolution (`[SECRET]:/path`) and type normalisation are baked into `prepare_config` so service code never needs to call them explicitly. If you add a new config source (e.g. AWS Parameter Store), add it inside `prepare_config`, not as a new function services must call.

**Extend, don't duplicate.** If a service needs a variant of an existing function, add the variant here rather than implementing it locally. The goal is zero duplicated infrastructure code across services.

**No breaking changes without a plan.** Removing or renaming public items requires updating each affected consumer. Adding new public items is always safe.

There is no CHANGELOG in this repo, so "the plan" goes in the section below — a short note per breaking release naming the signatures and, more importantly, naming the ones the compiler will **not** make a consumer look at. That distinction is what a bumper needs and cannot get from `cargo build`.

---

## Migrating consumers

### v0.43.0 — outbound response body size on the client span and a metric

**Drop-in from v0.42.0:** bump the tag; nothing to change. Every `send` / `send_traced*` / `send_with` call
gains, on its `http.client` span:
- `http.response.body.size`: the response's `Content-Length` when it has one, or else the bytes counted as
  the caller reads the body.
- `hs.http.response.body.size_source`: `header` or `counted`.
- `hs.http.response.body.compressed`: `true` when the size is of a still-encoded body (a `Content-Length`
  beside a `Content-Encoding`, or a counted body reqwest did not decode), `false` when it is the
  uncompressed size. reqwest's own decompression removes `Content-Length` along with `Content-Encoding`, so a
  body it decoded is counted, uncompressed.
- `hs.http.response.body.complete` (counted only): `false` when the body was dropped before its end or
  failed partway (a failure also marks the span `error = body`).

Nothing is recorded for a HEAD, a 1xx, 204 or 304. **Metric:** `http.client.response.body.size` (histogram,
`By`, 1 KiB to 512 MiB buckets), labelled by method, the bounded `server.address` and
`hs.http.response.body.compressed`.

**Not shown by the compiler:**
- **A counted body holds its span open until the body is read or dropped,** so in a trace that span now
  covers the download, not just the time to the headers. Calls whose response has a `Content-Length` are
  unchanged. `http.client.request.duration` is now recorded when the status arrives (like the server
  duration), so the metric does not move for either kind; a call with no response is still recorded at close
  as `error.type = no_response`.
- A counted response is rebuilt around the counting body. Status, headers, extensions and `url()` are the
  same; it is a different `reqwest::Response` value, so nothing that depends on its identity should notice.
- Without `otel` (or when nothing wants the span) the response is returned untouched and nothing is counted.

### v0.42.0 — `genai::Usage` reports cost and the upstream host

**No compile break for `..Default::default()` users:** `genai::Usage` gains `cost_usd: Option<f64>` and
`upstream_provider: Option<String>`. **Compile break:** a `Usage { .. }` literal that names every field without
`..Default::default()` must add the two (or the default).

- **Span:** `hs.gen_ai.cost_usd` (the provider-reported charge in USD, e.g. OpenRouter's `usage.cost`) and
  `hs.gen_ai.upstream_provider` (the host a router picked, e.g. OpenRouter's `provider`), both on the
  `gen_ai call finished` line too.
- **Metric:** `hs.gen_ai.client.cost` (counter, `USD`), same labels as `gen_ai.client.token.usage` minus
  `gen_ai.token.type`. Only calls that report a cost add to it. The upstream host is never a metric label.

**Not shown by the compiler:** nothing records a cost unless the caller fills `cost_usd`; Bedrock and
Anthropic responses carry none, so their spend still comes from tokens × price.

### v0.41.0 — spans only with `otel`; `genai::GenAiCall` for every GenAI call

**No compile break from v0.40.2:** bump the tag. Every public item is still there in every feature set.

**Span emission is gated at build time on `otel`** (`telemetry::EMIT_SPANS = cfg!(feature = "otel")`). Without
`otel`, `client_span`, `client_span_at`, the outbound HTTP span, the GraphQL operation span, `auth.login`,
`auth.gate` and `GenAiCall`'s span all hand back `Span::none()`; `record`, `record_outcome` and `.instrument`
on it are no-ops. Log events are not gated. Measured in release, with the subscriber `otel::init` installs when
`otel.enabled=false`: a client span (create, enter, record, drop) costs ~750 ns with `otel` compiled (unchanged
from v0.40.2) and ~1 ns without it (it was ~750 ns there too).

**Not shown by the compiler (services built without `otel` only):** their stdout lines lose the span prefixes
the fmt layer printed, e.g. `auth.gate{auth.gate.outcome=… auth.redirect.reason=…}:`. Each event keeps its own
fields, so a redirect refusal still logs its reason once, on the event; `auth.gate.session.load_failed`, which
is a span field and never a log line, is no longer visible anywhere without `otel`. A service that greps its
stdout for a span prefix should adopt `otel` (it can stay `otel.enabled=false`) to keep it.

**`genai::GenAiCall`**, callable in every build:

New: `hs_utils::genai::{GenAiCall, Usage, provider, operation}`. Around each model call:
`GenAiCall::start(operation, provider, model, task, streaming)`, put the request (and its transport span, via
`call.span().in_scope(..)`) inside `call.span()`, call `first_chunk()` on a stream's first content chunk, then
`finish(&Usage { .. })` or `fail(error_type)`, and `result(verdict)` once the reply is parsed. Dropped
unfinished, it records `error.type = cancelled`.

- **Span** `gen_ai`, named `{operation} {model}`: the OpenTelemetry GenAI attributes (`gen_ai.provider.name`,
  `gen_ai.request.model`, `gen_ai.request.stream`, `gen_ai.usage.*`, `gen_ai.response.finish_reasons`,
  `gen_ai.response.time_to_first_chunk`) plus `hs.gen_ai.task`, `hs.gen_ai.result`, `hs.gen_ai.duration_s`
  (total), `hs.gen_ai.ingestion_s` / `hs.gen_ai.generation_s` (streams only), `hs.gen_ai.output_tokens_per_second`
  and `hs.gen_ai.provider_latency_s`.
- **One INFO line** per finished call (`gen_ai call finished`, target `hs_utils::genai`), a WARN per failure,
  printed on stdout at the log level in every build, and exported as the span's events with `otel`. Cost per
  call, line included: ~0.6 µs without `otel`, ~2.4 µs with it compiled and disabled — against a model call
  of seconds.
- **Metrics** (with `otel` metrics on): `gen_ai.client.operation.duration`, `gen_ai.client.token.usage` (by
  `gen_ai.token.type`), `gen_ai.client.operation.time_to_first_chunk` (streams) and
  `hs.gen_ai.client.output_throughput`, labelled by operation, provider, model, stream, task and `error.type`.
  Token totals per task come from the metric, so they are exact whatever traces are sampled.

**Gating.**
- **Build time:** no spans at all without feature `otel` (above). No new dependencies.
- **Run time, `otel` compiled but `otel.enabled` unset or false:** `init` installs only the stdout layer — no
  exporter, no metrics layer, no network. Spans reach stdout's span context and nothing else.
- **No content, by construction.** There is no way to put a prompt, a reply or a tool argument on the span.
  If one is ever wanted, it goes behind an opt-in config key that defaults off, as the conventions require.
- **Labels are bounded.** `task`, `result` and `error_type` are `&'static str`. The model label keeps the first
  `MAX_METRIC_MODELS` (20) distinct models per process and calls later ones `other`, so a service that takes a
  model id from a user cannot mint one series per string. Spans keep the real id.
- **Switches that already exist:** `otel.enabled` (everything), `otel.metricsEnabled` (metrics), and
  `otel.level`: `info,hs_utils::genai=off` stops the spans and log lines being exported while the metrics
  still count every call. The stdout line follows the log level (`log.level=…,hs_utils::genai=warn`).
- **No per-chunk telemetry.** A stream records its first-chunk time and its totals, never an event per chunk.

**Not shown by the compiler:** `ttft` exists only for streamed calls. A non-streaming call reports a total and
its throughput includes the prompt read, so compare throughput within `gen_ai.request.stream`, never across it.

### v0.40.2 — quiet polls with no trace send "not sampled"; the metrics-off filter gap closed

**Drop-in from v0.40.1:** bump the tag; nothing to change.
- A DEBUG/TRACE outbound call (`send_traced_at(Level::DEBUG)`, the level for polling loops' claims, leases
  and long polls) made with **no trace around it** now sends `traceparent: …-00`. The service called then
  does not export its side of each poll as a sampled root trace. Before, it sent no `traceparent` at all,
  so every background poll became one root trace in the callee. An INFO call with no context is unchanged
  (it starts its own sampled trace), and a quiet call inside an exported span still continues it (`-01`).
  Expect a drop in root traces on services that are polled.
- With `otel.metricsEnabled=false` the v0.40.1 fix did not apply, because the metrics layer carrying
  `MetricsFilter` is not installed. The quiet layer's filter now also registers the server span as
  `Interest::sometimes`, so request spans survive stale filter state with metrics off too. Regression tests:
  `http_client::tests::a_quiet_call_with_no_trace_around_it_sends_not_sampled`,
  `otel::filter_state_tests::metrics_off`.

### v0.40.1 — request spans and request metrics were being lost after database queries

**Drop-in, and worth taking:** bump the tag; nothing to change. Every service using `actix_trace()` or
`axum_trace_layer()` whose handlers run sqlx queries was losing most of its server spans and
`http.server.request.duration` / `http.server.active_requests` counts. After 0.40.1 dashboards show the real
request rate, which can be many times what they showed before.

Why: `tracing-subscriber`'s per-layer filters keep each layer's last verdict in a thread-local, and a callsite
every filter calls `Interest::always` skips the check and reuses whatever is left there. The INFO server span
was the only such callsite. sqlx's per-statement `log::log_enabled!` (through the `tracing-log` bridge `init`
installs) runs a check that no event follows, so the next request span on that worker thread inherited
"every layer says no": created, but neither exported nor counted. The metrics layer's (internal)
`MetricsFilter` now registers request and client spans as `Interest::sometimes`, so each is checked
afresh. Regression test: `actix_layer::dangling_filter_pass`.

### v0.40.0 — bounded `server.address` on the outbound HTTP metric

**Drop-in from v0.39.x:** bump the tag. Nothing has to change, but the `server.address` label on
`http.client.request.duration` is now bounded:
- A dotless host (an in-cluster service name such as `user-data-service`) is always labelled by name.
- The first `MAX_METRIC_PEERS` (20) distinct dotted hosts a process calls are labelled by name; every later
  one is labelled `other`. A process that fetches arbitrary sites used to grow a set of histogram series per
  site, each exported for the life of the process.
- **`otel::set_metric_peer_hosts(&["api.example.com", ".example.org"])`** pins hosts that keep their own
  label whatever order they are first seen in: an exact host, or `.suffix` for that host and any subdomain.
  Call once at startup, before the first outbound call. Pin the external APIs whose latency a dashboard
  breaks out.

Spans are unchanged: `server.address` on a client span is always the real host.

### v0.39.0 — quiet long polls: `set_quiet_paths` and `client_span_at`

**Drop-in from v0.38.x:** bump the tag; nothing to change. (From v0.37.x, see v0.38.0 below.)

New, opt-in, for calls that wait by design, whose span duration is the wait and which, as exported entry spans,
set the service's p99:
- **`otel::set_quiet_paths(&["/jobs/claim"])`:** exact request paths whose server span is `DEBUG`, the same as
  `/healthcheck`. At `otel.level=info` the request and everything beneath it is not exported, and
  `http.server.request.duration` still counts it by `http.route`. Call once, before serving.
  To trace the work a poll does get, start a span with an explicit `parent: None`
  (`tracing::info_span!(parent: None, "jobs.claim.granted")`). It starts a new sampled root trace, and the
  quiet request's unsampled context does not apply to it.
- **`telemetry::client_span_at(level, system, op, peer)`** (also `otel::client_span_at`): `client_span` at a
  level. Use `DEBUG` for an SQS `ReceiveMessage` long poll or a blocking pop. `hs.client.operation.duration`
  still counts it.

### v0.38.1 — `session_recording.id` on server spans

**No compile break.** The axum and actix server spans record `session_recording.id` when the request carries
`x-session-recording-id` (`otel::SESSION_RECORDING_HEADER`) holding a UUID; any other value is dropped. A UI
whose pages are session-recorded sends its recording's id in that header (and a W3C `traceparent`, which the
layers already adopt), so a recording and the traces it caused can be joined.

**Not shown by the compiler:** a consumer whose UI calls it cross-origin must add the header to its CORS
allow-list; same-origin calls need nothing.

### v0.38.0 — Stripe Tax: `stripe.automaticTax` and a billing address on `createSubscriptionIntent`

**Compile break only for a struct literal:** `StripeConfig` gained `automatic_tax: bool`. A consumer that builds
`hs_utils::controller::StripeConfig { … }` field by field adds `automatic_tax` (or `..Default::default()`). Nothing
else breaks; the compiler shows the one place.

**Not shown by the compiler:**
- `automaticTax` defaults to **false**: nothing about checkout changes until a consumer turns it on
  (`stripe__automaticTax: "true"`, string or bool).
- When it's on, `createSubscriptionIntent` **refuses a call without `address`**, so the UI must collect it first
  (Stripe's Address Element, mode `billing`) and read `listSubscriptionPlans.automaticTax` to know. The address is
  saved on the customer with `tax[validate_location]=immediately`; Stripe refusing it comes back as "We couldn't find
  that address to work out tax: please check it".
- Prices should be `tax_behavior: exclusive` (tax added on top); a price's tax behaviour can't be changed once set.
- The Stripe account needs Tax set up (head office, a registration per country it charges tax in).

New: `stripe::{create_subscription, NewSubscription, BillingAddress, update_customer_address, TAX_LOCATION_INVALID}`,
`graphql::types::BillingAddressInput`, `SubscriptionConfig.automatic_tax`. `create_subscription_with_trial` is
unchanged (no tax).

### v0.37.2 — quiet healthchecks, per-call span levels, session ids out of traces

**Drop-in from v0.37.1:** bump the tag; nothing to change.

New, opt-in:
- **A client span's level, per call:** `.send_traced_at(tracing::Level::DEBUG)` and `.send_traced_opaque_at(level)`
  (functions `http_client::send_at` / `send_opaque_at`). For a hot polling loop: at `otel.level=info` its spans are not
  exported, `http.client.request.duration` still counts them, and the `traceparent` sent is the caller's, so the far
  end still continues the caller's trace. `.send_traced()` / `.send_traced_opaque()` are unchanged.
- **`http_client::TraceOptions`** with `.send_traced_with(opts)` / `send_with`: a level, `.opaque()`, or
  `.path("/api/x/{id}")` — record that template on `url.full` in place of a path whose segment is a credential.
- **`hs_utils::otel::OtelExtension`** (feature `otel-graphql`, which `otel-axum` now turns on): the GraphQL operation
  span without `controller`. `controller::graphql::OtelExtension` still works and is the same type.
- `mcp_resource_server::HttpTransport::request_as` (defaulted to `request`, so an outside transport is unaffected).

**The compiler will not tell you these:**

- **`/healthcheck` is a `DEBUG` server span** in both `actix_trace()` and `axum_trace_layer()` (exact path, any
  method). At `otel.level=info` nothing of it is exported: not its span, not a child span, not a backend call's
  client span. The `traceparent` such a call sends says "not sampled", so **the service it calls drops its side of
  that trace too**, whatever its route. At `otel.level=debug` it is an ordinary trace. `http.server.request.duration`
  and `http.server.active_requests` still count it (the metrics layer now sees this crate's request and client spans
  at any level). Its events still reach stdout at the log level.
- **The MCP session store no longer publishes session ids.** `DbSessionStore`'s calls record
  `url.full = …/api/mcpSession/{id}`, its log lines carry no id, and an error response's body is no longer logged
  (only its length). A dashboard or query on the concrete URL will stop matching.
- **Errors that carried a credential in a URL no longer do.** The consent bridge's Hydra calls drop the URL (with its
  `login_challenge` / `consent_challenge` / `logout_challenge`) from their errors, so its `warn!` lines lose the URL.
  The avatar hook's picture download records only the picture URL's origin, in its span and in its error.
- **`otel-axum` now compiles async-graphql** (default features off; `controller` still turns them on, as before).
  A first build of an axum service without `controller` takes longer.

### v0.37.1 — URLs and paths that are credentials

New, nothing changed:
- **`.send_traced_opaque()` / `http_client::send_opaque`** records only `scheme://host:port`. Use it for a URL whose
  path or query is a credential: Slack or Discord webhooks, a user-supplied "post to this URL" target, an MCP server
  URL with a key in it. It still sends `traceparent`.
- **`otel::set_path_redactor(fn(&str) -> String)`**, called once before serving, runs the concrete `url.path` the
  server layers record through the service's redactor. Use it when a path segment is a credential, such as
  `/hooks/{token}/…`. The span name is already the route template, so only the attribute needs it.

**The compiler will not tell you this:** a service that hand-redacted paths in its own `TraceLayer` loses that when
it moves to `axum_trace_layer()` or `actix_trace()`. Install the same function with `set_path_redactor` as part of
the move.

### v0.37.0 — otel metrics, actix-web tracing, client spans

**Not breaking** for a consumer that names `OtelConfig` or `DbConfig` only through serde. A struct literal of either
without `..Default::default()` stops compiling (new fields); the compiler shows each one.

New: feature `otel-actix` (`otel::actix_trace()`, the actix twin of `axum_trace_layer`), `http-client`
(`http_client::send` / `SendTraced`, turned on by every feature that calls out), `telemetry::client_span` for a
service's own calls (SMTP), `controller::graphql::OtelExtension`, `db.slowqueryms`, `WebSessionStore::count_active`
(defaulted, so an outside implementation is unaffected).

**The compiler will not tell you these:**

- **A service with `otel.enabled` now exports metrics too.** On by default, every `otel.metricsIntervalSecs` (60 s).
  Set `otel__metricsEnabled: "false"` to bump the tag without them. No `x-honeycomb-dataset` header is sent unless
  `otel.metricsDataset` is set: Honeycomb routes native OTLP metrics by itself.
- **hs-utils' own outbound HTTP now carries `traceparent`** (Kratos, Hydra, JWKS, Stripe, payment-data, image-service,
  the DCR upstream). A data service that already adopts an inbound `traceparent` starts parenting those requests
  under the caller's trace. Nothing to change.
- **The session store's database gets two `count(*)` queries a minute per replica** (indexed on `expires_at`), and a
  redis store one `SCAN` of its db index, for `hs.web_session.active`. Only with `otel` compiled in.
- **`build_pool` / `build_lazy_pool` keep a clone of each pool for its gauges**, for the life of the process, with
  `otel` compiled in. A service that drops a pool and builds a new one keeps the old one open.
- **The export filter is now separate from stdout's.** Unset `otel.level` exports what the log level allows, as
  before, except that the exporter's own crates (`opentelemetry*`, `reqwest`, `hyper`, `h2`, `rustls`) are never
  exported. Their errors still reach stdout.
- **Each server span records `http.route` and gets its name set just after it's created.** The axum span's name and
  fields are otherwise unchanged. A test that captures only `on_new_span` fields will not see `otel.name`; capture
  `on_record` too, as `telemetry::test_capture` does.

**Adopting it.**
- A data service: features `["db", "web", "otel-actix"]`, an `otel: OtelConfig` field on its config,
  `let _otel = hs_utils::otel::init(&cfg.log.level, &cfg.otel)?;` in place of `logging::init` (inside
  `#[actix_web::main]`), and `.wrap(hs_utils::otel::actix_trace())` in place of `.wrap(middleware::timing())`.
- A controller: `otel-axum`, `.extension(OtelExtension)` on its schema, and `.send_traced()` on its calls to data
  services.
- With a Collector on the host, set `otel__endpoint: "http://<host>:4318"` and `otel__apiKeyRequired: "false"`; the
  Collector holds the key.

### v0.36.0 — jsonwebtoken 10, rmcp 2

**Breaking** for a consumer that names rmcp itself: move its own `rmcp` requirement to `2.1`. `model::Content` is now
`ContentBlock` (`RawContent` and `.raw` are gone; use `as_text()`), `Annotated` and `RawResource` are gone (`Resource::new`),
and `ProgressNotificationParam` is built with `new` / `with_total` / `with_message`.

### v0.35.0 — `session.requiredAtBoot`: a session store that isn't essential at boot

**Not breaking** for a consumer of `build_session_store`: unset means `true`, which is what it already did. New:
`session.requiredAtBoot` (`session__requiredAtBoot`) and `db::build_lazy_pool`.

- `true` or unset: a Postgres store that can't connect is a startup error.
- `false`, for a service whose login isn't essential: it starts regardless, connects on demand, and creates its table
  in the background, retrying (backing off to once a minute) until the table is usable; a pre-provisioned one it can
  read counts. It never falls back to memory, so session requests fail until then. With no Postgres configured it
  never connects or retries. A changed password still needs a restart: the pool holds what it was given.

**The compiler will not tell you this:** a consumer with its own hand-rolled web session store builder ignores the key
and may still swallow a connection failure into `None`. Move it to `build_session_store`. Moving makes a failed
connection stop that service, so set `session__requiredAtBoot: "false"` if its login isn't essential. Locks and event
buses from a `false` store share the lazy pool, so they too fail until the database answers.

### v0.34.0 — the session pool is private; `SessionSetup::locks()` and `::event_bus()` instead

**Breaking:** `SessionSetup::pg_pool` is gone. Nothing outside this crate gets the session store's pool or redis
connection any more; it gets what is built on them, on the store's own backend:

- `setup.locks() -> Option<lock::LockManager>` (feature `lock`): named locks for short critical sections.
  `manager.acquire(name, wait).await -> Result<LockGuard, LockError>` (`Busy` after `wait`), then
  `guard.release().await`; dropping a guard releases too.
  - `lock-postgres`, Postgres store: session-level advisory locks (`pg_try_advisory_lock`, key
    `hashtextextended('hs_utils.lock:' || name, 0)`) on a connection held for the guard's life. A dropped
    guard closes its connection, so the server frees the lock; so does a dead replica's.
  - `lock-redis`, redis store: `SET hs_utils:lock:<name> <token> NX PX <lease>`, released only while the key
    still holds the guard's token. A **lease**: a dead holder frees it after `with_lease` (default 60 s), and a
    holder stalled past it loses it while still running, so size the lease above the longest section.
  - Memory store: in-process (`is_shared() == false`).
  - Any store whose backend feature is off: `None`, never a local lock posing as shared.
- `setup.event_bus::<E>(channel, capacity) -> Option<Arc<dyn pubsub::EventBus<E>>>` (feature `pubsub`):
  a `PgEventBus` (`LISTEN/NOTIFY`) for Postgres, a `RedisEventBus` (`PUBLISH/SUBSCRIBE`, feature
  `pubsub-redis`) for redis, an `InMemoryEventBus` for memory, else `None`. Call it once per channel (each call
  spawns that channel's listener task).

New features: `lock`, `lock-postgres` (implies `web-login-postgres`), `lock-redis` (implies `web-login-redis`),
`pubsub-redis` (implies `pubsub` and `web-login-redis`). `pubsub` itself is unchanged.

The compiler finds every consumer that read `pg_pool`. A consumer that needs the bus calls `setup.event_bus(…)`
where it used to pass the pool to `PgEventBus::new` — the same bus, on the same pool. `RedisSessionStore` now
resolves a Sentinel master with `Sentinel::async_master_for` per operation (what `SentinelClient` did internally),
so the lock and bus can share its connection; no behaviour change.

### v0.33.0 — a resource (and `aud`) per path for MCP servers with sub-resources

New, nothing changed: `apply_mcp_auth`, `auth_middleware` and `JwtVerifier::verify` answer exactly as before (a
golden test pins their 401 and metadata). A server with resources under its URL (e.g. `/mcp/o/{orgId}`) calls
`apply_mcp_auth_with(cfg, stores, resolver, accept)` instead and layers `auth_middleware_per_resource` with the
returned `ResourceAuthState`. `accept(rest)` decides which `{path}/{rest}` exist (raw path, never percent-decoded);
it drives both the 404s and `/.well-known/oauth-protected-resource{path}/{rest}`. Per path, the token's `aud` must
contain that resource byte for byte and no other value equal to `expected_audience` or under it at a `/`, so a token
with two of the server's audiences is refused everywhere. Nothing is normalised: Hydra copies `..`, `%2e%2e`, a
trailing `/`, `?` and `#` into `aud` verbatim. The middleware must see the full path (layer it outside any `nest`),
and the resource it verified is in the `VerifiedResource` extension.

### v0.32.4 — `web_login::account_redirect` for an app's "My account" link

New, nothing changed: `account_redirect(settings_url, headers, dest)` answers an app's `GET /api/account?dest_uri=`
with a 303 to the login host's settings page carrying `return_to=<app origin><sanitised dest>`. `dest` goes through
`safe_dest` (refusals log with `auth.redirect.site=account` and fall to `/`). An empty `settings_url` is a 404, a
non-URL a 500. Wire it to an `auth.accountSettingsUrl` config value and link the app's user menu to
`/api/account?dest_uri=<current path>`.

### v0.32.3 — the authorize URL carries the return page (`hs_return_to`)

`web_login`'s gate adds `hs_return_to=<this app's origin><the sanitised page>` to the IdP authorize URL. The IdP
ignores it; a login UI may read it off Hydra's login request to offer a "Back to <app>" link, but should only do so
when its origin matches one of the client's registered redirect URIs. It is the value already stored for the
callback (`safe_dest`), so nothing unsanitised leaves the app. No signature change: bump the tag.

### v0.32.2 — the advertised resource metadata URL is path-inserted

A 401's `WWW-Authenticate` now names the path-inserted metadata URL, as RFC 9728 §3.1 says
(`https://h/.well-known/oauth-protected-resource/mcp`, from `metadata::prm_url`), rather than one under the
resource path (which sat behind the auth layer itself). `metadata::router` also serves that path when the
resource's path is not `/mcp`. No signature change: bump the tag.

### v0.32.1 — the post-login redirect is sanitised

No API change: a consumer bump is a one-line tag change. `gate` sanitises the request target before storing it as
the `state → destination` map, and `callback` sanitises again before emitting the `Location`. The guard is
unconditional (no config key or feature flag turns it off). A refused destination becomes `/`, never a 4xx.

It covers only those two inputs. A consumer that accepts its own caller-supplied destination (e.g. a `dest_uri`
query parameter on its own login/logout routes) still needs its own origin-relative check; don't delete one as
redundant.

| request target / stored destination | now |
|---|---|
| `/dash?tab=runs`, `/api/auth`, `/`, `/x?a=b#f` | unchanged |
| `/../../etc/passwd` | rewritten to `/etc/passwd` |
| `*` | rewritten to `/*` |
| `//evil.example.com/x`, `/\evil.example.com/x`, `///…`, `//\…` | `/` |
| `/..//x`, `/.//x`, `/a/..//x` and similar dot-segment forms | `/` |
| a target containing CR or LF | `/` |

Telemetry: one `warn!` per refusal, `web_login: post-login redirect destination refused`, with
`auth.redirect.outcome`, `auth.redirect.reason` (`missing` | `control_character` | `unparseable` |
`not_origin_relative` | `escapes_root`), `auth.redirect.site` (`gate` | `callback`), `auth.redirect.dest` (raw,
capped at 256 bytes — note it can include query values, unlike `otel::redact_query`) and, at the callback,
`user.id`.

Also: `JwtClaims::scopes()` now merges RFC 9068 `scope` with Hydra's `scp` (array or string), without duplicates.

### v0.32.0 — `WebSessionStore` is fallible

All three trait methods changed. Any type implementing `WebSessionStore` outside this crate must change with them:

```rust
async fn load(&self, sid: &str)                     -> anyhow::Result<Option<Session>>;  // was Option<Session>
async fn store(&self, sid: &str, session: &Session) -> anyhow::Result<()>;               // was ()
async fn remove(&self, sid: &str)                   -> anyhow::Result<()>;               // was ()
```

`WebLogin::end_session` follows: `Option<String>` → `anyhow::Result<Option<String>>`.

**`load` announces itself; `remove` does not.** A `store.load(&sid).await?` inside an `Option`-returning function
stops compiling. A bare `store.remove(&sid).await;` still compiles — it is only an `unused_must_use` warning — so a
logout can keep answering "you are logged out" on a delete that failed. Grep each consumer for `.remove(` and
`.store(` on a session store and rule on every hit, especially hand-rolled logout handlers.

Posture: fail **open** where an unreadable row and an absent row deserve the same answer; fail **loud** where a write
is what makes the next request work. For which sites take which, read the trait docs.

---

## Module details

### `config.rs`

**Standard service `load()` pattern:**
```rust
prepare_config(&mut root);      // [SECRET]: resolution + normalise to strings
apply_env_overrides(&mut root); // KEY__subkey=val env var overrides
serde_json::from_value(root)
```

`prepare_config` calls `resolve_secrets` then `normalize_to_strings` internally. Services that use a `/sandbox/config.json` overlay call `deep_merge` before `prepare_config`:
```rust
if let Ok(overlay_text) = std::fs::read_to_string(&overlay_path) {
    if let Ok(overlay) = serde_json::from_str::<Value>(&overlay_text) {
        deep_merge(&mut root, overlay);
    }
}
prepare_config(&mut root);
apply_env_overrides(&mut root);
```

**Deserializers** are named `deser_{type}_or_str` and `deser_opt_{type}_or_str`. They accept both native JSON types and their string equivalents. All are used with `#[serde(deserialize_with = "...")]`. Do not use plain `serde(rename)` + string fields for numeric/bool config values — use the typed deserializers so structs carry the right Rust types.

**`normalize_to_strings`** converts all bool/number leaves to `Value::String` before deserialisation. This is why `deser_*_or_str` always encounters strings at runtime even if the JSON file had native types — the deserializers handle both because services may bypass normalisation in tests.

### `db.rs`

`DbConfig` and `DbSslConfig` both derive `Default` (needed for services that use `#[serde(default)]` on their `AppConfig.db` field, where the db section is optional).

`build_pool` defaults: `minpool=0`, `maxpool=3`. SSL defaults: if `ssl` is absent or `enabled` is absent/false, `PgSslMode::Prefer` is used (not `Disable`) — this allows unencrypted connections to local dev databases while not failing if the server offers TLS.

Port is stored as `String` in `DbConfig` because `prepare_config` normalises everything to strings. `build_pool` parses it at runtime and defaults to `5432` if empty.

### `healthcheck.rs`

`run()` uses only stdlib — no tokio, no reqwest. This is intentional: it must work before the async runtime is started. Do not add async variants here; use a dedicated health endpoint in the service if you need async checks.

`check_subcommand` calls `process::exit` directly. This is correct and intentional — it must terminate the process without starting the server.

### `server.rs`

`server::run` mirrors `HttpServer::new`'s generic bounds exactly. The function is intentionally thin — its value is as a hook point for future cross-cutting concerns (lifecycle notifications, graceful shutdown handling), not as an abstraction over actix-web.

The bounds require `actix-service` and `actix-http` as direct dependencies because `IntoServiceFactory` and the raw `Request` type are not re-exported through `actix_web::dev` in actix-web 4.

### `http_client.rs` and `telemetry.rs`: instrumented calls

**Every outbound call goes through a client span.** In this crate and in its consumers:

- **HTTP (reqwest 0.12):** `use hs_utils::http_client::SendTraced as _;` then `.send_traced()` where you would write
  `.send()`. It records a `{METHOD} {host}` span with the status and a redacted `url.full` (query values never), and
  with `otel` writes `traceparent`. That header is what makes a controller's trace continue into the data service
  it calls; a bare `.send()` starts an unconnected root on the other side. `clippy.toml` disallows
  `RequestBuilder::send` here, so `cargo clippy` flags a regression; consumers should carry the same file.
- **A URL that is its own credential** (a webhook, a user-supplied target): `.send_traced_opaque()`, which records
  the origin only. **A path segment that is a credential** on an outbound call (a session id the far end treats as
  a bearer): `.send_traced_with(TraceOptions::new().path("/api/x/{id}"))`, which records the template. On the server
  side (`/hooks/{token}`): `otel::set_path_redactor` at startup. The defaults record paths, because ids in paths are
  what make a slow call findable, so these are the call site's to say. **And strip the URL from the error** before
  logging or wrapping it (`.map_err(reqwest::Error::without_url)`): a reqwest error's text is the full URL, query
  values and all, which is exactly what the span redacts.
- **A hot loop** (polling): `.send_traced_at(Level::DEBUG)` (or `TraceOptions::level`). Not exported at
  `otel.level=info`, still counted in `http.client.request.duration`; `send_with` sends the caller's `traceparent`
  when the export cannot see the call's own span.
- **Healthchecks are quiet.** `http_span::server_span` makes `/healthcheck` a `DEBUG` span. A span the export filter
  drops would leave its children parentless, i.e. new roots, so `otel::quiet_unless_exported` marks it and
  `otel::QuietLayer` (installed by `init`, before the export layer) makes an unsampled OpenTelemetry context current
  while it is entered: the parent-based sampler drops everything beneath it, and the `traceparent` it sends on says
  "not sampled". The metrics layer's filter (`otel::metrics_filter`) takes this crate's request and client spans at
  any level, so they are still counted. `otel::test_export::install` builds the same stack in memory for tests.
- **Anything else** (redis, SMTP, a queue): `telemetry::client_span(system, operation, peer)`, then
  `.instrument(span.clone())` on the future and `record_outcome` / `record_error` on the result. Inside this crate,
  `telemetry::traced(span, fut)` does both for a `Result` future without attaching the error text.
- **Name the operation, never the data.** `system` and `operation` are the span name and metric labels; a key, a
  recipient, an id or SQL there leaks it to the trace store and makes one series per value. `client.target` takes a
  name from code (a lock or channel name), and only as a span attribute.
- **Metrics from code that doesn't know about `otel`** go through `telemetry::count` / `up_down` /
  `register_gauges`, which do nothing without `otel` (or before `init`). A new gauge name must be added to `CATALOG`
  in `otel/metrics.rs`, or it is dropped.
- **A gauge source runs on the exporter's thread at collection time:** memory reads and tiny files only. Anything
  that needs a query refreshes an atomic from its own task (see `session_store::session_gauges`).

### `middleware.rs`

`ApiKey` uses `EitherBody<B>` to return a `401` response without changing the response body type. The `forward_ready!` macro from actix-web delegates `poll_ready` to the inner service.

`forwarded_for` clones `connection_info()` before accessing headers to avoid a temporary lifetime issue with `req.connection_info().scheme()`.

---

## Versioning workflow

1. Implement and `cargo build` locally
2. Bump `version` in `Cargo.toml`
3. `git commit`, `git tag vX.Y.Z`, push the branch and the tag
4. Update `tag = "vX.Y.Z"` in each consumer's `Cargo.toml`
5. Run `cargo build` in each consumer to refresh `Cargo.lock`

**Never use a path dependency** (`path = "../hs-utils-rs"`) in a consumer. Always use `git + tag`. This ensures the consumer's `Cargo.lock` pins to a specific commit and Docker builds are reproducible.

**Never update a consumer's tag before pushing it to GitHub.** `cargo build` fetches from the remote; if the tag doesn't exist yet, the build fails.

---

## Common gotchas

- Adding a new public function is a minor version bump. Removing or changing a public function is a breaking change — leave a note under "Migrating consumers".
- `normalize_to_strings` converts numbers to strings, so `DbConfig.port` is always a string at deserialisation time. Don't add `port: u16` fields to `DbConfig` — keep them as `String` and parse in `build_pool`.
- The `[SECRET]:` prefix must appear in the raw config JSON (before `prepare_config` runs). A secret reference injected via an env var override will not be resolved because `apply_env_overrides` runs after `prepare_config`.
- `tracing::warn!` in `resolve_secrets` does not require the tracing subscriber to be initialised — messages before `logging::init` are silently dropped, which is correct behaviour.
