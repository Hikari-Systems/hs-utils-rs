//! One span, one log line and a set of metrics per generative-AI call — the
//! same shape whichever provider, SDK or service makes it.
//!
//! Callable in every build. The span is emitted only with feature `otel`
//! ([`crate::telemetry::EMIT_SPANS`]); without it [`GenAiCall`] still times the
//! call and logs its line. With `otel` the span is exported and the
//! span-metrics layer turns it into
//! `gen_ai.client.operation.duration`, `gen_ai.client.token.usage`,
//! `gen_ai.client.operation.time_to_first_chunk` and
//! `hs.gen_ai.client.output_throughput`.
//!
//! ```rust,ignore
//! use hs_utils::genai::{self, GenAiCall, Usage};
//! use tracing::Instrument;
//!
//! let mut call = GenAiCall::start(genai::operation::CHAT, genai::provider::AWS_BEDROCK,
//!                                 &model, "graph.extract", false);
//! let resp = req.send().instrument(call.span().clone()).await;
//! match &resp {
//!     Ok(r) => call.finish(&Usage { input_tokens: …, output_tokens: …, ..Default::default() }),
//!     Err(_) => call.fail("bedrock.converse"),
//! }
//! // later, once the reply has been parsed:
//! call.result("ok");
//! ```
//!
//! For a stream, pass `streaming = true` and call [`GenAiCall::first_chunk`] when
//! the first content chunk arrives; [`GenAiCall::finish`] once the stream ends.
//!
//! # What is recorded
//!
//! On the span (OpenTelemetry GenAI semantic conventions where they exist):
//! `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`,
//! `gen_ai.request.stream`, `gen_ai.request.max_tokens`, `gen_ai.response.model`,
//! `gen_ai.response.finish_reasons`, `gen_ai.usage.input_tokens`,
//! `gen_ai.usage.output_tokens`, `gen_ai.usage.cache_read.input_tokens`,
//! `gen_ai.usage.cache_creation.input_tokens`,
//! `gen_ai.response.time_to_first_chunk` (streams only) and `error.type`; and,
//! where the conventions have nothing:
//!
//! * `hs.gen_ai.task` — the caller's constant naming what the call is *for*
//!   (`calendar.extract`, `chat.turn`); the dimension cost is broken down by.
//! * `hs.gen_ai.duration_s` — total response time, request to last byte.
//! * `hs.gen_ai.ingestion_s` — time to first chunk: the provider reading the
//!   prompt. Streams only; a non-streaming call cannot separate it.
//! * `hs.gen_ai.generation_s` — first chunk to last. Streams only.
//! * `hs.gen_ai.output_tokens_per_second` — output tokens over generation time
//!   for a stream, over total time otherwise (so it includes the prompt read).
//! * `hs.gen_ai.provider_latency_s` — the provider's own figure, when it sends
//!   one (Bedrock's `metrics.latencyMs`).
//! * `hs.gen_ai.cost_usd` — what the provider says the call cost, in USD, when
//!   it reports one (OpenRouter's `usage.cost`). Also the
//!   `hs.gen_ai.client.cost` counter.
//! * `hs.gen_ai.upstream_provider` — the host a router sent the call to
//!   (OpenRouter's `provider`). Span only: it is not a metric label.
//! * `hs.gen_ai.result` — the caller's verdict on the reply, set any time
//!   before the call is dropped: `ok`, `empty`, `unparseable`, … .
//!
//! **Name the purpose, never the data.** `task`, `result` and the error type
//! are metric labels: constants from code. The model is from config. Never put
//! a prompt, a reply, a user id or an item id on this span; record those, if
//! at all, in the caller's own span.

use std::time::{Duration, Instant};

use tracing::field::Empty;
use tracing::Span;

/// Name of every GenAI span; the span-metrics layer keys on it. It must match
/// the literal in [`GenAiCall::start`] (a span name has to be a literal).
#[cfg_attr(not(feature = "otel"), allow(dead_code))]
pub(crate) const GENAI_SPAN: &str = "gen_ai";

/// `gen_ai.provider.name` values (the semantic conventions' list, plus the
/// providers this estate also calls).
pub mod provider {
    pub const AWS_BEDROCK: &str = "aws.bedrock";
    pub const ANTHROPIC: &str = "anthropic";
    pub const OPENAI: &str = "openai";
    pub const GCP_GEMINI: &str = "gcp.gemini";
    pub const MISTRAL_AI: &str = "mistral_ai";
    pub const DEEPSEEK: &str = "deepseek";
    /// Not in the conventions: OpenRouter, whatever model it routes to.
    pub const OPENROUTER: &str = "openrouter";
    /// Not in the conventions: a local or self-hosted Ollama.
    pub const OLLAMA: &str = "ollama";
}

/// `gen_ai.operation.name` values.
pub mod operation {
    pub const CHAT: &str = "chat";
    pub const TEXT_COMPLETION: &str = "text_completion";
    pub const GENERATE_CONTENT: &str = "generate_content";
    pub const EMBEDDINGS: &str = "embeddings";
    pub const INVOKE_AGENT: &str = "invoke_agent";
}

/// What a finished call reported. Every field is optional: providers differ in
/// what they send, and a stream cut off has little.
#[derive(Debug, Default, Clone)]
pub struct Usage {
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    /// Input tokens served from the provider's prompt cache (already counted
    /// in `input_tokens`, per the conventions).
    pub cache_read_input_tokens: Option<i64>,
    /// Input tokens written to the provider's prompt cache.
    pub cache_creation_input_tokens: Option<i64>,
    /// The provider's stop reason as it sends it (`end_turn`, `stop`,
    /// `max_tokens`, `length`, `tool_use` …).
    pub finish_reason: Option<String>,
    /// The model that answered, when it differs from (or refines) the one
    /// requested.
    pub response_model: Option<String>,
    /// The provider's own latency figure, when it sends one.
    pub provider_latency: Option<Duration>,
    /// What the provider says the call cost, in USD, when it reports one
    /// (OpenRouter's `usage.cost`).
    pub cost_usd: Option<f64>,
    /// The host a router picked to serve the call (OpenRouter's `provider`,
    /// e.g. `DeepInfra`), when the provider is a router.
    pub upstream_provider: Option<String>,
}

/// One GenAI call in flight. Create it just before the request, put the
/// request (and any transport span) inside [`span`](Self::span), then
/// [`finish`](Self::finish) or [`fail`](Self::fail) it. Dropped without either,
/// it records `error.type = cancelled` (the caller's future was dropped).
#[must_use = "a GenAiCall must be finished or failed, or its tokens go unrecorded"]
pub struct GenAiCall {
    span: Span,
    started: Instant,
    streaming: bool,
    first_chunk: Option<Duration>,
    done: bool,
}

impl GenAiCall {
    /// Start timing a call. `operation` and `provider` are from
    /// [`operation`] / [`provider`]; `model` is the requested model id;
    /// `task` is a constant naming what the call is for.
    pub fn start(
        operation: &'static str,
        provider: &'static str,
        model: &str,
        task: &'static str,
        streaming: bool,
    ) -> Self {
        let span = if !crate::telemetry::EMIT_SPANS {
            Span::none()
        } else {
            tracing::info_span!(
            "gen_ai",
            otel.name = %format!("{operation} {model}"),
            otel.kind = "client",
            otel.status_code = Empty,
            gen_ai.operation.name = operation,
            gen_ai.provider.name = provider,
            gen_ai.request.model = %crate::telemetry::truncate(model, crate::telemetry::MAX_ATTR_LEN),
            gen_ai.request.stream = streaming,
            gen_ai.request.max_tokens = Empty,
            gen_ai.response.model = Empty,
            gen_ai.response.finish_reasons = Empty,
            gen_ai.usage.input_tokens = Empty,
            gen_ai.usage.output_tokens = Empty,
            gen_ai.usage.cache_read.input_tokens = Empty,
            gen_ai.usage.cache_creation.input_tokens = Empty,
            gen_ai.response.time_to_first_chunk = Empty,
            error.type = Empty,
            hs.gen_ai.task = task,
            hs.gen_ai.result = Empty,
            hs.gen_ai.duration_s = Empty,
            hs.gen_ai.ingestion_s = Empty,
            hs.gen_ai.generation_s = Empty,
            hs.gen_ai.output_tokens_per_second = Empty,
            hs.gen_ai.provider_latency_s = Empty,
            hs.gen_ai.cost_usd = Empty,
            hs.gen_ai.upstream_provider = Empty,
            )
        };
        Self {
            span,
            started: Instant::now(),
            streaming,
            first_chunk: None,
            done: false,
        }
    }

    /// The call's span: instrument the request with it, and create any
    /// transport span (`client_span("bedrock", "Converse", …)`) inside it with
    /// `call.span().in_scope(|| …)` so it nests here.
    pub fn span(&self) -> &Span {
        &self.span
    }

    /// The request's output-token cap.
    pub fn max_tokens(&self, n: i64) {
        self.span.record("gen_ai.request.max_tokens", n);
    }

    /// The first content chunk of a stream has arrived. Only the first call
    /// counts; a non-streaming call ignores it.
    pub fn first_chunk(&mut self) {
        if self.streaming && self.first_chunk.is_none() {
            self.first_chunk = Some(self.started.elapsed());
        }
    }

    /// The response is complete: records usage and timings and logs one INFO
    /// line (exported with the span, and on stdout at the log level). A second `finish` (or a `fail` after it) is ignored.
    pub fn finish(&mut self, usage: &Usage) {
        if self.done {
            return;
        }
        self.done = true;
        let total = self.started.elapsed();
        let t = Timings::new(total, self.streaming.then_some(self.first_chunk).flatten(), usage.output_tokens);
        let s = &self.span;
        if let Some(n) = usage.input_tokens {
            s.record("gen_ai.usage.input_tokens", n);
        }
        if let Some(n) = usage.output_tokens {
            s.record("gen_ai.usage.output_tokens", n);
        }
        if let Some(n) = usage.cache_read_input_tokens {
            s.record("gen_ai.usage.cache_read.input_tokens", n);
        }
        if let Some(n) = usage.cache_creation_input_tokens {
            s.record("gen_ai.usage.cache_creation.input_tokens", n);
        }
        if let Some(r) = &usage.finish_reason {
            s.record("gen_ai.response.finish_reasons", truncate_label(r).as_str());
        }
        if let Some(m) = &usage.response_model {
            s.record("gen_ai.response.model", truncate_label(m).as_str());
        }
        if let Some(p) = usage.provider_latency {
            s.record("hs.gen_ai.provider_latency_s", p.as_secs_f64());
        }
        if let Some(c) = usage.cost_usd.filter(|c| c.is_finite()) {
            s.record("hs.gen_ai.cost_usd", c);
        }
        if let Some(u) = &usage.upstream_provider {
            s.record("hs.gen_ai.upstream_provider", truncate_label(u).as_str());
        }
        t.record(s);
        tracing::info!(
            parent: s,
            gen_ai.usage.input_tokens = usage.input_tokens,
            gen_ai.usage.output_tokens = usage.output_tokens,
            gen_ai.usage.cache_read.input_tokens = usage.cache_read_input_tokens,
            gen_ai.response.finish_reasons = usage.finish_reason.as_deref(),
            hs.gen_ai.duration_s = t.total,
            hs.gen_ai.ingestion_s = t.ingestion,
            hs.gen_ai.output_tokens_per_second = t.tokens_per_second,
            hs.gen_ai.cost_usd = usage.cost_usd,
            hs.gen_ai.upstream_provider = usage.upstream_provider.as_deref(),
            "gen_ai call finished"
        );
    }

    /// The call failed. `error_type` is a low-cardinality constant (the SDK
    /// error's kind, `timeout`, `throttled`, `http.429` …), never its message.
    /// Ignored after [`finish`](Self::finish).
    pub fn fail(&mut self, error_type: &'static str) {
        if self.done {
            return;
        }
        self.done = true;
        let t = Timings::new(self.started.elapsed(), None, None);
        t.record(&self.span);
        self.span.record("error.type", error_type);
        self.span.record("otel.status_code", "ERROR");
        tracing::warn!(parent: &self.span, error.type = error_type, hs.gen_ai.duration_s = t.total, "gen_ai call failed");
    }

    /// The caller's verdict on the reply (`ok`, `empty`, `unparseable`,
    /// `refused` …): a constant from code. Callable any time before the call
    /// is dropped, so after parsing too.
    pub fn result(&self, verdict: &'static str) {
        self.span.record("hs.gen_ai.result", verdict);
    }
}

impl Drop for GenAiCall {
    fn drop(&mut self) {
        if !self.done {
            self.fail("cancelled");
        }
    }
}

fn truncate_label(s: &str) -> String {
    crate::telemetry::truncate(s, crate::telemetry::MAX_ATTR_LEN)
}

/// The timing figures for one call, worked out once.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Timings {
    total: f64,
    ingestion: Option<f64>,
    generation: Option<f64>,
    tokens_per_second: Option<f64>,
}

impl Timings {
    fn new(total: Duration, first_chunk: Option<Duration>, output_tokens: Option<i64>) -> Self {
        let total_s = total.as_secs_f64();
        let ingestion = first_chunk.map(|d| d.as_secs_f64());
        let generation = ingestion.map(|i| (total_s - i).max(0.0));
        // Generation time for a stream; the whole call otherwise. A stream
        // whose first chunk was also its last has no generation time to
        // divide by, so it falls back to the total too.
        let denom = generation.filter(|g| *g > 0.0).unwrap_or(total_s);
        let tokens_per_second = output_tokens
            .filter(|n| *n > 0)
            .filter(|_| denom > 0.0)
            .map(|n| n as f64 / denom);
        Self {
            total: total_s,
            ingestion,
            generation,
            tokens_per_second,
        }
    }

    fn record(&self, span: &Span) {
        span.record("hs.gen_ai.duration_s", self.total);
        if let Some(i) = self.ingestion {
            span.record("gen_ai.response.time_to_first_chunk", i);
            span.record("hs.gen_ai.ingestion_s", i);
        }
        if let Some(g) = self.generation {
            span.record("hs.gen_ai.generation_s", g);
        }
        if let Some(r) = self.tokens_per_second {
            span.record("hs.gen_ai.output_tokens_per_second", r);
        }
    }
}

#[cfg(test)]
mod tests {
    // Some helpers serve only the span-field tests, which need `otel`.
    #![cfg_attr(not(feature = "otel"), allow(dead_code, unused_imports))]
    use super::*;

    fn get(rec: &[(String, String)], k: &str) -> Option<String> {
        rec.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    /// Without `otel` a call is timed and finished as usual, with no span.
    #[cfg(not(feature = "otel"))]
    #[test]
    fn without_otel_a_call_still_works_and_emits_no_span() {
        let mut call = GenAiCall::start(operation::CHAT, provider::OLLAMA, "llama", "t", true);
        assert!(call.span().is_disabled());
        call.first_chunk();
        call.finish(&Usage { output_tokens: Some(3), ..Default::default() });
        call.result("ok");
    }

    #[test]
    fn a_stream_splits_ingestion_from_generation() {
        let t = Timings::new(Duration::from_secs(10), Some(Duration::from_secs(2)), Some(400));
        assert_eq!(t.total, 10.0);
        assert_eq!(t.ingestion, Some(2.0));
        assert_eq!(t.generation, Some(8.0));
        assert_eq!(t.tokens_per_second, Some(50.0), "output over generation time, not total");
    }

    #[test]
    fn a_non_streaming_call_has_only_a_total() {
        let t = Timings::new(Duration::from_secs(4), None, Some(200));
        assert_eq!(t.ingestion, None);
        assert_eq!(t.generation, None);
        assert_eq!(t.tokens_per_second, Some(50.0), "over the whole call");
        assert_eq!(Timings::new(Duration::from_secs(4), None, Some(0)).tokens_per_second, None);
        assert_eq!(Timings::new(Duration::from_secs(4), None, None).tokens_per_second, None);
    }

    #[cfg(feature = "otel")] // reads span fields; spans exist only with `otel`
    #[test]
    fn a_finished_call_records_usage_on_its_span() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        let mut call = GenAiCall::start(operation::CHAT, provider::AWS_BEDROCK, "qwen.qwen3-next-80b-a3b", "graph.extract", true);
        call.max_tokens(4096);
        call.first_chunk();
        call.first_chunk();
        call.finish(&Usage {
            input_tokens: Some(5200),
            output_tokens: Some(310),
            finish_reason: Some("end_turn".into()),
            ..Default::default()
        });
        call.result("ok");
        drop(call);
        let rec = cap.lock().unwrap().clone();
        assert_eq!(get(&rec, "otel.name").as_deref(), Some("chat qwen.qwen3-next-80b-a3b"));
        assert_eq!(get(&rec, "gen_ai.provider.name").as_deref(), Some("aws.bedrock"));
        assert_eq!(get(&rec, "gen_ai.request.stream").as_deref(), Some("true"));
        assert_eq!(get(&rec, "gen_ai.usage.input_tokens").as_deref(), Some("5200"));
        assert_eq!(get(&rec, "gen_ai.usage.output_tokens").as_deref(), Some("310"));
        assert_eq!(get(&rec, "gen_ai.response.finish_reasons").as_deref(), Some("end_turn"));
        assert_eq!(get(&rec, "hs.gen_ai.task").as_deref(), Some("graph.extract"));
        assert_eq!(get(&rec, "hs.gen_ai.result").as_deref(), Some("ok"));
        assert!(get(&rec, "gen_ai.response.time_to_first_chunk").is_some(), "{rec:?}");
        assert!(get(&rec, "hs.gen_ai.duration_s").is_some());
        assert_eq!(get(&rec, "error.type"), None, "a finished call is not an error");
        assert_eq!(get(&rec, "hs.gen_ai.cost_usd"), None, "no cost reported, none recorded");
    }

    #[cfg(feature = "otel")] // reads span fields; spans exist only with `otel`
    #[test]
    fn a_routed_call_records_its_cost_and_upstream_host() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        let mut call = GenAiCall::start(operation::CHAT, provider::OPENROUTER, "qwen/qwen3-next-80b-a3b-instruct", "calendar.extract", false);
        call.finish(&Usage {
            input_tokens: Some(1000),
            output_tokens: Some(100),
            cost_usd: Some(0.00042),
            upstream_provider: Some("DeepInfra".into()),
            ..Default::default()
        });
        drop(call);
        let rec = cap.lock().unwrap().clone();
        assert_eq!(get(&rec, "gen_ai.provider.name").as_deref(), Some("openrouter"));
        assert_eq!(get(&rec, "hs.gen_ai.cost_usd").as_deref(), Some("0.00042"));
        assert_eq!(get(&rec, "hs.gen_ai.upstream_provider").as_deref(), Some("DeepInfra"));
    }

    #[cfg(feature = "otel")] // reads span fields; spans exist only with `otel`
    #[test]
    fn a_dropped_call_is_cancelled_and_a_failed_one_errors() {
        let cap = crate::telemetry::test_capture::capture();
        let _g = crate::telemetry::test_capture::install(&cap);
        drop(GenAiCall::start(operation::CHAT, provider::ANTHROPIC, "claude-x", "chat.turn", true));
        let rec = cap.lock().unwrap().clone();
        assert_eq!(get(&rec, "error.type").as_deref(), Some("cancelled"));
        assert_eq!(get(&rec, "gen_ai.response.time_to_first_chunk"), None, "no chunk, no TTFT");

        let mut call = GenAiCall::start(operation::CHAT, provider::OPENAI, "gpt-x", "chat.turn", false);
        call.fail("throttled");
        call.finish(&Usage { input_tokens: Some(1), ..Default::default() });
        drop(call);
        let rec = cap.lock().unwrap().clone();
        assert_eq!(get(&rec, "error.type").as_deref(), Some("throttled"));
        assert_eq!(get(&rec, "otel.status_code").as_deref(), Some("ERROR"));
        assert_eq!(get(&rec, "gen_ai.usage.input_tokens"), None, "finish after fail is ignored");
    }
}
