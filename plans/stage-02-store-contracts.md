# Stage 02: store contracts + in-memory impls (hs-utils-rs)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete

## Goal
Add the pluggable store layer mirroring TS
`lib/mcp-auth/stores.ts`: trait contracts (`ClientStore`,
`DcrRateLimitStore`, `JwksCacheStore`, `AsmCache`) + data types
(`ClientRegistration`, `JsonWebKeySet`, `JwksCacheEntry`) + in-memory
implementations. Purely additive — no existing behaviour changes yet
(Stage 5 wires these in). Introduces `async-trait`.

## Prerequisites
- Stage 1 shipped (v0.5.0). TS ref: `hs.utils/lib/mcp-auth/stores.ts`.

## Deliverables
- `src/mcp_resource_server/stores.rs` — types + 4 object-safe
  `#[async_trait]` traits + `InMemory*` impls (Map/Instant, mirroring
  the TS `create*` factories incl. the sliding-window rate limiter and
  the TTL ASM cache).
- `mod.rs` exports; `Cargo.toml` `async-trait` dep gated to
  `mcp-resource-server`.
- Unit tests: client get/set, rate-limit window allow/deny, jwks
  get/set, asm ttl fresh/stale.
- `cargo build` + `clippy --all-features --all-targets -D warnings` +
  `test` green.

## Implementation notes
- Trait named `JwksCacheStore` (not `JwksCache`) — `jwks.rs` already has
  `JwksCache` (the fetcher). Stage 5 makes the fetcher consult the
  store.
- `JsonWebKeySet { keys: Vec<serde_json::Value> }` (mirrors TS `{ keys:
  unknown[] }`). `ClientRegistration` serde snake/exact field names per
  `stores.ts`.
- In-memory state: `std::sync::Mutex<HashMap>` — no `.await` is held
  across the lock (ops are sync), safe.

## Working log
- 2026-05-15: stage doc created; scope from re-planned master. Starting.
- 2026-05-15: implemented `stores.rs` (types + 4 `#[async_trait]`
  object-safe traits + 4 `InMemory*` impls). Added `async-trait` dep
  (feature-gated). mod.rs exports added. clippy `--all-features
  --all-targets -D warnings` clean; `cargo test --features
  mcp-resource-server` 12/12 (7 kratos + 5 new store tests).

## Completion record
**Delivered:** `src/mcp_resource_server/stores.rs` —
`ClientRegistration`, `JsonWebKeySet`, `JwksCacheEntry`; traits
`ClientStore`, `DcrRateLimitStore`, `JwksCacheStore` (renamed to avoid
the `jwks::JwksCache` fetcher collision), `AsmCache`; in-memory impls
`InMemory{ClientStore,DcrRateLimitStore,JwksCacheStore,AsmCache}`
mirroring the TS `create*` factories (sliding-window rate limiter, TTL
ASM cache). `async-trait` added (gated to `mcp-resource-server`).
mod.rs re-exports the surface.

**Verification:** clippy `--all-features --all-targets -D warnings`
clean; 12 tests green; v0.5.0 behaviour unchanged (purely additive,
nothing consumes the traits yet — Stage 5 wires them).

**Deviations:** none. **Watch-outs:** Stage 3 (`db_stores`) and Stage 4
(`hydra_client_store`) implement these same traits; Stage 5 swaps
`metadata.rs`'s in-process `as_cache`/CIMD echo and the JWKS fetch path
onto the trait objects. `JwksCacheStore` name is deliberate — keep it
distinct from `jwks::JwksCache`.
