# Stage 03: Db-backed stores + mcp-data-service client (hs-utils-rs)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete

## Goal
mcp-data-service-backed implementations of the Stage-2 store traits,
mirroring TS `lib/mcp-auth/dbStores.ts` (routes, `X-Api-Key`, body
shapes). Additive; nothing consumes them until Stage 5.

## Deliverables
- `src/mcp_resource_server/db_stores.rs`: `HttpTransport` seam +
  `ReqwestTransport`; `McpDataServiceClient` (base default
  `http://mcp-data-service:3000`, trailing-slash trim, `X-Api-Key`);
  `DbClientStore` / `DbDcrRateLimitStore` / `DbJwksCacheStore` /
  `DbAsmCache` implementing the Stage-2 traits against the exact TS
  routes. mod.rs exports. 6 unit tests via a stub transport.
- clippy `--all-features --all-targets -D warnings` clean; `cargo test`
  18/18.

## Implementation notes
- TS `dbStores` *throws* on hard (non-204/404) errors; the Rust store
  traits return `Option`/`bool`/`()`. Degradation chosen: reads → `None`
  (logged), `record_and_check` → **`false` (fail-closed)** so an
  unreachable limiter denies DCR rather than opening it, writes →
  log-and-swallow. Documented in the module header.
- `HttpTransport` trait (async, object-safe) makes every Db store unit
  testable without a live mcp-data-service and without a mock-HTTP dev
  dep — same philosophy as Stage 1's fetcher seam.
- `enc()` mirrors `encodeURIComponent` (duplicated ~10 lines from
  `kratos_resolver`; not abstracting a trivial helper across modules).

## Working log
- 2026-05-15: implemented + tested. clippy/test green (18/18).

## Completion record
**Delivered** the four Db stores + transport seam + `McpDataServiceClient`
exactly per `dbStores.ts` routes/bodies. **Verification:** clippy
`--all-features -D warnings`, 18 tests green. **Deviation:** error
semantics (Option/fail-closed vs TS throw) — intentional, documented.
**Watch-out (Stage 5):** the JWKS verify path must call
`JwksCacheStore.get(authServerUrl)` → on miss fetch `jwks_uri` → `set`;
ASM metadata + CIMD swap onto `AsmCache`/`ClientStore`. DCR `/register`
must call `DcrRateLimitStore.record_and_check` before proxying to Hydra.