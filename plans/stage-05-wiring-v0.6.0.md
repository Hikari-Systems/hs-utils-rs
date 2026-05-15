# Stage 05: store wiring + apply_mcp_auth + v0.6.0 (hs-utils-rs)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete (pending tag push confirmation → done per user "continue")

## Goal
Wire the Stage 2–4 store traits into the live auth path and add an
`apply_mcp_auth` equivalent of TS `lib/mcp-auth/index.ts`, so the Rust
resource server mirrors the TS library end-to-end. Cut **v0.6.0**.

## Deliverables
- `jwks.rs` → stateless helpers (`discover_jwks_uri`, `fetch_jwks`,
  `decoding_key_for_kid`) mirroring `tokenVerifier.ts`. Old in-process
  `JwksCache` struct removed.
- `jwt.rs` → `JwtVerifier` consults a `JwksCacheStore` keyed by the AS
  URL (miss → discover → fetch → `set`); issuer accepted with/without
  trailing slash; audience + clock-skew as before. New `new()` signature
  `(jwks_store, auth_server_url, jwks_url_override, audience, skew)`.
- `metadata.rs` rewritten: PRM; ASM proxy with `sanitizeAsm` allowlist +
  `AsmCache` (5-min TTL) + S256 warn + 502; CIMD via `ClientStore`.
- `dcr.rs` NEW: TS `createDcrHandler` parity (rate-limit 5/60s,
  redirect-uri rules, uuid client_id, `ClientStore.set`, 201).
- `apply.rs` NEW: `McpAuthStores` (`in_memory()` / `from_config()` —
  Hydra clients + Db caches when `hydra_admin_url` set) and
  `apply_mcp_auth(cfg, stores, resolver) -> (Router, AuthState)`.
- `config.rs`: `hydra_admin_url`, `mcp_data_service_url` (default
  `http://mcp-data-service:3000`), `mcp_data_service_api_key`.
- `Cargo.toml`: re-add `uuid` (v4, DCR); version `0.5.0`→`0.6.0`.
- mod.rs exports updated. clippy `--all-features --all-targets -D
  warnings` clean; 26 tests green.

## Implementation notes / deviations
- PRM `resource` = configured `resource_server_url` (the Rust crate has
  no forwarded-host helper; TS derives it from the inbound forwarded
  host). Equivalent behind a stable public URL — documented in
  `metadata.rs`.
- Db store error semantics (Stage 3): reads → `None`, rate-limit →
  fail-closed, writes → log-swallow (TS throws). Intentional.
- The existing `mcp_auth` Hydra-DCR *proxy* (`forward_register`) is left
  in the crate but the resource-server wiring now uses the TS-parity
  `dcr.rs` handler gated on `enable_dcr` (per user: TS is north star;
  Rust not yet in real use). In the Hydra+Kratos path `enable_dcr` is
  false → `/register` not mounted (clients use Hydra `/oauth2/register`,
  advertised via the ASM proxy's `registration_endpoint`).
- `JwtVerifier::new` signature changed — Stage 6 updates both MCPs'
  `build_auth_state`.

## Working log
- 2026-05-15: implemented all of the above; build + clippy
  (`--all-features -D warnings`) + `cargo test` (26) green. Version
  bumped 0.6.0.

## Completion record
**Delivered** the full TS-parity wiring (jwks/jwt/metadata/dcr/apply +
config) at **v0.6.0**. **Verification:** clippy `--all-features
--all-targets -D warnings` clean; 26 unit tests (7 kratos + 5 stores +
6 db_stores + 4 hydra + 4 dcr) + the doc-tests ignored as before.
**Watch-outs for Stage 6:** `JwtVerifier::new` + `AuthState`
construction changed — both MCPs build `AuthState` via
`apply_mcp_auth(cfg, McpAuthStores::from_config(&cfg), resolver)` and
merge the returned router (metadata/CIMD/DCR) into their top-level
router, layering the returned `AuthState` on the `/mcp` subrouter. Drop
the MCPs' hand-rolled `JwksCache`/metadata wiring. Re-pin to v0.6.0.