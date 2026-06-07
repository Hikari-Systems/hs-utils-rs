# Stage 04: Hydra client store (hs-utils-rs)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete

## Goal
Read-through `ClientStore` over Hydra's admin API, mirroring TS
`lib/mcp-auth/hydraClientStore.ts`. Additive; consumed in Stage 5.

## Deliverables
- `src/mcp_resource_server/hydra_client_store.rs`: `HydraClientStore`
  (impl `ClientStore`) — `get` → `GET {admin}/admin/clients/{id}`
  (404/non-ok/transport-err → `None`, loose→`ClientRegistration` with
  the TS defaults: grant_types `[authorization_code]`, response_types
  `[code]`, token_endpoint_auth_method `none`), `set` → no-op. Reuses
  the Stage-3 `HttpTransport` seam. mod.rs export. 4 unit tests.
- clippy `--all-features --all-targets -D warnings` clean; `cargo test`
  22/22.

## Working log
- 2026-05-15: implemented + tested; clippy/test green (22/22).

## Completion record
**Delivered** `HydraClientStore` per `hydraClientStore.ts` (read-through,
no-op `set`, loose-JSON mapping with defaults). Reused `HttpTransport`
for dependency-free tests. **Verification:** clippy `--all-features -D
warnings`, 22 tests green. **Watch-out (Stage 5):** in the Hydra+Kratos
wiring the `clients` store = `HydraClientStore`; CIMD reads through it.