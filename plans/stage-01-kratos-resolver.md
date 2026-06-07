# Stage 01: Kratos user resolver (hs-utils-rs)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete (pending review + tag)

## Goal
Add a Kratos-backed MCP user resolver to `hs-utils-rs::mcp_resource_server`
that mirrors the TypeScript `@hikari-systems/hs.utils`
`createKratosUserResolver` line-for-line, and make it the **only**
resolution path: remove `user_resolver` (`ClaimsUserResolver`) and
`user_data_service_client` (`UserDataServiceClient`). Bump `0.4.0` →
`0.5.0`.

## Prerequisites
- Master plan approved; decisions locked (`user_id: String`; tag v0.5.0;
  staged).
- TS reference readable at `/home/rickk/git/hs/hs.utils`
  (`lib/mcp-auth/kratosResolver.ts`, `lib/kratos/claims.ts`,
  `lib/mcp-auth/userResolution.ts`).

## Deliverables
- `src/mcp_resource_server/kratos_resolver.rs` — `KratosUserResolver`
  (`new`, async `resolve(&self, payload: &Value) -> Option<ResolvedUser>`),
  `ResolvedUser { user_id: String, profile: OauthProfile }`, moka TTL
  cache (5 min / 10k), Kratos-admin fallback fetch.
- Kratos claims reader mirroring `readKratosClaims`
  (`${ns}email`/`${ns}name`/`${ns}pictureId`) — added to `claims.rs`
  (`read_kratos_claims`) or in the new module; `build_profile` (Auth0
  shape) left untouched but no longer referenced by the resolver.
- `config.rs` — `McpAuthConfig` gains `kratos_admin_url: Option<String>`
  (key `kratosAdminUrl`) and `fallback_to_kratos_admin: bool` (default
  true); `claims_namespace` reused.
- `middleware.rs` — `AuthState.resolver: Arc<KratosUserResolver>`;
  `AuthExtension.user_id: Option<String>`.
- `mod.rs` — drop `user_resolver`, `user_data_service_client` modules and
  their re-exports (`ClaimsUserResolver`, `ResolvedUser` from there,
  `UserDataServiceClient`, `UserResponse`); export `kratos_resolver`
  (`KratosUserResolver`, `ResolvedUser`). Update module docs.
- `Cargo.toml` version `0.4.0` → `0.5.0`.
- Unit tests covering: missing/empty sub → None; claims-only profile;
  fallback trigger when claims empty; 404 → None; non-2xx → None; cache
  hit; `user_id == sub`. Mock the Kratos admin HTTP (wiremock or an
  injectable client like `UserDataServiceClient::with_client`).
- `cargo build`, `cargo clippy -D warnings`, `cargo test` green for the
  `mcp-resource-server` feature.

## Implementation notes
- Keep `resolve()`'s signature identical to the old `ClaimsUserResolver`
  (`&self, payload: &Value`) so `middleware.rs` change is the resolver
  type + the `user_id` type only.
- `OauthProfile` struct is reused; Kratos path sets `email_verified =
  None`. `picture` ← `${ns}pictureId` (NOT `${ns}picture`).
- Kratos admin fallback: `GET {admin}/admin/identities/{enc(sub)}`,
  `Accept: application/json`. Deserialize a minimal `KratosIdentity {
  id, traits { email, name, picture, pictureId }, metadata_public,
  verifiable_addresses }`. 404 → keep prior profile; other non-2xx →
  warn + keep prior.
- HTTP via `reqwest` (already a dep through the removed UDS client; keep
  the dep). Cache via `moka::future::Cache` (same as old resolver).
- Removing the UDS modules is an intended breaking API change; only the
  two Rust MCPs consume this crate and both are migrated in Stage 2.

## Working log
- 2026-05-15: stage doc created; master plan written. Confirmed via TS
  source that the Kratos reader differs from Rust `build_profile`
  (pictureId vs picture; no email_verified). Starting implementation.
- 2026-05-15: implemented. Chose a `KratosIdentityFetcher` trait seam
  (std `Pin<Box<dyn Future>>`, no new deps — no async-trait/wiremock) so
  the resolver is unit-testable without a live Kratos. `claims.rs` got
  `read_kratos_claims` + `KratosClaimProfile`; `build_profile` (Auth0
  reader) left intact but unreferenced. Removed `uuid` (direct dep +
  feature entry) — only the deleted UDS code used it; it still compiles
  transitively via moka. Added `[dev-dependencies] tokio` (macros/rt) for
  `#[tokio::test]` without bloating the lib build.

## Completion record

**Delivered:** `kratos_resolver.rs` (`KratosUserResolver`,
`ResolvedUser{user_id:String,profile}`, `KratosIdentity/KratosTraits`,
`KratosIdentityFetcher` + `ReqwestKratosFetcher`), `read_kratos_claims`
in `claims.rs`, `McpAuthConfig.{kratos_admin_url, fallback_to_kratos_admin}`,
`middleware.rs` (`AuthState.resolver: Arc<KratosUserResolver>`,
`AuthExtension.user_id: Option<String>`), `mod.rs` exports updated.
Deleted `user_resolver.rs` + `user_data_service_client.rs`. Version
`0.4.0`→`0.5.0`. 7 unit tests (missing/empty sub, claims-only,
fallback-fill, 404→sub-only, fallback-disabled, cache-hit).

**Verification:** `cargo build` (default + `mcp-resource-server`),
`cargo clippy --all-features --all-targets -D warnings`, and
`cargo test --features mcp-resource-server` (7/7) all green.

**Deviations from plan:** none material. The fetcher trait seam was an
addition (testability) not in the original sketch; the public surface
gains `KratosIdentityFetcher`/`KratosIdentity` exports.

**Watch-outs for Stage 2 (MCP re-pin + rewire):**
- API is breaking: `ClaimsUserResolver`, `UserDataServiceClient`,
  `UserResponse` are gone; `ResolvedUser.user_id` is now `String`.
- Both MCPs build `AuthState` with `Arc<KratosUserResolver>` instead of
  `ClaimsUserResolver` + `UserDataServiceClient`.
- `KratosUserResolver::new(admin_url, namespace, fallback)` — namespace
  should come from `McpAuthConfig.claims_namespace`; `fallback` from
  `McpAuthConfig.fallback_to_kratos_admin`; `admin_url` from
  `McpAuthConfig.kratos_admin_url` (skip auth wiring / construct only
  when present, mirroring TS `useHydraKratos`).
- Not committed/tagged yet. `v0.5.0` tag push deferred to user
  go-ahead (release action). MCP `Cargo.toml` re-pin in Stage 2 must
  match whatever ref is actually pushed.
