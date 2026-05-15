# Stage 08: exact config-key parity with TS hs.utils (v0.6.1)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete

## Goal
Make the Rust config keys **identical** to the TS
`@hikari-systems/hs.utils` `lib/mcp-auth/config.ts:loadAuthConfig` +
`dbStores.ts` keys (hs.utils 0.0.83, which renamed mcp-data-service to
`mcp-data-service:url` / `:apiKey`). Previously the Rust port folded
several keys under `mcp.auth.*` (camelCase) that TS sources from
top-level keys.

## TS key set (the contract to match exactly)
mcp:auth block → `mcp:auth:{resourceServerUrl,expectedAudience,
supportedScopes,enableDcr,clockSkewSeconds,jwksUri,claimsNamespace,
allowedAudiences}`. Top-level → `oauth2:authorizationServer`,
`kratos:adminUrl`, `hydra:adminUrl`, `mcp-data-service:url`,
`mcp-data-service:apiKey`. (env: `:` → `__`.)

## Changes (hs-utils-rs config.rs)
- `McpAuthConfig` now deserializes **only** the `mcp:auth:*` fields
  (env `mcp__auth__<field>`), incl. renamed `jwks_uri` (was `jwksUrl` →
  now `jwksUri`, matching TS) and new `allowed_audiences`
  (`allowedAudiences`).
- `authorization_server_url`, `kratos_admin_url`, `hydra_admin_url`,
  `mcp_data_service_url`, `mcp_data_service_api_key` are now
  `#[serde(skip)]` and injected by the host via the new
  `McpAuthConfig::with_runtime(...)` — the host reads them from the
  top-level `oauth2:` / `kratos:` / `hydra:` / `mcp-data-service:` keys,
  exactly like TS `loadAuthConfig`.
- Dropped `fallback_to_kratos_admin` (not a TS config key — TS only has
  it as a resolver fn option; Kratos resolver keeps default `true`).
- `effective_jwks_url()` uses `jwks_uri`; `apply.rs` updated.
- Version `0.6.0` → `0.6.1`.

## Verification
clippy `--all-features --all-targets -D warnings` clean; 26 tests green.

## Watch-outs (Stage 6 follow-up in the MCPs + Stage 7 spot)
- Each MCP `AppConfig` must read top-level `oauth2.authorizationServer`,
  `kratos.adminUrl`, `hydra.adminUrl`, `mcp-data-service.{url,apiKey}`
  and call `auth_cfg.with_runtime(...)`. Kratos resolver `fallback` is
  now just `kratos_admin_url.is_some()` (default-true semantics).
- Spot env keys change: `mcp__auth__authorizationServerUrl` →
  `oauth2__authorizationServer`; `mcp__auth__kratosAdminUrl` →
  `kratos__adminUrl`; `mcp__auth__hydraAdminUrl` → `hydra__adminUrl`;
  `mcp__auth__mcpDataServiceUrl` → `mcp-data-service__url`.

## Completion record
Rust config keys now match the TS `hs.utils` 0.0.83 set exactly
(mcp:auth block + top-level oauth2/kratos/hydra/mcp-data-service). Ship
as v0.6.1; MCPs re-pin + add the top-level reads in the same pass.