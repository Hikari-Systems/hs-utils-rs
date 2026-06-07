# Stage 09: claims_namespace empty-string hardening (v0.6.2)

Master plan: `~/.claude/plans/kratos-rust-mcp-user-resolution.md`.

## Status
complete

## Goal
Make `McpAuthConfig.claims_namespace` treat an explicit empty/whitespace
value as "use the default" (`https://hikari-systems.com/`), exactly like
TS `loadAuthConfig` (`claimsNamespaceRaw === '' ? undefined` →
resolver default). Previously serde's `default` only fired when the key
was *absent*, so a `"claimsNamespace": ""` config (which
bioalphaengine-mcp ships) would have become a literal empty namespace
and silently broken Kratos claim resolution (`email` instead of
`https://hikari-systems.com/email`).

## Change
- `config.rs`: `claims_namespace` now `deserialize_with =
  "deser_namespace"` (+ existing `default`). `deser_namespace` maps
  null/empty/whitespace → `default_namespace()`, else the value.
- 3 unit tests (absent / empty+whitespace / explicit value).
- Version `0.6.1` → `0.6.2`.

## Verification
clippy `--all-features --all-targets -D warnings` clean; 29 tests green
(26 + 3 new).

## Result
A `"claimsNamespace": ""` (config.json or `mcp__auth__claimsNamespace=""`
env) is now safe and identical to TS. The "omit the key" convention is
no longer load-bearing — though still the tidiest. MCPs re-pin to
v0.6.2.