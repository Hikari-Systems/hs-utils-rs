# Template: Postgres web-login session store — first-time DB setup

**Audience:** an AI assistant (or engineer) working in a *service* repo that
consumes `hs-utils`'s `web-login-postgres` feature (`PgSessionStore`). Copy the
relevant parts of this file into **that service's README**, fill in the
placeholders, and commit a bootstrap SQL script alongside it.

This template exists because each service that uses `PgSessionStore` gets its own
database role, its own session table, and its own grant script — there is no
shared bootstrap. Adapt the values below to the service; do not paste them
verbatim.

---

## How to use this template (instructions to the per-repo LLM)

1. Choose a **table name** for this service. It must be unique within any database
   shared with other services. Convention: `<service>_web_session`
   (e.g. `lloquent_web_session`). It must be a valid Postgres identifier —
   `^[A-Za-z_][A-Za-z0-9_]*$`, ≤63 chars — or `PgSessionStore::with_table`
   returns an error at boot.
2. Choose a **runtime role** name (e.g. `<service>_app`) and decide the
   **privilege model** (§3 below): does the app create its own schema, or does a
   DBA pre-create the table?
3. Fill the placeholders (`<service>`, `<table>`, `<role>`, `<password>`,
   `<db>`, `<schema>`; default schema is `public`) into the SQL script in §2 and
   commit it to the service repo (e.g. `db/web_session_setup.sql`).
4. Paste the "README section" in §4 into the service README, adjusted to match.

Placeholders to replace everywhere: `<service>`, `<db>`, `<schema>` (default
`public`), `<role>`, `<password>`, `<table>`.

---

## 1. What the store needs

`PgSessionStore` keeps one row per session in a single table:

```sql
<table> (
    sid        TEXT PRIMARY KEY,
    data       JSONB NOT NULL,        -- the serialized Session
    expires_at TIMESTAMPTZ NOT NULL
)
-- plus an index: <table>_expires_at_idx ON <table> (expires_at)
```

It reuses the service's existing `PgPool`, so the runtime role is the **same DB
user the service already connects as** (`DbConfig`). Setup therefore boils down
to: a role, the table, an index, and the grants that let the role read/write it.

`PgSessionStore::ensure_schema()` will `CREATE TABLE IF NOT EXISTS` + the index
idempotently on boot — **but only if the runtime role has `CREATE` on the
schema.** Whether you rely on that or pre-create the table is the choice in §3.

---

## 2. Bootstrap SQL script template

Run as a Postgres **superuser / DBA** (the runtime role cannot grant itself
rights). Idempotent enough to re-run; review before applying to a shared DB.

```sql
-- ====================================================================
-- web-login session store setup for <service>
-- DB: <db>   schema: <schema>   table: <table>   role: <role>
-- Run as a superuser / owner.
-- ====================================================================

-- 1. Runtime role (skip if the service role already exists).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '<role>') THEN
        CREATE ROLE <role> LOGIN PASSWORD '<password>';
    END IF;
END
$$;

-- 2. Let the role reach the schema (needed for either privilege model).
GRANT USAGE ON SCHEMA <schema> TO <role>;

-- 3a. PRIVILEGE MODEL A — app self-provisions (simplest; dev / single-tenant).
--     The role creates its own table via ensure_schema(); grant CREATE.
--     Use EITHER 3a OR 3b, not both.
GRANT CREATE ON SCHEMA <schema> TO <role>;

-- 3b. PRIVILEGE MODEL B — least privilege (recommended for shared / prod DBs).
--     A DBA owns the table; the role only gets DML. Comment out 3a above,
--     uncomment this block, and DO NOT call ensure_schema() at runtime
--     (see §3) — or call it once while connected as the owner.
--
-- CREATE TABLE IF NOT EXISTS <schema>.<table> (
--     sid        TEXT PRIMARY KEY,
--     data       JSONB NOT NULL,
--     expires_at TIMESTAMPTZ NOT NULL
-- );
-- CREATE INDEX IF NOT EXISTS <table>_expires_at_idx
--     ON <schema>.<table> (expires_at);
-- GRANT SELECT, INSERT, UPDATE, DELETE ON <schema>.<table> TO <role>;
```

> If you used model A, the table/index are created by the app, so you do **not**
> need the `CREATE TABLE` / `GRANT ... ON <table>` lines — the role owns what it
> creates and already has full rights on it.

---

## 3. Privilege model: which one, and the code implication

| | Model A (self-provision) | Model B (least privilege) |
|---|---|---|
| Schema grant | `USAGE` + `CREATE` | `USAGE` only |
| Table created by | the app, via `ensure_schema()` | a DBA, in the setup script |
| Table grants | implicit (role is owner) | explicit `SELECT,INSERT,UPDATE,DELETE` |
| `ensure_schema()` at boot | **call it** | **don't** (role lacks `CREATE`) — or run it once as the owner |
| Good for | dev, single-tenant DB | shared / multi-service / prod DBs |

**Code implication (service side):**

```rust
// Model A:
let store = PgSessionStore::from_pool(pool.clone())
    .with_table(cfg.session_table.as_deref().unwrap_or(DEFAULT_SESSION_TABLE))?;
store.ensure_schema().await?;   // role has CREATE

// Model B:
let store = PgSessionStore::from_pool(pool.clone())
    .with_table(&cfg.session_table)?;
// no ensure_schema(): the DBA already created the table.
```

`sweep_expired()` only needs `DELETE`, so it works under both models — wire it to
a periodic task (e.g. hourly) regardless.

---

## 4. README section to paste into the service repo

> Adjust names; this is the block end users/operators read.

```markdown
### First-time database setup (web-login sessions)

This service stores browser-login sessions in Postgres (table
`<table>`) via `hs-utils`' `PgSessionStore`, so logins survive across
replicas without redis.

**One-time setup:** a DBA runs `db/web_session_setup.sql` (creates the
`<role>` role, grants, and — in the least-privilege model — the
`<table>` table and its index). See that script's header for the two
privilege models.

**Config:** the table name is set via `session_table` (defaults to
`web_sessions`). When this DB is shared with other services, give each a
distinct table name:

​```json
{ "session_table": "<table>" }
​```

The name must be a valid Postgres identifier (letters, digits,
underscore; not starting with a digit; ≤63 chars) or the service fails
to start.
```

---

## 5. Config wiring note

`PgSessionStore` is a library type; the `session_table` config field lives in the
**service's** `AppConfig`, read from its config JSON and passed to `with_table`.
A typical optional field:

```rust
#[serde(default)]
session_table: Option<String>,   // None → DEFAULT_SESSION_TABLE
```

Because `hs-utils` normalises config leaves to strings, a plain `Option<String>`
works without a custom `deser_*_or_str` deserializer.
```
