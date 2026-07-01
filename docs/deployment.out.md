The document is now fully updated. Here's a summary of what changed:

**Section 3 — Configuration model** — Updated the table to add `postgres` to the durable stores row (now `memory · sqlite · **postgres**`) and expanded the callout to cover **both** Redis AND Postgres backends being wired into the stock binary as separate Go modules pulled in via go.mod `replace`.

**Section 6b — Tier B topology** — Updated the description to say `set backend: postgres on the durable stores` alongside `backend: redis` on hot stores. The config example now includes the full `postgres:` block, durable-store backends (`identity.backend: postgres, session_backend: redis`, `permissions.backend: postgres`, `tenant.backend: postgres`, `audit.backend: postgres`) and the `keys.signing_key_registry` etcd section.

**Section 6b — ASCII diagram** — Added a `Postgres /Cockroach` box alongside Redis, showing the hot/durable split.

**Section 7 — Distribution-capable modules** — Changed the durable stores row from `⚠️ planned — memory/sqlite today` to `✅ backend: postgres`, citing the actual `infrastructure/postgres` module path.
