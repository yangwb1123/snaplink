Design produced at `docs/architect-analysis/cmd-sso-ctl-importcmd-governance-outbox-design.md`.

## Verification result

Every evidence citation confirmed against HEAD. Substance fully intact; three citations have minor line drift (`runImport`/`writeBatch` at :59/:90 vs claimed 82-137; `Validate` at :95 vs 103; `insertOutboxEventTx` at :14 vs 11) — consistent with an older-HEAD direction doc, not false claims. Two additional binding constraints surfaced during design verification:

1. **Postgres cycle**: `tenantcommerce` already imports `infrastructure/postgres` → the pair-write cannot be a method on `*postgres.UserProvider`; it must live in `tenantcommerce` (importing the upsert as an exported package function).
2. **Sqlite idempotency trap**: `ON CONFLICT(id) DO NOTHING` is PK-targeted; a random event ID on re-import would violate the `(tenant_id, idempotency_key)` unique index and error. The event ID must be deterministic.

## Design at a glance

Per-row atomic tx on both backends: `BEGIN → upsert user → insert outbox row → COMMIT`, one table per backend (`audit_outbox` sqlite / `tenant_commerce_outbox` postgres) so existing relay workers drain both classes unchanged.

**API changes** (no SPI change; `shared/core` and `interfaces/sso` untouched):
- `auditoutbox`: export `InsertEventTx(ctx, tx, event)` (rename of `insertFactTx`) + `Migrate(ctx, db)`; `FactFromAudit` gate untouched
- `sqlite/users.go`: `CreateOrUpdateTx` + `ImportUser` (the atomic pair-write, ~390 lines ≤ 500)
- `postgres/users.go`: exported `UpsertUserTx` package function (cycle constraint)
- `tenantcommerce/import.go` (new file): `ImportUserTx(ctx, db, u, event)` — gets `ErrIdempotencyConflict` for free from the existing `ensureOutboxFactTx`
- `importcmd`: seam widened with `ImportUser`; sqlite provider satisfies it directly, a small `postgresUserStore` adapter covers postgres; `--tenant` flag (required unless `--dry-run`, exit 2); `newImportFact` builds the bounded redacted event with deterministic ID/key `"import:"+tenant+":"+userID`, type `snaplink.audit.user.import`

**Key trade-offs flagged**: the required `--tenant` is the one deliberate CLI break; sqlite/postgres idempotency asymmetry (sqlite silently keeps the old row on a changed-fact collision, postgres errors) is documented with rationale.

**Acceptance mapping**: AC1-AC4 live in `test/` (package `ssotest`) driving `sqlite.UserProvider.ImportUser` / `tenantcommerce.ImportUserTx` — the exact functions the CLI calls, since `test/` cannot import `cmd/`; AC5 proves CLI wiring in-package. AC3 mirrors the existing `startRelay` harness (ManagedRelayFactory + modules manager + captureClient); AC4 reuses the real-server harness for the `/token` byte-identical oracle pin.

**Failure modes** cover crash-mid-import (idempotent rerun), pair rollback, concurrent sqlite writers, recipient rejection (quarantine/replay safety net), and the payload-spec-change conflict. **Migration** is a CLI-only deploy: next import run auto-creates the outbox table; relay workers drain with zero config; rollback is a binary revert.
