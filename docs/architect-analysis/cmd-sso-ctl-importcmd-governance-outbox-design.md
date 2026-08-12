# Design: import writes enqueue auth.user.import governance events in the same transaction as the user upsert

- Spec: `docs/architect-analysis/cmd-sso-ctl-importcmd-governance-outbox-requirements.md`
- Module: `cmd/sso-ctl/importcmd` + store seams (`infrastructure/defaultimpl/sqlite`,
  `infrastructure/postgres`, `infrastructure/postgres/tenantcommerce`, `infrastructure/auditoutbox`)
- Status: design (evidence re-verified against HEAD)

## 1. Verification of the untrusted evidence

Every citation in the evidence was re-checked against HEAD. All substance
confirmed; three citations carry minor line drift (the direction document was
written against a slightly older HEAD). No citation was false.

| Citation | Verified at HEAD | Verdict |
|---|---|---|
| `importer.go` `userStore` = `sso.UserProvider` + `Close`; `runImport`/`writeBatch` per-row autocommit upserts | `userStore` at importer.go:24; `runImport` :59, `writeBatch` :90 (claimed 82-137 — drift); `aliases.go:165-166` aliases `User`/`UserProvider` = `core.*`; `core.UserProvider` at `shared/core/spi.go:42` | Confirmed (line drift) |
| `sqlite/users.go:168` `CreateOrUpdate`, no Tx surface; `DB()` at :131 | `CreateOrUpdate` exactly :168; `ON CONFLICT(id) DO UPDATE` :185; `DB()` exactly :131 | Confirmed |
| `commerce/store.go:366` `OutboxStore`; `OutboxEvent.Validate()` requires TenantID + IdempotencyKey | `OutboxStore` exactly :366 (6 methods); `Validate` :95 (claimed 103 — drift); event vocabulary `snaplink.<domain>.<class>` at store.go:43-59 | Confirmed (line drift) |
| `auditgovernance/relay.go` + `managed_relay.go`; billing wiring precedent | `NewRelay` relay.go:56, `RunOnce` :137, `ManagedRelayFactory` managed_relay.go:45; `cmd/snaplink-billing/relay.go:127-132` builds `NewRelay` inside `ManagedRelayFactory.Build` | Confirmed |
| `usageledger/outbox.go` in-tx enqueue precedent | `insertOutboxEventTx` outbox.go:14 (claimed 11 — drift), bare `ON CONFLICT DO NOTHING` :27, `ensureOutboxFactTx` :42 → `commerce.ErrIdempotencyConflict` :54/58; `runLocked` store.go:168; `UNIQUE (tenant_id, idempotency_key)` store.go:109 | Confirmed (line drift) |
| `tenantcommerce/outbox.go` same shape | `insertOutboxEventsTx` :53, `insertOutboxEventTx` :60, bare `ON CONFLICT DO NOTHING` :70, fact-equality :83/107 | Confirmed |
| `memory_outbox.go` idempotency machinery | `prepareOutboxLocked` :13, `validateOutboxIdentityLocked` :36, `sameOutboxFact` :46, `ErrIdempotencyConflict` | Confirmed |
| T-2/T-8(a-e)/T-9 untouched by this change | `docs/campaigns/implementation-gate.md` lines 11-14 (T-8a claims, T-8d scope registry, T-2 discovery, T-8bce/T-9 hardening) and :77 (G5); none reference `sso-ctl import` | Confirmed |
| `test/` cannot import `cmd/` | `test/auditoutbox_governance_test.go` header: "test/ cannot import cmd/" | Confirmed |
| `auditoutbox.AppendInTx` fail-closed to `login_failure` | `FactFromAudit` (fact.go:64-86) rejects every non-`login_failure` class (`ErrClassNotPermitted`); `AppendInTx` sqlite.go:122; `insertFactTx` :137 with `ON CONFLICT(id) DO NOTHING` + unique `(tenant_id, idempotency_key)` index :61 | Confirmed |
| users table has no tenant column | sqlite DDL users.go:43-57; postgres users.go:23 — no `tenant_id` | Confirmed |

**Two additional binding constraints found during design verification:**

1. **Postgres import cycle**: `infrastructure/postgres/tenantcommerce` already
   imports `infrastructure/postgres` (`postgresbackend.Dialect`, `Run`). A
   method on `*postgres.UserProvider` that enqueues into `tenant_commerce_outbox`
   would create `postgres → tenantcommerce → postgres`. The pair-write for
   postgres therefore lives in `tenantcommerce` (which imports the users store's
   upsert as an exported package function), not on the provider.
2. **Sqlite `ON CONFLICT(id) DO NOTHING` is targeted at the primary key only** —
   a re-import with a fresh random event ID would violate the
   `(tenant_id, idempotency_key)` unique index and ERROR, not no-op. The event
   ID must therefore be **deterministic** (like the auditoutbox facts, where
   ID = event ID), so a re-import conflicts on the primary key and no-ops.

## 2. Design overview

Per-row transaction on both backends: `BEGIN → upsert user → insert outbox row
→ COMMIT`, one table per backend so a single existing drain worker covers both
event classes:

```text
sso-ctl import --tenant <t> --dsn <d>
  │  openDB: ensure outbox schema (fail fast, no writes yet)
  ▼
writeBatch (per row, unchanged skip/accumulate accounting)
  │  event := newImportFact(tenant, user)        [importcmd policy]
  ▼
userStore.ImportUser(ctx, u, event)              [the seam — one atomic tx]
  ├─ sqlite : (*sqlite.UserProvider).ImportUser
  │            BEGIN → upsertUserTx → auditoutbox.InsertEventTx → COMMIT
  └─ postgres: importcmd.postgresUserStore adapter
               → tenantcommerce.ImportUserTx(ctx, p.DB(), u, event)
                 BEGIN → postgres.UpsertUserTx → insertOutboxEventTx → COMMIT
  ▼
audit_outbox (sqlite) / tenant_commerce_outbox (postgres)
  └─ drained by existing auditgovernance.Relay / ManagedRelayFactory
     over auditoutbox.SQLiteOutboxStore / tenantcommerce.Store — zero config change
```

`test/` (package `ssotest`) drives `sqlite.UserProvider.ImportUser` /
`tenantcommerce.ImportUserTx` directly — the exact functions the CLI calls —
so AC1-AC4 are testable without importing `cmd/`. AC5 proves the CLI wiring
in-package.

## 3. API changes

### 3.1 `infrastructure/auditoutbox/sqlite.go` (338 → ~360 lines)

- **`InsertEventTx(ctx context.Context, tx *sql.Tx, event *commerce.OutboxEvent) error`**
  — exported rename of the private `insertFactTx` (same body, same semantics:
  `Validate()` → `INSERT ... ON CONFLICT(id) DO NOTHING`; only real DB errors
  surface). `AppendInTx` delegates to it. The `FactFromAudit` login-failure
  gate is untouched; this is the generic in-tx append the spec anticipates.
- **`Migrate(ctx context.Context, db *sql.DB) error`** — runs the existing
  `auditoutbox` namespace migration on a caller-owned pool (same body as
  `NewSQLiteOutboxStoreWithDB`'s migration step). Needed because the CLI must
  not construct the shared-pool store: its `Close()` closes the shared `*sql.DB`
  owned by the user provider (footgun).

### 3.2 `infrastructure/defaultimpl/sqlite/users.go` (329 → ~390 lines, ≤500)

- Extract private `upsertUser(ctx, execer, u *sso.User) error` (execer =
  `interface{ ExecContext(...) }`) from `CreateOrUpdate`; both
  `CreateOrUpdate` (pool) and the new Tx method share it. Semantics identical:
  nil/empty-ID check, attribute JSON, `CreatedAt` preservation, `ON
  CONFLICT(id) DO UPDATE`, unique-violation → `sso.ErrUserExists`.
- **`CreateOrUpdateTx(ctx context.Context, tx *sql.Tx, u *sso.User) error`**
  (R1, spec-required Tx-scoped upsert).
- **`ImportUser(ctx context.Context, u *sso.User, event *commerce.OutboxEvent) error`**
  — the pair-write: `BeginTx` → `upsertUser(tx)` → `auditoutbox.InsertEventTx(tx,
  event)` → `Commit`; `defer Rollback`; every failure rolls back both rows.
  New imports: `domains/tenant/commerce`, `infrastructure/auditoutbox`
  (infrastructure→infrastructure, downward, no cycle; layer test unaffected).

### 3.3 `infrastructure/postgres/users.go` (280 → ~315 lines, ≤500)

- Extract private `upsertUser(ctx, execer, u *core.User) error` shared by
  `CreateOrUpdate` and the new exported package function.
- **`UpsertUserTx(ctx context.Context, tx *sql.Tx, u *core.User) error`**
  (exported package function — satisfies R1's Tx-scoped upsert for postgres).
  Exported because the pair-write lives in `tenantcommerce` (cycle constraint
  §1.1); precedent: the postgres package already exports `Run`/`Dialect` for
  sibling use. No method on `*postgres.UserProvider`.

### 3.4 `infrastructure/postgres/tenantcommerce/import.go` (new file, existing package, ~55 lines)

- **`ImportUserTx(ctx context.Context, db *sql.DB, u *core.User, event *commerce.OutboxEvent) error`**
  — `BeginTx` → `postgres.UpsertUserTx(tx, u)` → private `insertOutboxEventTx(tx,
  event)` (existing: bare `ON CONFLICT DO NOTHING` + `ensureOutboxFactTx`
  fact-equality → `commerce.ErrIdempotencyConflict` on a true conflict) →
  `Commit`. `tenantcommerce` already imports `infrastructure/postgres`, so no
  new edge, no cycle.

### 3.5 `cmd/sso-ctl/importcmd/importer.go` (~149 → ~200 lines)

- Seam widened:
  ```go
  type userStore interface {
      sso.UserProvider
      ImportUser(ctx context.Context, u *sso.User, event *commerce.OutboxEvent) error
      Close() error
  }
  ```
- `openDB`:
  - sqlite branch: after `sqlite.NewUserProvider`, call
    `auditoutbox.Migrate(ctx, p.DB())` (fail fast on fresh DBs; error closes
    provider).
  - postgres branch: after `postgres.NewUserProvider`, call
    `tenantcommerce.NewWithDB(p.DB(), dialect)` to ensure `tenant_commerce_outbox`
    (discard the store — it has no `Close`, no pool ownership issue); return a
    new local adapter:
    ```go
    type postgresUserStore struct{ *postgres.UserProvider }
    func (s postgresUserStore) ImportUser(ctx context.Context, u *sso.User, e *commerce.OutboxEvent) error {
        return tenantcommerce.ImportUserTx(ctx, s.DB(), u, e)
    }
    ```
- `runImport(ctx, p, tenantID, users, batchSize)` / `writeBatch` gain the
  tenant; per row: `event := newImportFact(tenantID, ssoUser)` then
  `p.ImportUser(ctx, ssoUser, event)`. Error handling unchanged: accumulate,
  skip-count, continue (R6).
- **`newImportFact(tenantID string, u *sso.User) *commerce.OutboxEvent`** —
  CLI policy, keeps providers generic:
  - `ID` and `IdempotencyKey`: deterministic `"import:" + tenantID + ":" + u.ID`
    (mandatory for sqlite no-op re-import, §1.2; gives the relay a stable
    dedupe identity, mirroring auditoutbox facts).
  - `Type`: new const `commerce.EventType("snaplink.audit.user.import")` in
    importcmd's consts area (bounded vocabulary, dotted convention).
  - `TenantID`: flag value; `AggregateType: "user"`, `AggregateID: u.ID`,
    `AggregateVersion: 1`; `Status: commerce.OutboxPending`;
    `OccurredAt`/`CreatedAt`: now.
  - `Payload`: `{"user_id": u.ID, "provider": u.Provider}` — bounded, redacted
    (never hash, format, email, attributes; envelope already carries the type,
    so the spec's "event type" payload item is deliberately omitted as
    redundant). `PayloadDigest`: sha256 of canonical `json.Marshal` (map keys
    sort — identical to `commerce.service.go:174` and `auditoutbox/fact.go:139`;
    a ~6-line local helper; no export added to commerce).

### 3.6 `cmd/sso-ctl/importcmd/main.go`

- New `--tenant` flag: required unless `--dry-run` (matches the `--dsn` rule);
  validation: non-empty, ≤128 chars, no control characters → error + usage +
  exit 2 (parseFlags style, main.go:121-153). `importFlags.tenant` added;
  `Run` passes it to `runImport`.
- Usage text (`usageFunc`) and package doc comment updated (R4).

## 4. Compatibility constraints

- **No SPI change**: `shared/core/spi.go` untouched; `interfaces/sso` untouched
  (60-file ceiling); Tx-scoped upserts are concrete-provider extensions
  surfaced through the importcmd-local seam.
- **Contracts consumed as-is**: `commerce.OutboxStore`/`OutboxEvent`,
  `auditgovernance.Relay`/`ManagedRelayFactory`, `memory_outbox.go`,
  `tenantcommerce` outbox machinery, `auditoutbox.FactFromAudit` gate — none
  modified. One new event-type VALUE (`snaplink.audit.user.import`) is added
  by the CLI; the relay is type-agnostic and the vocabulary is bounded.
- **No new `Err*`**: `commerce.ErrIdempotencyConflict` reused (postgres path).
  No endpoint → no `docs/openapi.yaml`; no server knob → no
  `docs/config-reference.md`; no audit event → no `auditreport` classification.
- **One behavior break, deliberate**: `--tenant` becomes required for writes.
  Existing scripts that call `sso-ctl import --dsn ...` now exit 2 until they
  pass `--tenant`. This is the spec's R4 (the users table has no tenant column
  and `Validate()` requires `TenantID`); a default would fake tenant
  attribution. `--dry-run` is exempt.
- **SQLite idempotency asymmetry (documented)**: the sqlite insert is
  `ON CONFLICT(id) DO NOTHING` with no fact-equality check (auditoutbox
  semantics preserved); the deterministic key makes same-fact re-import a
  no-op, and a changed-fact collision (payload spec change in a future CLI)
  silently keeps the old row. Postgres surfaces `ErrIdempotencyConflict` for
  that case via the existing `ensureOutboxFactTx`. Both meet every acceptance
  criterion; no sqlite behavior of the login-failure path changes.
- **Budgets**: sqlite users.go ~390, postgres users.go ~315, importer.go ~200,
  auditoutbox/sqlite.go ~360 — all ≤500. No new package; no `layerName()`
  classification needed; no exemption maps touched. `interfaces/sso` file
  count unchanged.

## 5. Failure modes

| Failure | Behavior | Recovery |
|---|---|---|
| Outbox schema missing (fresh DB) | `openDB` migration creates it before any write; failure → exit 1, nothing written | Rerun after fixing DSN/permissions |
| Fact insert fails after user upsert (validation, DB error) | Tx rollback undoes the user row — no orphan on either side (AC2) | Error is attributed to the row; batch continues |
| Crash mid-import | Per-row tx: committed pairs persist, the in-flight pair rolls back | Rerun the import; deterministic ID/key make it a no-op for already-imported users |
| Re-import same file | User rows upsert (today's behavior); 0 new events (sqlite PK conflict; postgres fact-equality no-op) | None needed |
| True idempotency conflict (postgres, changed payload spec across CLI versions) | `ErrIdempotencyConflict` → that user's pair rolls back, row skipped | Operator: `ListDeadOutbox`/`ReplayOutbox` tooling or delete the stale row; then re-import |
| Concurrent writer (server + CLI on same sqlite file) | Per-row tx keeps locks short; busy-timeout handling already established in the package | Retry the import run |
| Relay recipient rejects the new type | Relay quarantine + dead-letter path (existing) — no silent loss | Add recipient support or replay; events are durable |
| Missing `--tenant` | Exit 2 before opening the DB — zero writes | Fix invocation |
| DB down mid-import | Per-row begin/upsert errors accumulate; "imported N, skipped M" contract unchanged | Rerun |
| Rollback of the CLI change | Old binary doesn't enqueue; pending rows remain and drain; nothing to undo | — |

## 6. Migration steps

1. **Code**: land §3.1-3.6 (no users-table schema change, no server change).
2. **Verify**: §7 commands + `make ci`.
3. **Deploy** the new `sso-ctl` binary only. Next import run auto-creates
   `audit_outbox` (sqlite, `auditoutbox` namespace) or `tenant_commerce_outbox`
   (postgres, `tenant_commerce` namespace) — `CREATE TABLE IF NOT EXISTS`,
   forward-only; existing server deployments and their migrations untouched.
4. **Rollout note for operators**: add `--tenant` to import scripts (breaking
   flag, §4). Existing relay workers (e.g. `cmd/snaplink-billing`) drain the new
   rows with zero config; confirm the recipient endpoint tolerates the new
   event type (dead-letter/replay are the safety net if it rejects).
5. **Docs**: usage text + importcmd package doc (R4). No other contract docs.
6. **Rollback**: revert the binary; no cleanup required.

## 7. Testable acceptance mapping

| Acceptance | Where | Proof shape |
|---|---|---|
| AC1 — N users → exactly N events, atomic pairs, TenantID/AggregateID match | `test/importcmd_governance_outbox_test.go` (package `ssotest`) | Real file-backed sqlite via `sqlite.NewUserProvider`; drive `p.ImportUser` per row (the CLI's exact call); assert via `auditoutbox.NewSQLiteOutboxStore(dsn).Pending()` — N rows, IDs in the imported set, `TenantID` = flag value; pairing invariant (no user without event, no event without user) via fresh `CreateOrUpdate`-free reads + store count. Per-row tx interpretation pinned (whole-import single tx is a non-goal, §3 of the spec) |
| AC2 — failing row rolls back its pair | `test/` + `cmd/sso-ctl/importcmd/main_test.go` | Store level: an event failing `Validate()` (empty `TenantID`) after the upsert forces the rollback path; assert zero user row AND zero event row, and that preceding/following pairs persist. CLI level: extend `TestRunImport_SkipsBadRows` (main_test.go:418) — accounting still reports skipped, run continues |
| AC3 — drain via `auditgovernance.Relay` + managed lifecycle | `test/` | Mirror `startRelay` from `test/auditoutbox_governance_test.go:206-233`: `ManagedRelayFactory{Build: NewRelay(outbox, captureClient, ...)}` + `modules.New`/`Activate`; captureClient over the harness; poll for N deliveries; second `RunOnce` → 0 (no duplicates); rows leave `pending` |
| AC4 — `/token` oracle link (T-8 discipline) | `test/` | Reuse the harness's real-server construction on the same sqlite file; after the AC2-style partial import, `POST /token` with the skipped identity and with an unknown identity → byte-identical status + body (unknown-user dummy-hash path; AGENTS.md §3) |
| AC5 — CLI wiring | `cmd/sso-ctl/importcmd/main_test.go` (in-package) | `runImport` via `newTestProvider` (main_test.go:341) → one event per user in the same file's `audit_outbox`; re-import → 0 new events and `TestRunImport_PersistsAndUpserts` stays green; `--dry-run` → 0 events + 0 user rows; missing `--tenant` → exit 2; `--dry-run` without `--tenant` → success |

Plus unit tests: `infrastructure/defaultimpl/sqlite` — `ImportUserTx` commit /
rollback and `CreateOrUpdateTx` parity with `CreateOrUpdate` (R1 testable);
`infrastructure/postgres/tenantcommerce` — `ImportUserTx` (gated on a live
postgres, matching sibling tests' env pattern).

## 8. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/importcmd/... -run 'TestRunImport_|TestParseFlags' -v
go test ./infrastructure/defaultimpl/sqlite/ -run 'TestImport|TestCreateOrUpdate' -v
go test ./test/ -run TestImportGovernanceOutbox -v
go test ./... -race
make ci
```

## 9. Non-goals (unchanged from the spec)

No CLI-side audit chain / `auditreport` classification; no run IDs / resumable
runs / crash-replay markers; no relay worker inside the CLI process; no change
to per-row skip semantics or to `/token`/discovery/scope registry; no
`core.UserProvider` SPI change; no widening of `FactFromAudit`'s
login-failure-only gate; no `layerExemptions` entry.
