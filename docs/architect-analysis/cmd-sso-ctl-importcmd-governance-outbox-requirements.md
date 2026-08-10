# Requirements Spec: import writes enqueue auth.user.import governance events in the same transaction as the user upsert

- Direction: "Import writes must enqueue auth.user.import governance events in the same transaction as the user upsert" (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-importcmd-347a57c8.json`, entry 1)
- Module: `cmd/sso-ctl/importcmd` (+ the store-level seam it calls: `infrastructure/defaultimpl/sqlite`, `infrastructure/postgres`, `infrastructure/auditoutbox`)
- Status: requirements (evidence-verified against HEAD)
- Values from direction: value 10, risk_reduction 9, effort 6, confidence 9

## 1. Evidence verification

Every citation in the direction was re-checked against the repository, plus the
files the direction's own acceptance implies. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/importcmd/importer.go` — `runImport`, `writeBatch`, `userStore` seam (only `sso.UserProvider` + `Close`) | `userStore` (importer.go:20-27) embeds `sso.UserProvider` + `Close` (`interfaces/sso/aliases.go:166` re-exports `core.UserProvider`, `shared/core/spi.go:42`). `runImport` (importer.go:82-113) batches and calls `writeBatch` (importer.go:115-137), which loops `p.CreateOrUpdate(ctx, ssoUser)` — per-row autocommit upserts, no transaction, no outbox row, no audit event. Errors accumulate; the doc comment states this is deliberate ("one bad row doesn't abort the batch"). `openDB` (importer.go:48-80) returns only `userStore` | Confirmed |
| `infrastructure/defaultimpl/sqlite/users.go:168` — `CreateOrUpdate`, no Tx surface | `CreateOrUpdate` is exactly at line 168; `INSERT ... ON CONFLICT(id) DO UPDATE SET ...` upsert; takes `ctx` only, no `*sql.Tx`. `DB() *sql.DB` accessor exists at users.go:131, so a Tx surface is feasible | Confirmed |
| `domains/tenant/commerce/store.go:366` — `OutboxStore` | `type OutboxStore interface` is exactly at line 366: `ClaimOutbox` / `CompleteOutbox` / `FailOutbox` / `QuarantineOutbox` / `ListDeadOutbox` / `ReplayOutbox`. `OutboxEvent` (store.go:74) with `Validate()` (store.go:103) requiring non-empty ID/TenantID/Type/AggregateID, AggregateType, `AggregateVersion != 0`, `IdempotencyKey`, `Status == pending`. Event vocabulary is dotted `snaplink.<domain>.<class>` (store.go:43-57; `infrastructure/auditoutbox/fact.go:31` uses `snaplink.audit.login_failure`) — the direction's literal `auth.user.import` name must be normalized to that convention | Confirmed |
| `infrastructure/auditgovernance/relay.go` — drain seam | `Relay` + `NewRelay(store commerce.OutboxStore, client Client, config RelayConfig)`; claim → deliver → complete, at-least-once; `RunOnce` is the per-batch call | Confirmed |
| `infrastructure/auditgovernance/managed_relay.go` — `ManagedRelayFactory` | `ManagedRelayFactory` (managed_relay.go:45) implements `modules.Factory`; `ManagedRelay` runners with Start/Ready/Quiesce/Stop lifecycle. Wiring precedent: `cmd/snaplink-billing/relay.go:127-129` builds `NewRelay` inside a `ManagedRelayFactory.Build` | Confirmed |
| `infrastructure/postgres/usageledger/outbox.go` — in-tx enqueue precedent | `insertOutboxEventTx` (usageledger/outbox.go:11): `event.Validate()` → `INSERT ... ON CONFLICT DO NOTHING` → `ensureOutboxFactTx` fact-equality check; conflict → `commerce.ErrIdempotencyConflict`. Runs inside `runLocked` (usageledger/store.go:168). `usage_ledger_outbox` DDL at usageledger/store.go:90-113 with `UNIQUE (tenant_id, idempotency_key)` | Confirmed |
| `infrastructure/postgres/tenantcommerce/outbox.go` — in-tx enqueue precedent | `insertOutboxEventsTx`/`insertOutboxEventTx` at tenantcommerce/outbox.go:53/60, same shape | Confirmed |
| `domains/tenant/commerce/memory_outbox.go` — idempotency machinery | `prepareOutboxLocked`/`validateOutboxIdentityLocked`/`sameOutboxFact`/`ErrIdempotencyConflict` all present | Confirmed |
| Acceptance claim: "not in the T-2/T-8(a-e)/T-9 test IDs" | `docs/campaigns/implementation-gate.md`: T-2 = discovery sweep (line 13), T-8(a) = `/token` claims (line 11), T-8(b)(c)(e) = endpoint hardening (line 14), T-8(d) = scope registry (line 12), T-9 = introspection 401 (line 14), G5 = T-2 + T-8(b-e) + T-9 (line 77). None reference `sso-ctl import` | Confirmed |
| Acceptance claim: "integration test in test/ (package ssotest)" | `test/` exists, package `ssotest`. `test/auditoutbox_governance_test.go` header states the split: "the CLI-side evidence ... lives in cmd/sso-ctl/auditexport/main_test.go (test/ cannot import cmd/)". The import flow must therefore be reachable from `test/` through a non-`cmd/` package (the store seam), with `cmd/`-side wiring proven in `cmd/sso-ctl/importcmd/main_test.go` (in-package) | Confirmed — shapes the test split below |

Decisive additional findings (not cited by the direction, binding on the design):

| Finding | Measured reality |
|---|---|
| `infrastructure/auditoutbox` is the sqlite in-tx connector precedent — but its gate blocks `user.import` | `SQLiteOutboxStore` (auditoutbox/sqlite.go) self-migrates `audit_outbox` DDL (namespace "auditoutbox") in the same sqlite file, implements `commerce.OutboxStore` (drainable by `NewRelay` unchanged), and has the in-caller-tx insert `AppendInTx` (sqlite.go:122) + private `insertFactTx` (sqlite.go:137, `ON CONFLICT(id) DO NOTHING`, unique `(tenant_id, idempotency_key)` index). BUT `FactFromAudit` (fact.go) is fail-closed to `login_failure` only — `AppendInTx` rejects every other class. The in-tx insert shape is reusable; the login-failure-only gate is not. The CLI's enqueue must be a new in-tx insert path (same table or a sibling), not `AppendInTx` |
| The `users` table has no tenant column | sqlite DDL (users.go:43-57), postgres DDL — no `tenant_id`. `OutboxEvent.Validate()` requires `TenantID`. The CLI needs a tenant identity source: a new required `--tenant` flag |
| `test/auditoutbox_governance_test.go` is the exact E2E template | Real server + sqlite + `WithTxAppender` + `ManagedRelayFactory` through `modules` manager + `captureClient` over httptest. The AC3 drain proof reuses this harness shape |
| Existing CLI test seam | `cmd/sso-ctl/importcmd/main_test.go:341` `newTestProvider` (real file-backed sqlite via `openDB`), `:378` `TestRunImport_PersistsAndUpserts` (persist + re-import upsert), `:407` `TestRunImport_SkipsBadRows` (bad row skipped, run continues) |
| Oracle-safety contract | AGENTS.md §3: unknown bcrypt user → cost-matched dummy hash; `/token` unknown-credential path must stay byte-identical for a partially-imported identity |
| Budgets | `infrastructure/defaultimpl/sqlite/users.go` 329 lines, `infrastructure/postgres/users.go` 280 lines, `cmd/sso-ctl/importcmd/importer.go` ~140 lines — all under the 500-line ceiling with room for the Tx surface. No new top-level package is required (extend existing ones); if one is created it must be classified in `layerName()` (`architecture_layer_test.go`) with no exemption |

Net verification result: the direction's factual core is fully confirmed — the
import path is invisible to the governance pipeline, and the in-tx outbox
pattern, `OutboxStore` contract, idempotency machinery, and relay/managed-relay
drain seams all exist unwired. The acceptance below preserves the supplied
checks verbatim in structure and re-anchors their testability to the verified
constraints: `test/` cannot import `cmd/` (the import flow is driven through
the store seam, exactly as the CLI calls it), the CLI needs a `--tenant`
identity (no tenant column, `Validate` requires it), the enqueue cannot reuse
`auditoutbox.AppendInTx` (login-failure-only gate), and the relay stays out of
the CLI process (drain is server/sidecar work; the harness proves it).

## 2. Goal and user outcome

A bulk user import through `sso-ctl import` becomes a governance-visible,
tenant-tied, attestable provisioning action: every imported user produces one
durable outbox event, committed in the same transaction as that user's upsert,
in the same database the server serves, drainable by the existing
`auditgovernance.Relay` / `ManagedRelayFactory` machinery unchanged.

Completion marker: importing N users yields exactly N outbox events whose
`AggregateID`s match the imported user IDs; a failing row rolls back its user
row and its event row together (no orphan on either side); the events drain
through the real relay machinery in the test harness; and `/token` behavior
for a partially-imported identity is byte-identical to an unknown user.

Maps to: the B4 governance-connector surface for the import CLI
(`docs/campaigns/implementation-gate.md` B4 row), with the T-8 discipline link
preserved as AC4 (a partially-imported user must never surface as a
distinguishable error at `/token`).

## 3. Scope

### In scope

1. A transaction-scoped user upsert on both backends (sqlite + postgres) so a
   user row and its outbox row commit atomically.
2. One idempotency-keyed `commerce.OutboxEvent` per imported user, written in
   the same transaction, following the verified in-tx patterns
   (`insertOutboxEventTx` postgres shape; `insertFactTx` sqlite shape).
3. Outbox DDL in the CLI's migration path (same DB/file as the users table)
   with the precedent column shape and the `(tenant_id, idempotency_key)`
   uniqueness that makes the insert idempotent.
4. A required `--tenant` flag on `sso-ctl import` (the events must be tied to a
   tenant; the users table has no tenant column).
5. The E2E evidence: store-seam tests in `test/` (package `ssotest`) proving
   count, atomic pair, rollback, and relay drain; CLI-wiring tests in
   `cmd/sso-ctl/importcmd/main_test.go` (only that package can import `cmd/`).
6. The `/token` oracle-safety assertion (AC4) as an E2E regression check.

### Explicit non-goals (must not be implemented in this change)

- Direction 2 (CLI-side audit chain, `auditreport` classification, audit
  schema migration in the CLI): out of scope; the outbox event is the
  governance surface here.
- Direction 3 (stable run IDs, resumable runs, crash-replay markers): out of
  scope. Only the idempotency the in-tx pattern itself demands is included
  (unique `(tenant_id, idempotency_key)` + fact-equality conflict check), so a
  re-import of the same file never double-emits.
- Running a relay worker inside the CLI process: the CLI only enqueues. The
  drain stays where relay workers live (server/sidecar); the harness proves
  drainability via `NewRelay`/`ManagedRelayFactory` in-process.
- Changing per-row skip semantics: a failing row still rolls back only its own
  pair and the batch continues ("imported N users, skipped M" accounting
  unchanged). A whole-import single transaction would change the documented
  behavior in importer.go:82-84 and is rejected.
- Any change to `/token`, discovery, scope registry, or the
  `core.UserProvider` interface itself (the Tx method is a concrete-provider
  extension surfaced through the importcmd seam, not a `shared/core` SPI
  change).

## 4. Requirements

### R1 — Transaction-scoped user upsert (both backends)

`infrastructure/defaultimpl/sqlite/users.go` and
`infrastructure/postgres/users.go` each gain a transaction-scoped upsert
(e.g. `CreateOrUpdateTx(ctx context.Context, tx *sql.Tx, u *sso.User) error`)
with the same validation, null handling, `CreatedAt` preservation, and
`ON CONFLICT(id)` semantics as the existing `CreateOrUpdate` (sqlite
users.go:168; postgres users.go:128). The `userStore` seam in importer.go is
widened with the Tx method (a local interface addition — `core.UserProvider`
in `shared/core/spi.go:42` is NOT modified).

Testable: a unit test opens a real sqlite DB, begins a tx, upserts via the Tx
method, rolls back, and asserts no row; commits and asserts the row.

### R2 — Per-user in-tx outbox enqueue

For every user a batch writes, exactly one `commerce.OutboxEvent` is inserted
in the same transaction as that user's upsert. Event contract (all fields
required by `OutboxEvent.Validate()`, store.go:103):

- `Type`: a new event-type constant following the verified dotted vocabulary
  `snaplink.<domain>.<class>` (store.go:43-57; `snaplink.audit.login_failure`
  precedent). The direction's `auth.user.import` label is the intent; the
  constant must be a single bounded vocabulary value declared in `consts.go`
  style, not a free-form string. Candidate: `snaplink.audit.user.import`.
- `TenantID`: the `--tenant` flag value (R4); validated non-empty.
- `AggregateType`: `"user"`; `AggregateID`: the imported user ID;
  `AggregateVersion`: `1`.
- `IdempotencyKey`: a stable composite of (tenant, user ID, event type) — it
  is mandatory (`Validate`) and is what makes a re-import a no-op.
- `Payload`: a bounded, redacted projection — user ID, provider/format tag,
  event type. Never the password hash, hash format, email, or any credential
  material (mirrors the `OutboxEvent` "must never contain credentials or PAN
  data" contract, store.go:73). `PayloadDigest` set from the payload.
- `Status`: `OutboxPending`; `OccurredAt`/`CreatedAt` = now.

Insert is idempotent per the verified precedents: `ON CONFLICT(id) DO NOTHING`
plus the unique `(tenant_id, idempotency_key)` index, and a fact-equality
conflict check in the `ensureOutboxFactTx` style (usageledger/outbox.go:27)
surfacing `commerce.ErrIdempotencyConflict` on a true conflict. A conflict on
a same-fact row is a no-op (re-import), not an error.

Testable: after the AC1 import, the outbox table has exactly N rows with the
imported IDs; re-importing the same file adds zero rows.

### R3 — Outbox DDL in the CLI's migration path, drainable by the standard seam

The CLI's migration path (sqlite: the `users` namespace migrations or the
auditoutbox namespace; postgres: the `users` migrations) creates the outbox
table in the same DB/file, with the precedent column shape and constraints
(`audit_outbox` DDL at auditoutbox/sqlite.go:40-62 for sqlite;
`usage_ledger_outbox` DDL at usageledger/store.go:90-113 for postgres). The
rows must be claimable/completable by a `commerce.OutboxStore` implementation
over the same pool — for sqlite this is `auditoutbox.SQLiteOutboxStore`
(already implements the full interface); for postgres an `OutboxStore`
implementation over the same DB. The CLI process never starts a relay; the
requirement is drainability, proven in-harness (AC3).

The enqueue must NOT reuse `auditoutbox.AppendInTx` (fact.go's gate is
fail-closed to `login_failure` only, by design); the new in-tx insert follows
the `insertFactTx` shape (sqlite.go:137) either as a new exported in-tx append
in `infrastructure/auditoutbox` or as the CLI-owned insert over the same table
columns — the design picks the smallest option that keeps one table per
backend so one drain worker covers both classes.

Testable: AC3's relay run claims and completes the import rows from the same
DB file the import wrote.

### R4 — `--tenant` flag (required)

`sso-ctl import` gains a required `--tenant` flag (no default; validated
non-empty; error + usage + exit 2 on missing/invalid, matching the existing
`parseFlags` validation style, main.go:122-153). `--dry-run` does not require
it (nothing is written). The flag is documented in the usage text and the
package doc comment. Tenant string passes through `auditgovernance.TenantSourceID`
validation only if the drain side demands it — the CLI itself validates
non-empty and bounded length.

Testable: `parseFlags` test — missing `--tenant` fails; `--dry-run` without it
succeeds; the value flows into every event's `TenantID` (AC1).

### R5 — `/token` oracle safety preserved (unchanged behavior, regression-pinned)

No code on the credential path changes. The E2E asserts that an identity whose
import row failed/skipped behaves at `/token` byte-identically to an unknown
user (cost-matched dummy bcrypt verification, same error class/body), per
AGENTS.md §3 and N2. This is a regression pin, not new server behavior.

### R6 — Batch accounting and dry-run unchanged

`runImport`/`writeBatch` keep their per-row attempt-all, accumulate-errors,
"imported N users, skipped M" contract (importer.go:82-113, main_test.go:378,
:407). A failing row rolls back only its own (user, event) pair; the batch and
run continue. `--dry-run` (runDryRun) still touches nothing.

### R7 — Engineering gates and contracts

- No new `Err*` exported (reuse `commerce.ErrIdempotencyConflict`); no
  endpoint → no `docs/openapi.yaml` change; no server config knob → no
  `docs/config-reference.md` change; CLI flag documented in usage/package doc.
- Budgets: both `users.go` files and `importer.go` stay ≤ 500 lines; no new
  top-level package; if the enqueue lives in `infrastructure/auditoutbox`,
  that package stays within its current bounds; `interfaces/sso` untouched
  (60-file ceiling).
- Verification per AGENTS.md §2: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`, then
  `go test ./... -race` and `make ci` before handoff.

## 5. Acceptance criteria

The direction's three acceptance checks, preserved in structure and made
testable. Split across two test homes because `test/` cannot import `cmd/`
(verified: `test/auditoutbox_governance_test.go` header; AGENTS.md "no package
imports `cmd/`"): the store-level import path lives in non-`cmd/` packages so
`test/` drives it directly — the exact function the CLI calls; `cmd/` tests
prove the CLI wires it.

### AC1 — N users → exactly N events, atomic pairs (test/, package ssotest)

Given a real file-backed sqlite DB (postgres variant where the harness has a
DB), importing N users through the store-level import path used by
`sso-ctl import` (R1+R2), then the outbox table contains exactly N rows; each
row's `AggregateID` is in the imported user-ID set; each row's `TenantID`
equals the `--tenant` value; and each (user row, event row) pair committed in
one transaction — the pairing invariant holds (no user without event, no
event without user).

Interpretation note (pinned, not relaxed): "committed in one transaction"
means each user row and its outbox row commit atomically in a single
transaction (the direction's problem statement: "in the same transaction as
the user upsert"). Per-row transaction semantics are preserved so a failing
row rolls back only its own pair — a whole-import single transaction would
change the documented skip behavior and is out of scope (§3).

### AC2 — failing row rolls back its pair (test/ + cmd/)

Given an import where a row fails mid-batch (e.g. invalid ID per the
`CreateOrUpdate` contract), that row's user row and its outbox row roll back
together: zero orphan users without an event and zero orphan events without a
user; all preceding and following good rows and their events persist. The
CLI-side accounting still reports the failure as skipped without aborting
(`cmd/sso-ctl/importcmd/main_test.go`, extending `TestRunImport_SkipsBadRows`
at main_test.go:407).

### AC3 — drain through `auditgovernance.Relay` reusing the managed relay lifecycle (test/)

Given the AC1 events in the outbox, running the standard relay machinery —
`auditgovernance.NewRelay` with a `captureClient`-style `Client` over
httptest, driven through `ManagedRelayFactory` + the `modules` manager exactly
as `test/auditoutbox_governance_test.go` does — delivers all N events once
(receipts accepted, `CompleteOutbox` recorded, events leave `pending`); a
second drain run delivers nothing new (no duplicates). This proves the events
are drainable by the existing seam unchanged, while the CLI itself never runs
a worker.

### AC4 — `/token` oracle link to T-8 discipline (test/)

After a partially failed import (AC2 scenario), authenticating with the
skipped identity at `/token` yields the byte-identical unknown-credential
response of an unknown user: cost-matched dummy bcrypt verification, same
error class/body — a partially-imported user must never surface as a
distinguishable error (AGENTS.md §3; N2). No new `/token` behavior is
introduced; this is the regression pin.

### AC5 — CLI wiring (cmd/sso-ctl/importcmd/main_test.go, in-package)

- `runImport` against a real sqlite DB (via `newTestProvider`, main_test.go:341)
  produces exactly one event per imported user in the outbox table of the same
  file (R2 wiring).
- Re-importing the same file produces zero new events (idempotent insert,
  R2) and upserts rows as today (`TestRunImport_PersistsAndUpserts` stays
  green).
- `--dry-run` produces zero events and zero user rows.
- Missing `--tenant` fails validation (exit 2); `--dry-run` without
  `--tenant` succeeds (R4).

## 6. Files

### Create

```text
docs/architect-analysis/cmd-sso-ctl-importcmd-governance-outbox-requirements.md — this spec
test/importcmd_governance_outbox_test.go — AC1-AC4 (package ssotest; mirrors test/auditoutbox_governance_test.go harness)
```

### Modify

```text
infrastructure/defaultimpl/sqlite/users.go — R1 Tx-scoped upsert (+ outbox DDL in the migration path if the sqlite table is added here); 329 → stays ≤ 500
infrastructure/postgres/users.go — R1 Tx-scoped upsert; 280 → stays ≤ 500
infrastructure/auditoutbox/sqlite.go — if chosen by design: exported generic in-tx append alongside insertFactTx; do NOT widen FactFromAudit's gate
cmd/sso-ctl/importcmd/importer.go — seam widened with the Tx method; runImport/writeBatch call the Tx path (R1/R2/R6)
cmd/sso-ctl/importcmd/main.go — --tenant flag, validation, usage text (R4)
cmd/sso-ctl/importcmd/main_test.go — AC5 wiring tests, --tenant validation tests
```

### Do not modify

```text
shared/core/spi.go — core.UserProvider contract (R1 keeps the Tx method a concrete-provider extension)
domains/tenant/commerce/store.go — OutboxStore/OutboxEvent contracts (consumed as-is)
infrastructure/auditgovernance/relay.go, managed_relay.go — drain seam (consumed as-is)
infrastructure/auditoutbox/fact.go — the login-failure-only gate (fail-closed by design; out of scope to widen)
interfaces/sso — 60-file ceiling; untouched
```

Confirm file/function/directory/fan-out ceilings before implementation
(AGENTS.md §2); `architecture_layer_test.go` classification only if a new
package is created (none is planned).

## 7. Dependencies and compatibility

- New/changed SPI: none at `shared/core`; a Tx-scoped method on the two
  concrete `UserProvider` implementations, surfaced through the importcmd seam.
- New option: `--tenant` (required unless `--dry-run`); CLI usage + package
  doc only (no server config reference).
- Storage migration: outbox table DDL in the CLI's migration path for both
  backends (idempotent `CREATE TABLE IF NOT EXISTS`, forward-only per S5).
  Existing databases gain the table on next CLI run; the server's own
  migrations are untouched.
- Event type: one new bounded `snaplink.*` vocabulary constant (R2); no new
  `Err*`; `commerce.ErrIdempotencyConflict` reused for true conflicts.
- HTTP/proto compatibility: none (no endpoint changes; CLI only).
- Rollout/rollback: events appear only for imports run with the new CLI; a
  rolled-back CLI simply does not enqueue. Relay workers drain the new rows
  with zero config change (same table, same `OutboxStore` contract).

## 8. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/importcmd/... -run 'TestRunImport_|TestParseFlags' -v
go test ./test/ -run TestImportGovernanceOutbox -v   # AC1-AC4
go test ./... -race
make ci
```
