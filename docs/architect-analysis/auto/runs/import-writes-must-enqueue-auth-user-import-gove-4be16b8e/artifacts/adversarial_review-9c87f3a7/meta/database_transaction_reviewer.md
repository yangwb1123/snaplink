All packages build clean. I have complete evidence. Here is the verification report.

---

# Verification: per-row atomicity claims (import → outbox governance)

**Headline finding: the implementation has NOT landed.** The pair-write symbols (`ImportUser`, `ImportUserTx`, `InsertEventTx`, `Migrate`, `UpsertUserTx`, `CreateOrUpdateTx`), the `--tenant` flag, `newImportFact`, and the AC1–AC5 tests do not exist anywhere in the repo (grep over all non-test `.go` files returns zero; `git log -S ImportUserTx` only matches the design docs). The campaign run `import-writes-must-enqueue-auth-user-import-gove-4be16b8e` has only requirements → design → adversarial_review artifacts; no `implement` artifact exists. What IS verifiable — every claim about the pre-existing machinery the design reuses — checks out, and the key sqlite idempotency trap is proven empirically.

## 1. PK vs `(tenant_id, idempotency_key)` unique-index behavior — VERIFIED + empirically proven

- `audit_outbox`: `id TEXT PRIMARY KEY` + `CREATE UNIQUE INDEX idx_audit_outbox_key ON audit_outbox(tenant_id, idempotency_key)` (sqlite.go:55–61); insert is `ON CONFLICT(id) DO NOTHING` (sqlite.go:148) — **PK-targeted only**, exactly as the design's §1.2 constraint states.
- `tenant_commerce_outbox`: `UNIQUE (tenant_id, idempotency_key)` (store.go:151), bare `ON CONFLICT DO NOTHING` (outbox.go:70). `usage_ledger_outbox`: same unique key (store.go:109), bare `ON CONFLICT DO NOTHING` (outbox.go:27).
- **Empirical proof** (modernc.org/sqlite v1.56, identical DDL + statement, executed against a real file):
  - Re-import with the SAME deterministic ID → `ON CONFLICT(id) DO NOTHING` → silent no-op, old row kept (row count 1) — **even with a changed payload**.
  - Re-import with a DIFFERENT ID but same `(tenant_id, idempotency_key)` → `constraint failed: UNIQUE constraint failed: audit_outbox.tenant_id, audit_outbox.idempotency_key (2067)` — an ERROR, not a no-op.
  
  This confirms both the design's trap (§1.2: random event ID on re-import would error) and the mandatory deterministic-ID derivation.

## 2. sqlite-silent-keep vs postgres-error asymmetry — VERIFIED

- Sqlite `insertFactTx` (auditoutbox/sqlite.go:137–165): `Validate()` → `ON CONFLICT(id) DO NOTHING`; **no fact-equality check**. Changed-fact collision with the deterministic ID → old row silently kept. Confirmed in code and empirically (case 2 above).
- Postgres `tenantcommerce.insertOutboxEventTx` (outbox.go:60–73): `ON CONFLICT DO NOTHING` → `RowsAffected()==0` → `ensureOutboxFactTx` (outbox.go:114–131): `FOR UPDATE` lookups by `id` and by `(tenant_id, idempotency_key)`; `sameOutboxFact` (7-field equality incl. `PayloadDigest`) mismatch or both-missing → `commerce.ErrIdempotencyConflict`. Same shape in `usageledger` (outbox.go:14–60).
- The documented asymmetry is real: sqlite changed-fact collision = silent keep (no error); postgres = `ErrIdempotencyConflict` (pair rolls back, row skipped).

## 3. Deterministic event-ID derivation — REQUIRED and PRECEDENTED; the new derivation is absent

- Precedent confirmed: `FactFromAudit` (fact.go:73–97) sets `ID = IdempotencyKey = audit event ID`, making re-append PK-idempotent — the design's "ID = event ID" rationale is exactly right.
- `newImportFact` with `"import:"+tenant+":"+userID` does not exist (no implementation).

## 4. Concurrent-writer semantics — VERIFIED at machinery level

- **Sqlite single-writer**: `PRAGMA busy_timeout=5000` applied process-wide to every connection via `RegisterConnectionHook` (busy_timeout.go:26–39); `beginImmediateRMW` (`BEGIN IMMEDIATE`, busy_timeout.go:42–55) is the established RMW pattern. Per-row transactions keep the write lock short. Caveat (pre-existing, not design-introduced): the existing sqlite `ClaimOutbox` uses a deferred `BeginTx` then read-then-write; the busy timeout is the mitigation.
- **Postgres**: drain claims run under `RunSerializable` (serializable + 40001 retry, tx.go:52–79) for tenantcommerce, `runLocked` (row-lock + 40001 retry, store.go:168–194) for usageledger, both with `FOR UPDATE SKIP LOCKED`. The design's "advisory/serialization" phrasing is accurate (advisory-style row locking + serializable retry).
- For the planned pair-write: sqlite insert-only tx serializes on the write lock with the 5s busy timeout; postgres `ON CONFLICT DO NOTHING` + `FOR UPDATE` checks are race-safe against a concurrent duplicate writer.

## 5. Crash-mid-import recovery — SOUND BY CONSTRUCTION, NOT IMPLEMENTED

Design-level claim only: per-row tx → committed pairs persist, in-flight pair rolls back; rerun no-ops via deterministic ID (sqlite PK conflict) / fact-equality (postgres). The machinery verified in §1–2 makes this sound, but there is no code or test to verify.

## 6. Relay workers drain both outbox classes — PARTIALLY TRUE; relay is unchanged and type-agnostic

- `auditgovernance.Relay` is **type-agnostic**: claims whatever the store returns, classifies delivery errors by HTTP status only (`classifyDeliveryError`, relay.go), no event-type filtering. A `snaplink.audit.user.import` row in `tenant_commerce_outbox` drains through the existing billing worker (`cmd/snaplink-billing/relay.go:68` `NewRelay`, :127 `ManagedRelayFactory`; "commerce" runner) with zero config — verified.
- **Ordering**: claims ordered `created_at_ns, id` (both sqlite and postgres stores) — per-batch creation order, no global ordering; no regression possible since the relay is untouched.
- **Dedup / at-least-once**: relay does no dedup (recipient dedupes via `idempotency_key`; a 409 → quarantine with `reasonConflict`); at-least-once by design (Publish → CompleteOutbox; crash between → lease expiry → redelivery). No regression possible.
- **Caveat**: for the sqlite `audit_outbox` table there is currently NO production drain worker in the repo — `auditoutbox` is consumed only by the `platform/audit/sqlite` TxAppender hook and tests; billing drains only the two postgres tables. The b4-5 "wire-the-module-as-the-b4-5-governance-connector" campaign is design-only. So "existing relay workers drain both classes" holds for postgres today; the sqlite drain worker is a sibling in-flight deliverable.

## 7. `ensureOutboxFactTx` idempotency-conflict reuse — VERIFIED

`tenantcommerce`'s private `insertOutboxEventTx` → `ensureOutboxFactTx` → `ErrIdempotencyConflict` on true conflict is exactly as claimed (outbox.go:60–131, cited line drift trivial: :53/:60/:70/:83/:107 — all confirmed). The planned `tenantcommerce.ImportUserTx` reuses it in-package (sound, no export needed). `memory_outbox.go` mirrors the same machinery (`prepareOutboxLocked` :13, `validateOutboxIdentityLocked` :36, `sameOutboxFact` :46).

## 8. Quarantined-recipient replay safety net — VERIFIED (API-level)

`QuarantineOutbox` / `ListDeadOutbox` (dead+quarantined) / `ReplayOutbox` (→ pending, attempts=0) exist on all four stores: SQLiteOutboxStore (sqlite.go:234/252), tenantcommerce, usageledger, MemoryOutboxStore. Relay test coverage pins quarantine classification (relay_test.go:92–100, 236). Caveat: no operator CLI consumes `ListDeadOutbox`/`ReplayOutbox` yet — the safety net is store-API-level, not a shipped tool surface.

## 9. Absent (unverifiable) — the entire new surface

| Claimed (design §3) | Status |
|---|---|
| `auditoutbox.InsertEventTx` / `Migrate` | absent; `insertFactTx` still private (sqlite.go:137) |
| `sqlite.CreateOrUpdateTx` / `ImportUser` | absent (users.go 329 lines, `CreateOrUpdate` :168, `DB()` :131 — all as cited) |
| `postgres.UpsertUserTx` | absent (users.go 280 lines); cycle constraint real: `tenantcommerce` imports `infrastructure/postgres` (store.go import block) |
| `tenantcommerce.ImportUserTx` (import.go) | absent; `NewWithDB` (store.go:240) available for the adapter |
| importcmd seam + `--tenant` + `newImportFact` | absent; `userStore` is still `UserProvider+Close` (importer.go:24), `runImport` :59, `writeBatch` :90 calls bare `CreateOrUpdate` |
| `test/importcmd_governance_outbox_test.go` (AC1–AC4) | absent; `startRelay` harness exists at test/auditoutbox_governance_test.go:202–233 (claimed 206–233, minor drift) |
| AC5 extensions (`TestRunImport_SkipsBadRows` :418, `newTestProvider` :341) | absent |

All verified packages build clean (`go build` exit 0).

## Conclusion

Every claim about pre-existing machinery is confirmed against HEAD, with the sqlite PK-vs-unique-index asymmetry proven by execution. But the deliverable this verification was asked to check — the per-row atomic pair-write on both backends — does not exist in the repository: no `ImportUser`/`ImportUserTx`/`InsertEventTx`/`UpsertUserTx`, no `--tenant`, no AC1–AC5 tests, no implement artifact. The atomicity, crash-recovery, and relay-drain behaviors are therefore **not verifiable as implemented**; they are verified only as sound design over confirmed machinery.

VERDICT: FAIL - the implementation is absent (no pair-write code, no `--tenant` wiring, no AC1-AC5 tests exist); every claim about the pre-existing outbox/relay machinery it reuses is verified at HEAD, and the sqlite PK-vs-unique-index asymmetry is empirically confirmed, but per-row atomicity itself is not implemented and cannot be verified.
