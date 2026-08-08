Spec complete: `docs/architect-analysis/cmd-sso-ctl-importcmd-governance-outbox-requirements.md`.

## Verification summary

Every citation in the direction checked against HEAD — all confirmed:

| Citation | Result |
|---|---|
| `importer.go` runImport/writeBatch, `userStore` = `sso.UserProvider`+`Close` only | Confirmed (importer.go:20-27, 82-137; `sso.UserProvider` aliases `core.UserProvider`, aliases.go:166) |
| `sqlite/users.go:168` `CreateOrUpdate`, no Tx surface | Confirmed — exactly line 168, `ON CONFLICT(id)` upsert; `DB()` accessor at :131 makes a Tx surface feasible |
| `commerce/store.go:366` `OutboxStore` | Confirmed — exact line; `OutboxEvent.Validate()` requires TenantID + IdempotencyKey |
| `auditgovernance/relay.go` + `managed_relay.go` | Confirmed; wiring precedent `cmd/snaplink-billing/relay.go:127` |
| `usageledger/outbox.go`, `tenantcommerce/outbox.go`, `memory_outbox.go` | Confirmed — in-tx insert (`ON CONFLICT DO NOTHING` + fact-equality), `ErrIdempotencyConflict` |
| T-2/T-8(a-e)/T-9 don't touch the CLI | Confirmed — `docs/campaigns/implementation-gate.md:11-14,77` (claims, hardening, scope registry, discovery) |

**Three binding constraints discovered beyond the direction's citations:**
1. `test/` cannot import `cmd/` (verified in `test/auditoutbox_governance_test.go` header) — the acceptance's "integration test in test/" is only testable if the tx+enqueue lives in the store seam, with CLI wiring proven in-package. Spec re-anchored accordingly (AC1-AC4 in `test/`, AC5 in `importcmd/main_test.go`).
2. `users` has no tenant column but `OutboxEvent.Validate()` requires `TenantID` — the spec adds a required `--tenant` flag (R4).
3. `auditoutbox.AppendInTx` is fail-closed to `login_failure` only — the enqueue must follow the `insertFactTx` shape, not widen the fact gate (pinned in §6 "Do not modify").

The three acceptance checks are preserved in structure and made testable (AC1 atomic pairs — interpreted as per-row pair transactions, consistent with the second check and the documented skip semantics; AC2 rollback; AC3 managed-relay drain mirroring `test/auditoutbox_governance_test.go`), plus the T-8 oracle link (AC4). Scope is bounded: directions 2 and 3 from the analysis are explicitly non-goals.
