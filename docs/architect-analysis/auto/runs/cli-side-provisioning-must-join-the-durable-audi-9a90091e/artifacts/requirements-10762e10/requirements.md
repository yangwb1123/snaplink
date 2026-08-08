Spec complete: `docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-requirements.md`.

## Verification results (all six citations checked against HEAD)

| Citation | Verdict |
|---|---|
| `importer.go:48-80` openDB — no `audit_events` in CLI migration path | **Confirmed with nuance**: direction 1 has landed (outbox migration now present), but `grep -rln audit_events infrastructure/defaultimpl/` returns nothing — the claim's core holds |
| `platform/audit/sqlite/sink.go` + `maintenance.go` | **Confirmed**: `audit_events` schema (prev_hash/hash) via `migrate.Run(..., "audit", ...)` in `New`/`NewWithDB`; `LastHash` implements `ChainTip` |
| `platform/audit/chainer.go` — `WithHashChain`/`ChainTip` | **Confirmed**: `WithHashChain` (recorder.go:61-77) seeds the chainer from `sink.(ChainTip).LastHash` at construction; `GenesisHash`, `VerifyChain`; pinned by `chain_resume_test.go` |
| `infrastructure/postgres/audit_sink.go:24-58` | **Confirmed**: DDL at exactly 24-58; `NewAuditSinkWithDB` (:121) same "audit" namespace; `LastHash` (:252) |
| `control_areas.go` + `bucketing.go` | **Confirmed — stronger than cited**: three test-enforced registrations (const in `event_types*.go` → `KnownEventTypes` → `controlAreaDefs`) via `TestKnownEventTypesIsComplete`, `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`, `TestControlAreaDefs_NoEventTypeClaimedTwice` |
| `auditexport`/`auditverify` consumers | **Confirmed with constraint**: `auditexport` is sqlite-DSN-only (`OpenReadOnly`); postgres attestation must be proven in-harness (sink `Query` + `VerifyChain`) — encoded into AC1 |

## Key findings shaping the spec

- **Direction 1 is already in HEAD**: import events exist as `commerce.OutboxEvent`s (`snaplink.audit.user.import`) draining to a control-plane client — they can never reach `audit_events` (`auditoutbox.FactFromAudit` is fail-closed to `login_failure`). The only in-scope route is the CLI recording `audit.Event`s itself through the same recorder/chainer the server uses (server precedent: `build_audit_secrets.go:34-53` + `build_app_core.go:385`, same DSN → same-table chain continuity is real).
- **No import audit event type exists** in the vocabulary — a new bounded const is required with the three registrations.
- **Pool ownership**: both sinks' `Close` closes the shared `*sql.DB`; the CLI must never Close the sink (process-lifetime object).

The four supplied acceptance checks are preserved verbatim in structure and made testable (fresh-DB verify AC1, ChainTip resume AC2, CC6.3 classification AC3, one-event-per-user export AC4), with scope strictly bounded: re-import dedupe stays direction 3, outbox/relay machinery untouched, no server or consumer changes.
