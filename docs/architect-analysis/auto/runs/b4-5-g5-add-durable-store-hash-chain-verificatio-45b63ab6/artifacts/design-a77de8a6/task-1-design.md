Design written to `docs/architect-analysis/auto/runs/b4-5-g5-add-durable-store-hash-chain-verificatio-45b63ab6/artifacts/design-a77de8a6/task-1-design.md` (doc-only stage; no `.go` edits, so no build gates triggered).

## Verification outcome — 8/8 evidence citations hold

Every claim was re-checked against the tree, not taken on faith:

- **Verified**: `auditverify` is file/URL-only today (flags 62-73, mutual exclusion 75-79, `VerifyChain` + exit 0/1 at 90-103); `auditexport` already does sqlite `--dsn` via `OpenReadOnly` + `VerifyExportBundle` ("v1 direct `--dsn` only"); sqlite `prev_hash`/`hash` columns with a never-migrate, schema-version-checked `OpenReadOnly`; `chainer.go` `VerifyChain`/`VerifyChainSegment`/`VerifyEventIntegrity`; `RecordTokenIssued` emits one row with no aggregation (pinned `Uncategorized` in `auditreport` drift/soc2 tests); memory default in `build_audit_secrets.go`.
- **Stale claim confirmed**: `importcmd` already ships `--backend postgres --dsn --dialect postgres|cockroach` — the flag-pattern precedent; the "no postgres" claim holds only for the audit toolbelt.
- **Material gap confirmed**: `postgres.AuditSink` has the hash-chain columns but `NewAuditSinkWithDB` migrates — no read-only constructor exists.
- **Trap confirmed empirically**: `NormalizedLimit` maps ≤0 → 100, >1000 → 1000 (`auditspi/query.go:86-92`); a paging loop without an explicit per-page `Limit` silently truncates to a chain **prefix**, which *verifies cleanly* — a false pass.
- **Bonus findings**: sqlite orders `ts_unix_ns DESC` with no tie-break (pg has `seq`), the resume-from-`LastHash` seam is real (`recorder.go:67-68`), and `sink.DB()` gives the tamper-test seam.

## Design summary

- **API**: `audit-verify --dsn <sqlite>` (mutually exclusive triple), `OpenReadOnly`, explicit per-page `Limit` + offset paging, `VerifyChain`, `token_issued events: N` L1 line in `--dsn` mode only (file/URL byte-identical); `audit-export --type token_issued` + `EventCount` pinned as the L1 surface, zero bundle changes; pg DSNs get an explicit "deferred" error (R-4's recommended default, with the follow-up seam spelled out).
- **Failure modes**: 8 rows (FM-1..FM-8) covering the clamp trap, schema mismatch, concurrent-write paging instability, WAL read-only locks, pg misdirection, mid-paging I/O, L1 parity drift, and tamper detection — each with a verification pin.
- **Migration**: additive flag, no schema/bundle/data migration, rollback = revert binary; pg branch documented as a future `OpenReadOnly` peer in `infrastructure/postgres` (root-module package, no module boundary).
- **Acceptance**: the four clauses map to the five named tests (`TestRun_DSN_CleanChainExitZero`, `_FlippedHashExitsOne`, `_ResumedChainAcrossRestart`, `_ExportVerifyParity`, `_TokenIssuedL1CountMatchesVolume`), all driven through real stores and the real `RecordTokenIssued` hook.
- **Pre-existing failure reported separately**: `TestArchitecture_DirectoryDepth`/`_DirectorySubdirFanout` fail on the pipeline's own `docs/architect-analysis/auto/**` artifact tree (root fan-out 24 > 21) — environmental, not caused by this work.
