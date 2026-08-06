Requirements specification written to `docs/architect-analysis/auto/runs/b4-5-g5-add-durable-store-hash-chain-verificatio-45b63ab6/artifacts/requirements-10762e10/requirements.md` (doc-only artifact; no `.go` edits, so no build gates triggered).

## Verification outcome — 8/8 citations checked, 1 literal claim stale

| Citation | Verdict |
|---|---|
| `auditverify/main.go:58-73,90-103` (file/URL-only, no `--dsn`) | **Verified** — flags at 62-73, mutual exclusion 75-79, `VerifyChain` + exit 0/1 at 90-103 |
| `auditexport/main.go:11-15,167-176` (sqlite `--dsn` via `OpenReadOnly` + `VerifyExportBundle`) | **Verified** — "v1 supports the direct `--dsn` mode only" |
| `platform/audit/sqlite/sink.go` `prev_hash`/`hash` columns | **Verified** — plus `OpenReadOnly` never migrates, schema-version-checked |
| `platform/audit/chainer.go:157-200` `VerifyChain` | **Verified** — genesis-anchored; `VerifyChainSegment`/`VerifyEventIntegrity` peers |
| `recorder_events.go:19` `RecordTokenIssued`, no L1 aggregation | **Verified** — emits one `token_issued` row; soc2report buckets it `Uncategorized` |
| `build_audit_secrets.go:34-61` memory default stock backend | **Verified** — `case "", "memory":`; sqlite/postgres selectable |
| "no postgres source anywhere in the toolbelt" | **Stale (literal)** — `cmd/sso-ctl/importcmd` already ships `--backend postgres --dsn --dialect postgres\|cockroach`. The claim holds only for the audit toolbelt; importcmd is the flag-pattern precedent |
| Postgres audit sink | **Not cited, but material** — `infrastructure/postgres.AuditSink` exists with the same hash-chain columns, but `NewAuditSinkWithDB` **migrates**; there is no read-only no-migration constructor (the `OpenReadOnly` peer is absent) |

## Spec content

- **R-1..R-3 (required)**: `audit-verify --dsn <sqlite>` via `OpenReadOnly` (never migrates, never write-locks), offset paging with explicit per-page `Limit` (trap: `NormalizedLimit` defaults ≤0 to 100, caps at 1000), reverse → `VerifyChain`; L1 `token_issued` count printed in `--dsn` mode only (file/URL output byte-identical); `audit-export --type token_issued` + `EventCount` pinned as the L1 count surface — no bundle format change.
- **R-4 (conditional, per acceptance)**: postgres `--dsn` added following importcmd's vocabulary **or** explicitly documented as deferred — the acceptance's own branch; recommended default is documented deferral since the no-migration pg constructor is a new cross-package seam.
- **AC-1..AC-4**: the four supplied acceptance clauses preserved and made testable with named tests (`TestRun_DSN_CleanChainExitZero`, `_FlippedHashExitsOne`, `_ResumedChainAcrossRestart` (L0 restart attestation), `_ExportVerifyParity` (head-hash/EventCount parity with `VerifyExportBundle`), `_TokenIssuedL1CountMatchesVolume` driven through the real `RecordTokenIssued` hook with `newHandlerCtx`).
- **Scope exclusions**: no server-side changes, no soc2report/apiclient/vocabulary directions, no L1 digest storage, no bundle-format bump.
