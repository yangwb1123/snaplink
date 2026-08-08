Consolidated test plan written: `docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-test-plan.md` (112 lines, superseding design §3.7). Every named function/line was verified against HEAD `8598a26b` before being cited.

## What the plan covers

**Test-home split (§1)** — the constraint map: store-level proofs in `test/importcmd_audit_chain_test.go` (ssotest, driving the exact package calls the CLI makes), CLI wiring in `cmd/sso-ctl/importcmd/main_test.go` (legal export→verify loop via `main.go:22-23`), SIEM guard in `auditsink`, CC6.3 in a new `auditreport` unit test, D-7 pinned via the existing `newSOC2Fixture` (soc2_test.go:19), F2 already pinned at HEAD (`TestWithHashChain_TipErrorSeedsGenesis`).

**Reviewer findings → tests (§2–3), each with fail-at-HEAD status:**

| Finding | Pinning test |
|---|---|
| Behind-clock ts clamp (SEC-1) | `TestAuditChain_BehindClockClampsToHead` — `now` hook + `MAX(ts_unix_ns)` floor, asserts no fork on second run, both backends |
| Crash-window silent gap + duplicate-on-rerun (DB-2) | `TestImportAuditChain_CrashWindowSilentGap` (verify exits 0 over an omission — the exact silence) + `TestImportAuditChain_CrashRerunAppendsDuplicates` (2N chain rows, N users/outbox, chain still continuous) |
| Shared-DSN TRUNCATE safety (DB-3) | AC1/AC2 postgres reworked: pre-run `LastHash` anchor + `MAX(ts)` floor → `VerifyChainSegment` over own rows only, cleanup by own-row ID delete, whole-table genesis/count assertions dropped |
| CheckSchema fail-fast (DB-1a) | `TestOpenDB_AuditSchemaAheadFailsFast` (version row stamped at MaxVersion+1) + new `postgresbackend.AuditMaxVersion()` accessor with its own unit test |
| Recording-failure exit (SEC-3) | `TestRunImport_RecordingFailureExitsNonZero` — failing-sink wrapper; users/outbox still committed, `Run` returns 1 |
| SIEM guard correction (EC-1) | `TestConformance_EveryKnownEventTypeIsTranscribed` — hard set-membership invariant that **fails at HEAD with the 44-type bypass**, plus the scope correction that the design's "3 lines" claim is wrong once the guard is honest |
| Chainless boundary (SEC-2) | `TestAuditChain_ChainlessBoundary_ExportRefuses` (no bundle on disk) + `_SegmentWindow` (`--anchor-hash ""` → exit 2) |
| D-7 (EC-2) | `TestChangeManagement_ImportEventsCounted` |

**Flagged without pins (§4)** — F7 (fork hazard: deterministic test would be flaky-by-design; nearest pin is the clamp test, rest is documented quiesce/busy_timeout constraint), F9 (structural only: `importDB` exposes no sink-Close path), SEC-4 (D-3 wording is doc-only; raw-vs-hashed decision-dependent test named), SEC-5 (batch-summary event is an open decision with its test specified if adopted).
