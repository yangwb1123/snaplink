# Test plan: CLI-side provisioning joins the durable audit chain (AC1–AC4 consolidation)

- Consolidates the acceptance mapping of `cmd-sso-ctl-importcmd-audit-chain-design.md` §3.7 into one concrete, executable test plan covering every reviewer finding from the three adversarial reviews (event classification, database transaction, security engineer) of that design.
- Status: test plan (design deltas referenced here are recorded in the review artifacts under `docs/architect-analysis/auto/runs/cli-side-provisioning-must-join-the-durable-audi-9a90091e/`; each delta is named DB-1…EC-2 below and must land in the same commit as the tests that pin it).
- Every function named below was verified against HEAD `8598a26b`.

## 1. Test-home split (the constraint that shapes everything)

`test/` (package `ssotest`) cannot import `cmd/`. Each finding therefore has one canonical home:

| Home | What it proves | Why it lives there |
|---|---|---|
| `test/importcmd_audit_chain_test.go` (new, `ssotest`) | AC1/AC2 store-level proofs driving the EXACT package calls the CLI makes: `sqlitestores.NewUserProvider` → `auditoutbox.Migrate` → `auditsqlite.NewWithDB(p.DB())` → `audit.New(sink, audit.WithHashChain())` → `ImportUser` + `rec.Record`; postgres mirror via `postgresbackend.NewAuditSinkWithDB(p.DB(), dialect)` | Store seam lives outside `cmd/`; mirrors `importcmd_governance_outbox_test.go` (existing helpers `newImportDB` test/:84, `importUsers` :112) |
| `cmd/sso-ctl/importcmd/main_test.go` (extend) | CLI wiring: `openDB` CheckSchema gates, `Run` exit codes, recording-failure exit, behind-clock clamp, export→verify loop, mixed-chainless export refusal | These touch `cmd/` internals (package-private `importDB`, `now` hook, exit codes) |
| `platform/audit/auditsink/conformance_test.go` (extend) | SIEM conformance guard correction (EC-1) | Guard lives with the tables it guards |
| `platform/audit/auditreport/control_area_import_test.go` (new) | AC3 CC6.3 classification | Unit surface of `controlAreaDefs` |
| `protocols/compliance/soc2_test.go` (extend) | D-7 `changeManagementEventTypes` pin (EC-2) | Existing `newSOC2Fixture` (:19) already wires a `MemorySink` |
| `platform/audit/chain_resume_test.go` | F2 tip-error genesis | **Already pinned at HEAD** (`TestWithHashChain_TipErrorSeedsGenesis` :59) — cited, no new test |

The export→verify loop is legal inside `cmd/` because `cmd/sso-ctl/main.go:22-23` imports both subcommands. Postgres env-gating follows the existing convention: `SSO_TEST_POSTGRES_DSN` / `SSO_TEST_POSTGRES_DIALECT` (cmd main_test.go:783, `infrastructure/postgres/tenantcommerce/import_test.go:19`); CI sets both (`.github/workflows/ci.yml:111-116`), so env-gated tests are not dead code.

## 2. Consolidated acceptance matrix (AC1–AC4, reworked per reviewer corrections)

### AC1 — fresh import produces exactly N chained events of the new type

| Test | Assertions | Reviewer corrections applied |
|---|---|---|
| `TestImportAuditChain_FreshSQLite` (test/, file-backed DSN, own file) | N users via `ImportUser` + `Record`; `sink.Query(audit.Query{Type: auditspi.EventAdminUserImported, TenantID: tenant})` → newest-first → reverse → `audit.VerifyChain` nil; `events[0].PrevHash == audit.GenesisHash`; exactly N rows; every row `Type == EventAdminUserImported`, `TenantID == tenant`, `Outcome == OutcomeSuccess`; exactly ONE genesis in the table; `sink.LastHash()` == last event's `Hash` | Whole-table assertions are SAFE on sqlite (private file) — kept. LastHash assertion added (feeds AC2 anchor) |
| `TestImportAuditChain_Postgres` (test/, env-gated, NOT parallel-unsafe: unique tenant ID + own-row cleanup) | Pre-run anchor: `headHash, _ := sink.LastHash(ctx)` and `floor := SELECT MAX(ts_unix_ns) FROM audit_events` captured BEFORE constructing the recorder (construction seeds from `LastHash`); N imports via the postgres mirror; own rows = `Query({Type, TenantID, Since: floor})` → reverse → `audit.VerifyChainSegment(ownRows, headHash)` nil; `ownRows[0].PrevHash == headHash`; cleanup `DELETE FROM audit_events WHERE id IN (own row IDs)` — NEVER `TRUNCATE` (the `infrastructure/postgres` package tests TRUNCATE `audit_events` at audit_test.go:18 and may run concurrently on the shared DSN; whole-table genesis/row-count assertions are dropped for postgres — DB-4) | DB-4: segment-anchored, own-row-scoped; anchor is a VALUE so a TRUNCATE of the anchor row is harmless; residual interleave risk = the existing convention's accepted residual |
| `TestAuditChain_ExportVerifyLoop` (cmd/sso-ctl/importcmd/main_test.go) | CLI import into fresh sqlite file → `auditexport.Run([]string{"--dsn", dsn})` → bundle → `auditverify.Run([]string{"--from-file", bundle}) == 0`; bundle contains exactly N `admin_user_imported` events; bundle `BoundaryPrevHash == ""` (genesis); bundle `HeadHash` == last event's `Hash` | Unchanged from design; real tool path |

### AC2 — same-table ChainTip resume across the process boundary

| Test | Assertions | Corrections |
|---|---|---|
| `TestImportAuditChain_Resume` (test/) | After AC1: `head := sink.LastHash()`; simulate the seam with a FRESH recorder (`audit.New(sink, audit.WithHashChain())` — shape-identical to the server→CLI seam: the server's recorder is the same constructor over the same pool); import M NEW distinct IDs; first new event's `PrevHash == head`; sqlite: `VerifyChain` over ALL N+M nil and exactly ONE genesis in the table (own file → safe); postgres: own-segment only — `VerifyChainSegment(newOwnRows, head)` nil, `newOwnRows[0].PrevHash == head`, whole-table genesis/row-count assertions dropped (DB-4) | DB-4 applies; resume semantics unchanged |
| `TestAuditChain_BehindClockClampsToHead` (cmd main_test.go) — **new, pins SEC-1** | Seed the file with head events at T+1h (direct sink writes); set the package `now` hook back to T; import M users; assert: every persisted `ts_unix_ns > head ts`; `LastHash()` returns the LAST imported row's `Hash` (not the pre-run head — proves CLI rows sort AFTER the head, so a second CLI run cannot fork); `VerifyChainSegment(ownRows, preRunHeadHash)` nil; postgres variant env-gated with the same own-segment assertions | SEC-1 delta: `openDB` reads `SELECT MAX(ts_unix_ns)` (+1ns floor) at recorder construction; `newAuditEvent` clamps `Timestamp = max(now(), floor)`; add package `var now = time.Now` hook in `importcmd` for the test. Pins F6 corrected (cross-host clock skew) |

### AC3 — classification: CC6.3, no uncategorized drift, one vocabulary constant

| Test | Assertions |
|---|---|
| `TestImportEventsFileUnderCC63` (new, `platform/audit/auditreport/control_area_import_test.go`) | `BuildSOC2Report` over a bundle of N import events → CC6.3 `TotalEvents == N`, "Uncategorized" == 0; exactly one control-area claim for the type |
| `TestChangeManagement_ImportEventsCounted` (new, extend `protocols/compliance/soc2_test.go`) — **new, pins EC-2/D-7** | Seed `newSOC2Fixture`'s MemorySink with `EventAdminUserImported` events → `Generate` → change-management section lists them; absence of the type from `changeManagementEventTypes` fails this test (D-7's line is currently unreachable by existing tests — this closes that gap) |
| Existing gates (must stay green, no new tests): `TestKnownEventTypesIsComplete` (event_types_completeness_test.go:29), `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` + `TestControlAreaDefs_NoEventTypeClaimedTwice` + `TestBuildSOC2Report_HandlesEveryKnownEventType` (auditreport drift_test.go:90/103/148), `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` (auditsink conformance_test.go:159), `TestConformance_UnknownEventTypeFallsBackSafely` (:204, fallback safety already pinned) | |
| `TestKnownEventTypesIsComplete` (existing) | The one-const vocabulary is compile+AST enforced; no per-format variants possible in `event_types*.go` |

### AC4 — event set + metadata fidelity, skips record nothing

| Test | Assertions |
|---|---|
| `TestAuditChain_ExportVerifyLoop` (cmd, AC1 real-tool row, shared) | Bundle `Metadata["target_user"]` set == imported ID set; `Metadata["provider"]` ⊆ closed vocabulary `auth0\|keycloak\|okta\|csv`; no other metadata keys; `Event.Provider` empty on every row (D-3); `auditverify --from-file` exits 0; re-export byte-stable for the event set | 
| `TestImportAuditChain_SkippedRowRecordsNothing` (cmd main_test.go) | Same failing-row trigger as direction-1 skip tests (main_test.go:556 `TestRunImport_SkipsBadRows`); zero `admin_user_imported` events for the skipped identity; successful rows still recorded; user/outbox pair semantics unchanged |

## 3. Reviewer findings → pinning tests

| # | Finding (source) | Design delta | Pinning test | Fails at HEAD? |
|---|---|---|---|---|
| DB-1a | "Newer schema → fail fast" (F1/§3.3) is FALSE as wired: `migrate.Run`/`postgres.Run` silently no-op when the DB is ahead; no `CheckSchema` in the CLI path (database reviewer correction 1a) | `openDB` calls `migrate.CheckSchema(ctx, db, "audit", auditsqlite.AuditMaxVersion())` (sqlite) and `postgresbackend.CheckSchema(ctx, db, "audit", postgresbackend.AuditMaxVersion())` after the outbox migration; new additive `AuditMaxVersion()` accessor in `infrastructure/postgres` (mirrors `AuthCodesMaxVersion`, auth_code.go:336). Note in code: this is STRICTER than the server's own postgres boot, which deliberately skips the gate | `TestOpenDB_AuditSchemaAheadFailsFast` (cmd main_test.go; sqlite always, postgres env-gated): stamp `schema_migrations_audit` at `MaxVersion+1` (`INSERT INTO schema_migrations_audit (version, name, applied_at) VALUES (max+1, 'future', ...)`) → `openDB` returns error, provider closed, no user rows; restore row → `openDB` succeeds. Trivial unit test for `postgresbackend.AuditMaxVersion()` in `infrastructure/postgres` (mirror `TestOAuthStores_MigrateIdempotentAndMaxVersions`, oauth_store_test.go:48) | Yes — no gate exists |
| DB-1b | F7 understates the hazard: sqlite single-writer does NOT prevent a chain fork (tip read once at construction; per-row INSERTs; server write between open and first Record forks the table) (database reviewer correction 1b) | F7 reframed as chain-fork hazard: imports must run with the server's audit writer quiesced, or accept a seam break with segment verification; live-file runs require the DSN `_pragma=busy_timeout(...)` (modernc ignores mattn-style `_busy_timeout`; migrate.go:107-108) | **No deterministic pin** — flagged in §4. Nearest pin: `TestAuditChain_BehindClockClampsToHead` (same ordering hazard from the clock side) | n/a |
| DB-2 | Crash between pair-commit and `Record` = silent gap (no chain row, no stderr); re-run duplicates already-recorded chain rows; FM table has no row tying this together (database reviewer Q2/Q3) | New FM row: "crash after pair commit, before Record → user un-attested; re-run attests but duplicates already-recorded rows; no checkpoint/resume marker exists (whole-file re-run); attestation is EVENTUAL — the crash window is real and silent" | `TestImportAuditChain_CrashWindowSilentGap` (cmd): run import with a failing sink → users + outbox pair committed, zero chain rows, `audit-verify` over the resulting bundle still exits 0 (verify detects breaks, not omissions — the exact silence the exit-code delta closes); then re-run with the working recorder → chain rows appear. `TestImportAuditChain_CrashRerunAppendsDuplicates` (cmd or test/): import N users twice → users still N (upsert), outbox still N (dedupe), chain rows == 2N, `VerifyChain` nil (continuity preserved) — the documented duplicate consequence | Yes — no FM row, no test |
| DB-3 | Whole-table postgres assertions race the shared-DSN TRUNCATE convention (database reviewer Q4) | AC1-postgres/AC2 reworked to segment-anchored, own-row-scoped assertions; cleanup by own-row ID delete (see §2) | AC1/AC2 postgres rows above | Yes — design's §3.7 as written would false-fail in CI |
| SEC-1 | Cross-host clock skew: behind-clock CLI rows sort before the server head → false tamper alarm + fork on second run; `lastTS` bump is intra-process only (security finding 1) | ts clamp `max(now, durable max ts + 1ns)` at construction (§2 AC2 row) | `TestAuditChain_BehindClockClampsToHead` + postgres variant | Yes — no clamp exists |
| SEC-2 | Mixed chainless boundary fails at EXPORT time, not verify time: `BuildExportBundle` self-verifies (`VerifyChainSegment`, auditexport.go:141-142,164) and exits 1 without a bundle on empty-hash rows; segment verify of genesis-anchored rows needs a `--since` window (bundle-embedded `BoundaryPrevHash == ""` works; `--anchor-hash ""` is rejected as misuse, auditverify main.go:108-113,190); chainless→chained is a one-way transition (security finding 2) | F4 corrected: export refuses before any bundle; chainless→chained documented one-way (enable `cfg.Audit.HashChain` on the server FIRST); §3.6 step 4 reworded | `TestAuditChain_ChainlessBoundary_ExportRefuses` (cmd): sqlite file with one empty-hash row + CLI-imported chained rows → `auditexport.Run` full export returns 1, no bundle file on disk. `TestAuditChain_ChainlessBoundary_SegmentWindow` (cmd): `auditexport --since <window covering exactly the CLI rows>` succeeds → bundle `BoundaryPrevHash == ""` → `auditverify --from-file` exits 0; `auditverify --anchor-hash ""` exits 2 (misuse) | Yes — no test |
| SEC-3 | F3 omission is silent to automation: `Run` returns 0 when recording fails; a zero-events run is byte-identical in exit status to a fully attested one (security finding 3) | Recording-failure counter in `importDB` (error-handler closure increments it); `runImport`/`Run` exit non-zero (and print a distinct failure summary) when any recording failed; fail-open on the user write preserved | `TestRunImport_RecordingFailureExitsNonZero` (cmd): failing-sink wrapper (`Record` returns error) → `runImport` returns error; stderr contains "audit record failed" + the distinct summary; users + outbox pair STILL committed; `Run` returns 1 | Yes — exits 0 today |
| SEC-4 | D-3 "never the email" invariant is false: `deriveID` falls back to `provider+":"+email` (parsers.go:367-378); CEF/OCSF replay exports metadata verbatim (cef.go:272-289, ocsf.go:140-160) (security finding 4) | D-3 wording corrected: "never the password hash, hash format, or attribute material; `target_user` may be email-derived and is exported verbatim on replay (server precedent: `recordAdminMeta` already exports raw target IDs)". Decision: keep raw (alignment with server precedent; hashing would cost correlation); redactor asymmetry documented (CLI recorder wires none — no-op for CLI events anyway) | AC4 metadata assertions pin the raw content. **No new test** — flagged in §4 (a flip to hashing would require `TestAuditChain_TargetUserHashed`) | n/a (doc fix) |
| SEC-5 | All-fail/all-skip run leaves no chain evidence at all; batch-summary event considered (security finding 5) | Open decision: either add one batch-summary event (same type, `OutcomeFailure` when any row failed) or document the omission class. The SEC-3 exit-code delta already closes the silence | **No pin yet** — flagged in §4; if adopted, `TestImportAuditChain_AllFailRunEmitsBatchSummary` | n/a |
| EC-1 | SIEM guard is rotten: soft `len(allKnownEventTypes) != len(KnownEventTypes)+2` Logf cannot fail; 129 vs 173 at HEAD (44 SDK consts untranscribed, riding the silent generic fallback); "+2" comment's premise is inverted (both recovery-code consts ARE in `KnownEventTypes` now) (event classification finding 4) | Guard corrected in the same commit: hard set-membership invariant — every `auditspi.KnownEventTypes` key must be present in `allKnownEventTypes` (runtime-enforceable without reflection) OR the snapshot is completed and the guard restored as a hard equality with the corrected comment. Scope correction to design §3.1: the "3 lines" transcription claim is wrong once the guard is honest — the change must also transcribe the 44 existing SDK-emitted types into `cefEventNames`/`ocsfEventActivities` (or move them to an explicit, documented `wantFallbackEventTypes` exclusion list following the auditreport "test names the gap" pattern, drift_test.go:28) | `TestConformance_EveryKnownEventTypeIsTranscribed` (auditsink, new): hard-fails on any `KnownEventTypes` key absent from `allKnownEventTypes`; the stale Logf is deleted. The new type's own transcription is covered by the per-type subtests of the existing `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` | **Yes — fails at HEAD with the 44-type bypass** (this is the correction's proof) |
| EC-2 | `changeManagementEventTypes` is unreachable by existing tests (D-7) (event classification finding 5) | No delta — line is additive; pin it | `TestChangeManagement_ImportEventsCounted` (§2 AC3) | Yes — no test |

## 4. Flagged: FM-table rows and design deltas WITHOUT a pinning test

Every row of the design's §3.5 FM table and every reviewer delta is listed; rows without an automated pin are called out explicitly:

| Item | Pinned by | Pin status |
|---|---|---|
| F1 migration fail-fast | `TestOpenDB_AuditSchemaAheadFailsFast` (DB-1a) + existing `TestOpenDB_BadDSN` (main_test.go:382) + `TestOpenDB_MigratesAuditSchema` (design R1 row: fresh sqlite `audit_events` exists + `schema_migrations_audit` current == `MaxVersion`; re-open idempotent) | ✅ |
| F2 tip-error genesis | `TestWithHashChain_TipErrorSeedsGenesis` — **already at HEAD** (chain_resume_test.go:59) | ✅ (existing) |
| F3 recording failure | `TestRunImport_RecordingFailureExitsNonZero` (SEC-3) + `TestImportAuditChain_CrashWindowSilentGap` (DB-2) | ✅ (new) |
| F4 chainless boundary | `TestAuditChain_ChainlessBoundary_ExportRefuses` + `_SegmentWindow` (SEC-2); note the row's wording itself is corrected (export-time refusal, not verify-time report) | ✅ (new) |
| F5 skipped rows | `TestImportAuditChain_SkippedRowRecordsNothing` (AC4) | ✅ (new) |
| F6 clock step-back | `TestAuditChain_BehindClockClampsToHead` (SEC-1) — the delta CHANGES this row from "pre-existing, not worsened" to "clamped at construction" | ✅ (new) |
| F7 concurrent server+CLI on one file | **⚠️ NO deterministic pin.** The fork hazard (tip-read + INSERT not atomic across processes) is pre-existing sink behavior; a deterministic race test would be flaky-by-design. Covered by: the reframed operational constraint (quiesce the server's audit writer; `_pragma=busy_timeout` in the DSN for live-file runs) documented in F7's rewritten text, plus the nearest behavioral pin `TestAuditChain_BehindClockClampsToHead`. Flagged: constraint-only, no automated enforcement | ⚠️ flagged |
| F8 `--dry-run` | Existing `TestRun_DryRun`/`TestRun_DryRunWithoutTenantTouchesNothing` (main_test.go:626/646) + design's `TestDryRun_NoAuditRows` (assert zero rows in `audit_events` after dry-run; dry-run opens no DB) | ✅ |
| F9 sink never Closed | **⚠️ NO pin — structural invariant.** `importDB` exposes no sink `Close` path and `*importDB` embeds `userStore` only; a regression would require someone to add sink teardown. A behavioral test is meaningless (each `openDB` builds a fresh sink on its own pool). Flagged: compile/structure-only, enforced by the bundle shape (D-4) | ⚠️ flagged |
| NEW FM row: crash window (pair commit → `Record`) | `TestImportAuditChain_CrashWindowSilentGap` + `TestImportAuditChain_CrashRerunAppendsDuplicates` (DB-2) | ✅ (new) |
| SEC-4 D-3 wording | Doc-only correction; the testable surface (raw vs hashed `target_user`) is pinned by AC4's metadata assertions. **Flagged**: if the raw-vs-hashed decision ever flips, add `TestAuditChain_TargetUserHashed` | ⚠️ flagged (decision-dependent) |
| SEC-5 batch-summary event | **Flagged: open decision, no pin.** If adopted, needs `TestImportAuditChain_AllFailRunEmitsBatchSummary` (all-fail run → exactly one `OutcomeFailure` event) plus a conformance-table entry for the same type; if rejected, the SEC-3 exit-code test closes the silence and the FM crash row documents the omission class | ⚠️ flagged |
| DB-1b F7 quiesce/busy_timeout constraints | Doc-only (see F7 row above); the DSN-pragma dependency is asserted in the rewritten F7 text and the CLI usage note | ⚠️ flagged |
| D-7 `changeManagementEventTypes` line | `TestChangeManagement_ImportEventsCounted` (EC-2) — closes the "unreachable by existing tests" gap | ✅ (new) |
| Design §3.1 "3 lines" SIEM claim | Corrected by EC-1: the guard fix forces either the 44-type transcription or an explicit exclusion list; `TestConformance_EveryKnownEventTypeIsTranscribed` pins whichever is chosen | ✅ (new) |

## 5. Implementation order and gates

1. Same commit as the code: registrations (§3.1 of the design, incl. the corrected SIEM tables), `importDB` + recorder wiring, CheckSchema gates + `postgresbackend.AuditMaxVersion()`, ts-clamp + `now` hook, recording-failure counter, F4/F7/FM-table doc corrections.
2. Tests land beside the code per §2–§3 homes.
3. Verification commands:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./platform/audit/auditspi/ ./platform/audit/auditreport/ ./platform/audit/auditsink/ \
  -run 'TestKnownEventTypesIsComplete|TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized|TestControlAreaDefs_NoEventTypeClaimedTwice|TestBuildSOC2Report_HandlesEveryKnownEventType|TestConformance_EveryEventTypeHasCEFAndOCSFMapping|TestConformance_EveryKnownEventTypeIsTranscribed|TestImportEventsFileUnderCC63' -v
go test ./protocols/compliance/ -run 'TestChangeManagement_ImportEventsCounted' -v
go test ./cmd/sso-ctl/importcmd/... -run 'TestOpenDB|TestRunImport|TestAuditChain|TestDryRun' -v
go test ./test/ -run TestImportAuditChain -v          # AC1/AC2 + postgres env-gated
go test ./infrastructure/postgres/ -run 'TestAuditMaxVersion' -v
go test ./... -race
make ci
```

Note: `TestConformance_EveryKnownEventTypeIsTranscribed` is expected to FAIL at HEAD (the 44-type bypass is the proof the guard was rotten); it passes only after the EC-1 correction lands in the same commit.
