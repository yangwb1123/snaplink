All claims verified. Here is the verification report.

## Verdict: exit-code semantics confirmed (with one correction to the design's evidence)

### Q1 — Exit 2: `usageErr`/dispatch remains the sole CLI-misuse path ✅

- Current code, independently grepped: `auditexport/main.go` has exactly two package-level `os.Exit` calls — `usageErr` at 287 (`os.Exit(2)`, called only from `dispatch`'s two misuse branches) and `errorf` at 293 (`os.Exit(1)`). The only other exit-2 is `flag.ExitOnError`'s internal parse-error path (pre-existing, unchanged).
- The design *deletes* `usageErr` and routes misuse as `dispatch → (2, err) → Run → return 2`, with `cmd/sso-ctl/main.go:72` (`os.Exit(run(args))`) already propagating `Run`'s return value as the process exit code. So "bogus outcome → exit 2 via dispatch" holds: `validateOutcome` runs at the top of `dispatch`, before any mode branch and before the store opens; it can never leak into `run()`'s exit-1 domain.
- Observable equivalence of the N-2 refactor checks out line-by-line: today `usageErr` prints `<prog>: <msg>` + banner + exit 2; the new `Run` prints `<prog>: <msg>` + banner when `code == 2` + returns 2. Runtime errors print message only, return 1 — identical to today's `errorf`. `dispatch`'s current `(int, error)` signature already returns nothing on misuse paths (`usageErr` never returns), so the refactor is minimal.
- Precise wording: `usageErr` the *function* is replaced; the exit-2 *class* (CLI misuse via dispatch) is preserved and remains the sole exit-2 path in the package (plus the pre-existing `flag.ExitOnError`).

### Q2 — Exit-1 routing in `run()` unchanged ✅

`run()` returns `(1, err)` for every failure (buildQuery at 137–140, store open, `BuildExportBundle`, `writeBundle`); `runVerify` returns `(1, err)` for read/parse/verify failures. The design only inserts advisory `warnUnknownType` after `buildQuery`, before store open — no error return, no re-mapping. `TestRun_OpenErrorExitsOne` (137) stays green.

### Q3 — Rule-6 contract docs ✅ (design's "no doc change" is correct, conditionally)

- Rule 6's mapping is `Err* → error-codes.md`, `endpoint → openapi.yaml`, `config knob → config-reference.md`. The design adds no `Err*` sentinel (plain `fmt.Errorf` message), no endpoint, no config knob — and `docs/error-codes.md:413–428` covers only auditexport **SDK** errors, explicitly non-wire. Nothing to add there.
- I searched all non-campaign docs (`error-codes.md`, `config-reference.md`, `observability.md`, `feature-matrix.md`, `deployment.md`, `DECISIONS.md`, `dr-framework.md`, `plugin-system.md`): **no doc outside code documents the audit-export CLI exit-code/flag contract** (`plugin-system.md`'s "audit-exporter tap" is module context; `config-reference.md:942–948` exit-code text belongs to the provisioner's `--one-shot`). The CLI contract lives in the package doc (`main.go:29–32`) and the flag help text — both of which R-4 updates. So §7.4's "no contract docs change" holds *provided R-4 is implemented as written* (it is, in §4.1).

### Correction to the design's evidence — N-1 is stale, not a live gap ⚠️

The design's decisive N-1 claim is **false in the current tree**: `EventRecoveryCodesRegenerated` (`event_types.go:254`) and `EventAdminRecoveryCodesReset` (`event_types.go:286`) **are** in `auditspi.KnownEventTypes` (172 entries; runtime check: both `true`). The design took the `conformance_test.go:161–171` "+2" comment at face value, but that comment predates commit `c4cc409b` (2026-07-02, "fix(audit): complete KnownEventTypes…"), which registered both types. The comment is now doubly stale — the test's own drift log reads `allKnownEventTypes=129 KnownEventTypes=172`, i.e. the +2 arithmetic describes neither list.

Impact on the design:
- **Exit codes unaffected** — `warnUnknownType` stays exit-0 advisory and `validateOutcome` exit-2 regardless. The warn-only stance (R-2) remains correct, but for the *right* reason: custom types are legal per `EventType`'s doc ("filter/UX aid ONLY", `event_types.go:227–232`) and the `warnUnknownAuditEventTypes` webhook precedent (`build_audit_webhook.go:130`), not because a strict check would hard-fail those two values.
- Must-fix before implementation: §2 N-1 (re-characterize as "no registry gap today"), the §6 failure-mode row "`--type` of a registry-gap type → spurious warning" (does not occur today; only hypothetical if the registry regresses), and §10's non-goal "no fix of the pre-existing `KnownEventTypes` gap" (premise is false).
- Worth flagging separately: the stale `conformance_test.go` comment is itself pre-existing doc drift (its `allKnownEventTypes` transcription list, 129 entries, also under-covers the 172-entry registry) — out of scope here, but it is the trap the design fell into.

Everything else re-verified exactly: exit-code doc at `main.go:29–32` (0/1/2), `buildQuery` unvalidated passthrough (183–194), `bindFlags` (116–131), tests at 88 / 110–135 / 137+ / 305 (banner asserts only `progName` + `--dsn`), closed outcome vocabulary (`auditspi/event.go:12–13`), token vocab lines 15/195–196, three `Record*Issued` emitters all `OutcomeSuccess`, `soc2report/pipeline_test.go:36` consumer, `captureQuiet`/`captureStderr` helpers reusable, and `auditspi` is stdlib-only (zero `github.com` imports — N-3 safe).

**Bottom line:** the three checks pass — exit 2 stays the sole misuse class via dispatch, `run()`'s exit-1 routing is untouched, and rule 6 is satisfied via R-4 (package doc + help text) since no repository doc owns the CLI exit-code contract. The design's N-1 section and its dependent rows (failure modes, non-goals) must be corrected before implementation, but that correction changes no exit-code behavior.
