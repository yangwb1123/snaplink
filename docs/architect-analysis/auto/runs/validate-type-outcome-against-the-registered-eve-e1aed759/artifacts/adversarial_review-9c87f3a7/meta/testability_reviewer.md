The design artifact is updated and internally consistent. Here is the validation summary:

## Validation verdict

**Q1 — The Run refactor genuinely resolves the unsatisfiable AC-1 in-process claim: CONFIRMED.**

Verified against the actual code, not the design's claims:
- `os.Exit` inventory at HEAD: only `usageErr` (line 287, `os.Exit(2)`, called from `dispatch` at 106/111) and `errorf` (line 293, `os.Exit(1)`, called from `Run` at 94). Deleting both makes `Run`'s return value the exit code on every testable path.
- `--outcome bogus` is a bad flag **value**, not flag syntax — `flag.ExitOnError` (the one remaining `os.Exit`) is never reached by the planned tests.
- Process-level equivalence holds: the only non-test caller is `cmd/sso-ctl/main.go:48,72` (`os.Exit(run(args))`), so the in-process `code == 2` assertion IS the process exit code. `soc2report/pipeline_test.go:36` (external `Run` consumer, expects 0) is unaffected.
- Test infrastructure already exists: `captureStderr(t, func())` with a code-capturing closure is the package's own pattern; no `t.Parallel` (no `usageFlags` global race). Baseline `go test ./cmd/sso-ctl/auditexport/ ./cmd/sso-ctl/soc2report/` re-run green.

**Q2 — Failure-table and no-warning mapping: CONFIRMED after amendments** (the plan as originally written had 3 untested rows, all now closed):
- Added: `TestRun_UnknownOutcomeVerifyModeExitsTwo` (pins row 2 via a nonexistent bundle path — exit 2 not 1 proves validation precedes the mode branch), `TestRun_MissingDSNExitsTwo` (pins row 9, which the refactor rewrites), both-bogus short-circuit folded into AC-1a (asserts no type warning; pins row 7).
- No-warning assertions are deterministic: `logout` (AC-2) and `token_issued` (AC-3) are both compile-time-registered in `KnownEventTypes`; `TestRun_TenantAndTypeFilter` needs only `captureQuiet` → `captureStderr`.
- AC-1a strengthened: seed a real store so a validate-after-open regression yields exit 0 + bundle and fails the test; assert the distinctive `not a valid outcome` line (the banner also contains `success|failure` after the help-text change, so substring-only assertions would be weaker).

**One stale finding corrected (matters for implementability):** the design's N-1 ("registry gap → spurious warning for `mfa_recovery_codes_regenerated` / `admin_recovery_codes_reset`") is **false at HEAD** — both types are in `KnownEventTypes` (`event_types.go:254,286`, added 2026-07-02/03). The conformance test's "+2" comment is stale in the opposite direction (real counts 129 vs 172, `t.Logf` only). That failure-table row is now untestable-by-construction and is demoted to a documented hypothetical; R-2's warn-only stance still holds on the documented custom-type contract + webhook precedent.

**Minor drifts fixed:** `seedStore` has 8 call sites (not 7); `usageErrorf` must not embed the `progName` prefix or `Run`'s print would double it (observable-equivalence detail).

The updated design is at the pipeline-expected path: `docs/architect-analysis/auto/runs/validate-type-outcome-against-the-registered-eve-4a69096f/artifacts/design-a77de8a6/task-1-design.md`. No `.go` files were touched, so no build gates apply; the change is doc-only.
