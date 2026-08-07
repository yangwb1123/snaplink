Design written to `docs/architect-analysis/auto/runs/validate-type-outcome-against-the-registered-eve-4a69096f/artifacts/design-a77de8a6/task-1-design.md` (the path `pipeline.yaml` expects for the design stage).

## Verification results (all claims independently re-checked)

**Confirmed exact:** `buildQuery` unvalidated passthrough (`main.go:183-194`), `bindFlags` at 116-131 with plain StringVars, `TestRun_EmptyWindowExitsZero` at 88, the range correction (`TestRun_TenantAndTypeFilter` at 110-135, not 139-157), token vocabulary at `event_types.go:15,195-196`, zero `auth.token.issue` in `.go` files, closed `success|failure` outcome vocabulary (`auditspi/event.go:9-13`), warn-only webhook precedent at `build_audit_webhook.go:130`, and the exit-2 routing constraint (`usageErr` is the only exit-2 path; `run()` maps to exit 1).

**Two corrections found:** the exit-code doc is at `main.go:29-32`, not 44-46 (substance exact); the requirements' AC-1 in-process test is unsatisfiable while `usageErr` calls `os.Exit(2)` — the design refactors `Run` into the single exit decision point, which is observationally identical because `cmd/sso-ctl/main.go:72` already does `os.Exit(run(args))`.

**Two new findings not in the evidence:**
- **N-1:** `KnownEventTypes` has a documented pre-existing gap — `EventAdminRecoveryCodesReset` and `EventRecoveryCodesRegenerated` are consts but not in the registry (`auditsink/conformance_test.go:161-171`). A strict exit-2 `--type` check would hard-fail legitimate exports; this independently confirms R-2's warn-only stance.
- **N-3:** `auditspi` is a stdlib-only leaf — direct import is safe and avoids the R-5-violating re-export alternative.

## Design highlights

- **API changes:** CLI help text + package doc only; no new flags, no library/API/bundle change; internal `validateOutcome` (exit 2 via `dispatch`) + `warnUnknownType` (advisory, exit 0) + non-exiting `usageErrorf`.
- **Failure modes:** table covering bogus outcome (exit 2, no bundle), unknown type (warning + bundle), registry-gap spurious warning, B4-5 auto-acceptance, both-bogus short-circuit, verify-mode behavior.
- **Migration:** single-package edit; no data/config migration; conditional B4-5 follow-up requires zero CLI change (R-3).
- **Acceptance mapping:** all four ACs mapped to named tests, including the no-warning assertions on existing tests and `TestRun_TokenTypeFilterExportsAndVerifies` pinning the mechanism on `token_issued` today.
- **Compatibility:** `soc2report/pipeline_test.go:36` (external `Run` consumer) confirmed compatible.
