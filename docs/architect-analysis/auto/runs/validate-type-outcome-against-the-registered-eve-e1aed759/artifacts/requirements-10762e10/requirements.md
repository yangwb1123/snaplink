Requirements specification complete: `docs/architect-analysis/auto/runs/validate-type-outcome-against-the-registered-eve-4a69096f/artifacts/requirements-10762e10/requirements.md` (the path `pipeline.yaml` expects; the earlier FAIL was "agent binary not found", not content).

**Evidence verification (all cited claims checked against the repo):**

| Claim | Verdict |
|---|---|
| `main.go:183` `buildQuery` unvalidated passthrough | ✅ Exact — `audit.EventType(o.typ)` / `audit.Outcome(o.outcome)` cast with no vocabulary check; only since/until validated |
| `main.go:116-135` `bindFlags` | ✅ Exact (StringVar at 120-121) |
| `main_test.go:88` `TestRun_EmptyWindowExitsZero` | ✅ Exact — exit 0 on genuinely empty window |
| `main_test.go:139-157` type-filtered verified-empty bundle | ⚠️ **Range corrected** — the test is `TestRun_TenantAndTypeFilter` at 110-135 (`Contiguous==false` + `VerifyExportBundle` at 127-134); 139-157 is a different test. Substance verified |
| `event_types.go:15,195-196` token vocabulary | ✅ Exact — `token_issued`, `refresh_token_issued`, `id_token_issued` |
| Zero `auth.token.issue` in code | ✅ Grep-confirmed: only docs/proposals (marked `[PROPOSED]`) and memory index; no `.go` matches |
| Exit-code contract | ✅ `main.go:44-46` (0/1/2); **key finding**: `usageErr` is the only exit-2 path — `run()` maps buildQuery errors to exit 1, so exit-2 for `--outcome` must route through `dispatch` |
| Warn-only precedent | ✅ `build_audit_webhook.go:130` + `KnownEventTypes` doc: custom types legal, registry is "filter/UX aid ONLY" |

**Spec decisions (scope kept to the direction):**
- **R-1**: `--outcome` is a closed vocabulary (`success|failure` only, no custom-outcome allowance anywhere) → unknown value exits **2** via `dispatch`/`usageErr`.
- **R-2**: `--type` is advisory → unknown value prints an explicit **stderr warning**, exit 0, bundle still produced (honors documented custom-type legality + webhook precedent; satisfies the acceptance's "exit 2 *or* explicit stderr warning" branch per surface).
- **R-3**: registry-driven via `auditspi.KnownEventTypes` — no hardcoded CLI list, so `auth.token.issue` works automatically once B4-5 registers it (the conditional AC-3 clause is testable today via `TestRun_TokenTypeFilterExportsAndVerifies` on `token_issued`).
- All four supplied acceptance checks preserved and mapped to named tests; existing tests kept green; no library/API/bundle-format change.
