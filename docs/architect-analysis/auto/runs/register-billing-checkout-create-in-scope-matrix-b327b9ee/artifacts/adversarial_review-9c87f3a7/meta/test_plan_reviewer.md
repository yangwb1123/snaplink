Audit complete. Report saved to `docs/architect-analysis/auto/runs/register-billing-checkout-create-in-scope-matrix-b327b9ee/artifacts/adversarial_review-9c87f3a7/meta/testability_mutation_auditor.md`. Every pin was actually mutated and run in both directions (`-count=1`), production change applied and re-run, then all 9 touched files restored byte-identical (diff-verified; `git status` unchanged).

## Verdict: mapping is sound, with 3 corrections

**Mutation matrix (15 probes)** — all named pins verified red-before/green-after or proven-stable:

| Pin | Pre-change | Post-change |
|---|---|---|
| TestMatrixShape (want+1) | FAIL (8≠9) | PASS |
| Alias assert (R1) | compile FAIL (`undefined: ScopeCheckoutCreate`) | PASS |
| Registry cases entry `Registered(checkout)==true` (R2) | FAIL (line 81) | PASS (requires matrixLiteral+1 too — proven load-bearing both directions) |
| **matrixOnly slice (auditor's find)** | **PASS (false==false)** | PASS — see correction 1 |
| config ORIGINAL negative (`billing:checkout:create`) | PASS | **FAIL (probe)** → R3 rebase required, proven |
| config rebased negative (`tenant-quota:projection:write`) | PASS | PASS (stable true negative) |
| config positive subtest (R3) | FAIL (`want nil, got … not registered`) | PASS |
| A1 exit-1 (fixture unchanged) | PASS | PASS |
| **A1 trap probe** (row appended to matrixYAML) | — | **FAIL (exit 0)** — trap live |
| Auto-cover ×2 + ByteIdenticalBody | PASS | PASS (9th row mints 200 + exact claim) |

**R3 rebase target validated**: `shared/core/consts.go:26` `ScopeTenantQuotaProjectionWrite` is a real const, absent from Matrix(), rejected by `validateScopeRegistry` pre- and post-change. Nuance: compose `config.yaml:66` registers it via `extra_scopes` — "not mintable" holds for the built-in path the harness exercises, which is the correct claim.

**matrixOnly is the only missed cross-check**: complete 18-site census; every other enumeration is covered by R1/R2/R3, auto-cover, comment-only, or auto-adapting production. The silent-gap probe (`-count=1`) proved the original registry test stays green post-change — the drift detection lives in TestMatrixShape + the R3 positive subtest; R2's role is fixture honesty + guard coverage.

**Corrections**:
1. matrixOnly is *not* a red/green pin — it's guard-coverage completeness; the load-bearing R2 pins are the cases entry and matrixLiteral (both proven).
2. A1's exit-1 assertion is at `main_test.go:138-139`, not 135.
3. The `main_test.go:123` comment must **not** be rebased to "nine-row" — the fixture deliberately stays 8 rows; the correct rebase names the omission explicitly (the auditor's "rebase required" left the direction open, and the wrong direction *is* the trap).

**Gates**: build+vet clean in every phase; the maintainability/architecture failure set is byte-identical pre/post mutation (the three pre-existing tooling-tree violations); tree fully restored.
