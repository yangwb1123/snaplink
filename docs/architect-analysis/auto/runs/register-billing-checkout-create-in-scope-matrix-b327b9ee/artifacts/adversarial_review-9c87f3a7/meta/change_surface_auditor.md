Re-sweep complete; report saved to `docs/architect-analysis/auto/runs/register-billing-checkout-create-in-scope-matrix-b327b9ee/artifacts/re-sweep-matrix-sites.md`.

## Verdict

**The design's breakage list is complete for breaking assertions** — but the sweep surfaced 4 additional sites it misses (3 comment-only, 1 drift-guard slice), plus a latent trap in the sso-ctl fixture that must be pinned explicitly.

### 1. `cmd/sso-ctl/configcmd/main_test.go` — 1 negative, 4 positive; zero assertion changes

| Line | Fixture | Polarity | Post-change |
|---|---|---|---|
| 135 | A1 (allowed_scope, enabled, explicit matrix) | **negative, exit 1** | Unchanged — registry built from the fixture's explicit 8-row `matrixYAML` literal (checkout absent), not `MatrixOrDefault()`; still exit 1 |
| 169 | A3 (allowed_scope) | positive, exit 0 | Unchanged — registered via `extra_scopes` |
| 174 | A3 (extra_scopes) | positive, exit 0 | Unchanged — cross-list dup is idempotent no-op |
| 240 | P1 (no registry block) | positive, exit 0 | Unchanged — byte-compat pin |
| 254 | P2 (enabled: false) | positive, exit 0 | Unchanged — no membership check |

No error-message or exit-code assertions change (the file asserts exit codes only). **Trap:** A1 stays negative only because `matrixYAML` (lines 125-126) is a fixture-local literal — adding the row to it, or switching to `scopecontract.Matrix()`, flips A1 to exit 0. The design must pin this explicitly. The comment at 123 ("Full eight-row scope-matrix-v2 table") goes false post-change — comment rebase required.

### 2. Deployment configs — compose already compliant; rest need nothing

Repo-wide: exactly **one** repo-owned config has a `scope_registry` block (`ops/deploy/compose/config.yaml`); baremetal-ha/k8s/k8s-distributed/k8s-prod/kustomize/helm configs and shipped examples are registry-free (default-off).

- **compose:32/66** — explicit matrix + `extra_scopes: [billing:checkout:create, …]` → checkout **already registered**; migration step 5's obligation is already satisfied. No new row; optional comment rebase at :57.
- **baremetal-ha/RUNBOOK.md:274**, **billing/stripe-adapter/README.md:21**, **docs/stripe-payment-adapter.md:8** — no registry config in those stacks → **no change**; only a forward-pointer rebase note (if/when those stacks adopt the registry).

### 3. Missed by the breakage list (new findings)

1. `interfaces/sso/options_misc.go:488` — "the eight-scope tenant matrix" comment → nine (comment-only).
2. `cmd/sso-ctl/configcmd/main_test.go:123` — matrixYAML comment goes false (see above; const must stay 8 rows).
3. `ops/deploy/compose/config.yaml:57` — "full eight-row matrix" comment.
4. `protocols/oauth/scoperegistry/registry_test.go:90` — the `matrixOnly` cross-check slice in the mint/enforce drift guard should gain `billing:checkout:create` (design R2 only mentions `matrixLiteral` + a `Registered` case).

Everything else verified unaffected: `test/scope_registry_test.go` and `cmd/sso-server/scope_registry_wiring_test.go` iterate `Matrix()` (auto-cover), `config/scope_registry_test.go`'s other subtests survive (cross-list idempotency), `config_oauth2.go` "eight" mentions are comments, and `feature-matrix.md:135` ("8 grant branches") / `DECISIONS.md:929` / `k8s-distributed/config.yaml:37` are unrelated to the scope matrix.
