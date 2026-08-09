All done. The design doc is updated (untracked campaign artifact, consistent with the batch workflow — my session touched only that file; no Go or config edits).

## Final test-file layout decision

The tight-budget analysis: R4 (~50) + R5 (~40) on top of 394 lines would land at ~475-485 — too close to 500. The split: **R5 moves to its own new file; R4 stays**.

| File | Today | Adds | Final | Headroom |
|---|---|---|---|---|
| `test/scope_registry_test.go` | 394 | R4 only (~50): import +1, `srProvisioner`/`srProvisionerScopes` ~4, variadic harness +3, provisioner seed +8, positive mint ~15, negative control ~14 | ~445 | ~55 |
| `test/scope_registry_compose_parity_test.go` **(new)** | — | R5 (~70-90): header, imports, `composeScopeRegistry` helper ~38, test ~16 | ~70-90 | ~410 |
| `config/scope_registry_test.go` | 208 | R2: `auditgovernance` import +2, two subtests ~17 each | ~244 | ~256 |
| `cmd/sso-server/scope_registry_wiring_test.go` | 100 | R1: `strings`/`auditgovernance` imports +2, one test ~45 | ~147 | ~353 |

R5 is the natural split: it owns the goccy import and the repo-relative file read (`../ops/deploy/compose/config.yaml` — `go test` runs with CWD = package dir) and needs none of `scope_registry_test.go`'s shared harness (`srCC`/`srSeedClients`), while R4 reuses `srCC`, the byte-identical pattern, and the harness — hence the minimal shared changes (`srRegistry`/`newScopeRegistryHarness` go variadic with `extras ...string`, existing call sites untouched; one `AddSeed` for the provisioner client). The 500-line cap is the AGENTS.md-budget-table reading — the machine gate skips `_test.go` (maintainability_budget_test.go:66) — and every file now holds it with margin.

## Re-verified constraints the implementer must not break — all green

1. **No new deps**: `goccy/go-yaml v1.19.2` already direct (go.mod:14); R5 adds only `os`/`path/filepath`/`testing`. Struct-tag decoding of the exact `oauth.scope_registry` block shape is proven by the config loader itself (`config/source.go`) against the live file.
2. **`interfaces/sso` untouched**: exactly **60** non-test files = the ceiling; zero files in this change set.
3. **config 208 → ~244**: cycle-safe — `auditgovernance`'s only snaplink deps are `domains/tenant/commerce` + `platform/lifecycle/modules`, neither imports `config`.
4. **wiring test 100 → ~147**: `buildApp` has zero `validateScopeRegistry` refs (re-verified), so R1's negative control (registration-absence, not boot failure) holds.
5. **Zero production-Go edits**: change set = 3 modified test files + 1 new `_test.go` + `ops/deploy/compose/config.yaml` only. No new packages (no `layerName()` classification); `test/` dir at 211 `_test.go`/0 non-test/7 subdirs — all dir gates unaffected; no `cmd/` imports.

Also fixed while amending §8: the row-2 example error string named `audit:policy:read`, but the loop (config_oauth2.go:62) names the first unregistered token in `strings.Fields` order — `audit:platform:cross_tenant`; the doc now pins the verbatim string. The two reviewer nits (`go test . -run` typo in requirements §11; `srClientAny` 56-60 citation) were already fixed in the current docs — verified, no action needed.

No `.go` edits were made, so the mandatory post-edit gates don't apply; the design-doc-only change requires no gate run.
