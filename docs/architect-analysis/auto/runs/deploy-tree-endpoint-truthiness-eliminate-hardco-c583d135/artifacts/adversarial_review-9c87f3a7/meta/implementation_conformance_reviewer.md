Verification complete. All evidence gathered from the live worktree — here is the case-by-case report.

## Summary verdict

R1 and R3 satisfy the corrected contract. R2 satisfies 7 of 8 sub-checks; **one contract deviation** (gate-default flip detection is not wired in phase 1) and **two flagged divergences** (baseline choice, test naming) found. No production code touched; both in-flight tests pass (`-race` on the operator module, root suite for R2).

## Per-acceptance-case report (9 Given/When/Then)

| Case | Real failing test? | Detection gate | Verdict |
|---|---|---|---|
| 1. `runningConfigPath` byte-equal to `PathAPIPrefix+PathAdminConfigRunning` | **Yes** — `TestAdminPathConstsMatchRootOwnedConstants` (operator `controller` pkg) | **ci-modules only** (`make ci` → Makefile:263 `cd cmd/sso-operator && go build ./... && go test -race -count=1 ./...`). Root gates never descend into the nested module — a precedented boundary (mcp/saml/ldap all share it), but a dev running only root-level commands gets zero signal for this exact drift class | Machine-checked. Failure message names both sides: `runningConfigPath = %q, want %q (root-owned consts)` — operator side (`runningConfigPath`, actual) and root side (`wantRunning`, const concatenation, provenance labelled), values byte-for-byte via `%q` |
| 2. `clusterDiffPath` byte-equal to `PathAPIPrefix+PathAdminConfigClusterDiff` | **Yes** — same test, second assertion | **ci-modules only** | Machine-checked |
| 3. go.mod require+replace `=> ../../`, tidy+build+test green, diff minimal | Build/test halves: **Yes** (require-removal → `no required module provides package` test failure; replace-removal → build+test both fail, loudly). Diff-minimality: **No** — no test asserts it | ci-modules for build/test; **diff minimality = review invariant**. Note the requirements' "matching sum lines only" wording is imprecise: the actual diff carries 8 indirect version bumps (MVS alignment, e.g. x/net 0.49→0.53, cbor 2.9.0→2.9.2) — identical fingerprint to the mcp precedent; go.sum gains **0** snaplink entries (local replace needs none) | Split: machine-checked (build/test) + review invariant (diff shape) |
| 4. Gate default ON → GET running = 200 | **Yes** — `TestDeployTreeAdminConfigRoutes_GateAwareTruthinessWithConstPaths` phase 1 | **Root suite** (`go test ./interfaces/sso/`) | **Machine-checked but contract-deviant**: phase 1 passes `sso.WithFeatureGates(sso.FeatureGates{AdminAPI: sso.Bool(true)})` — an **explicit** true, seeded via `adminAPILive.Store(gateOn(s.featureGates.AdminAPI))` (`accessors_feature_gates.go:36`). Case 4's premise is "gate default ON" and the corrected contract requires **"gate-default flip detection via phase 1's default state"** (audit §5: "Keep phase 1 default-based; that is the flip detector"). If `gateOn(nil)` ever flipped to OFF, this test still passes. **Fix: drop `WithFeatureGates` and rely on the unset default** |
| 5. POST cluster-diff with `{"snapshot":...}` = 200 | **Yes** — same test, phase 1 | Root suite | Machine-checked. Body `{"snapshot":{"rate_limit":5}}` sent in **all three phases** (phase 2 baseline POST included) — matches the audit's empty-body→400 nuance |
| 6. Gate closed → GET+POST 404 byte-identical to never-mounted | **Yes** — same test, phase 2 via `fghrAssertIdentical` (status + body + header set both directions) | Root suite | Machine-checked; **net-new coverage** for these routes. **Divergence flagged**: baseline is the const-derived `historyPath` (`PathAdminConfigHistory`), matching the requirements' letter; the audit recommends `fghrNeverMountedBaseline` — history is never-mounted only while the server lacks a config-audit store, so a future store-coupling flips the baseline to 200 (loud false failure). Non-blocking hardening |
| 7. Gate re-opened → both non-404 | **Yes** — same test, phase 3 | Root suite | Machine-checked |
| 8. Const-derived paths → rename breaks compile | **No failing test** — nothing fails if a future edit rewrites the test with literals; a const rename would break compilation of the current test (root `go build`/`go test`), but as a regression property it is vacuous | Root suite compile (incidental) | **Reclassify as review invariant** (per audit) — the current source is const-derived, which is the point; no gate enforces it forward |
| 9. `rg -n '/authenticate' cmd/sso-operator/` = 0; existing suites unchanged | rg sweep: **No test** — manual verification-plan step, not in `make ci`; suite-unchanged: machine-checked by root + ci-modules runs | Review invariant (rg) + suites | **R3 holds**: `rg` exit 1, 0 hits; the operator's 8 existing tests and `TestConfigAuditAPI_*`/`TestFeatureGates_AdminAPI*`/`TestSetAdminAPIGateEnabled_*` pass unchanged |

## In-flight naming vs design naming

| Design (requirements §5/§7) | In-flight | Match |
|---|---|---|
| `cmd/sso-operator/controller/adminpaths_parity_test.go` | `cmd/sso-operator/controller/root_consts_parity_test.go` (untracked) | **Mismatch** — filename diverges |
| R2 `TestConfigAudit_OperatorPaths_GateAwareTruthiness` | `TestDeployTreeAdminConfigRoutes_GateAwareTruthinessWithConstPaths` | **Mismatch** — function name diverges |
| R1 function name (unspecified in design) | `TestAdminPathConstsMatchRootOwnedConstants` | No contract to violate |
| Extend `interfaces/sso/config_audit_test.go` | Same file extended ✓ | Match |

The R2 test also defines its own `fghrPost` helper in `config_audit_test.go` (POST twin of `fghrGet`, preserving status/header/body) — consistent with the corrected contract's helper family, though the design named no such helper.

## Bottom line

- **Contract-compliant**: cases 1, 2 (with the ci-modules-only boundary made explicit), 4 (200 as tested, but not as the default-flip detector), 5, 6 (with baseline flagged), 7, 9; R3 confirmed at 0 `/authenticate` hits.
- **Must fix before handoff**: case 4's phase-1 gate-default detection — remove the explicit `WithFeatureGates(AdminAPI: Bool(true))` so phase 1 exercises `gateOn(nil)`; this is the only acceptance item the in-flight implementation actually fails.
- **Flagged, non-blocking**: history-route baseline vs `fghrNeverMountedBaseline` (audit hardening), and both test-name divergences from the design's naming (R1 filename, R2 function name) — the design_gate may enforce these names.
- **Reclassified as review invariants**: case 3 diff-minimality, case 8 const-derivation, case 9 rg sweep — none has a failing-test mechanism under a named gate; the machine-checked core is 6/9 (cases 1, 2, 4, 5, 6, 7), matching the audit's 6/9 grading.
