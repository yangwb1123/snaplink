# Requirements Spec: deploy-tree endpoint truthiness — root-const parity for the operator's admin paths

- Direction: "Deploy-tree endpoint truthiness: eliminate hardcoded admin-path literals via root-const parity test" (source: `docs/architect-analysis/auto/analyses/cmd-sso-operator-apiv1alpha1-1d574b40.json`, entry 1)
- Analysis module: `cmd/sso-operator/apiv1alpha1`; change surface: `cmd/sso-operator` `controller` package (parity test) + one root-module test extension in `interfaces/sso` (gate-aware truthiness test). Both halves are explicitly licensed by the direction's acceptance ("in interfaces/sso or the operator module, plus a parity check").
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-operator/controller/ssoconfigdrift_controller.go:47-49` — hardcoded admin-path literals | Constants are at lines 40–41: `runningConfigPath = "/api/v1/admin/config/running"` and `clusterDiffPath = "/api/v1/admin/config/cluster-diff"` (doc comment 36–39, block 40–43). Consumed at `controller/http.go:50,58,67` (GET `baseURL+runningConfigPath`) and `:88,97,106` (POST `baseURL+clusterDiffPath`) | Confirmed (line drift 6–8; symbols and byte values exact) |
| `shared/core/consts.go:34,463-467` — `PathAPIPrefix`, `PathAdminConfigRunning`, `PathAdminConfigClusterDiff` | `PathAPIPrefix = "/api/v1"` at line 34; `PathAdminConfigRunning = "/admin/config/running"` at 463; `PathAdminConfigClusterDiff = "/admin/config/cluster-diff"` (POST) at 467. `PathAPIPrefix+PathAdminConfigRunning` and `PathAPIPrefix+PathAdminConfigClusterDiff` are byte-identical to the two operator literals | Confirmed |
| Production gated mount (audit-corrected) — `interfaces/sso/server_routes_admin.go:48-56` + `server_backup.go:50-60` | `mountAdminSurface` (server_routes_admin.go:48-56) wraps `core.NewGatedRouter(s.router.Group(PathAPIPrefix), s.adminAPIGateOn)`; `mountConfigAuditAPI` (server_backup.go:50-60) registers running/applied/diff/cluster-diff **only when a snapshot source exists**, history only with a config-audit store — all via the const aliases (`interfaces/sso/aliases.go:373-377`). Closed gate ⇒ `GateHandler` → `http.NotFound` (`shared/core/router.go:367-375`), so gated-404 is by design, byte-identical to never-mounted (proven by `interfaces/sso/feature_gate_hotreload_test.go:88-130` for `/api/v1/admin/endpoints`). `platform/configaudit/mount.go:MountRoutes` (line 24) has **zero callers** repo-wide — unwired dead code; cite it as such, never as the production mount | Confirmed (audit correction: the earlier "mount.go:35-41 — Confirmed" was a shape-only false confirmation) |
| `interfaces/sso/config_audit_test.go:54-113` — existing sweep pattern against real routes | Sweep tests at 48 (`TestConfigAuditAPI_NotMountedWithoutSnapshotsOrStore`: 404 sweep with **raw literal** paths) and 65 (`TestConfigAuditAPI_SnapshotsWiredServesRedactedRunningAppliedDiff`: GET running = 200, POST cluster-diff = 200 with `{"snapshot":...}` body, history = 404 without store); `TestConfigAuditAPI_ClusterDiffNotMountedWithoutSnapshots` at 127 | Confirmed (drift ~6; sweep uses literals, not consts — the new test fixes this) |
| `cmd/sso-mcp/go.mod:5` — replace precedent for nested-module root import | Line 5: `replace github.com/yangwb1123/snaplink => ../../`; root module required as `v0.0.0-00010101000000-000000000000`; the module passes `ci-modules` (Makefile:262). `cmd/sso-operator/go.mod` currently has **no** replace/require of the root — it must be added. `go list -deps ./shared/core` shows shared/core pulls only the standard library (plus itself), so the go.mod/go.sum diff stays minimal | Confirmed |
| Gate default and live toggle surface | `gateOn(explicit)` = `explicit == nil \|\| *explicit` (`interfaces/sso/server_routes.go:206-208`) ⇒ AdminAPI unset = ON. `SetAdminAPIGateEnabled` is a public accessor (`interfaces/sso/accessors.go:42-49`), wired to the reload hook. `WithConfigSnapshots` at `interfaces/sso/options_admin.go:137-148` | Confirmed |
| No legacy `/authenticate` tests in the deploy tree | `rg '/authenticate' --include='*.go' .` → 4 hits: `cmd/sso-ctl/generate/scaffold_contract_test.go:131-137` (anti-pattern **guard** asserting scaffolds do NOT contain `/authenticate` — the pattern to keep) and `domains/authenticators/wasmauth/engine.go:48` (unrelated WASM comment). Zero hits in `cmd/sso-operator/`, `interfaces/sso/`, `shared/core/` | Confirmed |
| B4-3 / T-2 campaign context | `docs/campaigns/implementation-gate.md` row 3 (B4-3): legacy defect regression tests (`TestOIDCDiscovery` asserting `/authenticate`; `TestOIDCDiscoveryEndpoint` asserting the `8080:0` port bug) "不得带入部署仓" — must not be carried into the deploy tree; T-2 = sweep all-green (advertised endpoints never 404) | Confirmed |
| `interfaces/sso` file ceiling | Exactly 60 non-test `.go` files (at the ceiling; `_test.go` files are exempt per DIRECTORY_MAP) ⇒ extend `config_audit_test.go` (no new non-test file, no ceiling pressure) | Confirmed |
| Baseline gates | `cd cmd/sso-operator && go build ./...` OK; `go test -race -count=1 ./...` OK (controller 1.4s; `apiv1alpha1` has no tests). `python cli.py modules check` passes. `make ci-modules` line for the operator at Makefile:263 | Confirmed |

## 2. Goal and user outcome

The operator's drift controller (an out-of-process nested module) addresses the admin API with path constants that are byte-correct today but duplicated as raw literals. Any future rename/reshape of the root module's owned route constants (`PathAPIPrefix`/`PathAdminConfigRunning`/`PathAdminConfigClusterDiff`) would silently desynchronize the operator from the routes the server actually mounts — the same advertised-vs-actual drift class B4-3 removes from the deploy tree. And because both routes mount only behind the AdminAPI live gate plus the config-snapshot wiring condition, an endpoint sweep must treat gated-404 as expected-by-design, never as a truthiness failure.

Completion marker: two new tests exist and pass —

1. In the operator module: the controller's `runningConfigPath`/`clusterDiffPath` literals are byte-pinned to `core.PathAPIPrefix+core.PathAdminConfig{Running,ClusterDiff}`.
2. In the root module: GET `PathAPIPrefix+PathAdminConfigRunning` and POST `PathAPIPrefix+PathAdminConfigClusterDiff` (const-derived, not literal) return 200 against a mounted server with the gate open, 404 when the gate is closed (byte-identical to an unmounted route), and non-404 again after re-opening.

## 3. Product boundary

- Surface: deploy-tree truthiness/parity coverage only. No server behavior, no operator production code, no route changes.
- Defaults: the gate default (AdminAPI unset = ON) is the state the truthiness test uses; the gate-closed state is asserted explicitly via the existing public accessor.
- Explicit non-goals (do not implement):
  - No production-code change to the operator: the controller keeps its local constants. The acceptance pins a **parity check**, not a runtime import of the root module; keeping the operator binary free of root-module dependencies preserves the out-of-process module posture (AGENTS.md §4). Consuming the consts at runtime would be a separate direction.
  - No changes to `cmd/sso-operator/apiv1alpha1/*`, `crd-ssoconfigdrift.yaml`, the controller logic, `platform/configaudit/*`, `shared/core/*`, or `cmd/sso-mcp/*` (other analysis entries cover CRD types and RBAC separately).
  - No changes to existing tests' expectations (`TestConfigAuditAPI_*`, `TestFeatureGates_AdminAPIOff_HidesAdminSurface`, `TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404` all stay as-is and keep passing).
  - No new endpoints, `Err*`, config keys, OpenAPI surface, audit events, or RBAC manifests.
  - No `go.work` (AGENTS.md §4: nested modules use no `go.work`).
  - No `/authenticate`-asserting test anywhere (legacy defect tests are not carried into the deploy tree).

## 4. Module classification

- [x] Infrastructure/config/deployment (deploy-tree truthiness)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layers: `cmd/sso-operator/controller` (nested module, white-box test) and `interfaces/sso` (root module, test-only). Dependency direction: the operator test imports `github.com/yangwb1123/snaplink/shared/core` — `cmd/sso-operator` (nested module) → root `shared/core` (kernel). This is the exact direction the `cmd/sso-mcp` precedent already exercises (`cmd/sso-mcp/go.mod:5`) and `shared/core` imports no Snaplink package, so no upward/cyclic edge is introduced. No package imports `cmd/`.

## 5. Requirements

### R1 — Root-const parity test in the operator module

Add `cmd/sso-operator/controller/adminpaths_parity_test.go` (package `controller`, white-box — it must see the unexported consts):

- Assert `runningConfigPath == core.PathAPIPrefix + core.PathAdminConfigRunning`.
- Assert `clusterDiffPath == core.PathAPIPrefix + core.PathAdminConfigClusterDiff`.
- Message on failure names both sides byte-for-byte so the drift is self-explaining.

Module wiring (mirrors `cmd/sso-mcp/go.mod:5`): add to `cmd/sso-operator/go.mod` —

```text
replace github.com/yangwb1123/snaplink => ../../
```

plus `require github.com/yangwb1123/snaplink v0.0.0-00010101000000-000000000000` in the require block, then `cd cmd/sso-operator && go mod tidy`. Precision (empirically reproduced; matches the mcp precedent byte-for-byte): Go has **no test-only `replace` directive** — the replace is module-graph-wide by language design. It is inert for `go build ./...` only because no production package imports the root (`go list -deps .` stays operator-packages + stdlib; the root is linked into the test binary alone). What is genuinely test-only is the *import* (and thus the require's reason to exist): R1 imports `shared/core` only, whose closure is 100% stdlib. The tidy impact is bounded, not zero: the replaced root's requirements join the operator graph and MVS-align ~9 existing indirect deps — ~7 version bumps in go.mod requires (e.g. `x/net v0.49→v0.53`, `cbor v2.9.0→v2.9.2`) and a ~36-line go.sum swap (9 modules × 2 lines removed + 2 added); the replaced root itself records **zero** go.sum entries (a local replace needs none), and no new module paths appear. If tidy balloons beyond this minimal footprint (importing `platform/configaudit` instead of `shared/core` would add ~20 new paths / ~41 go.sum lines — otel/grpc/gonum…), stop and use the direction's sanctioned fallback: a checked-in generated parity file produced by a root-module generator, rather than a bloated nested go.mod.

### R2 — Gate-aware endpoint-truthiness test in the root module

Extend `interfaces/sso/config_audit_test.go` with `TestConfigAudit_OperatorPaths_GateAwareTruthiness`:

- Build `sso.NewServer(sso.WithConfigSnapshots(applied, runningFn))` — AdminAPI gate defaults ON (`gateOn(nil) == true`), snapshots wired so the two routes mount.
- Paths are built from the consts (`core.PathAPIPrefix+core.PathAdminConfigRunning`, `+core.PathAdminConfigClusterDiff`) — no raw literals in the new test (the existing sweep at config_audit_test.go:57-63 uses literals; the new test establishes the const-derived pattern).
- Gate open: GET running → 200; POST cluster-diff with `{"snapshot":{...}}` → 200 (non-404 with the exact methods the operator uses — `controller/http.go:50,88`).
- Gate closed (`srv.SetAdminAPIGateEnabled(false)`): both → 404, **byte-identical** to the never-mounted baseline `fghrNeverMountedBaseline` (`/definitely-not-a-real-route`, `interfaces/sso/feature_gate_hotreload_test.go:80`, same `package sso_test`) fetched on the same server — same byte-identity technique as `TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404`. Use the proven fghr constant, not the history-without-store route: history is never-mounted only while `WithConfigSnapshots` does not wire a store, so a future store-coupling flips the baseline to 200 and spuriously fails the test (loud false failure, but churn). History-404-in-open-state stays covered by the existing suite.
- Gate re-opened (`SetAdminAPIGateEnabled(true)`): both non-404 again — proving the routes were mounted-but-gated, not unmounted (the direction's "naive sweep misreads gated-404" guard).
- The POST carries the `{"snapshot":{...}}` body in **all three phases**: an empty-body POST cluster-diff is `400` (snapshot required — `platform/configaudit.HandleClusterDiff` binds and rejects an empty `Snapshot`), which would abort the 404 phase before gating is exercised. Phase 1 asserts on the **default** gate state (no `SetAdminAPIGateEnabled` call before its assertions): a gate-default flip to OFF fails phase 1 — that is the flip detector (redundant backstops exist in the existing suite; phase 3's explicit re-open makes it default-independent).

### R3 — No legacy defect tests carried into the deploy tree

- The new tests assert only const-derived paths; nothing asserts `/authenticate`.
- `rg -n '/authenticate' cmd/sso-operator/` stays 0 hits (currently 0; the word "authenticates" in `apiv1alpha1/ssoconfigdrift_types.go:24` is a doc-comment verb, not a path — untouched).
- No `TestOIDCDiscovery`-style test exists or is added anywhere in the deploy tree (`cmd/sso-operator/`, the new root test).

### Testable acceptance (Given/When/Then)

R1 parity — new test `cmd/sso-operator/controller/adminpaths_parity_test.go`:

1. Given the operator `controller` package, when `runningConfigPath` is compared with `core.PathAPIPrefix+core.PathAdminConfigRunning`, then they are byte-equal (test passes). Detection gate: `cd cmd/sso-operator && go test -race ./...` under `make ci` → ci-modules (`Makefile:263`); root gates never descend into the nested module — the CI-only detection boundary for R1, precedented by every nested module (mcp at Makefile:262, saml/ldap/etc.), with `make ci` as the mandatory handoff gate.
2. Given the operator `controller` package, when `clusterDiffPath` is compared with `core.PathAPIPrefix+core.PathAdminConfigClusterDiff`, then they are byte-equal. Detection gate: same as case 1 — ci-modules only.
3. Given the edited `cmd/sso-operator/go.mod` (require + replace `=> ../../`), when `cd cmd/sso-operator && go mod tidy && go build ./... && go test -race -count=1 ./...` runs (the Makefile:263 gate command), then everything passes. The build/test halves are machine-checked (replace removal → build and test fail loudly with `missing go.sum entry`; require removal → test fails with `no required module provides package`). The diff **shape** is a review-time check, not a machine assertion: tidy swaps ~36 go.sum lines across 9 MVS-aligned indirect deps (e.g. `x/net v0.49→v0.53`, `cbor v2.9.0→v2.9.2`) plus ~7 go.mod require bumps — not "only matching sum lines"; the replaced root itself records zero go.sum entries.

R2 truthiness — extended `interfaces/sso/config_audit_test.go`:

4. Given `sso.NewServer(sso.WithConfigSnapshots(...))` (gate default ON), when GET `PathAPIPrefix+PathAdminConfigRunning`, then status 200 (non-404).
5. Given the same server, when POST `PathAPIPrefix+PathAdminConfigClusterDiff` with a `{"snapshot":{...}}` body, then status 200 (non-404).
6. Given the same server, when `SetAdminAPIGateEnabled(false)` and then the same GET and POST run (the POST still carrying the snapshot body), then both are 404 and byte-identical to the never-mounted baseline `fghrNeverMountedBaseline` fetched on the same server (`feature_gate_hotreload_test.go:80`, `package sso_test`).
7. Given the gate re-enabled with `SetAdminAPIGateEnabled(true)`, when the same GET and POST run again, then both are non-404 (mounted-but-gated, not unmounted).
8. Review invariant (demoted from testable acceptance per audit): the test source builds paths from `core.PathAPIPrefix+core.PathAdminConfig*` with no raw literals, so a future const rename breaks this test at compile time — true of the code as written, but nothing fails if a future edit rewrites the test with literals; enforced at review, not by a gate.

R3 regression:

9. Given the change, when `rg -n '/authenticate' cmd/sso-operator/` runs, then 0 hits (review-time check — a manual verification-plan step, not part of `make ci`); and when the existing suite runs (`TestConfigAuditAPI_*`, `TestFeatureGates_AdminAPIOff_HidesAdminSurface`, `TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404`, all operator controller tests), then all pass unchanged (machine-checked via root + ci-modules runs).

### Acceptance mapping grade (per the test-design audit): 6/9 machine-checked

Cases 1, 2, 4, 5, 6, 7 fail on regression under a named gate (6 and 7 are net-new byte-identity coverage for these routes; 4 and 5 are partially redundant with the existing literal-path sweep — their net-new value is the const-derived request). Case 3 splits: build/test machine-checked, diff-minimality review-time. Case 8 is a review invariant (vacuous as a failing test). Case 9's rg sweep is review-time; its suite-unchanged half is machine-checked. Detection boundary: cases 1-2 pass/fail only under ci-modules (`make ci`), never under root-level gates.

## 6. Engineering-gate constraints (verified)

- **`interfaces/sso` is at its 60-file ceiling** (60 non-test `.go` files counted). `_test.go` files are exempt, so the truthiness test extends the existing `config_audit_test.go`; no new non-test file and no `layerExemptions` entry.
- **Nested-module import is precedented and gate-clean**: `cmd/sso-mcp/go.mod:5` already replaces the root module `=> ../../` and passes `make ci` (ci-modules runs `cd cmd/sso-mcp && go build ./... && go test -race -count=1 ./...`, Makefile:262). The operator gets the same treatment; `python cli.py modules check` (validates manifests/profiles, not nested go.mod contents) passes at baseline and is unaffected.
- **No `go.work`**; root `go.mod`/`go.sum` unchanged (test-only import lives in the nested module; root module gains no new dependency).
- **Budgets**: the new files are small (`adminpaths_parity_test.go` ≈ 25 lines, one test function; one added test function in `config_audit_test.go`). No file approaches 500 lines; no function approaches 50 lines; complexity/nesting trivial. `TestMaintainability_|TestArchitecture_` in the root module is unaffected (no production code touched).
- **Wire/contract invariants untouched**: no routes, no `Err*`, no config keys, no audit events, no SSRF surface (tests use `httptest`; no outbound fetch is added to production code). The `Cache-Control`/bearer-challenge contracts are untouched (no new credential endpoints).
- **Oracle-safe response tables unaffected**: this change adds no new error surfaces.

## 7. Files

### Create

```text
cmd/sso-operator/controller/adminpaths_parity_test.go — R1 parity test
    (package controller; imports github.com/yangwb1123/snaplink/shared/core,
    test-only; asserts runningConfigPath == core.PathAPIPrefix+core.PathAdminConfigRunning
    and clusterDiffPath == core.PathAPIPrefix+core.PathAdminConfigClusterDiff).
```

### Modify

```text
cmd/sso-operator/go.mod (+ go.sum) — add
    require github.com/yangwb1123/snaplink v0.0.0-00010101000000-000000000000
    and replace github.com/yangwb1123/snaplink => ../../  (mirror cmd/sso-mcp/go.mod:5);
    run go mod tidy in cmd/sso-operator.
interfaces/sso/config_audit_test.go — append
    TestConfigAudit_OperatorPaths_GateAwareTruthiness (R2, acceptance cases 4–8),
    const-derived paths only.
```

### Do not modify

```text
cmd/sso-operator/controller/ssoconfigdrift_controller.go, controller/http.go — the
    literals stay; this direction locks them with a parity test (runtime import is
    out of scope per the acceptance).
cmd/sso-operator/apiv1alpha1/*, crd-ssoconfigdrift.yaml, doc.go, main.go — other
    analysis entries' scope.
platform/configaudit/*, shared/core/*, interfaces/sso non-test files, cmd/sso-mcp/*,
    Makefile, root go.mod/go.sum.
```

## 8. Dependencies and compatibility

- New/changed SPI: none (test-only).
- New option/store wiring: none.
- New YAML/env keys: none.
- Storage migration: none.
- HTTP/proto compatibility: none (no production code path changes).
- Module graph: `cmd/sso-operator` gains a test-only *import* of the root module via a module-wide `replace` — identical mechanics to `cmd/sso-mcp`. The replace is inert for `go build ./...` only because no production package imports the root: the operator binary stays root-free (`go list -deps .` = operator packages + stdlib; test files are not linked into `sso-operator`). The production footprint is a bounded set of indirect dependency version bumps from MVS alignment (~7 go.mod require bumps, ~36 swapped go.sum lines across 9 deps, zero new module paths, zero snaplink sums) — not zero.
- Rollout/rollback: additive tests; removing them restores the previous tree exactly.

## 9. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [ ] `docs/openapi.yaml` — not applicable (no endpoint change).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`).
- [x] Campaign bookkeeping: `docs/campaigns/implementation-gate.md` row 3 (B4-3) is advanced by the deploy-tree half (operator-side path truthiness + root-side gate-aware sweep), matching T-2's "advertised endpoints never 404" contract; the "不得带入部署仓" constraint is preserved by R3.

## 10. Verification plan

```bash
go build ./... && go vet ./...                        # root module
go test -run 'TestMaintainability_|TestArchitecture_' .   # root gates
go test ./interfaces/sso/ -run 'TestConfigAudit_OperatorPaths|TestConfigAuditAPI|TestFeatureGates_AdminAPI|TestSetAdminAPIGateEnabled' -v
cd cmd/sso-operator && go mod tidy && go build ./... && go test -race -count=1 ./...
rg -n '/authenticate' cmd/sso-operator/               # expect 0 hits
python cli.py modules check                           # baseline passes; unchanged surface
make ci                                               # full gate incl. ci-modules
```

Pre-existing conditions to report separately: none found — operator module build/test, `modules check`, and the root suite are green at HEAD before this change.
