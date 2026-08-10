# Requirements Spec: openapi.yaml-anchored admin-path sweep for the operator's hardcoded admin paths

- Direction: "Sweep test tying the operator's hardcoded admin paths to the server's group-relative consts via docs/openapi.yaml (B4-3 truthiness, T-2)" (source: `docs/architect-analysis/auto/analyses/cmd-sso-operator-controller-6371f05a.json`, entry 3, the selected direction)
- Analysis module: `cmd/sso-operator/controller`; change surface: test-only — one new test function in the existing parity test file inside `cmd/sso-operator/controller/`. No production code, no root-module edits, no openapi.yaml edits.
- Status: requirements (evidence-verified against HEAD + worktree)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-operator/controller/ssoconfigdrift_controller.go:47-51` — hardcoded full-path constants | Constants at lines 48–51: `runningConfigPath = "/api/v1/admin/config/running"` (48) and `clusterDiffPath = "/api/v1/admin/config/cluster-diff"` (49), doc comment 46–47 ("appended to each cluster's BaseURL"). Consumed at `controller/http.go:50,58,67` (GET `baseURL+runningConfigPath`) and `:88,97,106` (POST `baseURL+clusterDiffPath`) | Confirmed (comment block starts at 46; constant block 48–51) |
| `shared/core/consts.go:34` — `PathAPIPrefix = "/api/v1"` | Line 34, exact | Confirmed (exact) |
| `shared/core/consts.go:463-467` — group-relative admin consts | `PathAdminConfigRunning = "/admin/config/running"` at 463; `PathAdminConfigClusterDiff = "/admin/config/cluster-diff"` (POST, comment cites `platform/configaudit.HandleClusterDiff`) at 467; block doc comment 454–461 | Confirmed (exact) |
| `docs/openapi.yaml:5340` — `/api/v1/admin/config/running` documented | Line 5340 `  /api/v1/admin/config/running:` with `get` (5342), responses 200 ("The redacted running config snapshot."), 401, 501 (`config_audit_not_available`) | Confirmed (exact) |
| `docs/openapi.yaml:5607` — `/api/v1/admin/config/cluster-diff` documented | Line 5607 `  /api/v1/admin/config/cluster-diff:` with `post`, responses 200 (redacted patch), 400 (missing/empty snapshot), 401, 501 | Confirmed (exact) |
| `Makefile:263` — nested-module test invocation | Line 263 is exactly `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` inside `ci-modules` | Confirmed (exact) |
| `cmd/sso-operator/go.mod` — "no dependency on shared/core and no go.work" | **Stale at spec time**: the worktree go.mod already carries `require github.com/yangwb1123/snaplink v0.0.0-00010101000000-000000000000 // test-only parity import of shared/core` plus `replace github.com/yangwb1123/snaplink => ../../` (added by the sibling deploy-tree-truthiness direction, spec `cmd-sso-operator-b4-3-deploy-tree-truthiness-requirements.md` R1). A test in the operator module CAN therefore import `shared/core` directly today. The production posture is unchanged: no production package imports the root, so the operator binary stays root-free. No `go.work` anywhere | Confirmed, with correction (premise superseded by landed sibling work; the *runtime* share-the-constant limitation still holds) |
| "no test anywhere asserts the concatenation" | **Stale at spec time**: `cmd/sso-operator/controller/adminpaths_parity_test.go` (untracked in the worktree, 26 lines) — `TestAdminPathConstsMatchRootOwnedConstants` — asserts `runningConfigPath == core.PathAPIPrefix+core.PathAdminConfigRunning` and `clusterDiffPath == core.PathAPIPrefix+core.PathAdminConfigClusterDiff`. The server-side leg also exists: `TestConfigAudit_OperatorPaths_GateAwareTruthiness` in `interfaces/sso/config_audit_test.go` (worktree-modified) hits GET running and POST cluster-diff (const-derived paths) against a real `sso.NewServer(sso.WithConfigSnapshots(...))`: 200 with gate open, byte-identical 404 with gate closed, 200 after re-open | Confirmed, with correction (both non-openapi legs of this direction's acceptance are already implemented in the worktree) |
| "no test parses docs/openapi.yaml from the operator run" | Repo-wide grep: the only `openapi` hits in `cmd/sso-operator/` are `go.sum`/`go.mod` (module metadata). Nothing parses the OpenAPI document anywhere in the operator module | Confirmed — this is the net-new leg |
| openapi.yaml parseability | `openapi: 3.0.3` at line 32, top-level `paths:` at line 143; both target paths are literal keys with no parameters/templating. `gopkg.in/yaml.v3 v3.0.1` (go.mod:58, indirect), `go.yaml.in/yaml/v3 v3.0.4` (go.mod:46), and `sigs.k8s.io/yaml v1.6.0` (go.mod:66) are all already in the nested module's graph — no new module path; tidy only promotes the chosen parser to direct | Confirmed |
| Live mount (which code serves the routes) | `interfaces/sso/server_backup.go:52,55` — `api.GET(PathAdminConfigRunning, ...)` / `api.POST(PathAdminConfigClusterDiff, ...)` on the gated `/api/v1` admin group (`server_routes_admin.go:48-56`, `core.NewGatedRouter(s.router.Group(PathAPIPrefix), ...)`), aliased at `interfaces/sso/aliases.go:373,377`; routes mount only when a snapshot source is wired. `platform/configaudit/mount.go:MountRoutes` has zero callers (dead code, per the sibling audit) — never cite it as the production mount. The 501 `config_audit_not_available` is emitted at the handler level (`platform/configaudit/handlers.go:122,143`, unit-tested at `handlers_test.go:95`); at the route level an unwired server returns 404 (route never mounted, `TestConfigAuditAPI_NotMountedWithoutSnapshotsOrStore`) | Confirmed (audit correction carried over from the sibling spec) |
| B4-3 / T-2 mapping | `docs/campaigns/implementation-gate.md` row 3 (部署仓): deploy-tree tests get sweep/truthiness assertions; T-2 = "sweep 全绿（广告端点绝不 404）". This direction is the admin-endpoint half of that row: the operator's two admin calls must never target a dead or re-semanticized route | Confirmed |
| Pre-existing conditions at spec time | `cd cmd/sso-operator && go build ./... && go test -count=1 ./controller/` green (0.112s); the worktree parity + truthiness + validate tests all pass | Confirmed (run at spec time) |

## 2. Goal and user outcome

The operator's drift controller addresses the server's admin API with two hand-maintained full-path constants (`/api/v1/admin/config/running`, `/api/v1/admin/config/cluster-diff`) that cannot be shared with the root module at runtime (nested module, no `go.work`, root-free binary posture). The server owns the same truth as a prefix + group-relative const pair (`PathAPIPrefix` + `PathAdminConfigRunning`/`PathAdminConfigClusterDiff`), and `docs/openapi.yaml` independently documents both full paths — a third, deploy-tree-reachable copy of the contract. A rename or prefix change on either side of any two of these three copies silently degrades the operator to perpetual "cluster B diff request failed" status, or worse, to a stale compatibility mount with different semantics — exactly the drift class B4-3's deploy-tree sweep (T-2) exists to catch.

Completion marker: a single committed test closes the triangle —

1. operator constants `==` the paths documented in `docs/openapi.yaml` (with method fidelity: `get` for running, `post` for cluster-diff), and
2. the documented paths `==` `core.PathAPIPrefix` + the root-owned group-relative consts, and
3. the already-landed server-side sweep keeps proving that those const-derived paths answer non-404/non-501 against a wired server.

Any drift in any of the three copies (operator const, root const, openapi.yaml) fails at least one test under `Makefile:263`'s `ci-modules` gate; a drift in the mounted routes themselves fails the server-side sweep under the root suite. The `docs/openapi.yaml` anchor makes the sweep robust to the one failure mode the consts-only parity cannot see: a coordinated rename of both Go consts that leaves the documented contract behind.

## 3. Product boundary

- Surface: verification coverage only — one new test function in `cmd/sso-operator/controller/adminpaths_parity_test.go` (extending the existing R1 parity file; same concern, one file).
- Explicit non-goals (do not implement):
  - No production-code change to the operator: `runningConfigPath`/`clusterDiffPath` stay local constants; this direction pins them, it does not import root consts at runtime (out-of-process module posture, AGENTS.md §4; the sibling deploy-tree spec already settled this).
  - No change to `docs/openapi.yaml` — it is the immutable anchor, not an output of this change. If the doc is wrong, the new test fails and the doc is fixed as a separate, deliberate contract change.
  - No root-module edits: the server-side leg already exists (`TestConfigAudit_OperatorPaths_GateAwareTruthiness`); this spec pins it, it does not re-implement it. `interfaces/sso` is at its 60-file ceiling; `_test.go` files are exempt and no new non-test file is proposed anywhere.
  - No new `Err*`, config keys, routes, audit events, RBAC manifests, or OpenAPI surface.
  - No `go.work`; no new module path (yaml.v3 already in the nested graph; tidy promotes it from indirect to direct).
  - No changes to `ssoconfigdrift_controller.go`, `http.go`, `validate.go`, the CRD types/manifest, `main.go`, `Makefile`, root `go.mod`/`go.sum`, or `platform/configaudit/*`.

## 4. Module classification

- [x] Infrastructure/config/deployment (deploy-tree admin-endpoint truthiness — the operator half of B4-3 row 3, T-2)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer: `cmd/sso-operator/controller` (nested module, white-box test). Dependency direction: the test imports `github.com/yangwb1123/snaplink/shared/core` (test-only; the require+replace already exists in the nested go.mod) and `gopkg.in/yaml.v3` (already in the module graph). `shared/core` imports no Snaplink package; no upward or cyclic edge is introduced. No package imports `cmd/`.

## 5. Requirements

### R1 — openapi.yaml anchor test (net-new)

Extend `cmd/sso-operator/controller/adminpaths_parity_test.go` with `TestAdminPathsMatchOpenAPIDocumentation` (same file as the existing consts-parity test — one file per concern; the file header comment's stale `root_consts_parity_test.go` self-reference is corrected in the same edit):

- Parse `../../docs/openapi.yaml` (relative to the package dir — `go test` runs with CWD = the package source dir, so the path is stable; the file is committed at the repo root and must exist).
- Assert `paths` contains exactly the two keys:
  - `"/api/v1/admin/config/running"` with a `get` operation (running is fetched with GET at `http.go:50`);
  - `"/api/v1/admin/config/cluster-diff"` with a `post` operation (cluster-diff is POSTed at `http.go:88`).
- Assert byte-equality of the operator constants against the documented keys: `runningConfigPath == "/api/v1/admin/config/running"` and `clusterDiffPath == "/api/v1/admin/config/cluster-diff"` (extracted from the parsed doc, never re-typed literals in the test).
- Assert the documented keys equal the root-owned const semantics: `"/api/v1/admin/config/running" == core.PathAPIPrefix + core.PathAdminConfigRunning` and `"/api/v1/admin/config/cluster-diff" == core.PathAPIPrefix + core.PathAdminConfigClusterDiff`.
- Failure messages name all three copies byte-for-byte (operator const, documented path, `PathAPIPrefix+consts`) so a drift is self-explaining.

Together with the existing `TestAdminPathConstsMatchRootOwnedConstants` (operator consts ↔ root consts) and `TestConfigAudit_OperatorPaths_GateAwareTruthiness` (root consts ↔ live mounted routes), the chain operator-consts → openapi.yaml → root-consts → mounted-routes is fully pinned: any single break fails at least one test, and no two-copy coordinated rename can hide.

### R2 — Consts-parity test (already landed; pin as regression)

`TestAdminPathConstsMatchRootOwnedConstants` in the same file stays as-is: `runningConfigPath == core.PathAPIPrefix + core.PathAdminConfigRunning` and `clusterDiffPath == core.PathAPIPrefix + core.PathAdminConfigClusterDiff`. It is the inner triangle edge; R1 makes the same assertion through the doc anchor so that a coordinated Go-const rename cannot silently pass both.

### R3 — Server-side mount sweep (already landed; pin as regression)

`TestConfigAudit_OperatorPaths_GateAwareTruthiness` in `interfaces/sso/config_audit_test.go` stays as-is: a real `sso.NewServer(sso.WithConfigSnapshots(applied, runningFn))` (gate default ON, snapshots wired) answers GET `PathAPIPrefix+PathAdminConfigRunning` with 200 and POST `PathAPIPrefix+PathAdminConfigClusterDiff` with a `{"snapshot":{...}}` body with 200 — the "non-404/non-501 when wired" clause of the acceptance, asserted at 200 which is strictly stronger. Gate-closed byte-identity with the never-mounted baseline and re-open recovery are preserved.

### Testable acceptance (Given/When/Then)

All operator cases run under `cd cmd/sso-operator && go test -race -count=1 ./...` — the exact `Makefile:263` gate command (`make ci` → `ci-modules`); root gates never descend into nested modules, precedented by every nested module. The server-side case runs under the root suite.

R1 openapi sweep (new):

1. Given the committed `../../docs/openapi.yaml` and the controller package, when `TestAdminPathsMatchOpenAPIDocumentation` runs, then it passes: both documented paths exist with the right methods, equal the operator constants byte-for-byte, and equal `core.PathAPIPrefix + core.PathAdminConfigRunning` / `core.PathAdminConfigClusterDiff`.
2. Given a hypothetical rename of `runningConfigPath` to `/api/v1/admin/config/live`, when the test runs, then it fails naming both the operator constant and the documented path.
3. Given a hypothetical rename of `core.PathAdminConfigRunning` (e.g. `/admin/config/current`) in both Go consts, when the test runs, then it fails on the doc-vs-consts assertion even though the operator-consts-vs-root-consts parity (R2) still passes — the coordinated-rename tripwire the consts-only parity cannot provide.
4. Given a hypothetical removal of the `post` operation (or the whole path) for `/api/v1/admin/config/cluster-diff` from openapi.yaml, when the test runs, then it fails on method fidelity or path presence.
5. Given a hypothetical deletion of `docs/openapi.yaml` from the tree, when the test runs, then it fails loudly (file missing — the document is committed, so a missing file is drift, not an environment condition).

R2/R3 pins (regression):

6. Given the current worktree, when `TestAdminPathConstsMatchRootOwnedConstants` runs under the `Makefile:263` command, then it passes unchanged (no edits to its assertions).
7. Given the current worktree, when `TestConfigAudit_OperatorPaths_GateAwareTruthiness` runs under the root suite, then it passes unchanged: wired server, gate open → GET running 200 and POST cluster-diff (with snapshot body) 200 — non-404/non-501; gate closed → both byte-identical to the never-mounted baseline; re-open → 200 again.
8. Given the change, when the full existing operator controller test set runs (`TestReconcile_*` × 8, `TestAdminPathConstsMatchRootOwnedConstants`, the truthiness/validate tests) under `cd cmd/sso-operator && go test -race -count=1 ./...`, then all pass unchanged — no existing test is modified or deleted, and no test expectation changes.

### Acceptance mapping grade: 9/9 machine-checked

Cases 1–8 are Go tests failing loudly under a named gate (`ci-modules` for the operator cases, the root suite for case 7); none is review-only. Case 1 is net-new coverage (nothing parses openapi.yaml in the operator module today); cases 6–7 pin the acceptance's already-landed halves; case 8 is the regression clause, machine-checked by the unchanged suite.

## 6. Engineering-gate constraints (verified)

- **Budgets**: `cmd/sso-operator/controller` holds 3 non-test files (`http.go` 133, `ssoconfigdrift_controller.go` 243, `validate.go` 151) against the 10-file cap and 4 test files; the change adds ~60–70 lines to one test file — no file approaches 500 lines, no function approaches 50, complexity/nesting trivial. No new package, no `layerExemptions`, no fan-out pressure.
- **`interfaces/sso` file ceiling**: at 60 non-test files; no non-test file is added or touched — the server-side pin lives in the already-modified `config_audit_test.go` (`_test.go` exempt).
- **Nested-module go.mod**: no new module path. `gopkg.in/yaml.v3 v3.0.1` is already in the graph (indirect, go.mod:58); `go mod tidy` after the test import promotes it to the direct require block — one-line move, zero go.sum additions beyond the existing MVS-aligned set from the sibling change. The root `require`/`replace` stays untouched.
- **Root gates**: no root `.go` production edits, so `go build ./... && go vet ./...` and `TestMaintainability_|TestArchitecture_` are unaffected; the nested change is detected only via `ci-modules` (Makefile:263), the precedented boundary.
- **Wire/contract invariants untouched**: no routes, `Err*`, config keys, audit events, or credential surfaces; oracle-safe response tables unaffected; no SSRF surface (tests read a committed file, no outbound fetch).
- **`python cli.py modules check`**: validates module manifests/profiles, not nested go.mod contents; passes at baseline, unaffected.

## 7. Files

### Create

None (the test extends the existing file below).

### Modify

```text
cmd/sso-operator/controller/adminpaths_parity_test.go — R1:
    add TestAdminPathsMatchOpenAPIDocumentation (parses ../../docs/openapi.yaml
    via gopkg.in/yaml.v3; asserts documented paths + get/post method fidelity ==
    runningConfigPath/clusterDiffPath byte-for-byte, and == core.PathAPIPrefix +
    core.PathAdminConfigRunning / core.PathAdminConfigClusterDiff; self-explaining
    failure messages); correct the stale "root_consts_parity_test.go" filename in
    the file header comment.
```

### Do not modify

```text
cmd/sso-operator/controller/ssoconfigdrift_controller.go, http.go, validate.go — the
    constants stay; this direction locks them with tests (runtime import out of scope).
cmd/sso-operator/go.mod, go.sum — already carry the test-only root require/replace
    and yaml.v3; tidy may promote yaml.v3 to direct, nothing else.
interfaces/sso/config_audit_test.go — the landed R3 pin stays untouched.
docs/openapi.yaml, shared/core/*, platform/configaudit/*, Makefile,
cmd/sso-operator/apiv1alpha1/*, crd-ssoconfigdrift.yaml, main.go, root go.mod/go.sum.
```

## 8. Dependencies and compatibility

- New/changed SPI: none (test-only).
- New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: none (no production code path changes).
- Module graph: `gopkg.in/yaml.v3` promoted indirect → direct in the nested go.mod on tidy; no new module paths; the operator binary stays root-free (`go list -deps .` unchanged — test files are not linked into `sso-operator`).
- Rollout/rollback: additive test; removing it restores the previous tree exactly. Reverting the comment correction is a no-op edit.

## 9. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [ ] `docs/openapi.yaml` — not applicable as an *output*; it is the immutable anchor this change asserts against. If the sweep fails, the doc or the code is genuinely drifted and the fix is a separate deliberate contract change.
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`).
- [x] Campaign bookkeeping: `docs/campaigns/implementation-gate.md` row 3 (B4-3, 部署仓) — completes the admin-endpoint truthiness half of the deploy-tree sweep (T-2): operator admin calls pinned to the documented contract via the openapi.yaml anchor, closing the triangle with the landed consts parity and the gate-aware server-side sweep. The "不得带入部署仓" constraint is untouched (no legacy defect assertions added anywhere).

## 10. Verification plan

```bash
cd cmd/sso-operator && go mod tidy && go build ./... && go vet ./...
cd cmd/sso-operator && go test -race -count=1 ./...        # ci-modules gate command (Makefile:263)
cd cmd/sso-operator && go test -race -count=1 ./controller/ -run 'TestAdminPaths' -v
go build ./... && go vet ./...                             # root module unaffected
go test ./interfaces/sso/ -run 'TestConfigAudit_OperatorPaths' -v   # R3 pin
go test -run 'TestMaintainability_|TestArchitecture_' .    # root gates
python cli.py modules check                                # baseline passes; unchanged surface
make ci                                                    # full gate incl. ci-modules
```

Pre-existing conditions to report separately: none found — the operator module builds and `go test -race -count=1 ./...` is green at spec time (controller 0.112s including the worktree's uncommitted parity/truthiness/validate tests), and the root suite's `TestConfigAudit_OperatorPaths_GateAwareTruthiness` passes. The two "stale" citations in the direction's evidence (go.mod root dependency; "no test asserts the concatenation") are superseded by the already-landed sibling work, which this spec pins rather than re-implements.
