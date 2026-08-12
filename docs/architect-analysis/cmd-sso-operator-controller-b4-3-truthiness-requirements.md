# Requirements Spec: truthiness validation of cluster-diff/running responses — never report "no drift" on unverifiable data

- Direction: "Truthiness validation of cluster-diff/running responses: never report 'no drift' on unverifiable data (B4-3 deploy-tree sweep, T-2)" (source: `docs/architect-analysis/auto/analyses/cmd-sso-operator-controller-6371f05a.json`, entry 1, the selected direction)
- Analysis module: `cmd/sso-operator/controller`; change surface: one new production file + one new unit-test file + one new reconcile-level test file in `cmd/sso-operator/controller/`; two call sites in `runCheck`. No other module, no root-module edits.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `postClusterDiff` at `http.go:69-95` "returns parsed.Patch with zero structural validation" | Function is at `http.go:82-118`. The cited behavior is at 108-117: `json.Unmarshal(body, &parsed)` into `clusterDiffResponse{Patch []patchOp}` then `return parsed.Patch` — no op-name, path, or snapshot-resolution check anywhere. Cited range is offset by ~13 lines (covers `patchOp`/`clusterDiffResponse` types at 27-36); substance exact | Confirmed (line numbers shifted, behavior exact) |
| `fetchRunningConfig` at `http.go:34-67` "accepts any body with a non-nil 'running' key, whatever its shape" | Function is at `http.go:49-80`. The only checks are `json.Unmarshal` into `map[string]interface{}` (object-ness enforced by the decoder) and `parsed.Running == nil` (70-79). `{"running": {}}` — an empty object — passes and yields an empty snapshot | Confirmed (line numbers shifted, behavior exact) |
| `runCheck` at `ssoconfigdrift_controller.go:118-150` sets `DriftDetected = len(patch) > 0` | Function is at `ssoconfigdrift_controller.go:130-162`; `driftDetected: len(patch) > 0` at line 158. A `200 {"patch":[]}` (or any structurally meaningless patch) therefore yields `driftDetected=false` → "no drift" | Confirmed (line numbers shifted, behavior exact) |
| Server emit set documented at `platform/configaudit/diff.go:20-27`; ops emitted at `diff.go:59,61,79` | `Diff` doc comment "Documented limits" at 15-30; "Only add/replace/remove ops are produced — no move/copy/test" at line 27. `add` at 59, `remove` at 61, `replace` at 79 | Confirmed (exact) |
| Emitted paths are "/"-rooted into the snapshot | `diffMaps` builds every child path as `parent + "/" + escapePointerSegment(k)` (`diff.go:57-58`); the root call starts at `""` (`diff.go:36`), so every emitted path has ≥1 segment and starts with "/". The root pointer `""` is never emitted. Escaping is strict RFC 6901 (`~`→`~0`, `/`→`~1`, order preserved, `diff.go:86-92`) | Confirmed |
| Server-side redaction preserves op structure | `RedactOps` (`platform/configaudit/redact.go:33-45`) rewrites only the `Value` of sensitive add/replace ops; `Op`/`Path` pass through verbatim — the operator sees server-emitted ops structurally unchanged | Confirmed (strengthens the direction: the emit set is observable at the wire) |
| Server rejects an empty snapshot | `HandleClusterDiff` (`platform/configaudit/handlers.go:105`): `err != nil \|\| len(req.Snapshot) == 0` → 400 `invalid_request`. A real cluster B never answers `200 {"patch":[]}` to an empty snapshot — so a 200 on an empty snapshot is unverifiable by definition | Confirmed (new finding, anchors acceptance (b)) |
| "The 8 existing tests use only hand-rolled fake servers and cover no invalid-patch case" | `ssoconfigdrift_controller_test.go` has exactly 8 `TestReconcile_*` functions (lines 139, 168, 188, 211, 232, 287, 305, 327). All use `runningServer`/`diffServer` httptest helpers; no test feeds a `move`/`copy`/`test` op, an unresolvable path, or an empty/non-object running body | Confirmed (exact) |
| "Status.DriftDetected unchanged on failure (never reset to false)" | Already the mechanism: `applyResult` (`ssoconfigdrift_controller.go:177-186`) writes `DriftDetected`/`PatchOpCount` only when `!result.failed`; a failed check keeps prior values. The direction's acceptance therefore asserts *existing* semantics on a *new* failure path | Confirmed (the acceptance is implementable with no `applyResult` change) |
| "Nested module `cmd/sso-operator/go.mod` has k8s-only deps, no go.work" | go.mod requires `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`, `sigs.k8s.io/controller-runtime` only. Production code imports only operator-local packages; the root import (`shared/core`) exists solely in `controller/adminpaths_parity_test.go` (test-only, via the `replace => ../../` directive). No `go.work` at root or in `cmd/sso-operator` | Confirmed, with nuance: a `replace` directive exists, so a root import *would* compile — but the direction's point stands as policy: the structural check is fully specifiable from the server's *documented* emit set and must NOT import `platform/configaudit` (preserves the out-of-process module posture; the parity pattern of `adminpaths_parity_test.go` remains the only sanctioned root touch) |
| B4-3 / T-2 mapping | `docs/campaigns/campaign-snaplink-b4.yaml` lines 64-68: "(3) discovery truthiness … deploy tree gets sweep/truthiness assertions"; `docs/campaigns/implementation-gate.md` row 3 is the deploy-tree (部署仓) row with T-2 "sweep 全绿". Sibling operator half already landed: `controller/adminpaths_parity_test.go`; sibling spec: `docs/architect-analysis/cmd-sso-operator-b4-3-crd-parity-requirements.md` (apiv1alpha1) | Confirmed — this spec is the controller half of the same row |
| Pre-existing conditions at HEAD | `cd cmd/sso-operator && go build ./... && go vet ./... && go test -count=1 ./...` green (controller 0.090s) — run at spec time | Confirmed |

## 2. Goal and user outcome

`runCheck` treats any 200 body from either admin endpoint as ground truth: `postClusterDiff` returns `parsed.Patch` with no structural validation, `fetchRunningConfig` accepts any non-nil `running` object, and `DriftDetected = len(patch) > 0`. A degraded or legacy cluster B, a proxy serving a canned `{"patch":[]}`, or an empty/degenerate running snapshot therefore surfaces as "no drift" — a false negative in the G1 trust path that the B4-3 deploy-tree sweep exists to catch. The server's emit contract is documented and bounded (only `add`/`remove`/`replace`, `/`-rooted RFC 6901 paths that resolve into the submitted snapshot, non-empty snapshots), so the operator can verify responses against that contract locally, without importing the server.

Completion marker: a running snapshot that is not a non-empty JSON object, or a cluster-diff patch containing an op outside `{add, remove, replace}` or a path the server could not have emitted, yields `failed=true` with a token-free reason in `Status.Message`; `Status.DriftDetected`/`PatchOpCount` keep their previous values (never reset to a false "no drift"); server-legitimate patches and the existing 8 reconcile tests behave exactly as today.

## 3. Product boundary

- Surface: `cmd/sso-operator/controller/` only — one new production file (`validate.go`, name at implementer's discretion) with two free functions, two call sites in `runCheck` (`ssoconfigdrift_controller.go:130-162`), plus tests. Read-only report-only behavior is preserved (doc.go non-goals: no apply, no canary, no remediation — validation adds no write path).
- Explicit non-goals (do not implement):
  - No import of `platform/configaudit` or any root package in production code. The check is derived from the server's *documented* contract and lives operator-side (same posture as `adminpaths_parity_test.go`'s test-only root import; production stays root-free).
  - No changes to `http.go` transport semantics, `applyResult`, `summarize`, `checkResult`, the CRD, `doc.go`, `main.go`, RBAC, audit, config keys, `Err*`, or OpenAPI.
  - No value-shape checks: `add`/`replace` `Value` may be any JSON value including `null`, and a `remove` carrying a `value` is not rejected — `patchOp`'s own doc (http.go:27-31) states the controller only counts/reports ops, never applies them, and RFC 6902 tolerates the extra field. The acceptance (c) requires ops be accepted *unchanged*, so no op rewriting.
  - No "add at an existing snapshot key" rejection. The acceptance (a) is one-directional ("an op whose path references no snapshot key"); the converse is not in the acceptance and is deferred (see §5 decision D2).
  - No op-order/duplicate/sortedness checks (the server sorts by path, `diff.go:32-33`, but order does not affect the truthiness of `len(patch) > 0`).
  - No `patch: null` vs `patch: []` distinction: the decoder maps both to a nil/empty slice and the server always emits `[]` (non-nil after `RedactOps`, `redact.go:34`); rejecting nil is a possible 3-line future tightening but is not in the acceptance.
  - No schema-level knowledge of the config model (which keys a real snapshot must contain). Only the documented emit set + the server's own empty-snapshot contract are enforced.

## 4. Module classification

- [x] Infrastructure/config/deployment (deploy-tree truthiness assertion — the controller half of B4-3, T-2)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer: `cmd/sso-operator/controller` (nested module; no new imports at all — validation is pure stdlib over `map[string]interface{}` and `patchOp`).

## 5. Requirements

### R1 — Structural validation of the cluster-diff patch

New file `cmd/sso-operator/controller/validate.go` (`package controller`, stdlib only). Free function:

```go
func validatePatch(patch []patchOp, snapshot map[string]interface{}) error
```

called from `runCheck` immediately after a successful `postClusterDiff`. It returns nil for a patch the server could have emitted; otherwise a non-empty error whose text names the failing op index and reason (implementer's wording; must not contain the bearer token — it cannot: the function receives neither tokens nor requests).

Per-op rules (each violation → error):

1. `op.Op` ∈ `{"add", "remove", "replace"}` — rejects `move`/`copy`/`test`/empty/unknown (the server's documented emit set, `diff.go:27,59,61,79`).
2. `op.Path` non-empty and starts with `/` (the server never emits the root pointer `""`; every emitted path has ≥1 segment, `diff.go:36,57-58`).
3. `op.Path` is valid RFC 6901: each segment unescapes strictly (`~` must be followed by `0` or `1`; `~2` etc. are invalid — the server's `escapePointerSegment`, `diff.go:86-92`, produces only `~0`/`~1`).
4. The path resolves into `snapshot` per RFC 6901 with every *intermediate* node an object (`map[string]interface{}`) — the server recurses only into objects (`diffMaps`), never into arrays (whole-array replace, `diff.go:18-21`) or through scalars:
   - `remove`/`replace`: the full path must resolve (the node exists in the snapshot; server emits `remove` only for keys present in `before`, `replace` only for keys present on both sides).
   - `add`: the parent path (path minus the last segment) must resolve to an object; the added key itself may be absent or present (the parent object is what the server recursed into, `diff.go:55-63`).
   - Empty patch (no ops) is valid — `validatePatch(nil or empty slice, …)` returns nil (an empty patch is exactly how "no drift" is truthfully reported today; `TestReconcile_NoDrift` depends on it).

### R2 — Structural validation of the running snapshot

Same file. Free function:

```go
func validateRunningSnapshot(running map[string]interface{}) error
```

called from `runCheck` immediately after a successful `fetchRunningConfig` and before `postClusterDiff`. Rule: `len(running) > 0` — an empty snapshot is rejected. Rationale is the server's own wire contract: `HandleClusterDiff` answers 400 to `len(req.Snapshot) == 0` (`handlers.go:105`), so a cluster B that 200s an empty patch for an empty snapshot is not a genuine server pair, and a cluster A whose running config is an empty object is itself a degraded/unverifiable source. Object-ness of the running body is already enforced by the decoder (`json.Unmarshal` into `map[string]interface{}`, `http.go:70-71`) — non-object shapes (`{"running": [1,2]}`, `{"running": "x"}`) fail in `fetchRunningConfig` today and stay failing (pinned by A3).

### R3 — Failure wiring in runCheck

`runCheck` (`ssoconfigdrift_controller.go:130-162`) gains two failure returns, in order:

```go
running, err := fetchRunningConfig(...)            // existing
if err != nil { ... }                              // existing
if err := validateRunningSnapshot(running); err != nil {
    return checkResult{failed: true, message: fmt.Sprintf("cluster A running config failed structural validation: %s", err)}
}
patch, err := postClusterDiff(...)                 // existing
if err != nil { ... }                              // existing
if err := validatePatch(patch, running); err != nil {
    return checkResult{failed: true, message: fmt.Sprintf("cluster B diff response failed structural validation: %s", err)}
}
```

No changes to `checkResult`, `applyResult`, `summarize`, or the success path: valid patches still produce `driftDetected = len(patch) > 0`, `patchOpCount = len(patch)`, `message = summarize(len(patch))`, and `RequeueAfter = requeueInterval(cr, failed)` — the failed path keeps the existing `shortRequeueInterval` (30s) cadence.

### D1 — Decision: validation is a new file, not http.go

`http.go` stays transport-only (fetch/parse/describe). Validation is controller policy over already-parsed data, lives in `validate.go` with `runCheck` as the only caller, and is directly unit-testable without HTTP or a fake client. Budget check: `controller/` goes from 2 → 3 non-test files (limit 10) and 4 → 7 total files (no total-file gate; the 10-file cap is on non-test files only); `validate.go` ~90-120 lines, no function approaches 50 lines, complexity trivial. `ssoconfigdrift_controller_test.go` (344 lines) is NOT extended beyond necessity — reconcile-level truthiness tests go in a new `ssoconfigdrift_truthiness_test.go` to keep every file well under 500 lines.

### D2 — Decision: "add at an existing snapshot key" and `patch: null` are deferred

The server never emits `add` for a key present in the snapshot (it emits `add` only for `after`-only keys, `diff.go:55-59`), so rejecting that case would tighten truthiness further; likewise a `null` patch body is never server-emitted. Both are deliberately OUT of the acceptance's enumerated cases: (a) is one-directional, (b) is about the running body, (c) requires the documented set to pass unchanged. Adding either rule risks over-rejecting against unknown future server evolution for zero acceptance coverage today; each is a ≤3-line future tightening if a canned-response variant shows up in the field.

### Testable acceptance (Given/When/Then)

All cases run under `cd cmd/sso-operator && go test -race -count=1 ./...` (the exact `Makefile:263` gate command; `make ci` → `ci-modules`). The root-module gates (`go build ./...`, `TestMaintainability_|TestArchitecture_`) do not descend into nested modules — `ci-modules` is the detection boundary.

Unit level — `validate.go` tests, table-driven, no HTTP (`validate_test.go`):

1. Given a patch with one op `{"op":"move","path":"/issuer"}` (table variants: `copy`, `test`, `""`, `"unknown"`), when `validatePatch` runs against any non-empty snapshot, then error is non-nil and names the op.
2. Given `{"op":"remove","path":"/nonexistent"}` or `{"op":"replace","path":"/nonexistent"}` with snapshot `{"issuer": "https://a.example"}`, when `validatePatch` runs, then error is non-nil (path references no snapshot key).
3. Given `{"op":"add","path":"/no_such_parent/x"}` with the same snapshot, when `validatePatch` runs, then error is non-nil (parent does not resolve).
4. Given paths `"issuer"` (no leading `/`), `""`, `"/iss~2uer"` (invalid escape), `"/issuer/nested"` (intermediate `issuer` is a scalar), and `"/clients/0/name"` with snapshot `{"issuer": "x", "clients": [{"name": "c"}]}` (intermediate segment indexes an array), when `validatePatch` runs on a `replace` op, then error is non-nil for each.
5. Given the server-legitimate patch `[{"op":"replace","path":"/issuer"}, {"op":"add","path":"/new_field","value":true}]` with snapshot `{"issuer": "https://a.example"}` (the exact fixture of `TestReconcile_DriftDetected`), when `validatePatch` runs, then nil; given `[{"op":"replace","path":"/clients/c1/redirect_uris","value":["u1"]}, {"op":"remove","path":"/old_key"}]` with snapshot `{"clients": {"c1": {"redirect_uris": ["u0"]}}, "old_key": 1}`, then nil (nested object paths resolve; `remove` on an existing key passes; array-valued replace at a resolvable path passes).
6. Given a nil or empty patch slice, when `validatePatch` runs, then nil (empty patch stays truthful "no drift").
7. Given `validateRunningSnapshot({})`, when called, then error non-nil; given `validateRunningSnapshot({"issuer": "x"})`, then nil.

Reconcile level — `ssoconfigdrift_truthiness_test.go`, reusing `buildReconciler`/`runningServer`/`diffServer` from the existing test file (same package):

8. (Acceptance a, op set.) Given cluster A returns `{"running": {"issuer": "https://a.example"}}` and cluster B returns `200 {"patch":[{"op":"move","path":"/issuer"}]}`, when `Reconcile` runs on a fresh CR, then `Status.Message` is non-empty and does not contain the bearer token, `Status.DriftDetected` is unchanged (false — never reset *to* anything), `Status.PatchOpCount` is unchanged (0), and the result's `RequeueAfter == shortRequeueInterval`. Given the same servers but a CR pre-seeded with `Status.DriftDetected=true, PatchOpCount=3`, when `Reconcile` runs, then `DriftDetected` is still true and `PatchOpCount` still 3 (never reset to false on unverifiable data).
9. (Acceptance a, path resolution.) Same as 8 with cluster B returning `200 {"patch":[{"op":"remove","path":"/no_such_key"}]}` (one variant is enough at reconcile level; the resolution matrix is covered by cases 2-4 at unit level): `failed` outcome, `Message` non-empty, `DriftDetected` unchanged.
10. (Acceptance b.) Given cluster A returns `{"running": {}}` (empty object — structurally invalid) and cluster B returns `200 {"patch":[]}`, when `Reconcile` runs, then `Status.Message` is non-empty (NOT the "no drift" summary), `DriftDetected` unchanged, `PatchOpCount` unchanged. The POST to cluster B never happens (validation fires first) — assert via a `diffServer`-replacement handler that fails the test if contacted. Pin variants that already fail today: cluster A returning `{"running": [1,2,3]}` and `{"running": "x"}` also yield `failed=true` with non-empty Message (decode path, regression lock).
11. (Acceptance c.) Given cluster A returns `{"running": {"issuer": "https://a.example"}}` and cluster B returns the server-legitimate `[{"op":"replace","path":"/issuer","value":"https://b.example"},{"op":"add","path":"/new_field","value":true}]`, when `Reconcile` runs, then `Status.DriftDetected == true`, `PatchOpCount == 2`, `Message == "drift detected: 2 patch operation(s) needed on cluster B"` — the ops are accepted unchanged (same observable outcome as `TestReconcile_DriftDetected` today).
12. (Regression.) All 8 existing `TestReconcile_*` tests pass unchanged — in particular `TestReconcile_NoDrift` (empty patch + non-empty running → no drift) and `TestReconcile_DriftDetected` (cases 5/11's fixture at reconcile level).

### Acceptance mapping grade: 12/12 machine-checked

Every case is a Go test failing loudly under the named gate (`ci-modules`, `Makefile:263`); none is review-only. Cases 1-7 are net-new unit coverage of the two validation functions; 8-10 are the direction's acceptance (a)/(b) at the observable `Status` level including the "never reset to false" semantics (8's pre-seeded variant is the sharp assertion); 11 is acceptance (c); 12 is the regression requirement. Cases 4/7 partially pin already-failing decode paths (b's "whatever its shape" half) — cheap locks, no behavior change.

## 6. Engineering-gate constraints (verified)

- **Budgets**: `controller/` has 2 non-test files today; +1 (`validate.go`) = 3 ≤ 10. Total files 4 → 7 (no total-file gate; the 10-file cap is non-test only). New test file sizes ~120-180 lines each; `validate.go` ~90-120 lines; no file approaches 500 lines, no function approaches 50, no `if` nesting beyond 3, complexity trivial. No new packages, no `layerExemptions`, no upward imports.
- **Nested-module go.mod**: zero changes — validation is stdlib-only over existing types (`patchOp`, `map[string]interface{}`). No new module paths, no `go.work`, no go.sum changes.
- **Root module**: no root `.go` edits; root gates (`go build ./... && go vet ./...`, `TestMaintainability_|TestArchitecture_`) unaffected; `make ci` picks up the change only via `ci-modules` (Makefile:263).
- **Wire/contract invariants untouched**: no routes, `Err*`, config keys, audit events, credential surfaces, or oracle-safe tables; no SSRF surface; no new HTTP behavior (validation is client-side, before/after the same two requests).
- **Fail-open doctrine preserved**: `runCheck` still returns `failed=true` + Message instead of a non-nil error for HTTP/parse/validation failures; `Reconcile` still never errors on those; the CR status-update error path is unchanged. The new checks convert a *false "no drift"* into a *truthful failure* — strictly more conservative, never less.
- **`python cli.py modules check`**: unaffected (validates module manifests/profiles, not nested go.mod contents); passes at baseline.

## 7. Files

### Create

```text
cmd/sso-operator/controller/validate.go — R1 + R2
    (package controller; validatePatch + validateRunningSnapshot + RFC 6901
    strict-unescape/path-resolution helpers; stdlib only; nil/empty patch
    accepted; error text names op index + reason).

cmd/sso-operator/controller/validate_test.go — acceptance cases 1-7
    (package controller; table-driven, no HTTP, no fake client).

cmd/sso-operator/controller/ssoconfigdrift_truthiness_test.go — cases 8-12
    (package controller; reuses buildReconciler/runningServer/diffServer;
    pre-seeded-status CR for the never-reset-to-false assertion; a
    contact-fail handler for the "POST never happens" assertion in case 10).
```

### Modify

```text
cmd/sso-operator/controller/ssoconfigdrift_controller.go — runCheck
    (lines 130-162): two validation call sites per R3; nothing else.
```

### Do not modify

```text
cmd/sso-operator/controller/http.go, adminpaths_parity_test.go,
ssoconfigdrift_controller_test.go (existing 8 tests stay byte-identical),
apiv1alpha1/*, crd-ssoconfigdrift.yaml, doc.go, main.go, go.mod, go.sum,
Makefile, root go.mod/go.sum, platform/configaudit/*, interfaces/sso/*,
shared/core/*.
```

## 8. Dependencies and compatibility

- New/changed SPI: none. The two new functions are unexported and called only from `runCheck`; the wire contract, status shape, and CRD are untouched.
- New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: none.
- Module graph: no change.
- Rollout/rollback: additive validation + tests; reverting the two `runCheck` call sites restores HEAD behavior exactly while the new tests then fail (the intended tripwire). A brief window where a degraded cluster B that previously produced "no drift" now produces `failed=true` is the intended behavior change, not a regression.

## 9. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [ ] `docs/openapi.yaml` — not applicable (no endpoint change).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`).
- [x] Campaign bookkeeping: `docs/campaigns/implementation-gate.md` row 3 (B4-3 deploy-tree) — this completes the controller half of the deploy-tree sweep/truthiness contract for the operator's HTTP response handling, sibling to the landed path-parity test (`adminpaths_parity_test.go`) and the apiv1alpha1 CRD-parity spec; the "不得带入部署仓" (no legacy defect assertions) constraint is untouched.

## 10. Verification plan

```bash
cd cmd/sso-operator && go build ./... && go vet ./...
cd cmd/sso-operator && go test -race -count=1 ./...   # ci-modules gate command (Makefile:263)
cd cmd/sso-operator && go test -race -count=1 ./controller/ -v   # focused: 12 acceptance cases
go build ./... && go vet ./...                       # root module unaffected (no root .go edits)
go test -run 'TestMaintainability_|TestArchitecture_' .          # root gates unaffected
python cli.py modules check                          # baseline passes; unchanged surface
make ci                                              # full gate incl. ci-modules
```

Pre-existing conditions to report separately: none found — the operator module builds, vets, and tests green at HEAD (controller 0.090s, run at spec time), and the acceptance's failure modes (move op, unresolvable path, empty running body + empty patch) all currently produce the false "no drift" the direction describes, i.e. the new tests fail on HEAD by design.
