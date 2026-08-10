# Design: openapi.yaml-anchored admin-path sweep for `cmd/sso-operator/controller`

Companion to `docs/architect-analysis/cmd-sso-operator-controller-b4-3-adminpaths-sweep-requirements.md`.
This document treats that spec (and the direction evidence it cites) as
untrusted evidence, records what was independently verified, and turns the
requirements into a concrete, ordered design with API changes, compatibility
constraints, failure modes, migration steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation was re-checked against the worktree (source files, go.mod,
Makefile, openapi.yaml, and a live `go test` run). Net result: all
substance confirmed; three corrections — the consts' line numbers drift by
~8 lines, the parity test lives under a different name than the evidence's
wording suggests (both legs exist, in two different files), and the
requirements spec's R1 relative path is **wrong by one level** and is
corrected here.

| # | Claim | Verdict |
|---|---|---|
| E1 | `ssoconfigdrift_controller.go:47-51` hardcoded full-path constants | **Confirmed content, corrected lines** — actual: doc comment 36–38, `const (` 39, `runningConfigPath` 40, `clusterDiffPath` 41, `)` 42. The claimed 48–51 is ~8 lines stale (file is worktree-modified by the sibling deploy-tree direction). Cosmetic: tests reference symbols, never lines |
| E2 | `controller/http.go:50,58,67` — GET `baseURL+runningConfigPath` | Confirmed exact — 50 build request, 58 request error, 67 non-200 error |
| E3 | `controller/http.go:88,97,106` — POST `baseURL+clusterDiffPath` | Confirmed exact — 88 build request, 97 request error, 106 non-200 error |
| E4 | `shared/core/consts.go:34` — `PathAPIPrefix = "/api/v1"` | Confirmed exact |
| E5 | `shared/core/consts.go:463,467` — group-relative admin consts | Confirmed exact — `PathAdminConfigRunning = "/admin/config/running"` at 463, `PathAdminConfigClusterDiff = "/admin/config/cluster-diff"` at 467. Composition `PathAPIPrefix + const` equals each operator constant byte-for-byte |
| E6 | `docs/openapi.yaml:5340` running `get`, 200/401/501 | Confirmed exact — path key at 5340, `get` at 5341, responses `200`/`401`/`501` |
| E7 | `docs/openapi.yaml:5607` cluster-diff `post`, 200/400/401/501 | Confirmed exact — path key at 5607, `post` at 5608, responses `200`/`400`/`401`/`501` |
| E8 | `docs/openapi.yaml` — `paths:` at 143, `openapi: 3.0.3` | Confirmed exact — `paths:` at 143, `openapi: 3.0.3` at line 32 |
| E9 | `Makefile:263` operator gate inside `ci-modules` | Confirmed exact — `ci-modules` target at 250, line 263 is `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` |
| E10 | `cmd/sso-operator/go.mod` carries test-only root require+replace | Confirmed — `require github.com/yangwb1123/snaplink v0.0.0-… // test-only parity import of shared/core` plus `replace => ../../`; no `go.work` anywhere; production packages import nothing from the root (binary stays root-free) |
| E11 | "no test asserts the concatenation" (claimed stale) | **Confirmed stale as claimed, with a naming correction** — `cmd/sso-operator/controller/adminpaths_parity_test.go` (untracked) holds `TestAdminPathConstsMatchRootOwnedConstants`, which asserts `runningConfigPath == core.PathAPIPrefix+core.PathAdminConfigRunning` and the cluster-diff twin. The evidence's quoted `TestConfigAudit_OperatorPaths_GateAwareTruthiness` is a *different* landed leg: `interfaces/sso/config_audit_test.go:88` (worktree-modified), the three-phase gate-aware server sweep (200 gate open / byte-identical-404 gate closed / 200 re-open) |
| E12 | `TestReconcile_*` × 8 | Confirmed — 8 in `ssoconfigdrift_controller_test.go` (10 package-wide counting the truthiness file's `TestReconcile_InvalidOpSet_FailsPreservingStatus` and `TestReconcile_UnresolvablePath_FailsPreservingStatus`) |
| E13 | Nothing in the operator module parses openapi.yaml | Confirmed — repo-wide grep: only `go.mod`/`go.sum` metadata hits; net-new leg stands |
| E14 | Baseline green | Confirmed — `cd cmd/sso-operator && go test -count=1 ./controller/` → `ok … 0.098s` at review time |
| E15 | Requirements-spec R1 path `../../docs/openapi.yaml` | **Not verified — wrong by one level.** From the package dir `cmd/sso-operator/controller`, `../..` resolves to `cmd/`; `../../docs/openapi.yaml` = `cmd/docs/openapi.yaml`, which does not exist (`ls` fails). The correct relative path is `../../../docs/openapi.yaml` (controller → sso-operator → cmd → repo root). Corrected in §3.4 |

Net: no claim invalidates the scope. E1's line numbers drift (cosmetic);
E15 is a real bug in the spec's R1 wording that would make the new test
fail with a misleading file-missing error; E11 needs the file/naming
clarification above. The central design (a third, openapi.yaml-anchored
copy of the path contract as the only tripwire against a *coordinated*
rename of both Go consts) is sound and the acceptance legs are accurately
characterized.

## 2. Scope and non-goals (unchanged from the spec)

- Surface: one new test function + one comment correction in
  `cmd/sso-operator/controller/adminpaths_parity_test.go` (~60–70 lines).
- Non-goals: no production-code change in the operator (the constants stay
  local — runtime import of root consts is out of scope, nested-module
  posture per AGENTS.md §4); no edit to `docs/openapi.yaml` (it is the
  immutable anchor, not an output); no root-module edits (the server-side
  leg R3 is pinned, not re-implemented); no new module path, no `go.work`,
  no `Err*`/config keys/routes/audit events/RBAC/OpenAPI surface changes;
  no changes to `ssoconfigdrift_controller.go`, `http.go`, `validate.go`,
  CRD types/manifest, `main.go`, `Makefile`, `platform/configaudit/*`, or
  root `go.mod`/`go.sum`.

## 3. API changes

### 3.1 Production API

None. No exported symbol, route, config key, error code, or wire surface
changes anywhere. `runningConfigPath`/`clusterDiffPath` remain unexported
constants consumed at `http.go:50,88`; the server's `shared/core` consts
remain the mount-time truth. The only "API" moved is the *test-visible
contract*: the operator module gains a test that reads the committed
OpenAPI document.

### 3.2 Module-graph change (the only go.mod delta)

`gopkg.in/yaml.v3 v3.0.1` moves from the indirect require block
(go.mod:58) to the direct block after `go mod tidy` — same version, zero
go.sum additions (hashes already present from the sibling change). The
root `require`/`replace` block and the sibling's version bumps stay
untouched.

### 3.3 Test surface (API in the test sense)

`cmd/sso-operator/controller/adminpaths_parity_test.go` (`package
controller`, white-box):

- `TestAdminPathsMatchOpenAPIDocumentation` — net-new, R1.
- `TestAdminPathConstsMatchRootOwnedConstants` — existing, untouched (R2 pin).
- Header comment: correct the stale `root_consts_parity_test.go`
  self-reference to the actual filename in the same edit.

### 3.4 Internal design decisions

- **Relative path corrected (E15).** The doc is read via
  `../../../docs/openapi.yaml` from the package dir, held in a file-level
  `const openAPIDocPath` (no literal leak; AGENTS.md convention). `go test`
  runs each package with CWD = package source dir (documented Go
  behavior), so the path is stable under the fixed `Makefile:263` gate
  command; this is the same precedent as the sibling CRD-parity test's
  `../crd-ssoconfigdrift.yaml`.
- **Decode strategy.** `gopkg.in/yaml.v3` unmarshal into
  `map[string]any`; mappings decode as `map[string]any`, so
  `doc["paths"].(map[string]any)` is a plain string-key lookup. A typed
  struct is unnecessary — only two keys of one top-level section are read.
  Assert `paths` presence with a self-explaining fatal before indexing.
- **One helper, small functions.** `loadOpenAPIDoc(t)` (read + unmarshal
  + type-assert `paths`) and `assertDocPath(t, paths, opPath, method,
  rootOwned)` keep the main test and every function well under the 50-line
  budget; `assertDocPath` is `t.Helper()` so failures point at the call
  site.
- **Assertion set (exactly the spec's R1).** For each of the two
  operator-consumed paths, in one helper call:
  1. presence: the documented key equals the operator constant
     (`runningConfigPath`, `clusterDiffPath`) — extracted from the parsed
     doc, never re-typed literals;
  2. method fidelity: the path's operation object contains `get` for
     running (`http.go:50`) and `post` for cluster-diff (`http.go:88`);
  3. doc-vs-root-consts: the documented key equals
     `core.PathAPIPrefix + core.PathAdminConfigRunning` /
     `core.PathAdminConfigClusterDiff`.
  Each failure message names all three copies byte-for-byte (operator
  constant, documented path, root-const composition) so a drift is
  self-explaining.
- **Presence-only assertions.** The test asserts the expected method is
  present; it never asserts the *absence* of other methods or paths. The
  document legitimately grows; the tripwire must only catch the contract
  disappearing or re-semanticizing. Case 4's "removal of `post` or the
  whole path" is covered by the presence assertions.
- **Pre-fix state.** All three copies currently agree, so the new test
  passes immediately (measured baseline green, E14). Unlike the CRD
  direction, there is no red-to-green demonstration available at commit
  time; the tripwire behavior is demonstrated by the hypothetical
  mutations in §7, and optionally by a temporary local mutation that is
  reverted before commit (never a commit checkpoint).

## 4. Compatibility constraints

- **openapi.yaml is an immutable input.** The change never writes or
  rewrites the document; if the sweep fails, the doc or the code is
  genuinely drifted and the fix is a separate, deliberate contract change
  (spec §9's position, kept).
- **No production behavior delta.** Test-only addition; the operator
  binary stays root-free (`go list -deps` of the binary is unchanged —
  test files are never linked). All 8 `TestReconcile_*` plus the
  truthiness/validate tests run unchanged.
- **CWD assumption.** `go test` sets CWD to the package source dir; the
  gate command (`Makefile:263`) is fixed, so `../../../docs/openapi.yaml`
  is stable. A run from any other CWD (e.g. `go test` with an explicit
  absolute package path still uses the package dir) is not a real mode.
- **Module graph.** yaml.v3 promoted indirect→direct at the same version
  (v3.0.1); no new module paths; `go.yaml.in/yaml/v3` fork and
  sigs.k8s.io/yaml stay indirect; root go.mod/go.sum untouched. The
  sibling's worktree go.mod hunks (root require/replace, version bumps)
  must remain untouched — do not judge the tidy diff against a clean
  checkout.
- **Gate boundaries.** Root gates do not descend into nested modules;
  `ci-modules` (Makefile:263) is the detection boundary, same as every
  nested module. `python cli.py modules check` unaffected.
- **Wire/security surface.** None: no routes, `Err*`, config keys, audit
  events, credential handling, or SSRF surface (the test reads a
  committed local file; no outbound fetch). Oracle-safe response tables
  untouched.
- **Future doc evolution.** An OpenAPI 3.1 bump keeps the `paths` mapping
  shape (3.x-stable); if the document is ever restructured so `paths`
  disappears, the test fails loudly — accepted tripwire behavior, not a
  false positive (the file is committed and reviewed).
- **Worktree hygiene.** Unrelated modified/untracked files (sibling
  direction's `validate.go`, truthiness/parity tests, config_audit_test.go
  edits) are preserved untouched.

## 5. Failure modes

| Failure mode | Detection | Severity |
|---|---|---|
| **Coordinated rename of both Go consts** (operator const AND `shared/core` const renamed together, doc untouched) | R1 doc-vs-root-consts assertion fails — the only tripwire that sees it; R2 consts parity passes by construction | The exact drift class the direction exists for (stale documented contract, deploy-tree route silently re-semanticized) |
| Single-side drift: operator const renamed, or doc path renamed, or root const renamed | R1 and/or R2 fail, naming the diverging copies byte-for-byte | Tripwire |
| Method flip in doc (running documented `post`-only, or `post` removed from cluster-diff) | R1 method-fidelity assertion fails | Operator call targets a dead/foreign operation |
| Path removed from doc, doc deleted, or doc moved | R1 presence assertion or `os.ReadFile` fails loudly (file is committed; missing = drift, not environment) | Tripwire |
| `paths` section restructured (spec bump, tooling rewrite) | R1 type-assert fatal names the missing key | Loud by design |
| yaml.v3 version bump with breaking decode | parse failure fails the test | Low (pinned v3.0.1) |
| Server route renamed/remounted in code (root consts renamed, mount changed, gate behavior changed) | R3 `TestConfigAudit_OperatorPaths_GateAwareTruthiness` fails under the root suite | The live-mount leg of the triangle |
| Admin gate default flipped to OFF | R3 phase 1 fails (runs on the default gate state) | The flip detector |
| R2 consts parity regresses | `TestAdminPathConstsMatchRootOwnedConstants` fails | Inner triangle edge |
| Spec's wrong `../../docs/openapi.yaml` path accidentally implemented | file-missing failure with a misleading message | Prevented by design (§3.4); the correction is committed with the test |
| New test function exceeding 50 lines | maintenance gate | Prevented by the two-helper split (§3.4) |

## 6. Migration steps (ordered)

1. **Extend the parity test file.** Add `TestAdminPathsMatchOpenAPIDocumentation`
   (+ `loadOpenAPIDoc`/`assertDocPath` helpers + `openAPIDocPath` const) to
   `cmd/sso-operator/controller/adminpaths_parity_test.go`; correct the
   stale `root_consts_parity_test.go` header self-reference. Do not touch
   the existing `TestAdminPathConstsMatchRootOwnedConstants`.
2. **`cd cmd/sso-operator && go mod tidy`** — promotes `gopkg.in/yaml.v3`
   indirect→direct at v3.0.1. Verify only that one line moved and no
   yaml.v3 lines were added to `go.sum`; leave the sibling's root
   require/replace and version bumps untouched.
3. **Focused run**:
   `cd cmd/sso-operator && go test -race -count=1 ./controller/ -run 'TestAdminPaths' -v`
   — must pass immediately (all three copies agree today). Optionally
   demonstrate the tripwire with a temporary local mutation of
   `runningConfigPath`, then revert it; never commit the mutation.
4. **Full gates** (exact commands in §8): operator module build/vet/test
   (the `Makefile:263` command), root build/vet + maintainability/
   architecture gates, `python cli.py modules check`, `make ci`.
5. **Commit** — conventional, imperative ("test: anchor operator admin
   paths to docs/openapi.yaml"), body explains the triangle and the
   coordinated-rename blind spot it closes, AI co-author trailer, no
   binaries, unrelated worktree changes untouched.
6. **Rollback** — delete the added test function/helpers/const (and revert
   the comment correction); the tree returns to the previous state
   byte-for-byte with zero production impact. The test is additive.

## 7. Testable acceptance mapping

All eight spec acceptance cases map to named tests under the
`Makefile:263` gate command (`cd cmd/sso-operator && go test -race
-count=1 ./...`); case 7 runs under the root suite. Cases 1–5 are net-new
coverage (nothing parses openapi.yaml in the operator module today); 6–7
pin the already-landed legs; 8 is the regression clause.

| Case | Given/When/Then (spec §5) | Test (file: function) | Assertion mechanics |
|---|---|---|---|
| 1 | Committed doc + package; `TestAdminPathsMatchOpenAPIDocumentation` runs → passes | `adminpaths_parity_test.go: TestAdminPathsMatchOpenAPIDocumentation` | Parse `../../../docs/openapi.yaml`; both keys present with `get`/`post`; keys == operator consts; keys == `core.PathAPIPrefix + core.PathAdminConfig{Running,ClusterDiff}` |
| 2 | Hypothetical rename of `runningConfigPath` to `/api/v1/admin/config/live` → fails naming both copies | same, presence assertion | `paths[opPath]` lookup misses; message names operator constant and documented key |
| 3 | Hypothetical rename of `core.PathAdminConfigRunning` in both Go consts → fails even though R2 passes | same, doc-vs-root-consts assertion | documented key vs `PathAPIPrefix+const` mismatch; R2 (consts vs consts) still passes — the coordinated-rename tripwire |
| 4 | Hypothetical removal of `post` (or whole path) for cluster-diff → fails on method fidelity or presence | same, method assertion | operation object lacks `post` (or path missing) |
| 5 | Hypothetical deletion of `docs/openapi.yaml` → fails loudly (file missing) | same, `loadOpenAPIDoc` | `os.ReadFile` error in a `t.Fatalf` naming the path |
| 6 | Current worktree, R2 runs under the gate command → passes unchanged | `adminpaths_parity_test.go: TestAdminPathConstsMatchRootOwnedConstants` | unchanged assertions; no edits to its body |
| 7 | Current worktree, R3 runs under the root suite → passes unchanged: gate open → GET running 200 + POST cluster-diff (snapshot body) 200; gate closed → byte-identical 404 to the never-mounted baseline; re-open → 200 | `interfaces/sso/config_audit_test.go: TestConfigAudit_OperatorPaths_GateAwareTruthiness` | three-phase const-derived paths; `fghrAssertIdentical` byte-identity in phase 2 |
| 8 | Change lands; full operator suite (8 `TestReconcile_*` in controller_test.go + truthiness/validate/parity tests) under the gate command → all pass, none modified | whole `./...` suite | `cd cmd/sso-operator && go test -race -count=1 ./...` green |

## 8. Verification plan (exact commands)

```bash
cd cmd/sso-operator && go mod tidy && go build ./... && go vet ./...
cd cmd/sso-operator && go test -race -count=1 ./...                # ci-modules gate, Makefile:263
cd cmd/sso-operator && go test -race -count=1 ./controller/ -run 'TestAdminPaths' -v
go build ./... && go vet ./...                                     # root unaffected
go test ./interfaces/sso/ -run 'TestConfigAudit_OperatorPaths' -v  # R3 pin
go test -run 'TestMaintainability_|TestArchitecture_' .            # root gates unaffected
python cli.py modules check
make ci                                                            # full handoff gate
```

Pre-existing conditions: none found — the operator controller package
passes at review time (`ok … 0.098s`, including the worktree's uncommitted
parity/truthiness/validate tests) and the root suite's
`TestConfigAudit_OperatorPaths_GateAwareTruthiness` is present and green.
The two "stale" evidence citations (go.mod root dependency; "no test
asserts the concatenation") are superseded by landed sibling work that this
design pins rather than re-implements, and the spec's R1 path error (E15)
is corrected in §3.4.
