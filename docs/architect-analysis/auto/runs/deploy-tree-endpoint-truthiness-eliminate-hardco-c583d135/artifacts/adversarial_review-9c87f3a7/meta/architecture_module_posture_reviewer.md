All checks complete. Here is the compliance report.

## Compliance report: operator require+replace (design `c583d135`)

The design's build-level change is now applied in the working tree (uncommitted): `replace github.com/yangwb1123/snaplink => ../../` + test-only `require` in `cmd/sso-operator/go.mod` (mcp precedent shape), R1 parity test, and R2 gate-aware truthiness test. Every rule checked **with the change in place**:

| Rule | Result | Evidence |
|---|---|---|
| Root go.mod/go.sum unchanged | ✅ | `git diff --exit-code HEAD -- go.mod go.sum` clean before and after |
| No go.work | ✅ | 0 `go.work*` files repo-wide |
| Operator binary root-free | ✅ | `go list -deps .` = only 3 operator packages; `go version -m` on built binary contains **no** root-module entry; 0 `plugin.Open` hits |
| dist/ cold-build isolation | ✅ | `modules smoke` wrote only `dist/modules/`, `profiles evidence` only `dist/profiles/` (ignored); zero tracked-file side effects; root module graph untouched |
| Out-of-process posture | ✅ | Root import is exercised solely by the test file; operator keeps its own go.mod; no hot-plugin registration, no profile change |
| interfaces/sso ceiling | ✅ | Exactly **60 non-test files** — R2 was added to the existing `config_audit_test.go` (no new file, per the "(no new files)" constraint); `_test.go` files don't count anyway |
| `modules check` | ✅ EXIT 0 | catalog 33 modules + 6 profiles |
| `modules smoke` | ✅ EXIT 0 | prototype/minimal/full/standard/standard-kafka built |
| `profiles evidence` | ✅ EXIT 0 | billing/small/full isolation evidence bundles OK |
| Tests | ✅ | R1 `TestAdminPathConstsMatchRootOwnedConstants`, R2 `TestDeployTreeAdminConfigRoutes_GateAwareTruthinessWithConstPaths` pass (incl. `-race`); full `interfaces/sso` package and operator `go test -race ./...` green; root `go build ./... && go vet ./...` OK |

**DIRECTORY_MAP ownership: no mismatch.** Line 81 lists `cmd/{sso-mcp,sso-operator}` as nested modules retaining their own `go.mod` — preserved exactly. Nothing in DIRECTORY_MAP constrains nested-module replaces; `cmd/sso-mcp/go.mod:5` is the in-repo precedent.

**Notes:**
- `go mod tidy` MVS-bumped 8 existing operator indirect deps (e.g., `x/net v0.49→v0.53`, `cbor v2.9.0→2.9.2`) because the replaced root module's requirements join the operator's graph — identical to the mcp precedent's go.sum; `go.sum` gained **0** snaplink entries (local replace needs none). Binary content changes only in those transitive patch versions, not in linkage.
- R2 uses const-derived paths (`core.PathAPIPrefix + PathAdminConfig*`), byte-identity vs. the never-mounted history route on the same server, explicit gate-open (default-flip proof), and POST-method fidelity.

**Pre-existing failure, reported separately (not caused by this change):** `TestArchitecture_DirectoryDepth` and `TestArchitecture_DirectorySubdirFanout` fail due to untracked `docs/architect-analysis/auto/` pipeline artifacts (250 dirs at depth 4–8; `docs` 18 subdirs, `auto/runs` 95; root 24 > frozen 21). Proven pre-existing: stashed exactly my 4 files and re-ran — still FAIL. All other maintainability/architecture tests pass.
