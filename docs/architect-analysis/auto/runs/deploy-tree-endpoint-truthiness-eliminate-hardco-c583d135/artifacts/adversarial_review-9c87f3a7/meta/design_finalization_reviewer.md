All corrections verified. Summary of the work:

## Corrected artifacts (before design_gate)

**1. Gated-mount citation fixed** — in all three deliverables (`task-1-design.md`, pipeline `requirements.md`, full spec). The production mount is now cited as `interfaces/sso/server_routes_admin.go:48-56` (`mountAdminSurface` wrapping `core.NewGatedRouter(s.router.Group(PathAPIPrefix), s.adminAPIGateOn)` at :49) feeding `server_backup.go:50-60` (`mountConfigAuditAPI`) via the const aliases (`aliases.go:373-377`). `platform/configaudit/mount.go:MountRoutes` is cited as unwired dead code — **re-verified: zero callers repo-wide, including tests** (grep exit 1; `MountRoutes` at mount.go:24).

**2. R2 baseline switched** — design/spec/cases now prescribe `fghrNeverMountedBaseline` (`/definitely-not-a-real-route`, `feature_gate_hotreload_test.go:80`, `package sso_test`), not history-without-store, with the store-coupling rationale.

**3. POST body pinned** — `{"snapshot":...}` body required in all three R2 phases in all documents; empty-body → 400 verified in `HandleClusterDiff` (binds, rejects empty `Snapshot`).

**4. R1 detection gate named** — acceptance cases 1–2 (and the design's failure-modes table) now name `cd cmd/sso-operator && go test -race ./...` under `make ci` → ci-modules (`Makefile:263`), with the CI-only boundary stated as precedented.

**5. Acceptance mapping re-graded 6/9** — grading table added to design artifact + full spec: cases 1,2,4,5,6,7 machine-checked (1–2 ci-modules-only); case 3 split (build/test machine-checked, diff-minimality review-time, wording corrected: ~36 go.sum lines swapped across 9 MVS-aligned deps, not "only matching sum lines"); case 8 demoted to review invariant; case 9 rg sweep review-time.

**6. Precision claims corrected** — replace is module-wide by language design; inert for build only because no production package imports the root (`go list -deps .` = 3 operator packages of 806); production footprint = ~7 go.mod require bumps + ~36 swapped go.sum lines across 9 deps, zero snaplink sums — not zero.

## Implementation alignment (so corrected text holds against source)

- `interfaces/sso/config_audit_test.go`: R2 renamed to `TestConfigAudit_OperatorPaths_GateAwareTruthiness` (spec name); phase 1 is now **default-based** (removed `WithFeatureGates(AdminAPI: true)` — restores the gate-default flip detector, the conformance reviewer's must-fix); phase 2 baseline → `fghrNeverMountedBaseline`; body retained in all phases.
- `cmd/sso-operator/controller/root_consts_parity_test.go` → renamed `adminpaths_parity_test.go` (spec name).

## Verification results

- `go build ./... && go vet ./...` ✅; `go mod tidy -diff` clean ✅; `modules check` ✅; `rg /authenticate` = 0 hits ✅
- R2 + configaudit/gate suites with `-race` ✅; R1 with `-race` ✅; operator full suite with `-race` ✅
- Pre-existing, reported separately (unchanged by this work): `TestArchitecture_DirectoryDepth` / `TestArchitecture_DirectorySubdirFanout` fail due to untracked `docs/architect-analysis/auto/` pipeline artifacts (root fanout 24 > 21) — already proven pre-existing by the module-posture reviewer's stash test.
