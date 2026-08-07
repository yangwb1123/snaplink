Design written to `docs/architect-analysis/auto/runs/deploy-tree-endpoint-truthiness-eliminate-hardco-c583d135/artifacts/design-a77de8a6/task-1-design.md` (the pipeline's design-stage output path).

## Verification verdict: evidence confirmed, no corrections needed

Every citation re-checked against HEAD:

- **Operator literals** at `ssoconfigdrift_controller.go:40-41` (cited 47-49; drift noted in the evidence itself), byte-exact; consumed at `http.go:50,58,67` (GET) and `:88,97,106` (POST)
- **Consts** `PathAPIPrefix` (34), `PathAdminConfigRunning` (463), `PathAdminConfigClusterDiff` (467); concatenation byte-equals the literals
- **Gated mount** at `platform/configaudit/mount.go` (not `interfaces/sso/mount.go` — the only path-level correction): `NewGatedRouter` + `ConfigSnapshotsWired()`; closed gate → `GateHandler` → `http.NotFound` (`shared/core/router.go:367-375`)
- **Test sweep** at `config_audit_test.go:48-63` (404) and 65+ (200) uses raw literals — confirmed
- **mcp replace** at `cmd/sso-mcp/go.mod:5`; operator go.mod has no replace and `go.sum` has **0** snaplink entries; `go list -deps ./shared/core` is stdlib-only; both modules are `go 1.26.1`
- **Precedents**: `TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404` + `fghrGet`/`fghrAssertIdentical` are in the same `package sso_test` as the R2 target file — reusable as-is; `interfaces/sso` at exactly 60 non-test files; `/authenticate` = 0 hits in the deploy tree; Makefile:262-263 ci-modules lines
- **Baselines green**: operator build + `go test -race ./...` OK; `python cli.py modules check` OK

## Design highlights

- **API changes**: none to production. Only a build-level change — test-only `require`+`replace => ../../` in `cmd/sso-operator/go.mod` (mcp precedent), keeping the operator binary root-free and preserving the out-of-process module posture
- **Two test halves**: R1 white-box parity test (`package controller`, sees unexported consts); R2 three-phase gate-aware truthiness test (open→200, closed→404 byte-identical to the unmounted history baseline, re-open→200) with const-derived paths
- **Failure modes table** adds what the spec implies but doesn't enumerate: tidy-balloon fallback (generated parity file), replace-removal build break, gate-default flip detection, byte-identity header-leak check, method fidelity (POST not GET), and the CI-only detection boundary for R1
- **Migration**: 8 ordered steps from go.mod edit through `make ci`, with rollback = revert two test files + go.mod/go.sum
- **Acceptance mapping**: all 9 Given/When/Then cases mapped to concrete tests and gate commands
