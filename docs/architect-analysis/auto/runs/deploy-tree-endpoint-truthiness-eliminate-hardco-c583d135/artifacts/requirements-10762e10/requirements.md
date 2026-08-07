The requirements specification is complete. Both deliverables are written; I modified no tracked files (the other dirty/untracked paths are pre-existing campaign artifacts).

## Deliverables

1. **Full spec** — `docs/architect-analysis/cmd-sso-operator-b4-3-deploy-tree-truthiness-requirements.md` (179 lines)
2. **Pipeline artifact** — `docs/architect-analysis/auto/runs/deploy-tree-endpoint-truthiness-eliminate-hardco-c583d135/artifacts/requirements-10762e10/requirements.md` (the run's required output path, verified from its `pipeline.yaml`)

## Evidence verification (all citations confirmed)

| Citation | Verdict |
|---|---|
| `ssoconfigdrift_controller.go:47-49` literals | Confirmed at **40–41** (drift 6–8, values byte-exact); used in `http.go:50,58,67` (GET) / `:88,97,106` (POST) |
| `consts.go:34,463-467` | Confirmed — `PathAPIPrefix="/api/v1"` (34), `PathAdminConfigRunning` (463), `PathAdminConfigClusterDiff` (467); concatenation byte-equals the literals |
| `mount.go:35-41` gated mount | Confirmed — `MountRoutes` 26–41, `NewGatedRouter` + `ConfigSnapshotsWired()` only; closed gate → `GateHandler` → 404 (`router.go:367-375`) |
| `config_audit_test.go:54-113` sweep | Confirmed — 404 sweep at 48, live 200 sweep at 65; existing sweep uses **raw literals** (new test fixes this) |
| `cmd/sso-mcp/go.mod:5` replace | Confirmed — operator go.mod has no replace yet; `go list -deps ./shared/core` is stdlib-only ⇒ minimal go.mod diff |

## Key decisions baked in

- **Two test halves per the acceptance**: R1 parity test in `cmd/sso-operator/controller` (white-box, test-only import of `shared/core` via the mcp replace mechanism — the operator binary gains no root dependency, preserving the out-of-process module posture); R2 gate-aware truthiness test extending `interfaces/sso/config_audit_test.go` (const-derived paths, gate open → 200, closed → 404 byte-identical to the unmounted `/admin/config/history` baseline, re-opened → 200, guarding the naive-sweep gated-404 trap).
- **R3** preserves the B4-3 "不得带入部署仓" constraint: `rg '/authenticate' cmd/sso-operator/` stays 0; no legacy-defect test pattern introduced.
- **Scope discipline**: no production-code changes, no CRD/RBAC/config/OpenAPI work, no `go.work`, no `layerExemptions`; `interfaces/sso` stays at its 60-file ceiling (test file exempt).
- 9 testable Given/When/Then acceptance cases; verification plan ends at `make ci`. Baselines green at HEAD: operator build + `go test -race ./...`, `python cli.py modules check`.
