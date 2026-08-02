Specification written to `docs/auto/interfaces-sso-direction3-spec.md`. It implements 方向三 from the analysis with re-measured evidence — the analysis's "至少 104" thin delegates is actually **174 of 234** `handle*` methods (74%) in the current tree, and the 60-file ceiling (`directory_fanout_test.go:59`) is confirmed machine-enforced at the exact current file count.

## The 3 improvements

1. **协议路由挂载下沉** — 109 non-admin thin delegates (selfservice 56, oauth/oidc/caep/rebac 24, netpolicy 6, federation 6, webhook 5, configaudit 5, permissions/audit 6, wasmauthz 1) plus their 40 mount sites move into owning packages via a `MountRoutes(r core.Router, d Deps, gates …)` pattern. Architecturally free: `core.Router`/`HandlerContext` live in `shared/core` below every layer, and the deps interfaces (`IntrospectDeps`, `selfservicecore.Deps`) already exist. Acceptance: handle-method count 234 → ≤125, `cli.py check-routes` lockstep, zero `layerExemptions` growth.

2. **Admin 管理面整组下沉** — the largest cluster (60 admin + 5 adminuser delegates, `mountAdminSurface` + 11 sub-mounts, `server_admin_handlers.go` 498 lines, `server_routes_admin.go` 332 lines) moves to `interfaces/admin`, which already owns `AdminMiddleware`, `Deps`, and every `HandleAdminX` body — same-layer work touching no exemption. Hot-reload gates stay byte-identical via closure-injected `adminAPIGateOn`. Acceptance: `server_admin_handlers.go` ≤200 lines, admin route set unchanged.

3. **文件归并与天花板棘轮** — after 1+2, merge residuals and ratchet `dirFileCountExemptions["interfaces/sso"]` from 60 to ≤52 (the gate's own "SHRINK THESE" contract makes lowering the sanctioned direction), regenerating via `SEED_DIRFANOUT=1`, and update the AGENTS.md §2 ceiling sentence. This converts the slimming into durable, gate-enforced headroom — the prerequisite that unlocks directions 一/二.

No `.go` files were modified; the deliverable is the spec document only.
