# Requirements Specification — `interfaces/sso` 系统性瘦身（薄委托下沉）

> Source: [interfaces-sso-analysis.md](interfaces-sso-analysis.md) 方向三. All
> numbers below were re-measured against the current tree (production files
> only, `_test.go` excluded) at spec time; where the analysis undercounted, the
> measured value is used.
>
> Measured baseline: 60 production files / 48,830 lines; 1,013 `func (s *Server)`
> methods; 234 `handle*` methods with `(ctx HandlerContext)` signature; **174
> (74%) are pure single-call delegates** `{ pkg.HandleX(s, ctx) }`; 40
> mount/register functions across 16 files; 24 "Relocated from ... (which was at
> the line budget)" comments. `dirFileCountExemptions["interfaces/sso"] = 60`
> (`directory_fanout_test.go:59`) is a frozen ceiling — the package is AT it, so
> any new production file fails the committed fan-out gate today.

## 改进一：协议路由挂载下沉（`MountRoutes(r core.Router, d Deps, gates …)` 模式）

**Name**: Sink protocol route registration and the 109 non-admin thin delegates into the owning protocol/domain/platform packages.

**Problem**: Route registration in `interfaces/sso` is a method-value bridge:
`func (s *Server) handleIntrospect(ctx HandlerContext) { oauth.HandleIntrospect(s, ctx) }`
exists only so `s.router.POST(PathIntrospect, s.handleIntrospect)` can hand the
domain handler a deps value. 174 of 234 `handle*` methods (74%) are exactly this
pass-through, and each carries a 3-line comment block plus a mount-site line.
The real logic already lives below (`HandleIntrospect(d IntrospectDeps, ctx)`),
so the package pays ~2,500 lines of pure indirection, and every future protocol
feature must squeeze one more delegate + one more mount line into an already
500-line-full file. The domain side needs no change at all: deps interfaces
(`IntrospectDeps`, `selfservicecore.Deps`, …) are narrow and already satisfied
by `*Server`.

**Evidence**:

- `interfaces/sso/handlers.go:35` — `func (s *Server) handleIntrospect(ctx HandlerContext) { oauth.HandleIntrospect(s, ctx) }`; same pattern at `:99`, `:104`, `:125` (PAR/Revoke/RevokeAll) and 170 more (measured: oauth 8, oidc 3, caep 6, selfservice 56, rebac 7, netpolicy 6, federation 5, federationhealth 1, webhook 5, permissions 3, audit 3, configaudit 5).
- `interfaces/sso/server_routes.go:181` — `s.router.POST(PathIntrospect, s.handleIntrospect)`: the route-mount sites (40 mounts across 16 files, e.g. `mountCoreOAuthOIDC` `server_routes.go:147`, `mountUnauthenticatedSelfServiceRoutes` `server_me.go:319`) are what force the method-value shape.
- `protocols/oauth/handle_introspect.go:109` — `func HandleIntrospect(d IntrospectDeps, ctx core.HandlerContext)`: the implementation is already fully sunk; only the mount + delegate are in `interfaces/sso`.
- `shared/core/router.go:43` — `type Router interface` plus `HandlerFunc`/`HandlerContext` all live in `shared/core` (below every layer), so a protocol/domain/platform package can register routes with zero upward import; `interfaces/sso/aliases.go:110` confirms `HandlerContext = core.HandlerContext` (alias, no conversion).
- Layer order (`architecture_layer_test.go`) permits `protocols/*`, `domains/*`, `platform/*` → `shared/core`; no exemption needed.

**Proposed behavior**: For each owning package, add a mount entry point that
registers the routes and wraps the existing `HandleX` in the closure, e.g.
`protocols/oauth.MountRoutes(r core.Router, d oauth.RoutesDeps, gates …func() bool)`
registering `POST core.PathIntrospect → func(ctx) { HandleIntrospect(d, ctx) }`
including the existing per-feature gate checks (hot-reload atomics stay in
`interfaces/sso` and are passed in as `func() bool`, preserving the
`GatedRouter`/live-flag semantics — byte-identical route set when unwired).
`interfaces/sso` keeps a one-line-per-area call in `Mount()`; the 109 delegates
for these areas are deleted. `Path*` constants move beside the mount (they are
`core.Path*` re-exports). Handlers with real bodies or direct test callers
(`handleHealth`, `handleAuthzPolicyBundle` — `health_test.go:21,36,122`) stay.

**Acceptance check**:

- `grep -c "func (s \*Server) handle" interfaces/sso/*.go` (non-test) drops from 234 to ≤ 125 (i.e. ≥ 109 delegates removed).
- `python cli.py check-routes` passes unchanged — runtime route set and OpenAPI stay lockstep (no path added/removed/renamed).
- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; full `go test ./...` green; feature-off byte-identity tests (`degradation_test.go`, `feature_gate_hotreload_test.go`) still pass.
- No new entry in `layerExemptions`; `interfaces/sso` gains no new imports that point upward.

## 改进二：Admin 管理面整组下沉至 `interfaces/admin`

**Name**: Move the entire `/api/v1/admin/*` surface (60 admin + 5 adminuser delegates, `mountAdminSurface` and its 11 sub-mounts) into `interfaces/admin`.

**Problem**: The admin management plane is the single largest delegate cluster
(65 of 174) and is already fully owned by `interfaces/admin`: middleware
(`admin.NewMiddleware`, `aliases.go:72`), deps (`interfaces/admin/deps.go:25
type Deps interface`), and every `HandleAdminX` body live there. Yet the routes
and 60 method-value bridges live in `interfaces/sso` (`server_admin_handlers.go`
498 lines with 42 thin delegates, `server_routes_admin.go` 332 lines with
`mountAdminSurface` + 11 sub-mounts). The package even re-exports path constants
in `server_routes_admin.go` with the comment "relocated from aliases.go to keep
that file within the per-file line budget" — the facade is cannibalizing its own
files. This is same-layer work (`interfaces → interfaces`), so no architecture
exemption is touched, and the admin surface is self-contained (scope-gated
behind `AdminMiddleware`, wrapped in a `GatedRouter`), making it the cleanest
whole-surface extraction.

**Evidence**:

- `interfaces/sso/server_admin_handlers.go` — 51 `handleAdmin*` methods, 42 pure delegates (e.g. `:32 handleAdminListUserMFA → admin.HandleAdminListUserMFA(s, ctx)`); 498 lines.
- `interfaces/sso/server_routes_admin.go:32` — `mountAdminSurface` calling 11 sub-mounts (`mountAdminAPIObservability`, `mountAdminUserState`, `mountAdminB2B`, `mountConfigAuditAPI`, `mountAdminBreakGlass`, `mountCryptoInventoryAPI`, `mountWebhookAdminAPI`, `mountRebacAdminAPI`, `mountWASMAuthzAdminAPI`, `mountAdminCompliance`, `mountAdminChangeApproval`); 332 lines; path-const re-exports "relocated from aliases.go" comment at its head.
- `interfaces/admin/middleware.go` — `AdminMiddleware` already lives in the target package; `interfaces/admin/deps.go:25` — `Deps` interface already satisfied by `*sso.Server`.
- `interfaces/sso/aliases.go:64,72` — SDK re-exports (`AdminMiddleware`, `NewAdminMiddleware`) survive untouched; only internal call sites move.

**Proposed behavior**: Add `interfaces/admin.MountAdminSurface(r core.Router, d Deps, gate func() bool)` that builds the `GatedRouter` group and registers all admin routes, wrapping each `HandleAdminX(d, ctx)` inline; `interfaces/sso` `Mount()` calls it with `s` and `s.adminAPIGateOn` (live-flag method, `server_routes.go:222` — passed as a closure so hot-reload gating is byte-identical). Delete the 60 admin + 5 adminuser delegates and the 12 mount functions from `interfaces/sso`; move the `PathAdmin*` constants to `interfaces/admin` (as `core.Path*` re-exports, same as today). `mountWASMAuthzAdminAPI`/`mountRebacAdminAPI` move with the rest; their backing gates stay closure-injected.

**Acceptance check**:

- `interfaces/sso/server_admin_handlers.go` ≤ 200 lines (from 498) and `server_routes_admin.go` deleted or ≤ 60 lines (from 332).
- `interfaces/admin` imports only downward packages (`shared/core`, `interfaces/middleware`, …); `architecture_layer_test.go` passes with `layerExemptions` unchanged.
- Admin conformance: full admin route set byte-identical — `python cli.py check-routes` passes; `TestArchitecture_` fan-in counts for `interfaces/admin` do not exceed its frozen `dirFileCountExemptions` value.
- `go test ./interfaces/admin/... ./interfaces/sso/...` green including `rootcov_admin*.go` suites; 401 `Bearer realm="admin"` and `admin:read`/`admin:write` gating tests unchanged.

## 改进三：下沉后文件归并与 60 文件天花板棘轮

**Name**: Consolidate the residual facade and ratchet `dirFileCountExemptions["interfaces/sso"]` down from 60, converting slimming into durable, machine-enforced headroom.

**Problem**: The 60-file ceiling (`directory_fanout_test.go:59`) is frozen
("SHRINK THESE; never grow them, never raise a ceiling") and the package sits AT
it — zero headroom for directions 一/二 or any future feature, which is exactly
the structural bottleneck the analysis identifies. Today the ceiling is held by
budget-driven file shuffling (24 "Relocated from ... (which was at the line
budget)" comments; `fileSizeExemptions` empty because content was moved rather
than removed), so the package is simultaneously full and fragmented. After 改进
一/二 the residual mount/delegate files shrink by 40-70%, making consolidation
possible without touching `layerExemptions`, and the exemption value can be
lowered to the new measured count — the only direction the gate permits — so the
relief is locked in by the committed test rather than by prose.

**Evidence**:

- `directory_fanout_test.go:59` — `"interfaces/sso": 60` with the SHRINK-ONLY contract; `AGENTS.md` §2: "`interfaces/sso` is at its 60-file ceiling. Extend an existing file or move behavior down to a domain package".
- `maintainability_budget_test.go:56` — `TestMaintainability_FileSizeBudget`, `maxFileLines = 500`, `fileSizeExemptions` empty: every one of the 60 files is at/near the line budget (e.g. `aliases.go` 500, `options_security.go` 500, `server_login_client.go` 500, `server_tenant_residency.go` 500), so files can be merged only after content leaves.
- `interfaces/sso/aliases.go` — 500 lines / 419 backward-compat re-exports ("Code generated" header, hand-maintained): the SDK facade must survive, so line relief comes from removing delegate/mount content, not from deleting the facade.
- Post-改进一/二 target residuals: `handlers.go` 488→~250, `server_me.go` 461→~200, `sso_selfservice.go` 469→~150, `server_extensions.go` 461→~200, `server_federation.go` shrinks, `server_backup.go`/`server_discovery.go`/`server_signup.go`/`server_userinfo.go` lose their delegate clusters.
- `architecture_layer_test.go` `layerExemptions` — the "god-package fan-in" entries are untouched by this direction (imports do not change); fan-out relief comes from the file count, not the exemption map.

**Proposed behavior**: After 改进一/二 land, (1) merge the residual route-mount
and delegate fragments back into cohesive files (`server_routes.go` +
remaining mounts; `options*.go` unchanged), deleting every file whose content
fell below cohesion threshold — target `interfaces/sso` production file count
**≤ 52** (from 60); (2) lower `dirFileCountExemptions["interfaces/sso"]` to the
new measured count and regenerate with `SEED_DIRFANOUT=1 go test -run
TestSeedDirectoryFanout -v .` so the committed gate enforces the reduced ceiling
(the shrink-only contract makes this the sanctioned ratchet); (3) update the
`AGENTS.md` §2 ceiling sentence to the new number, keeping the "extend or move
down" rule; (4) leave `layerExemptions`, `fileSizeExemptions`, and the
`interfaces/sso` 500-line budget untouched.

**Acceptance check**:

- `ls interfaces/sso/*.go | grep -v _test | wc -l` ≤ 52; `directory_fanout_test.go` exemption value lowered to the measured count and `SEED_DIRFANOUT=1` regeneration committed; `go test -run TestSeedDirectoryFanout -v .` shows no drift.
- `go test -run 'TestMaintainability_|TestArchitecture_' .` green; `python cli.py` filesize/fan-out/adr-compliance checks green.
- `python cli.py check-routes` and `python cli.py sdk-surface check` green — route set and SDK surface (including `aliases.go` re-exports) unchanged.
- `go test ./... -race` and `make ci` green; the ceiling sentence in `AGENTS.md` §2 matches the new exemption value, and headroom (60 − new count) is documented as the budget for directions 一/二 file additions.

---

**Dependency note**: 改进一 and 改进二 are independent and can land in either
order; 改进三 depends on both. This direction is a prerequisite for directions
一/二 of the analysis: it converts the frozen 60-file ceiling into real,
gate-enforced headroom without any `layerExemptions` growth.
