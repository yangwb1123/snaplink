# Design: `interfaces/sso` 系统性瘦身 — 方向三（薄委托下沉 + 天花板棘轮）

Source: `docs/auto/interfaces-sso-direction3-spec.md` (direction 3 of
`docs/auto/interfaces-sso-analysis.md`). This doc fixes the three improvements
down to API surface, storage model, failure modes, and the failure modes of the
design itself. All numbers re-verified against the tree at design time.

**Verified baseline**: 60 production files / 48,830 lines; 254 `func (s *Server)
handle*` methods total, of which exactly **234 have the sole-parameter
signature `(ctx HandlerContext)`** and 174 of those are single-call delegates
(109 non-admin + 65 admin); 40 mount functions across 16 files;
`dirFileCountExemptions["interfaces/sso"] = 60` (`directory_fanout_test.go:59`)
with `interfaces/sso` sitting exactly AT the ceiling.

**Three spec corrections surfaced during design** (each flagged inline):

1. **8 of the 13 target packages are themselves at a file ceiling — the spec's
   "add a mount entry point" cannot mean "add a new file" in most cases.**
   `protocols/oauth` (12 files = exemption 12), `platform/audit` (16 =
   exemption 16), `domains/federation` (24 = exemption 24),
   `protocols/oidc`/`protocols/caep`/`protocols/selfservice`/`domains/permissions`
   (10 each = default cap 10), and `interfaces/admin` (10 = default cap 10, and
   **it has no exemption entry at all**, so the spec's acceptance wording
   "fan-in counts ... do not exceed its frozen `dirFileCountExemptions` value"
   references a map entry that does not exist) are all AT their cap. A new
   `mount_routes.go` in any of them fails the committed fan-out gate — the very
   gate this direction exists to protect. Mount code must be appended to an
   EXISTING file in each constrained package, subject to the 500-line file
   budget (`fileSizeExemptions` is empty). Only `platform/configaudit` (8),
   `platform/netpolicy` (6), `platform/lifecycle/rebac` (7),
   `platform/lifecycle/wasmauthz` (4), and `platform/lifecycle/webhook` (9,
   one slot) may take a new file. Decisions 1 and 2 fix the placement table.
2. **The spec's acceptance grep is under-specified and would count 254, not
   234.** `grep -c "func (s \*Server) handle" interfaces/sso/*.go` matches 20
   body-bearing multi-arg helpers (`handleDeviceTokenGrant(ctx HandlerContext,
   client *Client, ...)`, `handleLivez(w, r)`, ...) that are NOT delegates and
   stay. The correct filter is the sole-parameter shape; with it, the target
   is ≤125 post-改进一 as specified. The anchored command is in Decision 1.
3. **`interfaces/admin` file placement is constrained to one file.**
   `deps.go` (177 lines) is the only admin file with ≥300 lines of headroom;
   `middleware.go` (492) and `connections.go` (498) are at budget. The admin
   surface entry point goes into `deps.go`.

---

## Decision 1: 改进一 API surface — `MountRoutes(r core.Router, d Deps, gates …)`

### Problem restated

174 of 234 sole-parameter `handle*` methods are pass-throughs
`{ pkg.HandleX(s, ctx) }` existing only so `s.router.POST(PathX, s.handleX)`
can hand the domain handler a deps value. The implementations already live
below (`protocols/oauth/handle_introspect.go:109 HandleIntrospect(d
IntrospectDeps, ctx core.HandlerContext)`); only the mount site + delegate are
in `interfaces/sso`. `core.Router`/`HandlerFunc`/`HandlerContext`/`GatedRouter`
all live in `shared/core/router.go` (below every layer; `aliases.go:110`
confirms `HandlerContext` is an alias), so owning packages can register routes
with zero upward import.

### API shape

Each owning package exports exactly one composition entry point:

```go
// protocols/oauth
type RoutesDeps interface { /* the union of the deps its Handle* need */ }
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool)
```

- **`r core.Router`** — the root router (or the `/api/v1` group for
  prefixed surfaces), passed from `interfaces/sso` `Mount()`. Never nil.
- **`d Deps`** — the package's existing narrow deps interface (e.g.
  `oauth.IntrospectDeps`, `protocols/selfservice` deps). `*sso.Server`
  satisfies all of them today, unchanged; the domain side changes nothing.
- **`gate func() bool`** — the hot-reload live flag, passed as a closure that
  READS the atomic at call time. `interfaces/sso` passes method values
  (`s.selfServiceGateOn`, `s.caepGateOn`, `s.brandingGateOn`,
  `s.adminAPIGateOn`). The mount wraps the same route blocks in
  `core.NewGatedRouter(r, gate)` exactly as `server_me.go:320,357,434` and
  `server_health.go:70` do today. **Design rule: capture the method value,
  never a `.Load()` result** — capturing the value at boot would freeze the
  flag and break hot-reload byte-identity (`degradation_test.go`,
  `feature_gate_hotreload_test.go`).
- **Boot-time wiring conditionals do NOT become closures.** Today's
  `if s.rebacStore != nil { ... }` / `if s.clientStore != nil` guards are
  one-shot boot decisions. The deps interfaces in this repo are already
  nil-tolerant accessors (`ProviderStore() provider.Store` "or nil when not
  configured"), so the owning package branches on `d.X() != nil` natively.
  This keeps route-registration logic in the owning package instead of
  re-exporting the wiring predicates back into `interfaces/sso`.
- **`Path*` constants**: the owning package uses `core.Path*` directly (they
  are already `core.Path*` re-exports); the SDK-facing re-exports stay in
  `interfaces/sso/aliases.go` (419 re-exports, untouched). No const moves.
- **Nil gate = programmer error**: `MountRoutes` panics if `gate` is nil.
  A silently-always-off surface would look like a feature regression; a
  nil-default always-on would bypass gating. `Mount()` only ever passes real
  method values, so the panic is unreachable in production and is pinned by a
  test.

### Per-package placement (ceiling-aware)

| Owning package | Delegates | Files today | Cap | Mount entry lands in |
|---|---|---|---|---|
| `protocols/selfservice` | 56 | 10 | 10 (default) | existing file with headroom |
| `protocols/oauth` | 8 | 12 | 12 (exemption) | existing file with headroom |
| `protocols/oidc` | 3 | 10 | 10 (default) | existing file with headroom |
| `protocols/caep` | 6 | 10 | 10 (default) | existing file with headroom |
| `platform/lifecycle/rebac` | 7 | 7 | 10 | new `mount.go` OK |
| `platform/netpolicy` | 6 | 6 | 10 | new `mount.go` OK |
| `domains/federation` (+`/health`) | 6 | 24 | 24 (exemption) | existing file with headroom |
| `platform/lifecycle/webhook` | 5 | 9 | 10 | new `mount.go` OK (1 slot) |
| `platform/configaudit` | 5 | 8 | 10 | new `mount.go` OK |
| `domains/permissions` | 3 | 10 | 10 (default) | existing file with headroom |
| `platform/audit` | 3 | 16 | 16 (exemption) | existing file with headroom |
| `platform/lifecycle/wasmauthz` | 1 | 4 | 10 | new `mount.go` OK |

For "existing file" rows, implementation must re-measure per-file lines at
edit time and append to the file with the most headroom under the 500-line
budget; if every file is at budget, extract a cohesive internal piece into
another existing file first (never into a new file — the cap is hard). The
mount block is one cohesive section (consts, `MountRoutes`, inline closures),
typically 60–120 lines per area.

### What stays in `interfaces/sso`

Handlers with real bodies or direct test callers: `handleHealth`,
`handleStatus`, `handleSetupStatus`, `handleJWKS`, `handleAuthzPolicyBundle`
(`handlers.go:328,411`; `health_test.go:21,36,122` call them), the 20
multi-arg helpers (`handleDeviceTokenGrant`, `handleLivez`/`handleReadyz`, …),
and `handleAdminTokenExchangeChain` (`accessors_threat.go:186`, body-bearing).
Probe endpoints (`/livez`, `/readyz`, health) stay unconditionally registered
outside rate limiting — their mount sites do not move.

### Acceptance (corrected)

```bash
grep -hE 'func \(s \*Server\) handle[A-Za-z0-9_]*\(ctx HandlerContext\)' \
  interfaces/sso/*.go | wc -l    # 234 today → ≤125
```

Plus `python cli.py check-routes` unchanged (route set byte-identical),
`go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`,
full `go test ./...`, `degradation_test.go` + `feature_gate_hotreload_test.go`
green, no new `layerExemptions` entry, no new upward import in any owning
package (all mount code imports `shared/core` only).

## Decision 2: 改进二 API surface — `MountAdminSurface(r core.Router, d Deps, gate func() bool)`

### Problem restated

The admin management plane is the largest cluster (60 admin + 5 adminuser
delegates; `server_admin_handlers.go` 498 lines with 42 thin delegates;
`server_routes_admin.go` 332 lines with `mountAdminSurface` + 11 sub-mounts)
and is already fully owned by `interfaces/admin`: `AdminMiddleware`
(`middleware.go`), `Deps` (`deps.go:25`, satisfied by `*sso.Server`), and every
`HandleAdminX` body. This is same-layer work (`interfaces → interfaces`), so no
architecture exemption is touched.

### API shape

```go
// interfaces/admin
func MountAdminSurface(r core.Router, d Deps, gate func() bool)
```

Construction is preserved verbatim, just relocated:

```go
api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
// …the 11 sub-mounts register on api, each branching on d.X() != nil
// for its store-wired routes (audit, netpolicy, rebac, wasmauthz, …)
```

- **`gate`** is `s.adminAPIGateOn` (`server_routes.go:222`, reads the live
  `adminAPILive` atomic) passed as a method-value closure — hot-reload
  (`SetAdminAPIGateEnabled` via config/reload) stays byte-identical: gate off
  ⇒ every admin route answers `http.NotFound` without a restart, exactly as
  the `GatedRouter` wrap guarantees today.
- **Middleware invariant**: the `/api/v1/admin/*` surface remains gated
  upstream by `AdminMiddleware` (GET `admin:read`, mutations `admin:write`,
  401 `Bearer realm="admin"`). `interfaces/admin` already owns that middleware,
  so the invariant holds with no import change; `Mount()` order guarantees
  `mountMiddleware` runs first (see Decision 3).
- **Path constants**: admin mounts use `core.PathAdmin*` directly. The
  SDK-facing re-exports already live in `aliases.go:293+` and stay there; the
  spec's "move the PathAdmin* constants to interfaces/admin" reduces to "the
  mount code references `core.PathAdmin*` in its new home" — `server_routes_admin.go`
  is deleted, `aliases.go` is not touched.
- **Nil gate**: same programmer-error panic discipline as Decision 1.

### File placement (spec correction 3)

`interfaces/admin` has 10 non-test files and **no `dirFileCountExemptions`
entry** — it is bound by the default `maxGoFilesPerDir = 10` and sits AT it.
A new `mount_admin.go` would fail the fan-out gate. `deps.go` (177 lines) is
the only file with ≥300 lines of headroom (`middleware.go` 492,
`connections.go` 498 are at budget). `MountAdminSurface` + the route table
(~150–200 lines) land in `deps.go` as a clearly delimited "surface composition"
section, bringing it to ~350–380 lines — within budget. The 5 `adminuser`
delegates' bodies live in `users.go` (464 lines); their inline mount closures
can be registered from the same `MountAdminSurface` section without touching
`users.go`.

### Acceptance (corrected)

- `server_admin_handlers.go` ≤ 200 lines (from 498); `server_routes_admin.go`
  deleted.
- `interfaces/admin` file count stays at **10** (default cap — not an
  exemption value, correcting the spec's wording); `deps.go` ≤ 500 lines.
- Admin route set byte-identical: `python cli.py check-routes`; `go test
  -run 'TestMaintainability_|TestArchitecture_' .`; admin conformance suites
  (`rootcov_admin*.go`) green; 401 `Bearer realm="admin"` and
  `admin:read`/`admin:write` gating tests unchanged.

## Decision 3: 改进三 — residual consolidation and the ceiling ratchet

### Mechanics

1. **Land 改进一 and 改进二 first** (independent; either order). Only then
   measure residuals: `handlers.go` 488→~250, `server_me.go` 461→~200,
   `sso_selfservice.go` 469→~150, `server_extensions.go` 461→~200,
   `server_federation.go` shrinks, `server_backup.go`/`server_discovery.go`/
   `server_signup.go`/`server_userinfo.go` lose their delegate clusters.
2. **Merge** residual route-mount/delegate fragments into cohesive files
   (`server_routes.go` + remaining mounts). Delete every file whose content
   fell below cohesion threshold. **Never touch `aliases.go`** (500 lines,
   "Code generated" header, hand-maintained SDK facade) or `options*.go`.
   Target: **≤ 52** production files (from 60).
3. **Ratchet in the same commit as the deletions**: set
   `dirFileCountExemptions["interfaces/sso"]` to the new measured count, then
   `SEED_DIRFANOUT=1 go test -run TestSeedDirectoryFanout -v .` and commit the
   regenerated `directory_fanout_test.go`. The shrink-only contract makes
   lowering the sanctioned direction; the committed test now enforces the
   reduced ceiling, converting the slimming into durable headroom for
   directions 一/二.
4. **Update `AGENTS.md` §2** ceiling sentence to the new number, keeping the
   "extend an existing file or move behavior down" rule; document headroom
   (60 − new count) as the budget for directions 一/二 file additions.
5. `layerExemptions`, `fileSizeExemptions`, and the `interfaces/sso` 500-line
   budget stay untouched. The 24 "Relocated from … (which was at the line
   budget)" comments die with the files they annotate; no new ones are added.

### New `Mount()` shape (post-1+2)

```go
func (s *Server) Mount() {
    s.mountMiddleware()                       // first: middleware chain order
    oauth.MountRoutes(s.router, s, nil)       // or the area's gate closure
    oidc.MountRoutes(s.router, s, nil)
    selfservice.MountRoutes(s.router, s, s.selfServiceGateOn)
    caep.MountRoutes(s.router, s, s.caepGateOn)
    rebac.MountRoutes(s.router, s, nil)
    netpolicy.MountRoutes(s.router, s, nil)
    federation.MountRoutes(s.router, s, nil)
    webhook.MountRoutes(s.router, s, nil)
    configaudit.MountRoutes(s.router, s, nil)
    permissions.MountRoutes(s.router, s, nil)
    audit.MountRoutes(s.router, s, nil)
    wasmauthz.MountRoutes(s.router, s, nil)
    admin.MountAdminSurface(s.router, s, s.adminAPIGateOn)
    s.mountAPIVersionPreview()
}
```

Each is one line; the 109 delegates and 40 mount functions are gone. The
`mountMiddleware`-first ordering and the unconditional probe registrations
(`handleHealth`/`handleLivez`/`handleReadyz` in `mountCoreOAuthOIDC`
position) are preserved.

### Acceptance

- `ls interfaces/sso/*.go | grep -v _test | wc -l` ≤ 52; exemption value =
  measured count; `TestSeedDirectoryFanout` shows no drift.
- `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `python cli.py check-routes`, `python cli.py sdk-surface check`,
  `go test ./... -race`, `make ci` green; AGENTS.md §2 sentence matches the
  committed exemption value.

## Decision 4: Storage model

**There is no runtime storage change in this direction.** No new stores, no
schemas, no migrations, no config keys, no wire-format changes. The design
touches exactly four "stored" artifacts:

1. **Hot-reload gate state** — unchanged: the `atomic.Bool` live flags
   (`adminAPILive`, `selfServiceLive`, `caepGate`, branding flag) stay on
   `*Server` (`sso_wiring.go`); the closures injected into the mounts read
   them at call time. This is the only mutable runtime state the design
   touches, and it does not move.
2. **Committed gate tables** — the only stored state that changes:
   `directory_fanout_test.go` `dirFileCountExemptions["interfaces/sso"]`
   (60 → ≤52, regenerated by `SEED_DIRFANOUT=1`) and the `AGENTS.md` §2
   sentence. Both are committed artifacts; drift between them is a gate
   failure by review, not by runtime.
3. **The wire-contract store** — `docs/openapi.yaml` and the runtime route
   table. Immutable under this direction: `cli.py check-routes` enforces
   lockstep (no path added/removed/renamed), and the SDK surface
   (`aliases.go` re-exports) is pinned by `cli.py sdk-surface check`.
4. **Path constants** — single source remains `shared/core` (`core.Path*`);
   `interfaces/sso/aliases.go` keeps the SDK re-exports; the moved mount code
   references `core.Path*` directly. No duplicate const definitions are
   created anywhere (a duplicate would silently diverge).

`MountRoutes`/`MountAdminSurface` are plain Go functions — compile-time
composition, not runtime registries. They do not touch `FeatureGates`,
`Server.Handle`, `AddReadyCheck`, or `audit.Recorder.AddSink` (AGENTS.md §4
"not hot-plugin registries" boundary), so no module/plugin lifecycle
interaction exists.

## Decision 5: Failure modes

Runtime failure modes of the relocated surface, in the order a deploy would
hit them:

1. **Nil gate closure** — the whole gated surface answers `http.NotFound`
   permanently (indistinguishable from unregistered paths to probes, per the
   GatedRouter contract). Mitigation: `MountRoutes`/`MountAdminSurface` panic
   on nil gate (boot-time programmer error, unreachable in production);
   a unit test pins the panic for each entry point.
2. **Gate-value capture at boot instead of closure** — freezing `adminAPILive`
   at its initial value would break hot-reload: `config/reload`'s
   `SetAdminAPIGateEnabled` would flip the atomic with no effect, and
   `feature_gate_hotreload_test.go`/`degradation_test.go` fail. Mitigation:
   the design rule "pass method values, never `.Load()` results" plus the
   existing hot-reload tests as the regression net.
3. **Wrong gate on a route block** (e.g., an admin route wrapped in the
   selfservice gate) — surface reachability regressions. Mitigation:
   `degradation_test.go` and `feature_gate_hotreload_test.go` assert
   per-surface reachability; `check-routes` pins the route set; the admin
   conformance suites (`rootcov_admin*.go`) pin `admin:read`/`admin:write`
   behavior.
4. **Double registration** — if a package mount and a leftover `interfaces/sso`
   mount register the same path, `GatedRouter`→`GatedRegistrar` overwrites or
   panics depending on inner router. Mitigation: the acceptance check requires
   every `Path*` const to have exactly one registration; `check-routes` (route
   set vs OpenAPI) and the route-set byte-identity tests catch duplicates.
5. **Boot-time wiring predicate drift** — a mount branches on
   `d.X() != nil` but the store is wired under a different condition in
   `interfaces/sso`, changing the registered route set for a given
   configuration. Mitigation: store-wiring stays the deps-accessor contract
   (nil-tolerant accessors are the repo norm); `check-routes` runs in the
   default configuration and the feature-off byte-identity tests cover the
   unmounted variants.
6. **Middleware-order regression** — admin/selfservice surfaces must stay
   behind `AdminMiddleware` and the tenant/geo/region chain; probes must stay
   outside rate limiting. Mitigation: `Mount()` keeps `mountMiddleware()`
   first and probe registrations unconditional in `mountCoreOAuthOIDC`
   position; `TestArchitecture_` middleware-order assertions and the
   documented order in AGENTS.md §2 are unchanged.
7. **Panic in a package mount** — a nil deps accessor or a nil store used
   without the nil-check would panic at boot. Mitigation: mounts branch on the
   same accessors the handlers use; the full `go test ./...` suite boots
   `*Server` in every configuration, so an unguarded accessor fails CI.

## Decision 6: What could break the design

Ordered by likelihood × severity. The first two are the ones that would stop
the direction dead:

1. **File-ceiling violations in target packages (HIGH, verified).** The naive
   reading of the spec ("add a mount entry point") produces a new file in
   `protocols/oauth`, `platform/audit`, `domains/federation`,
   `protocols/oidc`, `protocols/caep`, `protocols/selfservice`,
   `domains/permissions`, or `interfaces/admin` — all at their caps — and the
   committed fan-out gate fails with the very change meant to protect it.
   The placement table (Decisions 1–2) and the "append to existing file with
   measured headroom" rule are the mitigation; the implementation must
   re-measure line budgets per file at edit time because `fileSizeExemptions`
   is empty and cannot be grown.
2. **500-line budget blowout in mount-hosting files (HIGH).** `middleware.go`
   (492) and `connections.go` (498) in `interfaces/admin`, and near-budget
   files in the ceiling-bound protocol packages, cannot host a 60–200-line
   mount section. Every constrained file must be re-measured; if a file is at
   budget, its cohesive content is first exchanged with a smaller sibling in
   the SAME package (file moves within a package change no import paths).
3. **Acceptance-grep ambiguity (MEDIUM, verified).** The spec's literal grep
   counts 254 (includes 20 body-bearing multi-arg helpers that stay). If the
   acceptance is run as written, the gate is off by 20–29 methods and the
   "234 → ≤125" claim is unverifiable. Use the anchored sole-parameter filter
   from Decision 1; pin it in the PR description.
4. **`SEED_DIRFANOUT` regeneration drift (MEDIUM).** The ratchet requires the
   exemption edit, the regeneration run, and the file deletions in ONE commit;
   running the seed with a stale tree writes a stale map, and a concurrent
   shrink of another exempt dir produces a merge conflict on the sorted map.
   Mitigation: ratchet last, re-run `TestSeedDirectoryFanout` immediately
   before push, and treat any map diff as intentional-only.
5. **SDK surface breakage via `aliases.go` (MEDIUM).** `aliases.go` (500
   lines, 419 re-exports) must not be touched; moving `PathAdmin*` usage to
   `core.PathAdmin*` in `interfaces/admin` must not tempt a "cleanup" of the
   re-exports. `python cli.py sdk-surface check` and the `rootcov_*` suites
   pin this.
6. **Fan-in / `layerExemptions` surprise (LOW).** `interfaces/sso` still
   imports every owning package after the move (one import per `Mount*`
   call), and owning packages gain only `shared/core` imports, so the
   god-package fan-in entries are untouched. But `architecture_layer_test.go`
   also asserts per-directory fan-out/fan-in for NEW packages — none are
   created here, and `interfaces/admin`'s count must remain exactly 10.
7. **`check-routes` lockstep breakage (LOW).** Any path-const typo,
   double-registration, or reordering that changes the runtime route set
   fails the drift gate against `docs/openapi.yaml`. This is the design's own
   regression net; it also means the route-move PR must not touch OpenAPI at
   all (no path changed).
8. **Admin-surface behavioral drift (LOW).** `rootcov_admin*.go` conformance
   suites and the `Bearer realm="admin"` / `admin:read` / `admin:write`
   gating tests must pass untouched; any "improvement" to the admin route
   table while relocating it is out of scope and would fail these.
9. **Documentation drift (LOW).** AGENTS.md §2 ceiling sentence, the new
   exemption value, and the actual file count must agree; `make ci` and the
   review gates check them. The headroom budget for directions 一/二 is
   prose-only — it is enforced by the lowered ceiling, which is the point.

**Dependency note**: 改进一 and 改进二 are independent; 改进三 depends on both.
This direction is the prerequisite for directions 一/二: it converts the frozen
60-file ceiling into real, gate-enforced headroom with zero
`layerExemptions` growth and zero wire/behavior change.
