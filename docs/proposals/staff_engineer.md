All verification complete. The design's framework claims were tested empirically against the pinned deps (gin v1.12.0, echo v4.15.2) in a scratch module under `/tmp` (nothing added to the repo). Review follows.

---

# Staff Engineer Review — `interfaces-adapters-direction2-design.md`

**Review basis.** `ai-dev/prompts/README.md`, the six committed root Go gates (`architecture_gate_test.go`, `architecture_layer_test.go`, `directory_fanout_test.go`, `maintainability_budget_test.go`, `maintainability_complexity_test.go`, `maxdepth_test.go`), and `engineering.yaml`. Checks that actually ran on this revision: `go build ./...` (clean), `go test -run 'TestMaintainability_|TestArchitecture_' .` (ok), plus empirical experiments against the pinned gin/echo versions in `/tmp/ginexp`. Not run (design-only change, tree has unrelated in-flight work): `go vet`, `-race`, `TestE2E`, `make ci`, `python cli.py`.

## 1. Change / subsystem summary and affected contracts

The design implements the Direction-2 spec in three steps: (1) a `routertest.ConformanceSuite` with byte-equality assertions on the unmatched-route wire response across `StdRouter`/gin/echo; (2) constructor-installed 404/405 normalization in the gin/echo adapters; (3) a public `GatedRegistrar` capability promoted from `shared/core`'s unexported `gatedRegistrar` (router.go:343), with registration-time middleware snapshots plus RWMutex in both adapters.

Affected public contracts: `shared/core.Router` family (new exported `GatedRegistrar`), `sso` aliases, gin/echo adapter constructors (`NewGinRouterWithOptions`/`NewEchoRouterWithOptions`, `WithFrameworkNotFound`), and the wire semantics of unmatched responses on the two adapters (stdlib-identical 404). No production wiring changes (verified: `cmd/sso-server/build_app_core.go:155` uses `NewStdRouter()`; `Mount()` installs middleware before routes at `server_routes.go:92,108-131`).

Most of the design's "eight binding facts" verified true: `default404Body` without newline and no nosniff (gin.go:33; reproduced), `HandleMethodNotAllowed: false` default (gin.go:213), gin `Next()` self-advancing (context.go:188-197), echo `Response.Write` unguarded (response.go:71-78), `DefaultHTTPErrorHandler` committed early-return (echo.go:428), `Group.Add`/`RouterGroup.Handle` generic registration (group.go:121, routergroup.go:103), aliases at `aliases.go:111-115`, `router_test.go` is `package core`, anchors at :443/:500, `headersEqual` at :546, line counts (router.go 440, gin 160, echo 140, `permissionstest/conformance.go` 321). **Four material defects remain: one committed-gate violation in the file plan, one compile-level error in the echo mechanism, one incomplete gin pin, and one internal-inconsistency cluster.**

## 2. Findings

### F1 — High: `routertest` under `shared/core/` violates the committed import-boundary gate
- **Path/symbol**: `architecture_gate_test.go` rule 3 (`fromDir: "shared/core/"`, `forbidden: "github.com/yangwb1123/snaplink/"`, empty exempt map, ratchet forbids growth) vs. the design's `shared/core/routertest/conformance.go` importing `core`.
- **Current behavior**: Rule 3 states the `shared/core` subtree is a dependency-free leaf that must import no internal package. The design's own file plan (and the spec's, spec line 41-42) puts a non-test file importing `github.com/yangwb1123/snaplink/shared/core` under that prefix → `TestArchitecture_ImportBoundaries` fails on step 1. Precedents confirm the constraint: `corecredential` (the existing subpackage) imports **no** Snaplink package (grep verified); `permissionstest` lives under `domains/permissions/`, outside the rule. The design verified the *layer* gate ("auto-classified shared", `architecture_layer_test.go:61`) and the subdir count, but never checked rule 3 — its "no exemptions" claim is therefore wrong: making this pass would require adding an exemption the ratchet forbids.
- **Impact**: Step 1 cannot land as designed without either a forbidden exemption or relocation; the design's central "budget headroom verified" claim is incomplete.
- **Minimal correction**: relocate the suite to `interfaces/adapters/routertest/` (rank `interfaces`; imports `shared/core` downward, layer-legal; gin/echo test files import it same-rank; depth 3, ≤15 subdirs, ≤10 files — all within budget, no exemptions anywhere) or `shared/routertest`.
- **Focused test**: `go test -run TestArchitecture_ImportBoundaries .` stays green with the relocated package; `importRules` untouched.

### F2 — High: Decision 2's echo mechanism does not compile against pinned echo v4.15.2
- **Path/symbol**: `e.NotFoundHandler = notFound; e.MethodNotAllowedHandler = notFound` (design §Decision 2) — these are **package-level vars** in echo v4.15.2 (`echo.go:352,358`), not `Echo` struct fields (struct verified at `echo.go` `type Echo struct`). Compile failure reproduced: `ec.NotFoundHandler undefined (type *echo.Echo has no field or method NotFoundHandler)`. The spec prescribes the same broken API (spec line 97).
- **Current behavior / impact**: The design's only echo normalization mechanism cannot build. Also note `NotFoundHandler`/`MethodNotAllowedHandler` package vars are global — mutating them would break the per-router opt-out model and cross-router isolation.
- **Minimal correction** (verified working): install `e.RouteNotFound("/*", notFound)` at construction. Empirically this yields byte-identical `"404 page not found\n"` + nosniff for **all five** unmatched classes on v4.15.2: unknown path, wrong-method POST, HEAD, OPTIONS, trailing slash (`matchedRouteMethod` from the per-node notFoundHandler wins over the 405/OPTIONS branches, router.go:710-753). Two caveats to document: (a) it must be installed before the engine serves its first request — a late registration panics on pooled contexts (`router.go:691` index-out-of-range, reproduced when installed after prior requests); (b) an embedder's later `Group.Use(...)`/`RouteNotFound` on the same engine silently overwrites the node handler (same later-wins precedence the design documents for gin `NoRoute` — currently undocumented for echo).
- **Focused test**: suite scenarios 3–7 on echo after the fix; `go vet ./interfaces/adapters/echo/...`.

### F3 — High: gin scenario 7 (trailing slash) stays red after step 2 — pin incomplete
- **Path/symbol**: gin `RedirectTrailingSlash: true` default (`gin.go` `New()`); design pins only `HandleMethodNotAllowed = false` + `NoRoute`.
- **Current behavior**: `GET /known/` on a `GET /known`-only engine → **301** `Location: /known` with stdlib redirect body (reproduced), not a 404 of any byte shape. The matrix's baseline label "red: gin/echo (byte level)" is wrong for gin — it is a status-level divergence.
- **Impact**: Step 2's claim "suite scenarios 3–7 turn green on all backends" is false; the "each step leaves the tree green" invariant breaks at step 2.
- **Minimal correction**: pin `engine.RedirectTrailingSlash = false` in the gin adapter constructor alongside `HandleMethodNotAllowed` (and confirm `RedirectFixedPath` stays false — it is the default). Update the matrix baseline cell for scenario 7 to "red: gin (301)".
- **Focused test**: scenario 7 on gin after the pin (asserts byte-identity with `referenceNotFound`).

### F4 — Medium: echo OPTIONS analysis wrong; design internally inconsistent about scenario 6
- **Path/symbol**: echo router `router.go:753-754` — OPTIONS on a known path is routed to `optionsMethodHandler` (204 NoContent + `Allow` header), **not** `MethodNotAllowedHandler` (reproduced: `204 allow="OPTIONS, GET"`).
- **Impact**: the matrix's "red: echo (405 JSON)" baseline for scenario 6 is factually wrong (it is 204 + Allow today), and the delivery order ("scenarios 3–7 turn green on all backends") contradicts the acceptance mapping ("scenarios 3/4/5 green on echo", silently dropping 6). With the F2 correction scenario 6 does go green, but only via a mechanism the design never identified. The design should also state the deliberate semantic choice explicitly: StdRouter answers 404 for OPTIONS; echo's native 204+Allow is arguably more correct HTTP — the suite pins the StdRouter contract by design, but that decision deserves a line.
- **Minimal correction**: reconcile the three statements after F2; document the OPTIONS contract decision.
- **Focused test**: scenario 6 on echo before/after the F2 fix.

### F5 — Medium: the `sso.GatedRegistrar` alias as wired breaks the 500-line file gate
- **Path/symbol**: `interfaces/sso/aliases.go` is exactly **500 lines** (verified; at the cap; `fileSizeExemptions` is empty and capped at 0).
- **Impact**: Decision 3a's "alias goes in aliases.go (one line)" pushes the file to 501 → `TestMaintainability_FileSizeBudget` fails. The design's budget-headroom audit covered router.go and the adapters but not aliases.go. (The `root_policy.exempt_files` entry for aliases.go is a filename-pattern exemption — it does not touch the file-size gate.)
- **Minimal correction**: place the alias in an `interfaces/sso` file with headroom (e.g. `server_userinfo.go` 157, `quota.go` 177, `origin_validation.go` 236) — still no new file, 60-file ceiling untouched — or trim one line from aliases.go.
- **Focused test**: `go test -run TestMaintainability_FileSizeBudget .` after the edit.

### F6 — Low: estimate/claims inconsistencies (budgets still hold)
- Adapter line arithmetic does not compose: "gin 160 → ~235; echo 140 → ~220" (total) vs. step-2-only "+75 (~235) / +75 (~215)" vs. step-3 "both < 260". Step 3 adds mutex + `snapshotMiddlewares` + `RegisterGated` on top of step 2, realistically landing gin near ~270. All under 500, so the gate is safe — re-derive the numbers at implementation and pick one total per backend.
- Scenario 5 baseline: echo HEAD on a GET-only route is 405 with an **empty body** (reproduced), not "405 JSON".
- Scenario 7 baseline: gin is a 301 (see F3), not byte-level.

## 3. Gate table

| Authoritative rule | Observed value / result | Evidence | Status |
|---|---|---|---|
| File ≤ 500 lines, exemptions empty/capped 0 | router.go 440; gin 160; echo 140; aliases.go **500 (at cap)**; `routertest` ~400 est. | `wc -l`, `maintainability_budget_test.go` | **Red as designed**: F5 (+1 line → 501); rest green |
| Function ≤ 50 lines, cyclo ≤ 15, caps 0 | No new code yet; design's functions are small | — | Green (N/A, by design) |
| `if` nesting ≤ 3 | Design targets ≤ 3 per function | — | Green (by design) |
| Directory depth ≤ 3 | `shared/core/routertest` = 3; `interfaces/adapters/routertest` = 3 | `maxdepth_test.go` | Green (either layout) |
| Files/dir ≤ 10 (frozen ceilings; `interfaces/sso` 60) | No new sso files; `interfaces/adapters` 3 files | `directory_fanout_test.go` | Green |
| Subdirs ≤ 15 (stricter; see drift below) | `shared/core` 1 → 2 | `directory_fanout_test.go` | Green |
| Import boundaries: `shared/core/` imports nothing internal; oauth↔oidc | `routertest/conformance.go` imports `core` | `architecture_gate_test.go` rule 3, exempt map nil | **Red as designed**: F1; baseline gate run green today |
| Layer direction (no `layerExemptions`) | shared→shared; adapters→shared; auto-classified | `architecture_layer_test.go:61` | Green |
| Root policy | No new root files | `engineering.yaml` | Green |
| Python vs Go thresholds | Python `max_subdirs=15` (`checks/config.py:54`, asserted `test_directory_fanout.py:10`); Go gate `maxSubdirsPerDir=16` — Go gate is **looser**; AGENTS.md table says 15 and flags the ">16 drift" | both files | Design cites 15 (stricter) — compliant; drift reported, no action needed |

## 4. Technical-debt register (verified debt only)

| Debt | Evidence | Dependency | Priority |
|---|---|---|---|
| gin/echo adapters read `middlewares` at request time; `Use()` concurrent with `ServeHTTP` is a real data race today; `Use` after registration retroactively mutates live routes | `interfaces/adapters/{gin,echo}/adapter.go` `wrapHandler` closure reads `g/e.middlewares` per request, no lock | Decision 3c (design addresses) | High |
| gin 301 trailing-slash and echo 204+Allow OPTIONS are framework-native semantics that diverge from StdRouter's 404 contract, unverified anywhere today | F3/F4 reproductions | Decisions 2 (suite pins them) | Medium |
| `interfaces/sso` at 60/60 file ceiling and aliases.go at 500/500 — zero headroom for future aliases | `ls interfaces/sso/*.go \| wc -l` = 60 non-test; `wc -l aliases.go` = 500 | F5 fix establishes the relocation pattern | Low (binding) |
| Spec drift: spec's echo `MethodNotAllowedHandler` field assignment (spec line 97) and `routertest` placement (spec lines 41-42) are both wrong against code; the design inherited both | F1/F2 | Correction pass on spec when design lands | Medium |

## 5. Maintainability assessment, quick wins, evidence gaps

**Assessment.** Structurally strong: three independently shippable decisions, stateless suite with a factory-per-subtest rule, derived (not hardcoded) reference bytes, fail-closed default for normalization, and a genuinely useful 12-item risk list. The weakness is verification depth: two of the eight "binding facts" are wrong against the pinned frameworks (echo fields; gin trailing-slash class), and the gate audit missed two committed rules (import-boundary rule 3; the 500-line cap on aliases.go). Both are cheap to fix at design time and expensive if discovered at step-gate time — which is exactly what this review is for.

**Quick wins.** All four High/Medium defects have one-line-ish corrections: relocate `routertest` (F1); `e.RouteNotFound("/*", notFound)` (F2); pin `RedirectTrailingSlash = false` (F3); move the alias off aliases.go (F5).

**Evidence gaps.**
- The "27 scenarios" `permissionstest` precedent count is unverified (conformance.go has 1 `t.Run`; the count is table-driven) — rhetorical claim only, no impact.
- Echo virtual-host routing (`e.findRouter(r.Host)`): `RouteNotFound` normalizes only the default host router; an embedder registering `e.Host(...)` routers on the passed engine would get unnormalized 404s on those hosts — worth one line in the engine-level boundary caveat (design item 7).
- The design's assumption that `gin.Default()`'s Logger/Recovery stamp no response headers is standard knowledge, not re-verified here; it is load-bearing for scenarios 11-13 on gin.
- `-race` concurrency behavior of the adapters today (pre-fix) was not exercised; the race claim rests on source reading.

**Bottom line:** direction is sound and the suite concept is the right investment, but the design as written cannot land steps 1–2 green: F1 breaks a committed gate on step 1, F2 breaks compilation on step 2, F3 breaks step 2's green invariant, and F5 breaks step 3's gate. Fix F1–F3 before implementation starts; F4–F5 during the same pass.
