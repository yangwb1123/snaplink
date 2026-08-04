# Architecture Review — interfaces/adapters Direction 2 (router backend conformance suite)

Reviewer role: senior architect (advisory; no files modified).
Basis: design `docs/auto/interfaces-adapters-direction2-design.md`, spec
`docs/auto/interfaces-adapters-direction2-spec.md`, current tree at
`9cdc22c2`, pinned deps gin v1.12.0 / echo v4.15.2 (`go.mod:10,15`).

Checks that actually ran on this revision: `go build ./...` (clean),
`go test -run 'TestMaintainability_|TestArchitecture_' .` (pass), source
reads of `shared/core/router.go`, both adapters, `interfaces/sso/aliases.go`,
`server_routes.go`, `build_app_core.go`, all six committed root gates, and
the pinned framework sources in the module cache (gin `gin.go`/`context.go`/
`routergroup.go`/`render/json.go`; echo `echo.go`/`response.go`/`router.go`/
`group.go`), plus line-count emulation of both size gates and the
import-boundary rule. No test suite run against new code (none exists yet).

## 1. Scope, assumptions, verified architecture summary

**Scope.** The design converts cross-backend unmatched-route behavior into an
executable contract: (1) a `routertest.ConformanceSuite` asserting byte
equality against a runtime-derived `http.NotFound` reference across
StdRouter/gin/echo; (2) constructor-installed 404/405 normalization in the
gin/echo adapters (default on, `WithFrameworkNotFound()` opt-out); (3)
registration-time middleware snapshots + RWMutex in both adapters and a
public `GatedRegistrar` promoted from `shared/core`'s unexported
`gatedRegistrar`.

**Assumptions.** No production behavior changes are intended; blast radius is
SDK-embedder-only. Both verified: `cmd/sso-server/build_app_core.go:155`
wires `sso.NewStdRouter()`, and no in-repo file outside
`interfaces/adapters/{gin,echo}` imports either adapter.

**Verified architecture summary.** The direction is sound and the suite
concept is the right investment: it mirrors the `permissionstest` precedent
(`domains/permissions/permissionstest/conformance.go`, 321 lines), the
reference bytes are derived at runtime (stdlib drift tracks all backends
together), each decision is independently shippable, and the gating
motivation is real — `core.NewGatedRouter` gates the admin API
(`accessors_threat.go:201`), CIBA (`server_routes.go:239`), OIDC userinfo
(`server_userinfo.go:33`), federation, self-service, branding, and CAEP, and
the production `TracingMiddleware` stamps `X-Request-Id`
(`interfaces/middleware/middleware.go:113`) — the exact header-fingerprint
scenario 12 forbids.

Eight of the design's eight "binding facts" verify against source
(one with a wrong mechanism description, see F9):
gin `default404Body` without newline/nosniff; echo `Response.Write` with no
committed guard; echo `DefaultHTTPErrorHandler` early-returns on committed;
gin `Next()` self-advances (only `Abort()` stops the chain); production
`Use()`-before-routes (`server_routes.go:108-131`); `RouterGroup.Handle`
/`Group.Add` generic registration; sso aliases at `aliases.go:111-115`;
`router_test.go` is `package core` (the spec's StdRouter hookup placement
would be an import cycle; the design's resolution is correct).

But the design's gate audit is incomplete in two committed rules, its echo
mechanism cannot compile, its gin trailing-slash analysis misses a 301 that
survives Decision 2, and its baseline matrix contains several factually
wrong cells. Four findings block the design as written; the rest are
accuracy/process gaps. All were independently re-verified for this review.

## 2. Findings table

| # | Sev | Finding | Evidence (verified) | Impact | Recommendation |
|---|---|---|---|---|---|
| F1 | High | `routertest` under `shared/core/` violates committed import-boundary rule 3 | `architecture_gate_test.go` rule 3: `fromDir "shared/core/"`, `forbidden "github.com/yangwb1123/snaplink/"`, empty exempt map (ratchet: shrink-only). `shared/core/routertest/conformance.go` imports `core` → `TestArchitecture_ImportBoundaries` fails on step 1. Precedent confirmed: `corecredential` imports no Snaplink package | Step 1 cannot land as designed without a forbidden exemption; the design's "no exemptions" claim is false. Its audit checked the layer gate (`layerName()` auto-classifies `shared`) and subdir counts but not rule 3 | Relocate to `shared/routertest/` (preferred) or `interfaces/adapters/routertest/` (acceptable). Both are layer-legal (shared→shared / interfaces→shared), depth ≤ 3, within all fan-out budgets, zero gate changes. See Decision options |
| F2 | High | Decision 2's echo wiring does not compile | echo v4.15.2: `NotFoundHandler`/`MethodNotAllowedHandler` are **package-level vars** (`echo.go:352,358`), not `Echo` struct fields (struct `echo.go:70`; only `HTTPErrorHandler` is a field, `:93`). `e.NotFoundHandler = ...` is a compile error. Mutating the package vars would be global state (cross-router contamination) | The design's only echo normalization mechanism cannot build; step 2 fails | Verified replacement: `e.RouteNotFound("/*", notFound)` (`echo.go:544`; per-node `notFoundHandler` wins over 405/OPTIONS branches, `router.go:746-755`) + delegating `HTTPErrorHandler` (405→404 conversion) + `OPTIONS("/*")` catch-all for the OPTIONS tuple. Two caveats to document: must install before the engine serves its first request (pooled-context panic risk on late registration), and an embedder's later `RouteNotFound` silently overwrites the node handler |
| F3 | High | gin scenario 7 (trailing slash) stays red after step 2 — pin incomplete | `RedirectTrailingSlash: true` is gin's `New()` default (`gin.go:213`); `handleHTTPRequest` runs `redirectTrailingSlash(c); return` before the NoRoute path (`gin.go:728`). `GET /known/` → 301 `Location: /known`, not 404 | Step 2's "scenarios 3–7 turn green on all backends" is false; embedders get 301 where StdRouter gives 404 (redirect-following OAuth clients could replay a wrong-path token request at the canonical path) | Pin `engine.RedirectTrailingSlash = false` beside `HandleMethodNotAllowed = false` (and confirm `RedirectFixedPath` stays false — it is the default). Update the matrix baseline cell for scenario 7 ("red: gin (301)") |
| F4 | High | `aliases.go` is at exactly 500 lines; the one-line alias breaks the file-size gate | `wc -l interfaces/sso/aliases.go` = 500 (at cap; file ends `\n`); `maintainability_budget_test.go` `maxFileLines = 500`, `fileSizeExemptions` empty and frozen; `checks/filesize.py` agrees. Repo precedent confirms the pressure: six files document re-exports relocated out of aliases.go "to keep that file within the per-file line budget" | Step 3 fails `TestMaintainability_FileSizeBudget` and `cli.py check-filesize`; the design's "budget headroom verified" misses the one file it proposes to touch | Place `type GatedRegistrar = core.GatedRegistrar` in an `interfaces/sso` file with headroom (`origin_validation.go` 236, `server_userinfo.go` 157, `quota.go` 177) — no new file, 60-file ceiling untouched. Update the design's wiring-points and budget section |
| F5 | Medium | Baseline matrix cells are factually wrong | (a) echo HEAD on method-mismatch → 405 with **empty body**: `DefaultHTTPErrorHandler` has a HEAD special case (`c.NoContent(he.Code)`, Issue #608, `echo.go:428+`), not "405 JSON". (b) echo OPTIONS on known path → **204 + Allow** via `optionsMethodHandler` (`router.go:753-754`), not "405 JSON". (c) gin scenario 7 is a 301, not byte-level red. (d) "byte-pinned JSON ... green" for scenarios 1/8/14 is false cross-backend: gin `WriteJSON` uses `json.Marshal` — no trailing newline, `application/json; charset=utf-8`; echo `c.JSON` uses `Encoder.Encode` — trailing newline, `charset=UTF-8` | The baseline record is step 1's whole proof (it is what demonstrates the gate has teeth); wrong cells misdirect the delivery order and the "green today" column contradicts the matrix | Correct the four cells; scenarios 1/8/14 need explicit per-backend byte pinning or a suite-level handler contract that is byte-stable across backends |
| F6 | Medium | "Step 1 lands red" and "each step leaves the tree green" are mutually exclusive | Design §Delivery order: "Step 1 — suite lands red" vs. "Each step lands with ... green". A committed red `go test ./...` breaks the mandatory verification gates (`go build && vet`, maintainability/architecture, handoff `make ci`) | Process contradiction; step 1 as described is unlandable under the committed workflow | Record the red baseline per scenario from a scratch worktree (evidence artifact, e.g. `docs/auto/` baseline file), then land suite + fixes atomically in green commits. The baseline record still proves the gate has teeth |
| F7 | Medium | `WithFrameworkNotFound()` silently destroys the gating oracle guarantee | Decision 2's opt-out skips normalization while the Decision-3 gate handlers unconditionally write `http.NotFound` bytes. Gate-off then = stdlib bytes; never-mounted = framework bytes (gin `default404Body`; echo JSON). Byte-distinguishable — exactly the oracle `GatedRouter`'s doc calls out. The suite's Factory rule forbids wiring the opt-out, so nothing exercises or documents the interaction | Anti-enumeration regression for the exact use case GatedRouter was built for (admin API gate); embedders get no warning | State in the design that gating and `WithFrameworkNotFound()` are incompatible for indistinguishability; add to the opt-out doc and the failure-mode table as an oracle degradation (not a "divergence"); optionally route the gate's 404 through the framework-native unmatched handler when opted out |
| F8 | Medium | Registration-time snapshots silently remove retroactive protection for gin/echo embedders | Both adapters read `g/e.middlewares` at request time in `wrapHandler` (`gin/adapter.go:88-96`, `echo/adapter.go:74-82`) — today `Use(authzMW)` after registration *does* protect already-registered routes. Decision 3c changes this to registration-time snapshotting (StdRouter's contract). No in-repo caller depends on it (verified) | SDK-embedder upgrade hazard: previously protected routes silently unprotected/untraced. The wrong direction for a security control (retroactive is safer) | Release note + `Use()` doc comments on both adapters: "middleware added via Use() no longer applies to previously-registered routes; register security middleware before routes". Keep scenario 10 pinning the new semantics |
| F9 | Low | Design misstates gin's default-404 mechanism | `serveError` sets `Header()["Content-Type"] = mimePlain` (`text/plain`, no charset) and writes `default404Body` via `c.Writer.Write` — not `c.String`, no `charset=utf-8` (`gin.go:764-780`). Conclusion (gin red at baseline) holds and is stronger: mismatch on newline, charset, and nosniff | Textual inaccuracy in a load-bearing claim; no code impact | Fix the design text |
| F10 | Low | Constructor mutation of embedder engines undocumented | `NewGinRouter` flips `HandleMethodNotAllowed` and replaces `NoRoute`; `NewEchoRouter` (as fixed) wraps `HTTPErrorHandler` and installs `RouteNotFound`/OPTIONS — on the embedder's own engine, whose other routes inherit the changed 404/405 semantics. Pre-construction configuration is silently overwritten; the gin flip is a no-op today (default already `false`) | Embedder API surprise; routes outside the adapter change wire behavior | Document on both `New*Router(engine)` constructors that the engine's 404/405 configuration is adopted and normalized at construction; state the pre-construction-overwrite rule in the precedence table |
| F11 | Low | Gate-off is proven by wire bytes, not handler non-execution | gin's writer appends body after commit (`response_writer.go`); a dropped `c.Abort()` produces 404+handler-body → scenarios 11–13 fail red for writing handlers (all production gated handlers write). But a side-effect-only handler (audit write, store mutation) would not be caught | Byte assertions are necessary but not sufficient | Gate scenario handlers increment a `t`-visible counter; assert counter == 0 when gate-off. One line per scenario |
| F12 | Info | Residual observations | (a) echo virtual hosts: `RouteNotFound` normalizes only the default host router; an embedder's `e.Host(...)` routers get unnormalized 404s — add to the engine-level boundary caveat. (b) Line-arithmetic inconsistency in the design's budget section (160→~235 vs +75→~235 vs <260) — all under 500, re-derive at implementation. (c) `Allow` header silently discarded when echo 405→404 — deliberate, consistent with StdRouter (which never emits `Allow`), document it. (d) HEAD-on-GET → 404 deviates from RFC 9110 §9.3.2's "identical to GET" convention (Go 1.22+ ServeMux auto-serves HEAD from GET) but matches today's sso-server wire — document as deliberate. (e) `NewGinRouterWithOptions(nil, ...)` nil-engine unspecified | Documentation items | Include in constructor docs and release notes |

## 3. Decision options

### D1 — `routertest` home

| Option | Trade-offs | Verdict |
|---|---|---|
| `shared/routertest/` (new sibling of `core` in the shared layer) | Mirrors the `permissionstest` precedent (test-support package beside the interface **owner**); auto-classified `shared`; zero gate changes; future backends (chi/fiber, wherever they live) reach it downward. Cost: a test-support package inside the kernel layer — but `permissionstest` establishes exactly this pattern in `domains/` | **Preferred** |
| `interfaces/adapters/routertest/` | Keeps `shared/` free of test-support code and sits beside its only consumers today; layer-legal, all budgets hold. Cost: the *core contract's* suite lives under a specific backend's directory — wrong ownership signal if a future backend appears outside `interfaces/adapters`, and third-party embedders must import `interfaces/adapters` internals to reuse it | Acceptable alternative |
| `shared/core/routertest/` + gate exemption | Matches the design's file plan. Cost: requires an exemption the ratchet forbids and the design itself vows not to add; would also make `corecredential`'s dependency-free property ambiguous for future audits | Rejected |

### D2 — `GatedRegistrar` alias home

| Option | Trade-offs | Verdict |
|---|---|---|
| Existing `interfaces/sso` file with headroom (`origin_validation.go` 236 / `server_userinfo.go` 157 / `quota.go` 177) | Follows the repo's established "relocated re-exports" pattern (six precedents); no new file; 60-file ceiling untouched | **Preferred** |
| Trim one line from `aliases.go` then add the alias | Keeps aliases together. Cost: fragile; the file is "Code generated" and at the cap with zero headroom for the next alias | Rejected (retire the pattern) |

### D3 — echo normalization mechanism

| Option | Trade-offs | Verdict |
|---|---|---|
| `RouteNotFound("/*")` override + delegating `HTTPErrorHandler` (405→404 conversion, sentinel swallow) + `OPTIONS("/*")` catch-all | Verified to produce byte-identical stdlib 404s for all five unmatched classes, multi-group safe, explicit embedder routes keep priority. Cost: must be installed before first request; embedder's later `RouteNotFound` overwrites (document, same later-wins precedence as gin `NoRoute`) | **Preferred** (replaces the design's non-compiling field assignments) |
| Mutate echo package-level `NotFoundHandler`/`MethodNotAllowedHandler` vars | Would compile. Cost: **global state** — breaks per-router opt-out isolation and cross-router embeddings sharing a process | Rejected |

### D4 — red-baseline process

| Option | Trade-offs | Verdict |
|---|---|---|
| Scratch-worktree baseline record + atomic green landing | Suite+f Step-2 fixes land in one green commit; the per-scenario red evidence is committed as an artifact; every handoff gate stays green | **Preferred** |
| Land the suite red in-tree (design as written) | Matches the spec's literal "套件先于修复落地". Cost: breaks the committed `go build/vet` + maintainability/architecture + `make ci` handoff contract, and every CI run between steps is red | Rejected |

## 4. Prioritized implementation sequence

Milestones, compatibility plan, risks, acceptance checks.

**Phase 0 — design correction (no code).** Fix the design doc: relocate
`routertest` (F1), replace the echo mechanism (F2), add the gin TSR/FixedPath
pins (F3), move the alias (F4), correct the matrix cells and the JSON-byte
pinning decision (F5), adopt the scratch-baseline process (F6), document the
opt-out × gating incompatibility (F7) and the constructor-mutation rule (F10).
Acceptance: the design's "budget headroom verified" and "no exemptions"
claims are true against all six committed gates.

**Phase 1 — suite + normalization land atomically.** `routertest` at its
chosen home with StdRouter hookup (green from the start); gin/echo
conformance files; Decision 2 fixes (gin: `NoRoute` normalization +
`HandleMethodNotAllowed=false` + `RedirectTrailingSlash=false`; echo:
`RouteNotFound("/*")` + delegating error handler + OPTIONS catch-all). The
red baseline is captured from a scratch worktree before the fixes and
committed as an evidence artifact. Compatibility: adapter constructors keep
their variadic signatures (`NewGinRouter(engine ...*gin.Engine)` unchanged,
delegating); the normalization is default-on with `WithFrameworkNotFound()`
opt-out; zero in-repo production impact (StdRouter only).
Risks: echo `RouteNotFound` before-first-request constraint; embedder
pre-construction 404/405 config silently overwritten (documented).
Acceptance: `go build ./... && go vet ./...`; `go test -run
'TestMaintainability_|TestArchitecture_' .`; scenarios 3–7 byte-identical
to `referenceNotFound` on all three backends; deleting the normalization
installation turns the suite red.

**Phase 2 — snapshot + gated registration.** RWMutex + registration-time
snapshots in both adapters; `GatedRegistrar` promotion in
`shared/core/router.go`; alias in the chosen sso file; `RegisterGated`
implementations (gin gate handler with mandatory `c.Abort()`; echo gate
middleware with `errGateOff` sentinel); suite scenarios 10–14 green; the
`-race` concurrent `Use`+`ServeHTTP` tripwire. Compatibility: the
`gatedRegistrar`→`GatedRegistrar` rename is additive (an unexported-method
interface could not be implemented outside `shared/core` anyway); the
snapshot semantic change is the one embedder-visible behavior change —
release-note it (F8). Risks: scenario-12 byte assertion must never be
weakened to `strings.Contains` (the abort tripwire); `RegisterGated` must
route through `snapshotMiddlewares()` (design risk item 9).
Acceptance: `go test ./... -race`; scenarios 11–13 assert byte identity and
zero header fingerprint; `TestArchitecture_ImportBoundaries` and
`TestMaintainability_FileSizeBudget` green without exemptions.

**Phase 3 — full handoff.** `go test ./test/ -run TestE2E -v`; `make ci`
(nested modules, examples, config, module validation); release notes
covering F7/F8/F10/F12; correct the spec's two wrong claims (echo field
assignment at spec line 97; StdRouter hookup placement at spec lines 41–42)
in the same change.

## 5. Unknowns needing owner/product decisions

1. **Red-baseline process** (F6): will the team accept the scratch-worktree
   baseline record + atomic green landing, or does the spec's literal
   "suite lands before fixes" require an in-tree red commit (breaking the
   handoff gate)?
2. **`routertest` home** (F1/D1): `shared/routertest` (contract adjacency,
   permissionstest-pattern fidelity) vs `interfaces/adapters/routertest`
   (kernel purity) — an ownership-signal decision for future backends.
3. **`WithFrameworkNotFound()` × gating** (F7): is the opt-out allowed to
   silently degrade the oracle guarantee (documented), or should the gate
   track the configured 404 regime when opted out (small design change)?
4. **Cross-backend JSON byte pinning** (F5d): scenarios 1/8/14 — per-backend
   expected bytes, or a suite handler contract byte-stable across backends?
   (gin and echo JSON bytes differ today in trailing newline and charset
   case.)
5. **gin TSR pin** (F3): breaking gin's trailing-slash redirect for
   embedders (opt-out covers them) — confirm the StdRouter-404 contract wins
   over framework-native 301.
6. **echo OPTIONS catch-all** (F2): an explicit `OPTIONS("/*")` route is
   embedder-visible; confirm acceptable and covered by the opt-out.
7. **Spec correction scope**: whether the spec's two incorrect claims are
   fixed in the same change that lands the design.

Bottom line: the design's direction, suite shape, oracle reasoning, and
snapshot/race model are correct, and its resolution of the spec's import-cycle
contradiction is right. As written it cannot land: F1 and F4 violate committed
gates the design claims to respect, F2 does not compile, F3 leaves scenario 7
permanently red. All four have one-line-ish corrections that do not change the
design's shape.
