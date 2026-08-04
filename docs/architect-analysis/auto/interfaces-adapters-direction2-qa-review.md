# QA Review: interfaces/adapters — Direction 2 (router backend conformance suite)

Review of `docs/auto/interfaces-adapters-direction2-design.md` against
`docs/auto/interfaces-adapters-direction2-spec.md`, current code, and the
pinned framework sources (gin v1.12.0, echo v4.15.2, both in root `go.mod`).
All baseline claims were re-measured empirically, not inferred. **No code in
the repo was changed; this is advisory analysis of a design artifact.**

## 1. Test inventory and commands actually run (this revision)

| Command | Result |
|---|---|
| `go build ./... && go vet ./...` | clean |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | pass |
| `go test ./shared/core/... ./interfaces/adapters/...` | pass (core, corecredential, gin, echo) |
| `go test -race ./shared/core/... ./interfaces/adapters/...` | pass |
| `go test ./... -race`, `go test ./test/ -run TestE2E`, `make ci` | **not run** — no code changed; adapters are embedder-only surfaces, every production/E2E wiring uses `sso.NewStdRouter()` (verified: `cmd/sso-server/build_app_core.go:155`, 10+ `test/*.go` sites). Pending at implementation steps, per proportionality. |

Plus a disposable harness (module in `/tmp` with `replace` to this repo,
deleted after) that measured, on the current tree: gin/echo unmatched-path
bytes for all five 404/405 tuples, trailing-slash behavior, `Use()`-after-
registration, gate-off header leak via `GatedRouter` fallback, JSON body bytes
per backend, and candidate normalization wirings for both frameworks.

### Verified design claims (all **Verified**, with source)

- gin `default404Body = "404 page not found"` no trailing newline (`gin.go:33`);
  written via `serveError` (`gin.go:759`); no `X-Content-Type-Options`.
- gin `Context.Next()` advances `c.index` itself — only `Abort()` stops the
  chain (`context.go:188-196`).
- gin `HandleMethodNotAllowed: false` is the `New()` default (`gin.go:213`);
  `RedirectTrailingSlash: true` default (`gin.go:211`).
- echo `Response.Write` writes the body through unconditionally
  (`response.go:71`); `DefaultHTTPErrorHandler` early-returns when committed
  (`echo.go:428`).
- echo group creation registers `RouteNotFound("", NotFoundHandler)` and
  `RouteNotFound("/*", NotFoundHandler)` (`group.go:31-32`); a later
  `RouteNotFound` registration **overwrites** the node's handler
  (`router.go:478`), no panic, no duplicate.
- echo's router hardcodes the **package-level** `NotFoundHandler` /
  `MethodNotAllowedHandler` vars and an `optionsMethodHandler` 204 path
  (`router.go:745-755`); `Echo` has **no** `NotFoundHandler` /
  `MethodNotAllowedHandler` fields (struct grep).
- Production wiring: `mountMiddleware()` runs `Use()` before any mount
  (`interfaces/sso/server_routes.go:92,113-132`); stock binary and E2E use
  StdRouter only.
- `shared/core/router_test.go` is `package core` (import-cycle claim holds);
  `aliases.go:111-115` aliases exist; `interfaces/sso` sits at 60 non-test
  files (ceiling); budgets: `router.go` 440, gin adapter 160, echo adapter
  140, `permissionstest/conformance.go` 321; `architecture_layer_test.go:61`
  auto-classifies `shared`; `routertest` directory is free.
- Adapter tests are happy-path only (gin 12, echo 11: GET/POST/Bind/DELETE/
  PATCH/Query/Redirect/SetGet/MiddlewareInvocationCount/Group/
  RequestAndResponseWriter/AcceptsExistingEngine) — no 404/405/gating/order
  coverage, exactly as the spec claims.
- No production callers of `NewGinRouter`/`NewEchoRouter` (grep, excluding
  the adapters' own tests).

### Measured baseline (ground truth for the "red" column)

| # | Scenario | Measured today |
|---|---|---|
| 3 | Unknown path | gin: 404 `"404 page not found"` (no `\n`, no nosniff) · echo: 404 JSON `{"message":"Not Found"}\n` |
| 4 | POST on GET-only | gin: 404 wrong bytes · echo: **405 JSON** |
| 5 | HEAD on GET-only | gin: 404 wrong bytes · echo: **405, empty body** (DefaultHTTPErrorHandler HEAD→`NoContent` path) |
| 6 | OPTIONS on known | gin: 404 wrong bytes · echo: **204, empty body + Allow** (`optionsMethodHandler`) |
| 7 | Trailing slash `/known/` | gin: **301 redirect** (`RedirectTrailingSlash`) · echo: 404 JSON |
| 10 | Use after register | gin and echo both apply the late middleware to `/a` (401 + `X-MW`) — request-time read confirmed |
| 11/12 | Gate-off | gin and echo both: 404 but `X-Probe` stamped by global middleware (fallback leak confirmed) |
| 1/8/14 | JSON bodies | core/echo: `{"e":"x"}\n`, `Content-Type: application/json` · gin: `{"e":"x"}`, `Content-Type: application/json; charset=utf-8` — **cross-backend equality does not hold for JSON** |

## 2. Requirement-to-test matrix

| Spec requirement | Design coverage | Status | Evidence |
|---|---|---|---|
| `routertest.ConformanceSuite` (factory + `Run`, permissionstest shape) | Decision 1 API | **Verified feasible** | `permissionstest/conformance.go:30-38` precedent; no import cycle (`router_test.go` is `package core`; gin/echo conformance tests are internal tests of their own packages) |
| Byte equality (status+body+headers), not `Contains` | `referenceNotFound` + full header-map equality | **Verified feasible** | Measured `http.Error` also `Del("Allow")`, so even the echo 405→404 conversion yields header-map-identical output |
| Red baseline before fixes proves the gate | Step 1 record | **Contradiction — see F-5** | Measured red mechanisms differ from the design's parentheticals (F-3) |
| echo unknown-path/method-mismatch/HEAD byte-identical after fixes | Decision 2 | **Design wiring is invalid; alternative verified** — see F-1 | `e.NotFoundHandler`/`e.MethodNotAllowedHandler` do not exist; correct wiring measured green for scenarios 3-7 |
| Deleting not-found installation → suite red | Scenarios 3-7 | **Verified feasible** | Constructor-installed handlers are the only thing producing stdlib bytes (baseline measured red without them) |
| `Use()` after registration leaves registered routes unchanged | Scenario 10 | **Verified** | StdRouter snapshots (`router.go:224`); gin/echo request-time read measured; production wiring unaffected (`Use` before routes) |
| `-race` clean incl. concurrent `Use`+`ServeHTTP` | 3c + adapter tests | **Structurally sound** | After 3c `ServeHTTP` never touches the slice; current packages race-clean |
| Gate-off = 404 plain text, no global-mw header leak, three backends | Scenarios 11-13 | **Verified feasible** | gin gate: `Handle` + `Abort()` (only chain stopper, verified); echo gate: `Add` middleware + sentinel + delegating `HTTPErrorHandler` (default early-return verified) |
| Build/vet, maintainability+architecture, `make ci` | Step gates | **Verified for current tree**; `make ci` deferred to implementation | commands above |
| New backend cannot claim `WithRouter` without the suite | Review convention | **Accepted limitation** (same as permissionstest) | no compile-time enforcement exists; documented |

## 3. Findings (by severity)

### F-1 — High: Decision 2's echo wiring references fields that do not exist
`e.NotFoundHandler = notFound` / `e.MethodNotAllowedHandler = notFound` cannot
compile against echo v4.15.2: the `Echo` struct has only `HTTPErrorHandler`
(verified by struct grep), and the router dispatches to the **package-level**
`NotFoundHandler`/`MethodNotAllowedHandler` vars, with OPTIONS hardcoded to a
204 `optionsMethodHandler` (`router.go:745-755`). The design's "per-backend
wiring" section is unimplementable as written.
**Verified alternative (measured, adapter-realistic order — group created
first, overrides installed after):**
```go
prev := e.HTTPErrorHandler
e.HTTPErrorHandler = func(err error, c echo.Context) {
    var he *echo.HTTPError
    if errors.As(err, &he) && he.Code == http.StatusMethodNotAllowed {
        http.NotFound(c.Response(), c.Request()) // http.Error also Del("Allow")
        return
    }
    prev(err, c)
}
g.RouteNotFound("", notFound)      // overwrites group-creation default (router.go:478)
g.RouteNotFound("/*", notFound)
g.OPTIONS("/*", notFound)          // kills the hardcoded 204; static routes still win
```
Measured: scenarios 3-7 byte- and header-identical to `http.NotFound` on echo,
multi-group unaffected, explicit `OPTIONS /path` routes keep priority.
**Acceptance assertion for the fix:** scenarios 3-7 green on echo; the echo
conformance test fails if any of the three installation lines is deleted.

### F-2 — High: Decision 2's gin wiring omits the trailing-slash pin
Scenario 7 is **301 today** (measured) — `RedirectTrailingSlash: true` is
gin's default and redirects before `NoRoute` runs. The design pins only
`HandleMethodNotAllowed` + `NoRoute`, so step 2 would leave scenario 7 red on
gin. **Fix:** the constructor must also pin `e.RedirectTrailingSlash = false`
and `e.RedirectFixedPath = false` (measured: all five 404 tuples then
byte-identical, including `/known/` and `/known//`).

### F-3 — Medium: baseline-record parentheticals are wrong in four cells
Matters because step 1's whole point is an accurate red-baseline record
("what could break" #2); wrong mechanisms mislead the fix review:
- scenario 5 echo: 405 **empty body** (HEAD→NoContent), not "405 JSON";
- scenario 6 echo: **204 + Allow**, not "405 JSON" (the router never consults
  the error handler for OPTIONS);
- scenario 7 gin: **301** (status-level), not "byte level";
- scenario 11: red at **body level on both** (gin newline vs native 404; echo
  JSON vs stdlib text), not "header level".

### F-4 — Medium: scenarios 1/8/14 need explicit per-backend pinning
Cross-backend JSON byte equality is false today: core/echo emit
`{"e":"x"}\n` + `application/json`; gin emits `{"e":"x"}` +
`application/json; charset=utf-8` (measured). If the suite asserts
cross-backend equality for these, scenarios 1/8/14 are red on gin — silently
contradicting the "green today" column; if it pins per-backend bytes, the
suite cannot catch JSON drift. The design must state: the **only
cross-backend byte contract is the unmatched-route 404**; JSON responses get
per-backend pins, and the Content-Type assertion must allow gin's charset
suffix (prefix match) or pin per backend. Also state the suite's scoping
relative to the spec's "同一套 handler 挂在不同后端产生相同线上行为" goal.

### F-5 — Medium: delivery-order contradiction ("suite lands red" vs "every step leaves the tree green")
These are mutually exclusive: with the suite wired in, `go test
./interfaces/adapters/...` fails until step 2 lands, and AGENTS.md mandates
green gates after every `.go` edit. Resolve explicitly — recommended: run the
suite against the **unfixed** tree from a scratch worktree, record the red
output (scenario-by-scenario) in the step-2 commit message or a
`docs/auto/` baseline note, then land suite + normalization atomically. This
preserves the gate's teeth without a red tree. Alternative: land the suite
with per-scenario `t.Skip` markers referencing a tracking issue, removed in
step 2 (weaker — CI stays green without exercising the assertions).

### F-6 — Low: `NewGinRouterWithOptions(engine *gin.Engine, opts ...Option)` nil handling unspecified
The variadic `NewGinRouter()` allows zero engines (→ `gin.Default()`); the
WithOptions entry point must document nil behavior (nil → `gin.Default()`?)
or make the engine optional.

### Info (no action required, document only)
- **Panic semantics diverge:** `gin.Default()` installs Recovery (panic → 500
  HTML) while StdRouter/echo propagate. Pre-existing, outside scope, but the
  Factory rule (public constructor) means the gin conformance run exercises
  the Recovery-wired engine; note it as a documented divergence.
- **Echo OPTIONS catch-all is embedder-visible:** it changes `Routes()` and
  global OPTIONS semantics on the engine — the only per-instance way to kill
  the hardcoded 204; must be called out in adapter release notes.
- **`Allow` header:** the echo 405→404 conversion is header-safe for free —
  `http.Error` deletes `Allow` (measured).

## 4. Prioritized scenario list

The 14-scenario matrix is sound. Priority order for implementation and review:

1. **P0 (red-baseline proof):** 3 (UnknownPath), 4 (MethodMismatch),
   5 (HeadOnGetRoute) — the spec's named acceptance tuples.
2. **P0:** 6 (OptionsOnKnownPath), 7 (TrailingSlash) — mechanisms diverge
   per backend (F-1, F-2); these are the ones a naive fix will miss.
3. **P1:** 10 (UseAfterRegister) — the snapshot contract change.
4. **P1:** 11, 12 (gate-off bytes, no header leak) — the security-relevant
   property (admin/federation/CAEP gates in production); 12 is the three-
   backend reproduction of `router_test.go:500`.
5. **P1:** 13 (GatedGroup_PreservesGate) — regression guard for
   `GatedRouter.Group` composition.
6. **P2:** 8 (MiddlewareOrderAndAbort), 9 (GroupPrefix), 1, 2, 14 (happy
   path) — green today; pin per-backend bytes (F-4).

Suggested additions (small, high value):
- **A1:** gate toggle `live → false → true` on one instance (re-enable path;
  currently only covered across separate scenarios).
- **A2:** wrong method on a **gated-off** path (gin: `NoRoute`; echo: 405→404
  conversion) — both must equal the reference; pins the cross-direction
  interaction.
- **A3:** double `Abort()` (Abort after Abort) — no-op, no double write.

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**Gaps**
- The red-baseline record has no pinned artifact/command (F-5). Recommend:
  `go test ./interfaces/adapters/... -run 'Conformance' -v` against the
  unfixed tree, output committed with step 2.
- Scenario 1/8/14 assertion semantics are underspecified (F-4) — decide
  before step 1 lands, or the suite will need a rewrite mid-delivery.
- No coverage decision for engine-level middleware (`engine.Use`/`e.Use`)
  stamping headers on unmatched requests — the design documents the boundary
  but the suite cannot detect it; acceptable, but state it as a non-goal in
  the suite doc comment.

**Flake risks:** none identified — no timing, network, randomness, or shared
state; reference bytes derived at runtime from `http.NotFound` (stdlib drift
moves all backends together); fresh `Factory(t)` per subtest; gin Logger noise
goes to stderr only. The `-race` concurrent test is deterministic by
construction (structural race-freedom, not timing-based) — keep it as a
tripwire, as designed.

**Fixtures needed:** none — no golden files (reference is derived), no
network, no storage. The suite is stateless.

**Exit criteria**
- Step 1: suite files + StdRouter hookup green; red baseline for gin/echo
  recorded (F-3-corrected mechanisms); `go build/vet` +
  maintainability/architecture green.
- Step 2: scenarios 3-7 green on all backends with the F-1/F-2-corrected
  wiring; delete-the-installation tripwire demonstrated once.
- Step 3: scenarios 10-14 green; `-race` concurrent test green;
  `interfaces/sso` still 60 files; `router.go` ≤ 500.
- Handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  `make ci` — none of which should change outcome (production wiring is
  StdRouter-only, verified).

## Bottom line

The design's architecture (suite + normalization + registration-time
snapshot/`GatedRegistrar`) is sound, and its framework-internals research is
accurate. Two High findings block step 2 as written (echo wiring references
nonexistent fields; gin missing the `RedirectTrailingSlash` pin) — both have
empirically verified replacements. The baseline record needs correction
(F-3), scenario 1/8/14 pinning must be decided before the suite lands (F-4),
and the "red tree vs green tree" delivery contradiction needs an explicit
resolution (F-5). No security or wire-contract regressions are introduced for
the stock server (StdRouter-only wiring).
