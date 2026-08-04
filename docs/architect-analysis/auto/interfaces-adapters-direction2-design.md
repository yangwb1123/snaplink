# Design: interfaces/adapters — Direction 2 (router backend conformance suite)

Design for `docs/auto/interfaces-adapters-direction2-spec.md`. Implements the
three evidence-backed decisions in order 1 → 2 → 3, each independently
shippable under the mandatory gates. This document decides the API surface,
the state/storage model, the failure modes, and the things that could break
the design.

## Ground truth verified beyond the spec

The spec's evidence was re-verified against current code. Eight additional
facts materially constrain the design and are treated as binding:

- **gin fails byte-equality today, at the body and header level, not just on
  method mismatch.** gin v1.12.0's unmatched-route response is
  `default404Body = []byte("404 page not found")` (`gin.go:33`) — no trailing
  newline — written via `c.String`, which sets `Content-Type: text/plain;
  charset=utf-8` but **not** `X-Content-Type-Options: nosniff`. `http.NotFound`
  (via `http.Error`) writes `"404 page not found\n"` plus nosniff. So gin's
  current agreement with StdRouter is status-code-deep only; the suite's byte
  assertions make gin red at baseline too (spec requires echo red; gin red is
  a strengthening, not a conflict). gin's normalization is a real fix, not a
  pinning exercise.
- **echo's `Response.Write` has no committed guard** (`response.go`:
  `WriteHeader` warns "response already committed" on a second call, but
  `Write` writes through `r.Writer` unconditionally). Therefore
  `http.NotFound(c.Response(), c.Request())` is byte-safe on echo: one
  `WriteHeader(404)` + one body write, exactly once. No echo-specific
  workaround is needed to reproduce the stdlib bytes.
- **echo's `DefaultHTTPErrorHandler` early-returns when the response is
  committed** (`if c.Response().Committed { return }`). This makes the
  Decision-3 gate sentinel safe under the *default* handler, but an
  embedder-replaced handler may not early-return — the adapter therefore
  installs a delegating `HTTPErrorHandler` wrapper (Decision 3).
- **In gin, only `Abort()` stops the handler chain.** `Context.Next()`'s own
  loop advances `c.index` and runs the next handler even if the current
  handler never calls `c.Next()` (`context.go`). A route-level gate that
  merely returns would let the wrapped handler (and every sso middleware in
  it) run. The gin gate handler MUST write the 404 and call `c.Abort()`.
- **Production wiring registers middleware before any route.**
  `interfaces/sso/server_routes.go:113-132` calls `s.router.Use(Tracing |
  Tenant | Geo | region)` during mount, before the admin surface registers
  routes; `cmd/sso-server/build_app_core.go:155` uses the default StdRouter.
  Registration-time snapshotting therefore changes no production behavior —
  it only aligns adapter semantics with StdRouter's documented "Use affects
  future registrations" contract.
- **Both frameworks expose generic method registration**: gin
  `RouterGroup.Handle(method, path, handlers...)` (`routergroup.go:103`) and
  echo `Group.Add(method, path, handler, middleware...)` (`group.go:121`).
  `RegisterGated` needs no five-way switch.
- **`sso.Router`/`HandlerFunc`/`MiddlewareFunc` are type aliases of core
  types** (`interfaces/sso/aliases.go:111-115`). The public gating interface
  gets a matching alias (`sso.GatedRegistrar = core.GatedRegistrar`) so the
  adapters keep importing exactly one Snaplink package, and the 60-file
  ceiling of `interfaces/sso` is untouched (alias goes in `aliases.go`).
- **`shared/core/router_test.go` is `package core` (internal test).** Importing
  `routertest` (which imports `core`) from an internal test of `core` is an
  import cycle. The StdRouter hookup therefore lives in
  `shared/core/routertest/conformance_test.go` (the suite's own smoke test),
  per the spec's file plan. The gin/echo conformance tests are internal-test
  files in their own packages and import `routertest` with no cycle.

Budget headroom verified: `shared/core/router.go` is 440 lines (promotion +
doc rewrite ≈ +25 → ~465 < 500); gin adapter 160 → ~235; echo adapter
140 → ~220; `routertest/conformance.go` ≈ 400 (the 321-line
`permissionstest/conformance.go` precedent covers 27 scenarios; this matrix
is ~14 with byte equality). `shared/core` already has one subpackage
(`corecredential`); `routertest` makes two (limit 15), and `layerName()`
classifies any `shared/...` package automatically (`architecture_layer_test.go:61`)
— no `layerExemptions` entry needed.

---

## Decision 1 — `routertest.ConformanceSuite`: byte equality as an executable constraint

### API surface

```go
// Package routertest hosts shared behavioral fixtures for core.Router
// implementations. Backend authors (StdRouter, gin, echo, future peers)
// hook their factory into ConformanceSuite to lock the wire bytes
// sso.WithRouter embeddings depend on. Lives in a separate package so
// shared/core stays free of the testing import (permissionstest pattern).
package routertest

type ConformanceSuite struct {
    // Factory returns a FRESH router per subtest; instances MUST NOT be
    // shared across subtests (state leakage would mask backend bugs).
    // Factory must build via the backend's public constructor so the
    // suite exercises default wiring, not a test-only configuration.
    Factory func(*testing.T) core.Router
}

func (s ConformanceSuite) Run(t *testing.T)
```

Shape is identical to `permissionstest.ConformanceSuite` (factory + case
table + `t.Run` per scenario, fresh instance per subtest). `core.Router` is
the minimal surface the suite needs; gating scenarios wrap the factory
result in `core.NewGatedRouter(router, live)` inside the suite, so no
`GatedRegistrar`-specific type appears in the suite's API.

**Reference bytes are derived, not hardcoded.** A helper computes the
canonical unmatched response at runtime:

```go
func referenceNotFound(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
    rec := httptest.NewRecorder()
    http.NotFound(rec, r)
    return rec
}
```

Every 404 scenario compares status, `rec.Body.String()` full equality, and
full header-map equality (order-insensitive, mirroring `headersEqual` in
`shared/core/router_test.go`) against this reference. Consequences: the
contract is "identical to the stdlib's canonical 404", which is exactly the
contract `StdRouter.ServeHTTP` already has; if stdlib bytes drift, all three
backends drift together and the suite still passes (correct — the reference
moved, and backends track it).

### Scenario matrix

Each scenario is a subtest against a fresh `Factory(t)` instance:

| # | Scenario | Asserts | Baseline today |
|---|---|---|---|
| 1 | `FiveMethodDispatch` | GET/POST/PUT/PATCH/DELETE each → 200, byte-pinned JSON, `Content-Type: application/json` | green |
| 2 | `PathParamsAndQuery` | `/tenants/:tid/users/:uid?active=1` → param extraction + query | green |
| 3 | `UnknownPath_ByteIdenticalToHTTPNotFound` | status + body + headers vs `referenceNotFound` | **red: gin (newline, nosniff), echo (JSON 404)** |
| 4 | `MethodMismatch_ByteIdenticalToHTTPNotFound` | POST on GET-only route → reference bytes (locks StdRouter "method mismatch = 404", not 405) | **red: gin (newline, nosniff), echo (405 JSON)** |
| 5 | `HeadOnGetRoute_ByteIdenticalToHTTPNotFound` | HEAD on GET-only route → reference bytes; no auto-GET degradation | **red: gin, echo (echo 405 JSON)** |
| 6 | `OptionsOnKnownPath_ByteIdenticalToHTTPNotFound` | OPTIONS on a known path → reference bytes | **red: echo (405 JSON)** |
| 7 | `TrailingSlash_ByteIdenticalToHTTPNotFound` | `/known/` → reference bytes (exact segment match) | red: gin/echo (byte level) |
| 8 | `MiddlewareOrderAndAbort_HandlerNotRun` | `Use(m1, m2)` before registration; m2 writes 401 then `Abort()`; asserts order m1→m2, handler never runs, response is exactly the 401 bytes, no double write | green |
| 9 | `GroupPrefix_InheritsMiddleware` | group prefix + parent middleware apply, child-only middleware does not leak to sibling | green |
| 10 | `UseAfterRegister_DoesNotAffectRegisteredRoutes` | register `/a`; `Use(mw)`; register `/b`; `/a` must NOT see mw, `/b` must (StdRouter snapshot contract) | **red: gin/echo (request-time read)** |
| 11 | `GateOff_ByteIdenticalToNeverMounted` | `NewGatedRouter(router, live)`; live=false → gated path byte-identical to never-registered path; live=true → 200 | red on gin/echo at header level today |
| 12 | `GateOff_SkipsGlobalMiddleware_NoHeaderLeak` | `Use(header mw)` BEFORE gated registration; gate-off response must not carry `X-Probe-Header` and must equal the never-registered baseline | **red: gin/echo (header leak via GateHandler fallback)** |
| 13 | `GatedGroup_PreservesGate` | gating through `NewGatedRouter(...).Group(...)` (adapter Group returns a router that still implements `GatedRegistrar`) | red on gin/echo (fallback) |
| 14 | `GateOn_ServesRoute` | live=true → 200 with handler bytes | green |

Scenarios 3–7 share one assertion helper (`assertByteIdenticalToNotFound`);
8–10 share a middleware-order harness. Scenario 12 is the three-backend
reproduction of `TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak`
(`shared/core/router_test.go:500`); scenario 11 of
`TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404` (:443).

The suite depends on nothing from Direction 1/3 specs: `Abort`/`Aborted`
already exist on `HandlerContext` (shipped), and no response-capture
primitive is referenced. If a future adapter regresses `Abort()` semantics,
scenario 8 fails loudly on that backend — the spec's cross-direction guard.

### State model

None. The suite is stateless; every scenario builds a fresh router from the
Factory and discards it. `live` toggles are closure booleans captured by the
scenario, exactly as in the StdRouter tests. This is the same model as
`permissionstest` — the Factory-per-subtest rule is the only state rule.

### Wiring points

- `shared/core/routertest/conformance_test.go` — suite self-smoke AND
  StdRouter hookup: `(ConformanceSuite{Factory: ...NewStdRouter}).Run(t)`.
  External package (it is its own package), no cycle.
- `interfaces/adapters/gin/conformance_test.go` — `package ginadapter`;
  Factory = `NewGinRouter()` (public constructor, default wiring).
- `interfaces/adapters/echo/conformance_test.go` — `package echoadapter`;
  Factory = `NewEchoRouter()`.

### Failure modes

| Failure | Behavior | Classification |
|---|---|---|
| New backend (chi/fiber/httprouter) claims `sso.WithRouter` support without the suite | no compile-time enforcement exists; the suite is a convention, like `permissionstest` | Fail closed by review gate: "supports `WithRouter`" is not claimable without a green `conformance_test.go` |
| Suite wired with a non-default Factory (normalization opted out) | suite passes while default construction diverges | Fail closed by rule: Factory must call the public constructor with no options; enforced by review + the baseline-first record |
| Scenario 3–7 reference drifts with stdlib | all backends track the drift together | Acceptable by construction (reference is derived at runtime) |
| A backend panics on an edge scenario (e.g. echo double-write) | subtest fails with the panic, other subtests still report | Fail loud per subtest |

---

## Decision 2 — Unmatched-response normalization: 404 bytes are a contract, not a coincidence

### API surface

Constructor options, default = normalized:

```go
// gin
func NewGinRouter(engine ...*gin.Engine) *GinRouter        // unchanged; delegates
func NewGinRouterWithOptions(engine *gin.Engine, opts ...Option) *GinRouter

// echo
func NewEchoRouter(engine ...*echo.Echo) *EchoRouter        // unchanged; delegates
func NewEchoRouterWithOptions(engine *echo.Echo, opts ...Option) *EchoRouter

type Option func(*options)
func WithFrameworkNotFound() Option  // opt-out: keep the framework's native 404/405
```

`NewGinRouter(engine ...*gin.Engine)` keeps its exact signature — the
variadic is already consumed by the engine argument, so a second
options-bearing entry point is required for source compatibility. Existing
call sites (`NewGinRouter()`, `NewGinRouter(e)`) compile unchanged against
the delegating constructor. There are zero in-repo production callers of
either adapter constructor (verified: only the adapters' own tests), so the
blast radius is embedder-facing only.

### Per-backend wiring (default path)

**gin** — installed at construction on whatever engine is in use:

```go
e.HandleMethodNotAllowed = false            // pin: method mismatch falls into NoRoute → 404
e.NoRoute(func(c *gin.Context) {            // replaces gin's default404Body path
    http.NotFound(c.Writer, c.Request)      // exact stdlib bytes: trailing \n, text/plain, nosniff
})
```

`HandleMethodNotAllowed = false` is already gin v1.12.0's `New()` default
(`gin.go:213`) — the assignment pins it at the adapter layer so a framework
bump that flips the default cannot silently reintroduce 405. No `NoMethod`
handler is installed (it is dead while the flag is false).

**echo** — installed at construction:

```go
notFound := func(c echo.Context) error {
    http.NotFound(c.Response(), c.Request())  // exact stdlib bytes (Write has no committed guard)
    return nil                                // HTTPErrorHandler not invoked
}
e.NotFoundHandler = notFound                  // replaces JSON {"message":"Not Found"}
e.MethodNotAllowedHandler = notFound          // replaces 405 JSON; locks StdRouter's "method mismatch = 404"
```

echo's router reaches `MethodNotAllowedHandler` whenever the path exists
under a different method (HEAD on a GET-only route, OPTIONS on a known
path, wrong-method POST — scenarios 4/5/6). Mapping all of them to the
`http.NotFound` bytes is the deliberate wire-semantics decision: StdRouter
answers 404 for every unmatched tuple, and the suite pins that for every
backend.

**Precedence rule (both adapters):** normalization is installed at
construction time; an embedder who assigns `engine.NoRoute(...)` /
`e.NotFoundHandler = ...` *after* construction replaces it (later
assignment wins, framework-native behavior restored without recompiling the
adapter). `WithFrameworkNotFound()` skips installation entirely for
embedders who want framework-native 404/405 from the start — an explicit,
documented divergence. The default is always the byte-identical version, so
`sso.WithRouter(adapter)` and `NewStdRouter()` produce interchangeable wire
responses out of the box.

### State model

Per-router: zero new state. The not-found handlers are constructor-installed
closures on the engine; they hold no mutable state and are race-free. The
only storage change is the `options` struct (two bools) that exists for the
lifetime of the constructor call.

### Failure modes

| Failure | Behavior | Classification |
|---|---|---|
| Embedder replaces the not-found handlers after construction | normalization overridden; embedder owns the divergence | Documented precedence; opt-out exists for the from-start case |
| Framework upgrade changes 404/405 default bytes | suite scenarios 3–7 go red | Fail closed at upgrade review (versions pinned in go.mod: gin v1.12.0, echo v4.15.2) |
| echo `WriteHeader` called twice (regression) | echo logs "response already committed" and drops the second status | Fail loud in test logs; scenarios 3–7 assert single-write bytes, so a double-write path fails byte equality |
| Deleting the not-found installation code | suite immediately red | The intended tripwire (spec acceptance) |

---

## Decision 3 — Registration-time middleware snapshots, race safety, public gated registration

Three sub-decisions, one delivery step.

### 3a. Public `GatedRegistrar` in `shared/core`

```go
// GatedRegistrar is the optional capability a Router implementation may
// provide so GatedRouter can gate route MATCHING itself (checked before
// that route's own middlewares run) instead of wrapping the handler.
// Implementors MUST evaluate live() BEFORE running any middleware of the
// route (including Use()-registered global middleware), so a gated-off
// route is byte-identical to a route that was never registered. StdRouter
// and the gin/echo adapters implement this; a Router that does not falls
// back to handler-wrapping in GatedRouter (reachability still correct,
// but global middleware may observe gated-off requests).
type GatedRegistrar interface {
    RegisterGated(method, path string, handler HandlerFunc, live func() bool)
}
```

- `shared/core/router.go`: unexported `gatedRegistrar` (and its
  `registerGated` method) is renamed to the public `GatedRegistrar` /
  `RegisterGated`; the internal call site at `router.go:205` updates.
  `GatedRouter.register` asserts `g.inner.(GatedRegistrar)` — the fallback
  `GateHandler` branch stays for third-party routers (unchanged semantics,
  documented degraded guarantee).
- `interfaces/sso/aliases.go`: `type GatedRegistrar = core.GatedRegistrar`
  (one line; 60-file ceiling untouched). Adapters implement the sso alias
  and assert `var _ sso.GatedRegistrar = (*GinRouter)(nil)`.
- `GatedRouter`'s doc comment is rewritten: the "a custom Router … never
  implements this" sentence becomes the public-contract statement above.

### 3b. Adapter implementations of `RegisterGated`

**gin** — gate as a route-level handler registered BEFORE the wrapped
handler; `c.Abort()` is required (verified: gin's `Next()` loop advances on
its own, only `Abort()` stops the chain):

```go
func (g *GinRouter) RegisterGated(method, path string, handler sso.HandlerFunc, live func() bool) {
    g.group.Handle(method, path,
        func(c *gin.Context) {
            if !live() {
                http.NotFound(c.Writer, c.Request)
                c.Abort() // stops gin's handler chain: wrapHandler and its sso middlewares never run
            }
        },
        g.wrapHandler(handler),
    )
}
```

When live, the gate is a no-op and the chain proceeds into `wrapHandler`.
When off, the 404 bytes are written before any sso middleware exists (they
live inside `wrapHandler`'s closure), so `Use()`-registered header-stamping
middleware cannot fingerprint the response — scenario 12's property. A wrong
method on a gated route never reaches the gate: gin's tree has no match →
`NoRoute` (normalized Decision 2), consistent with StdRouter's
not-matched-at-all semantics.

**echo** — gate as route-level middleware via `Group.Add`; the sentinel
error stops echo's chain before the handler:

```go
var errGateOff = errors.New("snaplink: gated route off") // package-private

func (e *EchoRouter) RegisterGated(method, path string, handler sso.HandlerFunc, live func() bool) {
    e.group.Add(method, path, e.wrapHandler(handler), func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            if !live() {
                http.NotFound(c.Response(), c.Request())
                return errGateOff // chain stops; no handler, no sso middleware
            }
            return next(c)
        }
    })
}
```

The constructor installs a delegating error handler so the sentinel is
swallowed and every other error keeps its existing treatment:

```go
prev := e.HTTPErrorHandler
e.HTTPErrorHandler = func(err error, c echo.Context) {
    if errors.Is(err, errGateOff) {
        return // 404 already written
    }
    prev(err, c)
}
```

The wrapper captures the handler current at construction; the default
`DefaultHTTPErrorHandler` would in fact early-return on the committed
response, so the wrapper is belt-and-braces for embedder-replaced handlers
(who, if they replace it after construction, own the sentinel behavior —
documented).

### 3c. Snapshot + race safety in both adapters

State model change — the shared slice becomes write-locked and
registration-snapshotted; the request path stops reading it entirely:

```go
type GinRouter struct {   // EchoRouter identical
    engine      *gin.Engine
    group       *gin.RouterGroup
    mu          sync.RWMutex
    middlewares []sso.MiddlewareFunc
}

func (g *GinRouter) snapshotMiddlewares() []sso.MiddlewareFunc {
    g.mu.RLock()
    defer g.mu.RUnlock()
    return append([]sso.MiddlewareFunc{}, g.middlewares...)
}
```

- `Use(...)`: `g.mu.Lock()` around the append.
- Every registration (`GET`/`POST`/…/`RegisterGated`): snapshots via
  `snapshotMiddlewares()` and passes the copy into `wrapHandler`, which
  closes over the **copy**, not over `g`. This is StdRouter's exact semantic:
  `registerGated` does `append([]MiddlewareFunc{}, r.middlewares...)` at
  registration time.
- `Group(...)`: snapshots the parent's list at group creation (already the
  semantics; now under `RLock`).
- `ServeHTTP`: delegates to the framework engine; never touches
  `g.middlewares`. Concurrent `Use()` + `ServeHTTP` is therefore race-free
  **by construction** — the `-race` concurrent test is a regression tripwire
  (it fails loudly if someone reverts to request-time reads), not the proof
  itself.

Engine-level middleware stays out of the adapter's hands: sso middlewares
remain inside `wrapHandler`'s closure (installing them as `engine.Use` /
`e.Use` would run them on unmatched requests too, breaking the normalized
404 bytes — the opposite of the goal). Route registration stays
single-threaded (gin's own contract: no route registration during serving);
only `Use()`/`ServeHTTP` are exercised concurrently in the race test, per
the spec.

### State model summary

| State | Backend | Location | Synchronization |
|---|---|---|---|
| Middleware list | StdRouter | `r.middlewares` (root) / group copy | registration-only (no runtime reads) |
| Middleware list | gin/echo | `g.middlewares` / `e.middlewares` | `sync.RWMutex`; read only under `RLock` at registration |
| Per-route snapshot | StdRouter | `StdRoute.middlewares` | immutable after registration |
| Per-route snapshot | gin/echo | closure capture inside `wrapHandler` | immutable after registration |
| Gate func | all | `StdRoute.live` / gin gate handler / echo gate middleware | per-request evaluation, no shared mutation |
| Suite | — | none (Factory per subtest) | — |

### Failure modes

| Failure | Behavior | Classification |
|---|---|---|
| Third-party Router without `GatedRegistrar` | `GatedRouter` falls back to `GateHandler` wrapping: gate-off still 404, but global middleware may stamp headers | Fail open-ish, degraded; documented, no worse than today |
| Embedder replaces echo `HTTPErrorHandler` after construction | sentinel may reach a handler that double-writes | Documented boundary; default path safe (wrapper + committed early-return) |
| Concurrent `Use` + `ServeHTTP` under the old request-time read (regression) | race detector fires in the new concurrent test | Fail closed by `-race` |
| Route registered while `Use()` runs concurrently | snapshot is atomic (RLock); the route sees either the pre- or post-Use list, never a torn copy | Fail closed by lock |
| `Use()` after registration on gin/echo | previously-registered routes unchanged (StdRouter contract); behavior change vs today's request-time read | Deliberate; no production caller depends on the old behavior (wiring verified: `Use` before routes) |

---

## What could break the design

1. **gin's chain semantics are the load-bearing risk in 3b.** A reviewer
   "simplification" that drops `c.Abort()` from the gate handler silently
   reverts to handler-wrapping: gin's `Next()` loop advances without
   `c.Next()`, so the wrapped handler and its sso middlewares run, stamping
   the header fingerprint scenario 12 exists to forbid. Mitigation: the
   gate-off scenarios (11–13) fail red the moment the abort disappears, and
   the gin gate handler carries a comment stating why `c.Abort()` is
   mandatory.
2. **Baseline-first discipline is the whole point.** If the suite lands
   after the fixes, nothing proves the gate has teeth. Order is fixed:
   step 1 lands the suite against unfixed adapters and the red baseline is
   recorded (echo red on 3/4/6, gin red on 3–7 at byte level) before step 2
   turns it green. Skipping that record is a process failure, not a code
   failure.
3. **`WithFrameworkNotFound()` is a divergence hatch.** An embedder who
   opts out gets framework-native 404/405 (echo JSON) and the suite must
   never be wired against that configuration (Factory rule, Decision 1). A
   future "helpful" refactor that makes the opt-out the default would flip
   the wire contract silently — the default is normalized, always, and the
   suite's Factory rule pins it.
4. **Framework upgrades.** gin's `default404Body`, `HandleMethodNotAllowed`
   default, echo's 405 routing, and any future auto-HEAD/trailing-slash
   behavior all live in pinned deps (gin v1.12.0, echo v4.15.2 in go.mod).
   A bump that changes any of them turns the suite red — the designed loud
   failure; the bump review must re-verify scenarios 3–7 and the explicit
   constructor pins (`HandleMethodNotAllowed = false`, installed handlers).
5. **`http.NotFound` drift in the stdlib** moves the reference for all
   backends at once. The contract is "identical to the stdlib's canonical
   404", which is the contract StdRouter already has; the suite tracks it
   by construction. Not a divergence risk, but worth stating so nobody
   hardcodes the bytes later.
6. **Snapshot semantics are an observable behavior change for gin/echo
   embedders** who today rely on `Use()` after registration retroactively
   affecting routes (request-time read). Verified no in-repo caller does
   this; it is a documented contract change in the release notes, and
   scenario 10 pins the new semantics.
7. **Engine-level framework middleware sits outside the guarantee.** gin's
   `engine.Use(...)` / echo's `e.Use(...)` (including `gin.Default()`'s
   Logger/Recovery) run before route-level handlers and before the
   not-found handlers, on unmatched and gated-off requests alike. Today
   they do not touch response bytes (Logger writes to stderr), but an
   embedder's engine-level middleware could stamp headers that StdRouter's
   guarantee forbids. This is an adapter boundary, documented on the
   constructors: the byte-identical guarantee covers `sso.Router.Use()`
   middleware; engine-level middleware is the embedder's framework surface
   (the opt-out exists for embedders who want full framework semantics).
8. **The `-race` concurrent test passes by construction after 3c** (the
   request path never reads the slice). It is a regression tripwire, not a
   correctness proof; the design's actual race argument is structural —
   `ServeHTTP` cannot touch `g.middlewares`. Reviewers should not mistake
   the test's green for the lock being optional: the lock protects
   `Use`/`Group`/registration against each other.
9. **`RegisterGated` must snapshot at the same moment as plain
   registration.** If 3b is implemented to read `g.middlewares` at request
   time inside the gate (copy-paste from the old `wrapHandler`), the
   gated-route path reintroduces the race and the snapshot contract.
   Implementation rule: `RegisterGated` must route through
   `snapshotMiddlewares()` + `wrapHandler`, never a bespoke middleware
   loop.
10. **`interfaces/sso` ceiling and `shared/core` budget.** The alias adds
    one line to `aliases.go` (no new file); `router.go` grows ~25 lines to
    ~465 (limit 500). If review demands more doc on `GatedRouter`, the
    rewrite must stay tight or the doc moves to `GatedRegistrar`'s comment
    — the file cannot grow further without a split.
11. **echo sentinel collision.** `errGateOff` is package-private; no
    embedder can construct it, so no legitimate echo error can be
    swallowed. If it ever needs to cross the package boundary (unlikely),
    it becomes an exported sentinel with a documented contract.
12. **The suite's Factory rule is review-enforced, not machine-enforced.**
    Nothing stops a backend's `conformance_test.go` from building a
    non-default router. The permissionstest precedent has the same
    property; the baseline-first record and the review checklist
    ("Factory uses the public constructor, no options") are the guard.

---

## Delivery order, budgets, and gate compliance

Each step lands with `go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .` green; each step
leaves the tree green:

- **Step 1 — suite lands red.** Create `shared/core/routertest/` (2 files),
  `interfaces/adapters/{gin,echo}/conformance_test.go`; record the red
  baseline (echo: scenarios 3/4/6; gin: 3–7 byte-level). StdRouter hookup
  (inside `routertest/conformance_test.go`) is green from the start.
  `shared/core` gains its second subpackage; no exemptions.
- **Step 2 — normalization (Decision 2).** Constructor options +
  per-backend handlers; suite scenarios 3–7 turn green on all backends.
  gin adapter ≈ +75 lines (~235), echo ≈ +75 (~215); complexity ≤ 3 `if`
  levels per function.
- **Step 3 — snapshot + `GatedRegistrar` (Decision 3).** Promote the
  interface in `shared/core/router.go`; alias in `aliases.go`; adapter
  implementations; mutex + snapshot; `Use-after-register` and concurrent
  `Use`+`ServeHTTP` tests in both adapter test files; suite scenarios
  10–14 turn green. `router.go` ≈ 465; both adapters < 260.
- Handoff per step: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  `make ci` (full gate incl. nested modules, examples, config, module
  validation). No new `interfaces/sso` files; no `layerExemptions`; no
  budget exemptions.

## Implementation notes (as landed)

The implementation resolved the four defects the design-stage reviews found;
all are corrections to the design, none change its shape:

- **`routertest` lives at `interfaces/adapters/routertest/`, not
  `shared/core/routertest/`.** `shared/core/` is a dependency-free leaf —
  `architecture_gate_test.go` rule 3 forbids any file under it from importing
  a Snaplink package — so a suite importing `core` cannot live under
  `shared/core/` without a forbidden exemption. `interfaces/adapters/routertest`
  imports `shared/core` downward (layer-legal, auto-classified `interfaces`),
  is depth-3, and adds one subdir to `interfaces/adapters` (3 ≤ 15). The
  StdRouter hookup is the suite's own smoke test in that package.
- **echo normalization uses `e.RouteNotFound("/*", notFound)`, not
  `e.NotFoundHandler = …`.** echo v4.15.2's `NotFoundHandler`/
  `MethodNotAllowedHandler` are package-level vars, not `Echo` struct fields
  (assigning them would fail to compile and would be global state). The
  per-node `notFoundHandler` installed by `RouteNotFound("/*")` wins in
  `router.Find` for all five unmatched classes (unknown path, wrong method,
  HEAD, OPTIONS, trailing slash) — verified by source trace and by the
  suite. The constructor also installs the delegating `HTTPErrorHandler`
  wrapper (gate sentinel swallow) from Decision 3b in the same step.
- **gin pins `RedirectTrailingSlash = false` and `RedirectFixedPath = false`
  alongside `HandleMethodNotAllowed = false`.** gin's `New()` defaults TSR to
  true and redirects BEFORE NoRoute, so scenario 7 (`/known/`) was a 301, not
  a byte-level divergence — without the pin it can never go green.
- **The `sso.GatedRegistrar` alias landed in `interfaces/sso/origin_validation.go`**
  (the documented home for re-exports relocated off `aliases.go`, which is at
  exactly 500 lines — one more line fails `TestMaintainability_FileSizeBudget`).
- **Scenario 1/8/14 do not assert cross-backend JSON byte equality** (gin
  omits the trailing newline and appends `; charset=utf-8`; StdRouter and
  echo differ too) — they pin status + JSON value + `Content-Type` prefix.
  Byte equality is reserved for the unmatched-response contract, which is
  what the normalization owns.
- Baseline-record cells corrected: echo HEAD on a GET-only route is 405 with
  an EMPTY body (not 405 JSON); echo OPTIONS on a known path is 204 + `Allow`
  (not 405 JSON); gin trailing-slash is a 301 (not a byte-level red); the
  gin gate-off fallback leaks at header AND body level (its `GateHandler`
  fallback writes `default404Body` without newline/nosniff).
- The red baseline was recorded from scratch runs of the suite against the
  un-normalized configurations (gin `WithFrameworkNotFound()`: scenarios
  3–7 red — missing newline/nosniff and the 301; echo
  `WithFrameworkNotFound()`: scenarios 3–5 red — JSON 404/405 + `Allow`);
  the suite + fixes land atomically in one step.
- Gate-off scenarios additionally assert the wrapped handler never executes
  (atomic counter == 0) and that a WRONG METHOD on a gated-off route is also
  byte-identical to never-mounted (it never reaches the gate: no route
  matches at all, same as StdRouter).

## Acceptance mapping

| Spec acceptance | Where it is proven |
|---|---|
| Suite exists; `go test ./...` green; new backends cannot claim `WithRouter` without it | Step 1; `routertest.ConformanceSuite` + three wiring files; review convention |
| Byte equality (status + body + headers), not `strings.Contains` | All scenarios via `referenceNotFound` + `assertByteIdentical` helpers |
| Baseline: echo fails method-mismatch and unknown-path before fixes | Step 1 red-baseline record (echo scenarios 3/4/6; gin 3–7 red at byte level) |
| echo unknown-path/method-mismatch/HEAD byte-identical after fixes | Step 2; scenarios 3/4/5 green on echo |
| Deleting not-found installation → suite immediately red | Regression property of scenarios 3–7 (constructor-installed handlers) |
| `Use()` after registration leaves registered routes unchanged | Scenario 10; currently red on gin/echo, green after step 3 |
| `-race` clean incl. concurrent `Use`+`ServeHTTP` | New adapter test cases; structural race-freedom (ServeHTTP never reads the slice) |
| Gate-off = 404 plain text, no global-middleware header leak, three backends | Scenarios 11–13; red on gin/echo today (fallback leaks), green after step 3 |
| `go build/vet`, maintainability + architecture gates, `make ci` | Step gates; `routertest` auto-classified `interfaces` (no exemption); budgets verified above |
