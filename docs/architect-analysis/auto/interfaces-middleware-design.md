# Design: interfaces/middleware — Typed named-slot pipeline (`middleware.Chain`)

Source: `docs/auto/interfaces-middleware-spec.md` (direction 1 expansion).
Every line reference below was re-verified against the tree at design time.

Design summary: the canonical chain order (probe mux → Recover → Tracing →
Metrics → TrustedProxies → RateLimit → Degradation → AcceptVersion → BodyLimit
→ Compression → CORS → SecurityHeaders → RequestLog → Router) becomes a typed
`Chain` with one unexported field per slot and one builder method per slot, so
a wrong order is unrepresentable at compile time. Assembly collapses from
seven hand-written functions spread over three `interfaces/sso` files into one
construction site. The dual middleware signature (`http.Handler`-shaped vs
`core.MiddlewareFunc`) collapses to one, with a single `FromCore` boundary
adapter. Four ordering invariants become committed regression tests.

## Package layout: new `interfaces/middleware/chain` subpackage, re-exported as `middleware.Chain`

**Decision.** The chain lives in a new subpackage `interfaces/middleware/chain`
(one non-test file, `chain.go`), and `middleware.go` re-exports
`type Chain = chain.Chain` and `var FromCore = chain.FromCore` so the spec
name `middleware.Chain` holds for consumers.

**Why not extend `middleware.go`.** Budget math kills the in-file option:

- `interfaces/middleware` holds exactly 10 non-test files
  (`directory_fanout_test.go:34` `maxGoFilesPerDir = 10`; verified: the dir is
  at the ceiling) — no new root file is allowed, so the Chain must go into
  `middleware.go` or a subpackage.
- `middleware.go` is 166 lines. Chain struct + 12 builders + `Wrap` +
  `SlotOrder` + probe mux + `FromCore` is ~300 lines; migrating `Tracing`
  (+10) and `Logger` (+8) and the alias line (+3) lands at ~490 — inside the
  500-line file budget but with zero headroom, and it permanently couples the
  chain machinery to the leaf middlewares.
- The spec's own trigger ("or splits into a new `chain` subpackage if it
  crosses 450 lines") fires: ~490 > 450.

**Budget arithmetic for the subpackage** (all verified ceilings):

| Budget | Before | After |
|---|---|---|
| `interfaces/middleware` non-test files | 10 (at ceiling) | 10 (no new root file) |
| `interfaces/middleware` subdirs | 0 | 1 (`chain`; cap 16) |
| `chain/` non-test files | — | 1 (~300 lines, cap 500) |
| `interfaces/sso` non-test files | 60 (at ceiling) | 60 (edits only) |
| `server_routes.go` lines | 488 | ~420 (net −70) |
| `sso_wiring.go` lines | 446 | ~390 |
| `server_health.go` lines | 443 | ~425 |

**Import direction.** `chain` imports only `net/http` and `shared/core`
(slots accept already-constructed middlewares; `FromCore` needs
`core.MiddlewareFunc`/`core.NewContext`). `middleware.go` imports `chain`
(parent → child, no cycle: `chain` never imports its parent). Both packages
classify as layer `interfaces` by the first-segment rule in
`architecture_layer_test.go:49-60` — no `layerName()` change, no exemption.

**Alias, not defined type.** `type Middleware = func(http.Handler) http.Handler`
is a type *alias* in both packages (one canonical declaration in `chain`,
re-declared identically in `middleware`). Rationale: every slot-filling
constructor in the tree already returns the unnamed func type (`Recover`,
`Compress`, `AcceptVersion`, `Degradation`, `RequestLogger`,
`metrics.Middleware`, `ratelimit.DynamicMiddleware`, `tracing.Middleware`,
`cors.Middleware`, `handler.SecurityHeaders`, `TrustedProxies.Middleware`) —
an alias makes all of them assignable with zero conversions. A defined type
would buy nothing (the underlying types are identical, so no type safety is
gained) and would force conversions at every call site.

## API surface

```go
// chain/chain.go
package chain

import (
    "net/http"

    "github.com/yangwb1123/snaplink/shared/core"
)

// Middleware is the single chain signature. Alias (not defined type) so
// every func(http.Handler) http.Handler constructor is assignable as-is.
type Middleware = func(http.Handler) http.Handler

// SlotName identifies one canonical chain position.
type SlotName string

const (
    SlotRecover         SlotName = "recover"
    SlotTracing         SlotName = "tracing"
    SlotMetrics         SlotName = "metrics"
    SlotTrustedProxies  SlotName = "trusted_proxies"
    SlotRateLimit       SlotName = "rate_limit"
    SlotDegradation     SlotName = "degradation"
    SlotAcceptVersion   SlotName = "accept_version"
    SlotBodyLimit       SlotName = "body_limit"
    SlotCompression     SlotName = "compression"
    SlotCORS            SlotName = "cors"
    SlotSecurityHeaders SlotName = "security_headers"
    SlotRequestLog      SlotName = "request_log"
)

// Chain is a typed middleware pipeline. One unexported field per canonical
// slot; nil = slot not installed. The zero value is a valid empty chain.
// Not safe for concurrent mutation: wire all slots, then Wrap once.
type Chain struct {
    recover, tracing, metrics, trustedProxies, rateLimit, degradation,
    acceptVersion, bodyLimit, compression, cors, securityHeaders,
    requestLog Middleware
    probes map[string]http.Handler
}

func (c *Chain) WithRecover(m Middleware) *Chain         // ...one per slot
func (c *Chain) WithTracing(m Middleware) *Chain
func (c *Chain) WithMetrics(m Middleware) *Chain
func (c *Chain) WithTrustedProxies(m Middleware) *Chain
func (c *Chain) WithRateLimit(m Middleware) *Chain
func (c *Chain) WithDegradationGate(m Middleware) *Chain
func (c *Chain) WithAcceptVersion(m Middleware) *Chain
func (c *Chain) WithBodyLimit(m Middleware) *Chain
func (c *Chain) WithCompression(m Middleware) *Chain
func (c *Chain) WithCORS(m Middleware) *Chain
func (c *Chain) WithSecurityHeaders(m Middleware) *Chain
func (c *Chain) WithRequestLog(m Middleware) *Chain

// WithProbes registers probe endpoints served OUTSIDE every chain slot.
// The map is copied. An empty map means Wrap does not build a probe mux.
func (c *Chain) WithProbes(probes map[string]http.Handler) *Chain

// Wrap applies installed slots outermost → innermost in the canonical
// order and returns the finished handler. With zero slots (and no probes)
// it returns router unchanged.
func (c Chain) Wrap(router http.Handler) http.Handler

// SlotOrder returns the canonical slot list (probes are structurally
// outside the chain and are not listed). Pins the order for tests.
func (c Chain) SlotOrder() []SlotName

// FromCore adapts a route-level core.MiddlewareFunc into the chain
// signature. Honors Abort() exactly like StdRouter's middleware loop
// (shared/core/router.go:270-277): run fn(ctx); pass through only when
// the context was not aborted. Uses core.NewContext, so the response
// writer gets the standard tracking wrapper.
func FromCore(fn core.MiddlewareFunc) Middleware
```

**`middleware.go` additions (3 lines + migrations):**

```go
type Middleware = chain.Middleware   // single chain signature
type Chain = chain.Chain             // spec name: middleware.Chain
var FromCore = chain.FromCore        // the one boundary adapter
```

**Slot semantics.** `With*` are nil-tolerant (nil = not installed; `Wrap`
skips nil slots), chainable, last-call-wins. `Wrap`'s body is a fixed
sequence of `if c.slot != nil { h = c.slot(h) }` in canonical order — there
is no slice to shuffle, so a wrong order is unrepresentable. The probe mux
mirrors `buildProbeMux` (`server_routes.go:475-485`) byte-for-byte: new
`http.ServeMux`, one `Handle` per probe path, `Handle("/", inner)`; when no
probes are registered, `Wrap` returns the chained handler directly (the
server always registers `/livez` + `/readyz`, so production behavior is
unchanged — including ServeMux's path-cleaning semantics).

## Storage model

There is no new durable or persistent state. The complete state inventory:

1. **Chain slots** — in-memory function fields, constructed once per
   `Handler()` call and never retained by `Server`. This matches today's
   `buildMiddlewareChain` exactly: `Handler()` re-runs `Mount()` and rebuilds
   the chain on every call (`server_routes.go:354-361`). Do not cache the
   chain on the server in this change.
2. **`s.rateLimitStore`** — the one side-effectful assignment. Today
   `buildMiddlewareChain` creates `ratelimit.NewPolicyStore(...)` per
   `Handler()` call (`server_routes.go:379-381`) so `SetRateLimitPolicy`
   (`server_routes.go:405-431`) can swap live policies. The collapsed
   construction site MUST keep this assignment (and its per-call recreation
   semantics — calling `Handler()` twice resets the store today; preserve
   that behavior byte-identically rather than "fixing" it in this change).
   The existing `rate_limit_hotreload_test.go` covers the regression.
3. **Degradation gauge seeding** — `degradationGate()` (`server_health.go:347-360`)
   seeds `s.metrics.DegradationMode` at construction and builds the
   `OnReject` closure over `s.metrics`. It stays as a small server helper
   with exactly one call site (inside the chain construction).
4. **Idempotency replay cache** — untouched: `core.IdempotentCache` is
   injected via options and used by the post-auth `/token` path
   (`beginTokenIdempotency`/`finishTokenIdempotency`,
   `server_token.go:58-99`). The generic `middleware.Idempotency` middleware
   currently has **zero call sites** (verified: no `middleware.Idempotency(`
   reference outside its definition) — its migration is signature-only.
5. **Probes map** — copied in `WithProbes` (snapshot semantics; the server
   passes a fresh literal per `Handler()` call).

No serialization, no persistence, no new config, no new `Err*`, no endpoint.

## Migration: one construction site in `interfaces/sso`

**Before (7 hand-written functions across 3 files):**
`buildMiddlewareChain` + `wrapInnerMiddlewares` + `buildProbeMux`
(`server_routes.go:362-485`), `wrapPanicRecovery` + `wrapCompression` +
`wrapAPIVersioning` (`sso_wiring.go:389-421`), `degradationGate`
(`server_health.go:347-360`), plus the route-level `TracingMiddleware()` on
`router.Use` (`server_routes.go:112-114`).

**After — `server_routes.go` keeps one builder, `Handler()` shrinks to:**

```go
func (s *Server) Handler() http.Handler {
    s.Mount()
    return s.buildChain().Wrap(s.router)
}

// buildChain is the single chain construction site. Slot order is enforced
// by chain.Wrap; this function only decides WHICH slots are installed and
// injects the server's stateful middlewares.
func (s *Server) buildChain() *middleware.Chain {
    c := &middleware.Chain{}
    if s.panicRecovery {
        c.WithRecover(middleware.Recover(s.logger))
    }
    c.WithTracing(s.tracingSlot())               // request-ID + OTel, see below
    if s.metrics != nil {
        c.WithMetrics(metrics.Middleware(s.metrics))
    }
    if s.trustedProxies != nil {
        c.WithTrustedProxies(s.trustedProxies.Middleware)
    }
    if s.rateLimitPolicy != nil {
        s.rateLimitStore = ratelimit.NewPolicyStore(s.resolvedRateLimitPolicy())
        c.WithRateLimit(ratelimit.DynamicMiddleware(s.rateLimitStore))
    }
    if s.degradation != nil {
        c.WithDegradationGate(s.degradationGate()) // single call site
    }
    c.WithAcceptVersion(s.versioningSlot())        // Deprecation(AcceptVersion)
    if s.bodyLimit > 0 || len(s.bodyLimitByPath) > 0 {
        c.WithBodyLimit(bodyLimitMiddleware(s.bodyLimit, s.bodyLimitByPath))
    }
    if s.compressionEnabled {
        c.WithCompression(middleware.Compress)
    }
    if s.corsPolicy != nil {
        c.WithCORS(cors.Middleware(*s.corsPolicy))
    }
    if s.securityHeadersEnabled {
        c.WithSecurityHeaders(handler.SecurityHeaders(s.resolvedSecurityHeadersPolicy()))
    }
    if s.debugRequestLogging {
        c.WithRequestLog(middleware.RequestLogger(s.logger, s.debugRequestLogBodies))
    }
    probes := map[string]http.Handler{
        core.PathLivez:  http.HandlerFunc(s.handleLivez),
        core.PathReadyz: http.HandlerFunc(s.handleReadyz),
    }
    if s.metrics != nil {
        probes[core.PathMetrics] = promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{})
    }
    return c.WithProbes(probes)
}
```

`mountMiddleware` (`server_routes.go:108-135`) drops the
`TracingMiddleware()` `router.Use` line; tenant/geo/region stay on
`Router.Use` exactly as today. `sso_wiring.go` loses the three `wrap*`
functions; `server_health.go` keeps `degradationGate` and
`bodyLimitMiddleware` with exactly one call site each (satisfies the spec's
grep acceptance: no hand-written adapter remains outside the construction
site). `cmd/sso-server` and `cmd/sso-minimal` are untouched — they compose
through `sso.Server`.

**AcceptVersion slot composition.** The canonical slot list has one
versioning slot, but today's `wrapAPIVersioning` installs a *pair*:
`Deprecation` wraps outside `AcceptVersion` (`sso_wiring.go:407-420`).
`buildChain` composes them server-side before the slot:
`c.WithAcceptVersion(func(h http.Handler) http.Handler { ... Deprecation(cfg)(AcceptVersion(cfg)(h)) ... })`,
preserving the exact pair order (`Deprecation → AcceptVersion → BodyLimit`
outermost→innermost).

## Tracing slot: dual-gating composition

Two independent options feed one slot today at different layers:

- `middleware.Tracing()` (request-ID + W3C traceparent), gated by
  `s.requestIDMW` (`WithTracingMiddleware`, `options_security.go:486-494`),
  currently installed on `router.Use` — runs inside the outer chain, before
  tenant/geo/region.
- `tracing.Middleware(s.tracingOperation)` (OTel spans), gated by
  `s.tracingOperation != ""` (`WithTracing`, `options_httpstack.go:43`),
  currently in the outer chain between Metrics and Recover.

After migration both land in the chain's Tracing slot, composed
request-ID-innermost, OTel-outermost (`WithTracing(otel(requestID(h)))`).
The OTel span then covers the request-ID stamping and everything downstream,
which is the closest match to today's semantics (OTel is the outermost
tracing; request-ID runs inside the router but still before tenant/geo/region
— the chain is outside the router, so that relative order is preserved).

**Documented behavior delta (intentional, release-noted):** requests now
rejected by slots outside the router — rate-limited 429s, degradation 503s,
body-limit 413s — will carry `X-Request-Id`/`traceparent`/`X-Trace-Id` where
today they do not (Tracing ran inside the router, after those rejections).
Panic responses remain header-less (Recover wraps outside Tracing — unchanged).
Audit enrichment is unaffected: the trace ID lands in the request context
earlier, before tenant/geo/region resolve.

## Failure modes

- **Nil slots** — every `With*` accepts nil (not installed); `Wrap` skips.
  Prevents nil-deref when options are omitted; byte-identical to today's
  conditionals.
- **Zero-value `Chain`** — `Wrap(router)` returns `router` unchanged.
- **Empty probe map** — no probe mux is built; `Wrap` returns the chained
  handler. The server always registers `/livez` + `/readyz`, so production
  keeps ServeMux semantics (path cleaning, `/` fallthrough) byte-identical.
- **Concurrent mutation** — `Chain` is not safe for concurrent writes. The
  server wires it synchronously inside `Handler()` before serving; document
  "wire, then Wrap, then serve".
- **Probe-map aliasing** — `WithProbes` copies the map, so caller mutation
  after wiring cannot race with serving goroutines.
- **Panic in a slot** — Recover remains outermost; unchanged.
- **`FromCore` misuse** — a `core.MiddlewareFunc` that writes without
  `Abort()` will have its response double-written (write + pass-through),
  exactly as it would inside `StdRouter`'s loop today; the adapter mirrors
  router semantics rather than inventing new ones.
- **Missing side effect** — if the collapsed construction drops the
  `s.rateLimitStore` assignment, `SetRateLimitPolicy` silently no-ops
  (returns false). Covered by `rate_limit_hotreload_test.go` and by keeping
  the assignment adjacent to the `WithRateLimit` call in `buildChain`.

## What could break the design

1. **Tracing relocation changes response headers on rejection paths**
   (429/503/413 now carry request-ID/traceparent). Tests asserting exact
   header sets on those paths must be audited; the delta is a fix (correlation
   IDs on every response), not a regression, and goes in release notes.
2. **Direct `core.HandlerContext` invocations of migrated middlewares break.**
   `interfaces/sso/health_test.go:121` calls `middleware.Tracing()(ctx)` with
   a `core.HandlerContext`; `test/middleware_test.go` drives
   `Auth`/`CORS`/`Logger`/`Tracing`/`RequestID` through the fake-context
   harness. Migrated to handler shape, these tests must be rewritten to
   `httptest.NewRecorder()` + `ServeHTTP`. Auth/CORS tests are deleted with
   the surfaces; Logger/Tracing tests migrate; the fake-context harness
   shrinks to the remaining route-level middlewares.
3. **`sso.AuthMiddleware`/`sso.CORS` removal is an SDK break.**
   `aliases.go:43-44` drops both; feature matrix + release notes carry the
   removal note. `interfaces/cors` is untouched and remains the CORS path.
   `LoggerMiddleware`/`TracingMiddleware`/`RequestIDMiddleware`/
   `RecoverMiddleware` aliases (`aliases.go:45-48`) stay — their types follow
   the migrated functions automatically.
4. **Slot-order drift inside `Wrap`.** The canonical sequence lives in one
   function body; `TestChain_CanonicalSlotOrder` pins the list, and the four
   invariant tests (below) pin the security semantics — a future slot swap
   fails CI, not review.
5. **Byte-identity of the probe mux.** If `WithProbes` were ever called with
   an empty map in production, ServeMux semantics (path cleaning) would
   disappear. Mitigation: `buildChain` always registers livez/readyz; the
   probe-bypass test asserts byte-identity against today's mux construction.
6. **Generic `Idempotency` has no production call site** (verified). The §3d
   invariant test must construct its own post-auth composition; nothing in
   production enforces it. Accepted: the invariant is a documented contract
   for future route wiring (`idempotency.go:142-153`), and the chain cannot
   see route-level order by construction. The test pins the contract so a
   future mis-wiring fails.
7. **Line-budget regression.** `chain.go` must stay under 500 lines (~300
   estimated). The 10-file ceiling forbids ever splitting `chain`'s code into
   a sibling file in the parent dir — future slots extend `chain.go` or
   warrant their own subpackage.
8. **Import-cycle trap.** `chain` must never import `interfaces/middleware`
   (its parent) — that would cycle with the re-export in `middleware.go`.
   It needs only `net/http` + `shared/core`; slot names and the alias are
   declared locally.
9. **`Handler()` re-creation semantics.** The chain (and `rateLimitStore`)
   is rebuilt per `Handler()` call. If a future change caches the chain,
   `SetRateLimitPolicy` hot-reload and probe handler freshness (metrics
   registry swap) would silently stale — the design preserves per-call
   construction and says so in `buildChain`'s doc.
10. **Layer gate.** `chain` classifies as `interfaces` via the first-segment
    rule — no `layerName()` edit, no exemption. The architecture gate must
    stay green with `middleware.go → chain` (same-layer, rank 5 → 5, legal).

## Ordering invariants as executable tests

Four tests + the slot-order pin, each with a documented negative control
(deliberate slot swap must fail; verified during implementation):

- **(a) Forged-XFF/rate-limit** (`chain` package): `WithTrustedProxies` +
  `WithRateLimit` with a `ratelimit.Policy` whose `Key` records the key it
  saw. Canonical order keys on the resolved real IP
  (`middleware.RealClientIP`); swapped order keys on the fallback
  (`RemoteAddr`) — the recorded key differs, proving the invariant
  (`server_routes.go:364` + `ratelimit/middleware.go:50-116`).
- **(b) Degradation-position**: with RateLimit, Degradation, BodyLimit
  installed, an over-limit request to a shedding gate yields the rate-limit
  refusal (429, not 503) — flood protection outside the gate; a huge-body
  request to the shedding gate is refused 503 before the body limit reads
  the body — short-circuit outside body-limit (`server_routes.go:368-372`).
- **(c) Probe bypass**: `/livez`, `/readyz`, `/metrics` responses are
  byte-identical with and without a fully populated chain, under a shedding
  gate and over the rate limit (no bucket consumed, no trusted-proxy
  dependency). Mirrors `buildProbeMux` exactly.
- **(d) Idempotency-after-auth** (`interfaces/sso` composition site): a
  cached success seeded through an authenticated path is never replayed to an
  unauthenticated request carrying the same `Idempotency-Key`
  (`idempotency.go:142-153`); the deliberately swapped composition (auth
  inside Idempotency) must replay the cached 200 — the failing negative
  control. No new audit event: the `idempotency_capture_missing` canary is
  untouched.

## Verification

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/middleware/... ./interfaces/sso/... -run 'Chain|Idempotency|Probe|RateLimit|Degradation' -race
make ci
```

Acceptance mapping: `TestChain_CanonicalSlotOrder` green; grep for
`wrapPanicRecovery\|wrapCompression\|wrapAPIVersioning\|buildProbeMux` in
`interfaces/sso` returns only the `buildChain` construction site (or
absence); probe tests unchanged and green; no new `interfaces/sso` file;
`interfaces/middleware` non-test count stays ≤ 10; `grep -rn
"core.MiddlewareFunc" interfaces/middleware` hits only the `FromCore`
signature. Untouched by design: `shared/core/router.go`,
`interfaces/ratelimit`, `platform/tracing`, `platform/audit`, and the
`idempotency_capture_missing` canary.
