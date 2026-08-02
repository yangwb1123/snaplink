Design doc written to `docs/auto/interfaces-middleware-design.md`. Every budget and signature claim was re-verified against the tree before writing.

## Key decisions

**## Package layout** — New `interfaces/middleware/chain` subpackage (not an extension of `middleware.go`). The 10-file fanout ceiling forbids a new root file, and the in-file estimate lands at ~490 lines (>450 trigger, ~zero headroom under the 500 cap). `middleware.go` re-exports `type Chain = chain.Chain` + `var FromCore = chain.FromCore` so the spec name `middleware.Chain` holds. `chain` imports only `net/http` + `shared/core`; both packages classify as `interfaces` by first-segment rule — no `layerName()` change.

**## API surface** — `type Middleware = func(http.Handler) http.Handler` as a *type alias* (not defined type): every existing constructor (`Recover`, `Compress`, `AcceptVersion`, `Degradation`, `RequestLogger`, `metrics.Middleware`, `ratelimit.DynamicMiddleware`, `tracing.Middleware`, `cors.Middleware`, `handler.SecurityHeaders`, `TrustedProxies.Middleware`) is assignable with zero conversions. 12 unexported slot fields, 12 nil-tolerant `With*` builders, `WithProbes` (map copied), `Wrap` (fixed-sequence `if` chain — no slice to shuffle), `SlotOrder()`, `FromCore` (mirrors `StdRouter`'s Abort loop at `router.go:270-277`).

**## Storage model** — No persistent state. Chain is rebuilt per `Handler()` call (preserving today's semantics); the one side-effectful assignment is `s.rateLimitStore` (kept in `buildChain` so `SetRateLimitPolicy` hot-reload keeps working); degradation gauge seeding stays as a one-call-site helper; idempotency cache untouched.

**## Tracing slot** — Two independent options (`requestIDMW` request-ID/W3C + `tracingOperation` OTel) compose into the single Tracing slot, OTel-outermost. Flagged the intentional behavior delta: 429/503/413 rejections now carry `X-Request-Id` (today they don't, since Tracing ran inside the router).

**## Failure modes / what could break it** — 10-item risk register: the `health_test.go:121` direct `Tracing()(ctx)` break, fake-context harness rewrites in `test/middleware_test.go`, the `sso.AuthMiddleware`/`sso.CORS` SDK break, the parent→child import cycle trap, probe-mux byte-identity (ServeMux path-cleaning), and the finding that generic `middleware.Idempotency` has **zero production call sites** — so test (d) pins a documented contract, not an enforced composition.

## Notable verification findings beyond the spec

- `server_routes.go` is 488/500 lines — the collapse nets −70, relieving the pressure that forced `wrap*` relocation
- `mountMiddleware`'s `TracingMiddleware()` `router.Use` (line 113) is the only server-side `core.MiddlewareFunc` tracing consumer; tenant/geo/region stay on `Router.Use`
- `Deprecation` wraps outside `AcceptVersion` today — the single AcceptVersion slot receives the server-composed pair to preserve exact order
