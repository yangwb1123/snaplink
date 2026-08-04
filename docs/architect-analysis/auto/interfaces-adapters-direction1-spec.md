# Requirements Specification: interfaces/adapters — Direction 1

Short-circuit + response-capture capability for `HandlerContext`, eliminating
silent security degradation under the gin/echo adapters.

Source: `docs/auto/interfaces-adapters-analysis.md`, 方向一.
Module: `interfaces/adapters` (gin + echo) plus the shared router kernel
`shared/core/router.go` and its consumers in `interfaces/middleware` and
`interfaces/sso`.
Out of scope (separate directions): cross-backend conformance suite (方向二),
real embedding/e2e delivery path (方向三), any change to the `Router`
interface shape.

Background facts established by inspection (all verified in current code):

- `HandlerContext` (11 methods) carries no abort, written, or response-capture
  primitive. `SetResponseWriter` exists only on the concrete `*core.Context`.
- `StdRouter.ServeHTTP` and both adapters' `wrapHandler` run all middlewares
  and then the handler unconditionally.
- Two production sites silently degrade under adapters via the concrete-type
  assertion `ctx.(*core.Context)`: `interfaces/middleware/idempotency.go:74`
  and `interfaces/sso/server_token.go:125`.
- No `Abort`/`Written` symbol exists anywhere in `shared/core/` or
  `interfaces/adapters/` (grep: zero hits).
- gin `Context.Writer` and echo `Response.Writer` are public, reassignable
  fields (`go doc` verified), so writer-swap capture is wireable in both
  adapters.

Dependency order: 1 → 2 → 3. Each improvement lands with the mandatory gates
(`go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`)
and no new `layerExemptions` or budget exemptions.

## 1. Short-circuit primitive: `Abort()`/`Aborted()`/`Written()` on `HandlerContext`, honored by all three backends

**Name**: Chain-termination primitives and backend-identical stop semantics.

**Problem**: A middleware that writes a terminal response (401, 204, cached
replay) cannot prevent the handler from executing afterwards. This produces
double writes (corrupting the oracle-safe byte contract) and makes
"rejecting" security middleware impossible to compose. Under the adapters the
degradation is worse: even gin's native `c.Abort()` cannot help because
`wrapHandler` drives the chain itself and calls the handler directly, never
via gin's chain machinery — the adapter user gets neither gin abort semantics
nor a Snaplink-level equivalent.

**Evidence**:
- `shared/core/router.go` — `StdRouter.ServeHTTP`:
  `for _, mw := range route.middlewares { mw(ctx) }; route.handler(ctx)` —
  unconditional handler execution; `HandlerContext` interface has no
  abort/written query.
- `interfaces/adapters/gin/adapter.go` — `wrapHandler`:
  `for _, mw := range g.middlewares { mw(ssoCtx) }; handler(ssoCtx)` — same
  unconditional pattern; `ginContext` never calls `c.Abort()`.
- `interfaces/adapters/echo/adapter.go` — `wrapHandler`: identical pattern.
- `interfaces/middleware/middleware.go:50` — `Auth` writes
  `ctx.JSON(401, {error: invalid_token/unauthorized})` and returns; the
  handler still runs and writes a second response (gin: superfluous
  `WriteHeader`; echo: second write errors). The analysis doc lists this as
  the 附带症状 of the missing primitive.
- `interfaces/middleware/middleware.go` — `CORS`: for OPTIONS writes
  `204 No Content` via the raw writer, then the handler runs anyway — a
  double write even on StdRouter today.
- `grep -rn "Abort\|Written" shared/core/ interfaces/adapters/` (excluding
  tests): zero hits — the concept does not exist at the interface level.

**Proposed behavior**:
- Add to `HandlerContext`: `Abort()` (mark the chain stopped), `Aborted() bool`,
  `Written() bool` (response committed at least once).
- `*core.Context`: `Aborted` flag plus a written-tracking response writer
  installed at `NewContext` time (flips on `Write`/`WriteHeader`), so
  `Written()` reflects writes through any replaced writer. Request-scoped;
  no shared state.
- `ginContext.Written()` → `c.Writer.Written()`; `echoContext.Written()` →
  `c.Response().Committed`. Both adapters track `Aborted` on their own
  struct field (gin's internal abort index is irrelevant since the adapter
  drives the chain).
- `StdRouter.ServeHTTP`, `GinRouter.wrapHandler`, `EchoRouter.wrapHandler`:
  after each middleware, `if ctx.Aborted() { break }`; invoke the handler
  only when `!ctx.Aborted()`.
- Migrate the two terminal-writing middlewares: `middleware.Auth` and
  `middleware.CORS` call `ctx.Abort()` after writing their terminal response.

**Acceptance check**:
- New test (same route table executed against `StdRouter`,
  `ginadapter.GinRouter`, `echoadapter.EchoRouter`): route with `Auth`
  middleware + handler that writes `200 {"ok":true}` and sets a side-effect
  flag → all three backends return byte-identical `401` bodies, side-effect
  flag unset, no superfluous-write warnings (gin runs in test mode where
  these surface).
- Same three-backend test for `CORS` OPTIONS → byte-identical `204`, handler
  not executed.
- Existing adapter tests and `TestGatedRouter_*` still pass unchanged
  (abort is opt-in; no existing behavior changes when middleware never
  aborts).
- `go build ./... && go vet ./...` and the maintainability/architecture gate
  pass.

## 2. Response-capture primitive: `SetResponseWriter` promoted to `HandlerContext`, real wiring in gin/echo contexts

**Name**: Capture primitive on the interface; backend-agnostic idempotent
replay capture.

**Problem**: `/token` idempotent-replay capture (AGENTS.md wire contract:
"Concurrent retries are idempotent only inside the grace window") and the
shared idempotency middleware both install their capture wrapper through a
concrete-type assertion on `*core.Context`. Under `ginContext`/`echoContext`
the assertion fails and capture is silently skipped: the first response is
never cached, so every retry re-executes the full grant — the idempotency
contract silently disappears the moment an embedder swaps in an adapter, with
no error, log, or test catching it.

**Evidence**:
- `interfaces/middleware/idempotency.go:74` —
  `if c, ok := ctx.(*core.Context); ok { c.SetResponseWriter(...) }` —
  silent no-op for adapter contexts.
- `interfaces/sso/server_token.go:125` — identical assertion in
  `beginTokenIdempotency` (the production /token capture path; called from
  the token flow at `server_token.go:78-82`).
- `shared/core/router.go` — `SetResponseWriter` is defined only on the
  concrete `*Context`, absent from the `HandlerContext` interface; its own
  doc says it exists "Used by the idempotency wrapper to capture token
  response bodies" — an interface-level capability living off the interface.
- `interfaces/middleware/idempotency.go` — `CommitIdempotentResponse`
  depends on the earlier capture having been installed
  (`ctx.ResponseWriter().(*idempotentResponseWriter)`), so a failed capture
  also silently disables the commit path.
- AGENTS.md §3 — "Single-use stores consume atomically ... Concurrent retries
  are idempotent only inside the grace window" (wire contract).

**Proposed behavior**:
- Add `SetResponseWriter(w http.ResponseWriter)` to the `HandlerContext`
  interface.
- `ginContext.SetResponseWriter`: `c.Writer = w` (public field, verified via
  `go doc github.com/gin-gonic/gin.Context.Writer`).
- `echoContext.SetResponseWriter`: `c.Response().Writer = w` (public field,
  verified via `go doc github.com/labstack/echo/v4.Response`).
- Replace both concrete-type assertions (`idempotency.go:74`,
  `server_token.go:125`) with the plain interface call. After this change
  `grep -rn '\.(\*core\.Context)' interfaces/` must return nothing.
- Keep the ordering guarantee: the adapters' `wrapHandler` runs middlewares
  before the handler, and the swap is visible to the handler's `ctx.JSON`
  because gin/echo write through `c.Writer` / `c.Response()`.

**Acceptance check**:
- Three-backend test: `POST /token` (client-credentials grant) with
  `Idempotency-Key: k` twice through `GinRouter` and `EchoRouter` (and
  StdRouter as baseline): response 1 and response 2 are byte-identical
  (status + body), and the grant is executed exactly once (issuer/store
  side-effect counter unchanged on retry).
- `grep -rn '\.(\*core\.Context)' interfaces/` → zero hits.
- Existing StdRouter token-idempotency tests (in-package, e.g.
  `TestToken*Idempotency*`) still pass unchanged.

## 3. Hit-short-circuit + loud commit: one idempotent-hit path, retired "handler must cooperate" convention, no silent capture loss

**Name**: Composed abort+capture semantics for the idempotency feature;
loud failure on capture loss.

**Problem**: Even with primitives 1 and 2 in place, the idempotency feature
still has a design hole: the cache-hit shortcut only works if the handler
cooperates (`HandleIdempotentRequest` at handler entrance) — a convention the
code itself documents as a limitation — and the token endpoint re-implements
the whole mechanism inline, so there are two divergent implementations of the
same security behavior. Additionally, when the capture wrapper is missing
(any future regression), `CommitIdempotentResponse` skips caching silently:
replay protection disappears without a trace.

**Evidence**:
- `interfaces/middleware/idempotency.go:55-60` — self-admitted limitation:
  "NOTE: because StdRouter runs all middlewares then the handler, middleware
  cannot prevent the handler from executing. This middleware sets up the
  capture infrastructure; the handler (or a wrapper) must call
  HandleIdempotentRequest for the cache-hit shortcut."
- `interfaces/middleware/idempotency.go:82-92` — `HandleIdempotentRequest`
  exists only because of that limitation ("For endpoints where the handler
  cannot be easily modified, use HandleIdempotentRequest at the handler
  entrance").
- `interfaces/sso/server_token.go:78-135` — `beginTokenIdempotency` /
  `finishTokenIdempotency` re-implement the same capture + hit-check inline
  (with the line-125 assertion), i.e. two copies of the same security logic.
- `interfaces/middleware/idempotency.go:111-123` — `CommitIdempotentResponse`
  returns nothing and silently does nothing when the capture wrapper is not
  installed, even though a key was present (idempotency was requested).

**Proposed behavior**:
- With `Abort()` from improvement 1, `middleware.Idempotency` short-circuits
  cache hits at the middleware level: on hit, write the cached body
  (Content-Type + 200) and call `ctx.Abort()`; the chain then skips the
  handler on all three backends. The `HandleIdempotentRequest`-at-entrance
  convention and its documented limitation are retired.
- Oracle-safe ordering invariant (explicit, tested): a middleware-level hit
  short-circuit is only valid when the middleware position postdates
  authentication — a cached success must never be replayed to a request that
  would have failed client authentication. The /token hit check therefore
  stays where `beginTokenIdempotency` runs today (after client auth and
  grant-type rejection); the consolidation is limited to the capture and
  replay helpers (improvement 2), not the middleware position.
- `CommitIdempotentResponse` becomes loud: when a key is present but no
  capture wrapper is installed, it records an audit event (via the standard
  audit path; bounded cardinality) instead of silently skipping — per
  AGENTS.md "fail open with audit/logging" for non-decision helpers while
  making degradation observable.
- Delete the duplicated inline capture in `server_token.go` in favor of the
  shared middleware helpers; the /token path keeps its own post-auth hit
  check, expressed through the shared replay helper.

**Acceptance check**:
- Three-backend test: route wired with `middleware.Idempotency(cache)` +
  handler with a side-effect counter; two requests with the same
  `Idempotency-Key` → byte-identical 200 responses on StdRouter, gin, echo;
  the counter increments exactly once (hit path aborts the chain before the
  handler on all three backends).
- Oracle-safety regression test: `POST /token` with `Idempotency-Key` and a
  wrong client secret returns `400 invalid_client` (never the cached 200) —
  on all three backends.
- `grep -rn '\.(\*core\.Context)' interfaces/` → zero hits; audit event
  emitted (and unit-tested) when commit runs without a capture wrapper.
- Existing token-idempotency and middleware tests pass unchanged.

## Summary

| # | Improvement | Removes |
|---|---|---|
| 1 | `Abort`/`Aborted`/`Written` on `HandlerContext` + chain-stop in StdRouter/gin/echo | double writes from rejecting middleware; adapter bypass of abort semantics |
| 2 | `SetResponseWriter` on the interface, wired in gin/echo | silent loss of /token idempotent replay capture under adapters |
| 3 | Middleware-level hit short-circuit + loud commit + single implementation | "handler must cooperate" convention; duplicated token capture; silent capture loss |

Done in order 1 → 2 → 3; each step is independently shippable and gated.
