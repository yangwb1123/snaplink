# Adapters delivery contract — Router backends

The `interfaces/adapters` package delivers the SDK's "embed into any web
framework" capability: `sso.WithRouter(adapter)` mounts the SSO server onto a
router the embedder owns. This document is the single declared contract for
Router backends; the executable evidence is the
[`routertest` conformance suite](../interfaces/adapters/routertest/conformance.go),
the [router-backend e2e matrix](../test/router_backend_matrix_test.go), and the
[embed examples](../docs/examples/embed-gin/main.go) /
[`embed-echo`](../docs/examples/embed-echo/main.go).

## 1. Supported backends

| Backend | Constructor | Conformance | Matrix e2e |
|---|---|---|---|
| `std` | `sso.NewStdRouter()` | yes | yes |
| `gin` | `ginadapter.NewGinRouter(engine...)` / `NewGinRouterWithOptions` | yes | yes |
| `echo` | `echoadapter.NewEchoRouter(engine...)` / `NewEchoRouterWithOptions` | yes | yes |

"Supported" means *passing the routertest conformance suite and the
router-backend matrix* — a claim no backend can make without green evidence.
The matrix runs the same protocol scenarios (PKCE authorization code with
userinfo round-trip, refresh rotation with family kill, DPoP-bound code) and
the same unmatched-surface byte checks against all three backends.

## 2. Unmatched-response normalization

Every unmatched request — unknown path, wrong method on a known path, HEAD on
a GET-only route, OPTIONS, trailing-slash variant — is normalized to
`http.NotFound`'s exact bytes (status `404`, body `404 page not found\n`,
`Content-Type: text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`),
matching `StdRouter.ServeHTTP`. This is what makes `sso.WithRouter(adapter)`
wire-interchangeable with `NewStdRouter()`.

**Scope of the byte-identity guarantee.** Byte identity covers the unmatched
surface only. JSON success and error bodies are *semantically* identical
across backends — same status, same parsed JSON value, same `Content-Type`
prefix, same header set — but not byte-identical, because each framework's
JSON serializer differs:

| Backend | Body | Content-Type |
|---|---|---|
| std | trailing `\n` | `application/json` |
| gin | no trailing `\n` | `application/json; charset=utf-8` |
| echo | trailing `\n` | `application/json; charset=UTF-8` |

Clients parse JSON, so raw byte equality on error bodies would buy nothing;
the matrix therefore pins status + JSON value + Content-Type prefix +
header-set for JSON errors (including the credential-endpoint
`Cache-Control: no-store` / `Pragma: no-cache` contract on every backend).

## 3. `WithFrameworkNotFound` and embedder overrides

`WithFrameworkNotFound()` opts out of the unmatched-response normalization:
the engine keeps its framework-native 404/405 behavior. This gives up the
byte-identity guarantee, and the routertest conformance suite must never be
wired against this configuration.

Post-construction embedder overrides have the same effect, later assignment
wins:

- gin: assigning `engine.NoRoute` / `engine.HandleMethodNotAllowed` after
  construction replaces the normalization.
- echo: replacing `engine.HTTPErrorHandler` or registering routes on the
  engine after construction overrides the catch-all.

**Panic recovery ordering.** The SDK's `wrapPanicRecovery` is the outermost
wrapper of the handler chain. A framework recovery middleware, when attached
by the embedder, runs *innermost* (defer LIFO) and therefore owns the panic
bytes: `gin.Default()`'s Recovery catches panics from SSO handlers first and
writes gin's plain-text 500. The examples use `gin.New()` / `echo.New()` so
panics unwind to the SDK's recovery, which writes the normalized
`{"error":"internal_error"}` JSON on every backend. Production gin deployments
should set `GIN_MODE=release`.

## 4. `GatedRegistrar` / `RegisterGated`

Both adapters implement `sso.GatedRegistrar`: the gate is a route-level
handler registered *before* the wrapped handler, so `live()` is evaluated
before any SSO middleware runs, and a gated-off route is byte-identical to a
never-registered one (no header leaks). Implementation notes:

- gin: `c.Abort()` inside the gate is mandatory — gin's `Next()` loop
  advances on its own, so a gate that merely returns would let the wrapped
  handler run anyway.
- echo: the gate returns a swallowed sentinel (`errGateOff`); the
  constructor-installed delegating `HTTPErrorHandler` ignores it because the
  404 is already written.
- Group-derived routers preserve the gate; `core.NewGatedRouter` is the
  coordination point for whole-router gating.

## 5. Capture primitives

`SetResponseWriter` / `Aborted` / `Written` are the handler-context facade
for response interception (audit, capture, streaming):

- `Abort()` is opt-in and sticky: middleware that calls it stops the chain
  before the handler runs.
- `Written()` reports "committed at least once": gin delegates to its
  writer's `Written()`; echo reads `Response().Committed`.
- `SetResponseWriter` swaps the writer underlying `ctx.JSON`/raw writes:
  gin requires a facade (`ginCaptureWriter`) because `Context.Writer` is
  typed `gin.ResponseWriter`; echo's `Response.Writer` is a plain public
  field. One documented gin edge: a `WriteHeaderNow`-only path records the
  status on the original writer, not the capture — every terminal Snaplink
  response goes through `ctx.JSON` (WriteHeader first), so the edge is
  dormant.

## 6. Enforcement

The contract is pinned by executable truth, not prose:

- **Conformance suite** (`interfaces/adapters/routertest`): byte-equality
  scenarios for matching, method dispatch, gated routes, and the unmatched
  surface, wired into gin and echo via public constructors with default
  wiring. Scenario inventory is pinned by `checks/adapters_check.py` — a
  removed scenario fails `make ci`. The pinned inventory:

  `FiveMethodDispatch`, `PathParamsAndQuery`,
  `UnknownPath_ByteIdenticalToHTTPNotFound`, `MethodMismatch_ByteIdenticalToHTTPNotFound`,
  `HeadOnGetRoute_ByteIdenticalToHTTPNotFound`, `OptionsOnKnownPath_ByteIdenticalToHTTPNotFound`,
  `TrailingSlash_ByteIdenticalToHTTPNotFound`, `MiddlewareOrderAndAbort_HandlerNotRun`,
  `GroupPrefix_InheritsMiddleware`, `UseAfterRegister_DoesNotAffectRegisteredRoutes`,
  `GateOff_ByteIdenticalToNeverMounted`, `GateOff_SkipsGlobalMiddleware_NoHeaderLeak`,
  `GatedGroup_PreservesGate`, `GateOn_ServesRoute`.
- **Router-backend matrix** (`test/router_backend_matrix_test.go`): the
  protocol scenarios and unmatched-surface checks of §1–§2, outcome-pinned
  (absolute 200 + tokens, not only cross-backend equality), including a
  concurrent `Use()` subtest run under `-race`.
- **Embed examples** (`docs/examples/embed-gin`, `docs/examples/embed-echo`):
  reference usage; their smoke tests run in `make ci` and
  `go test ./docs/examples/...`.
- **Concurrency contract**: adapter `Use()` appends to a mutex-guarded local
  slice and requests snapshot at registration, so concurrent `Use()` +
  `ServeHTTP` is race-free by construction; the matrix's `-race` subtest is
  the regression tripwire. Concurrent *route registration* is an embedder
  error (races inside gin/echo themselves) and is not supported.

**Check split.** `python cli.py adapters` runs the static checks plus the
behavioral conformance/matrix runs without `-race`. Race coverage lives in
`make ci`'s `race` target and `make test-e2e` (`go test -race -count=1
./test/...`).
