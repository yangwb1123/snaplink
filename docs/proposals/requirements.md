Specification complete and saved to `docs/auto/interfaces-middleware-direction2-spec.md`. All evidence citations were verified against actual source line numbers. Summary:

## Requirements Specification: direction 2 — core 层「请求级状态注册表 + 响应捕获栈」

**Scope constraints** (verified): `shared/core` at frozen 23-file ceiling (`directory_fanout_test.go:63`) → registry/capture code must be net-file-neutral (carve `Context`/`trackingResponseWriter` out of `router.go`, 456 lines); `interfaces/sso` at 60-file ceiling; `shared/core` imports no Snaplink packages (typed keys instantiated by owning packages); `HandlerContext.SetResponseWriter` removal lands with all 3 adapters + `backgroundHandlerContext` in one change.

### ## 1. 类型化请求级状态注册表（typed request-state registry）
- **Problem**: state split across ~11 private `struct{}` context keys (`subjectKey`, `idempotencyKey`, `requestInfoKey`, `traceIDContextKey`, geo `ctxKey`, `breakGlassActorKey`, `actorContextKey`, `claimsCtxKey`…) plus an untyped string-keyed `sync.Map` value bag with 4 production string keys (`"tenant:resolved"` `tenant/middleware.go:17`, `"auth_hook_skip_mfa"` `accessors_threat.go:20`, `"device_ctx"` `server_finish_login.go:140`, cross-package read `"extensions"` `loginui.go:31`).
- **Proposed**: `core.RequestKey[T]` + `Get[T]/Set[T]` on `HandlerContext`; string-key shim deleted after migration.
- **Acceptance**: zero `ctx.Set("`/`ctx.Get("` hits in production; cross-type key use fails to compile; `shared/core: 23` unchanged.

### ## 2. core 层响应捕获栈（composable capture stack）
- **Problem**: capture is writer-swap based (`SetResponseWriter` + `trackingResponseWriter` re-wrap at `router.go:60-90`); `idempotency.go:16-25` documents how capture "silently broke under the adapters before"; gin needs `ginCaptureWriter` facade, echo swaps `Response().Writer`, `request_log.go`'s `requestLogResponseWriter` is a separate http-level capture with no defined composition; failures surface only via the `idempotency_capture_missing` audit canary (`recordCaptureMissing` `idempotency.go:212`); `backgroundHandlerContext.SetResponseWriter` silently no-ops (`sso_wiring.go:304`).
- **Proposed**: order-independent `CaptureStack` with install-time layer handles (capture structurally impossible to miss); delete `SetResponseWriter`, `InstallCapture`, `recordCaptureMissing`, `EventIdempotencyCaptureMissing`.
- **Acceptance**: routertest conformance on std/gin/echo with two simultaneous captures seeing identical status+body; zero `SetResponseWriter|InstallCapture` outside core; audit taxonomy + `docs/observability.md` updated in same change.

### ## 3. 统一请求状态表面（single request-state surface）
- **Problem**: http.Handler-level middlewares write `r.Context()` (TrustedProxies via third-party `peertrust.WithRequestInfo`, `rs.HTTPMiddleware`), HandlerContext-level write the bag — same data reachable two ways; worst case `ResolveTenantID` (`tenant/middleware.go:137-149`) is a second full copy of the Host→Domain→Tenant lookup because the rate-limit rejection metric runs before tenant middleware.
- **Proposed**: registry lives on `r.Context()` (`core.RequestStateOf`), `HandlerContext` is a view; tenant resolution memoized in one slot — rejection path reuses it, `ResolveTenantID` deleted.
- **Acceptance**: cross-signature read/write tests; mock-Store count proves zero second lookups when slot is filled; `requestInfoKey`/`ResolveTenantID` grep-zero.

A delivery order (registry → surface → capture stack, each independently gated with `go test ./... -race` + `make ci`) closes the spec.
