Spec written to `docs/auto/interfaces-adapters-direction2-spec.md`. I verified each claim against the code before writing:

**Verified evidence base**
- `shared/core/router.go` — `StdRouter.ServeHTTP` falls through to `http.NotFound` for unmatched routes (incl. method mismatch); `gatedRegistrar` doc explicitly states adapters "never implements this, and GatedRouter falls back to handler-wrapping"; `StdRouter.registerGated` snapshots middlewares at registration.
- `interfaces/adapters/gin/adapter.go` / `echo/adapter.go` — `wrapHandler` iterates `g.middlewares` at **request** time with no lock; echo uses `echo.New()` defaults (JSON 404 / 405 on method mismatch); gin relies on `gin.Default()` coincidences.
- `adapter_test.go` (11+11 cases) — all happy path, zero 404/405/gating/middleware-order coverage.
- `shared/core/router_test.go:188,204,443,500` — single-backend property locks (`MethodMismatchFallsThrough`, `NotFound`, `LiveToggleControlsReachabilityByteIdenticalTo404`, `GateOffSkipsGlobalMiddleware_NoHeaderLeak`).
- Precedent: `domains/permissions/permissionstest/conformance.go` `ConformanceSuite`, wired by memory/sqlite/postgres/redis.

**The 3 decisions**

| ## | Name | Core gap |
|---|---|---|
| 1 | `routertest.ConformanceSuite` | New test-only package (permissionstest pattern; `shared/core` imports no Snaplink packages, so adapter tests can legally consume it); fixed route table + scenario matrix asserting **byte equality** (status + body + headers), wired into std/gin/echo; baseline must fail on echo before fixes |
| 2 | 未匹配响应归一化 | Adapters must explicitly install not-found/method-not-allowed handlers emitting `http.NotFound` bytes (404 plain text, not echo's JSON 405), with an explicit opt-out for app-owned 404s; pinned by suite scenarios, not framework defaults |
| 3 | 注册期快照 + 公开门控注册 | Snapshot middleware at registration (StdRouter parity), race-free `Use()`/`ServeHTTP`, and promote `gatedRegistrar` to a public interface adapters implement so gate-off is byte-identical to never-mounted — including no global-middleware header fingerprints |

Each decision carries the required problem → evidence (file/symbol) → proposed behavior → acceptance check chain; acceptance checks are falsifiable (they fail today on gin/echo and pass after the change), which is what makes byte consistency an executable constraint rather than documentation.
