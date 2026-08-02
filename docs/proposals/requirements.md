Requirements spec written to `docs/auto/interfaces-grpcserver-transport-governance-spec.md`. All evidence was verified directly against the code before writing:

**Verified evidence chain:**
- `interfaces/admin/middleware.go:317-345` — `HTTPMiddleware` runs the full 6-step chain; `authorizeGRPC` (:220) does bearer + scope only; `enforceIdleTimeout`/`Touch` (:395/:405) never fires on gRPC.
- `interfaces/admin/governance.go:306/364/381/408` — all governance checks take `http.ResponseWriter`/`*http.Request`; policy state already lives on the shared `Middleware` (wired at `cmd/sso-server/build_app.go:309-338`), so gRPC has the data but no execution path.
- `cmd/sso-server/main_servers.go:192` — interceptor chain is only Recovery + adminMW; TLS optional at :170-181; `-grpc-listen` defaulted on.
- `interfaces/grpcserver/grpcadmin/admin_paginate.go` — confirmed direction 2's self-admitted deferred debt (excluded per scope: the task targets direction 1 only).

**The 3 improvements (decomposition of direction 1):**
1. **Governance parity on the interceptor chain** — shared transport-agnostic gate running IP policy / rate limit / write quota on both gRPC unary and stream interceptors in HTTP order, so the two transports cannot drift again.
2. **Destructive confirmation + idle timeout on gRPC** — `grpc-metadata-x-confirm` convention, and `GetByID`/`Touch` idle enforcement inside `authorizeGRPC` (JTI already available from claims).
3. **Transport hardening** — TLS never silently plaintext by default (ephemeral cert or startup refusal), plus a fail-closed startup guard that rejects configs where governance is enabled but not enforceable on the gRPC plane.

Each section has a concrete acceptance check (unit tests in `interfaces/admin`, e2e in `test/`, contract-doc updates per AGENTS.md §5, and the mandatory gate commands).
