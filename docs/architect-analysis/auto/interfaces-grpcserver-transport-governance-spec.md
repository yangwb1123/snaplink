# Requirements Spec: interfaces/grpcserver — gRPC 管理面传输级治理补齐

> Source: `docs/auto/interfaces-grpcserver-analysis.md` direction 1.
> Scope: module `interfaces/grpcserver` + owning wiring in
> `cmd/sso-server/main_servers.go` / `interfaces/admin/middleware.go`.
> The gRPC plane is the primary automation/batch channel (long-lived tokens,
> scripts, gateway upstreams) yet bypasses every transport-level control the
> HTTP admin surface enforces. This spec closes that posture drift with
> exactly 3 improvements.

## 1. gRPC 拦截器链补齐 IP 策略 / 速率限制 / 写配额治理检查

**Name**: Transport governance parity — IP policy, rate limit, write quota on the gRPC interceptor chain.

**Problem**: `HTTPMiddleware` runs `checkIPPolicy` → `checkRateLimit` → `checkDestructiveConfirm` → bearer auth → `enforceIdleTimeout` → `checkWriteQuota` for every HTTP admin request, but the gRPC path (`authorizeGRPC`, shared by `UnaryServerInterceptor`/`StreamServerInterceptor`) executes only bearer validation + `HasAdminScope`. An attacker or compromised automation client that connects directly to the gRPC port bypasses the operator's entire rate-limit (shared token bucket), IP allowlist/geo-lock, and per-tenant write-quota control surface. `grpcServerOptions`' TLS remains optional while `-grpc-listen :8081` is enabled by default — the bypass is reachable on a stock deployment.

**Evidence**:
- `interfaces/admin/middleware.go:317-345` — `HTTPMiddleware` chain order (`checkIPPolicy` → `checkRateLimit` → `checkDestructiveConfirm` → auth → `enforceIdleTimeout` → `checkWriteQuota`); `middleware.go:220` `authorizeGRPC` performs only bearer + scope and never calls any of `checkIPPolicy`/`checkRateLimit`/`checkWriteQuota`.
- `cmd/sso-server/main_servers.go:192` `grpcInterceptorOptions` — chain is only `Recovery*Interceptor` + `adminMW`; `main_servers.go:145` `grpcServerOptions` adds TLS only when `tlsCert != "" && tlsKey != ""`; `cmd/sso-server/main.go:406` starts gRPC with `grpcListen` defaulted on.
- `interfaces/admin/governance.go:306,364,408` — `checkRateLimit`, `checkIPPolicy`, `checkWriteQuota` all take `http.ResponseWriter`/`*http.Request`; the policy state they read (`rateLimitStore`, `ipPolicy`, `quota`) already lives on the shared `Middleware` construction object (governance.go setters, wired in `cmd/sso-server/build_app.go:309-338`), so gRPC has the data available — only the execution path is missing.
- grpc-gateway REST surface (`build_http.go` `adminMW.HTTPMiddleware(gw)`) runs the full chain, proving the same `RegisterXxxServiceHandlerServer` services are protected differently per entry point.

**Proposed behavior**:
- Add a transport-agnostic governance gate in `interfaces/admin` (e.g. `governGRPC(ctx, fullMethod, claims, actorID, tenantHint) error`) that executes, in the same order as HTTP: IP policy (peer addr from `peer.FromContext`), rate limit (shared `ratelimit.PolicyStore` bucket), and write quota (actor + tenant hint from claims) for `admin:write` methods.
- Invoke it from both `UnaryServerInterceptor` and `StreamServerInterceptor` (streams gate at call open; quota counts once per stream, not per message) immediately after `authorizeGRPC` succeeds; failures map to `codes.ResourceExhausted` (rate/quota) and `codes.PermissionDenied` (IP policy), preserving oracle-safety (no per-cause detail leakage; details only in audit).
- HTTP path behavior must remain byte-identical; refactor `HTTPMiddleware` to call the same shared gate so the two transports cannot drift again. Empty/unset policy stays unlimited — byte-identical to today's build.
- Update `docs/config-reference.md` to state the checks now apply to the native gRPC admin plane, and `docs/observability.md` for the new audit reasons.

**Acceptance check**:
- New tests in `interfaces/admin` (package-internal, mirroring existing middleware tests): with `SetRateLimitPolicyStore` at limit, a gRPC unary admin call fails `ResourceExhausted` while a non-gated RPC (authz) still passes; with `SetIPPolicy` allowlist, a gRPC call from a non-allowlisted `peer` fails `PermissionDenied`; with `SetWriteQuota`, exceeding quota on gRPC `admin:write` methods fails while `admin:read` passes.
- `test/` e2e: start `sso-server` with governance config, drive the same mutation via native gRPC and via grpc-gateway REST, assert identical accept/reject outcomes.
- Existing HTTP-path tests stay green unmodified (byte-identical HTTP behavior).
- `go build ./... && go vet ./...` and `TestMaintainability_|TestArchitecture_` pass; file/function budgets respected (gate extraction keeps `HTTPMiddleware` under 50 lines).

## 2. gRPC 破坏性操作确认与 admin token 空闲超时

**Name**: Destructive-action confirmation (`X-Confirm`) and admin-token idle timeout on gRPC.

**Problem**: Two governance controls are structurally HTTP-only today. (a) `checkDestructiveConfirm` refuses classified mutations unless the request carries `X-Confirm: true` — a header concept with no gRPC equivalent, so a destructive bulk operation issued over gRPC (the automation channel) is not guarded by the operator's confirmation rules. (b) `enforceIdleTimeout` checks `adminTokenStore.GetByID(claims.JTI)` against `sessionTTL` and calls `adminTokenStore.Touch` on every protected HTTP request; on gRPC, `authorizeGRPC` never touches the store, so long-lived automation tokens never expire by idle and `Touch`-based revocation observability is absent on the gRPC plane.

**Evidence**:
- `interfaces/admin/governance.go:381` `checkDestructiveConfirm` reads `r.Header.Get(HeaderConfirm)` (`HeaderConfirm = "X-Confirm"`, governance.go:255); `governance.go:243` `errDestructiveConfirmRequired`; wired via `SetDestructiveActions` (`build_app.go:338`).
- `interfaces/admin/middleware.go:395` `enforceIdleTimeout` and `middleware.go:405` `_ = a.adminTokenStore.Touch(...)` appear only in the HTTP chain (`middleware.go:342-345`); `authorizeGRPC` (`middleware.go:220-252`) resolves claims (JTI is available) but never calls `adminTokenStore`; `Middleware.adminTokenStore`/`sessionTTL` fields (middleware.go:88-96) are set at `build_app.go:309`.
- `interfaces/admin/middleware.go:298` `StreamServerInterceptor` calls `authorizeGRPC` per stream open — the natural hook point for confirmation and touch.

**Proposed behavior**:
- Confirmation: accept `grpc-metadata-x-confirm: true` (gRPC metadata lower-cases header keys; reuse `HeaderConfirm` constant) on gated mutations whose `(method, path_prefix)` rule matches the RPC's `fullMethod`; absent/not-true yields `codes.FailedPrecondition` with an identical error string for all rules (details only in audit), mirroring the HTTP `409` oracle posture. Streams check once at open.
- Idle timeout: in `authorizeGRPC` (or the shared gate from improvement 1, after auth), when `sessionTTL > 0` and `adminTokenStore != nil` and `claims.JTI != ""`, `GetByID` and reject expired/revoked with `codes.Unauthenticated`, then `Touch` — identical semantics to `enforceIdleTimeout`; stream interceptor additionally `Touch`es on stream close (bounded: open + close, not per message).
- Failure semantics: expired/revoked token and confirmation refusal are indistinguishable to the caller per rule class (no oracle widening); reasons recorded only in the existing `EventAdminGRPCCalled` audit event.
- Document the gRPC metadata convention in `docs/config-reference.md` (admin_destructive_actions section) and OpenAPI where the gateway proxies the same services.

**Acceptance check**:
- Unit tests: `SetDestructiveActions` with a rule matching `/snaplink.admin.v1.UserAdminService/Delete` — gRPC call without `grpc-metadata-x-confirm` fails; with `grpc-metadata-x-confirm: true` passes; non-matching RPCs unaffected; all rule failures return identical `FailedPrecondition` strings.
- Unit tests: with `sessionTTL` set and `adminTokenStore` seeded stale, a gRPC admin call fails `Unauthenticated`; a fresh call updates `LastUsedAt` (assert `Touch` recorded); stream open + close each touch.
- e2e in `test/`: idle-expired admin token rejected identically via native gRPC and gateway REST.
- Mandatory gates (`go build ./... && go vet ./...`, maintainability/architecture tests) pass; `docs/error-codes.md` gains any new `Err*` if introduced.

## 3. gRPC 管理面传输安全兜底：TLS 默认开启与治理配置一致性护栏

**Name**: Transport hardening — default/enforced TLS and fail-closed wiring when governance is configured but not applied to gRPC.

**Problem**: `grpcServerOptions` enables TLS only when both `-tls-cert` and `-tls-key` are provided; the gRPC port defaults on (`-grpc-listen :8081`), so the default deployment exposes bearer-authenticated admin RPCs (including token/session revocation, key rotation, snapshot, release operations) in plaintext on the network. Additionally there is no wiring guard: an operator who configures `ip_policy`/`rate_limit`/`admin_destructive_actions`/`session_ttl` for the admin surface gets those guarantees on HTTP/gateway only, and the server starts happily with the gRPC plane ungoverned — silent posture drift at startup rather than an error.

**Evidence**:
- `cmd/sso-server/main_servers.go:170-181` — `if tlsCert != "" && tlsKey != "" { ... opts = append(opts, grpc.Creds(...)) }`; TLS silently optional.
- `cmd/sso-server/main.go:406` — `startGRPCServer(a, grpcListen, ...)` with `grpcListen` defaulted; `main_servers.go:102` only disables when `grpcListen == ""`.
- `interfaces/admin/middleware.go:76-98` — governance fields (`quota`, `ipPolicy`, `destructive`, `rateLimitStore`, `sessionTTL`, `adminTokenStore`) are set on the shared `Middleware`; `grpcInterceptorOptions` (main_servers.go:192) appends the same `adminMW` interceptors regardless of whether governance was configured, with no validation that configured controls are actually enforceable on the gRPC path (today they silently are not).
- `interfaces/admin/middleware.go:84,103` — nil/empty policy is documented as "byte-identical to a build without them", confirming unset-vs-bypassed is currently indistinguishable at startup.

**Proposed behavior**:
- TLS default-on: when the gRPC port is enabled and no `-tls-cert`/`-tls-key` are supplied, start gRPC with an auto-generated, self-signed ephemeral cert (logged fingerprint + documented override), or refuse to start with an explicit error under a new `admin.governance.grpc_tls=required`-style knob; either way, plaintext gRPC admin must never be the silent default. Certificates/logging follow existing `docs/config-reference.md` conventions (new knob documented there).
- Consistency guard (fail closed at startup): if any governance control (`ipPolicy`, `quota`, `rateLimitStore`, `destructive`, `sessionTTL`) is configured for the admin surface AND the gRPC listener is enabled, `startGRPCServer` must verify the same control is wired into the gRPC path (improvements 1-2 make this possible); otherwise return a startup error naming the missing control. This converts silent drift into an explicit configuration error.
- No new layer exemptions; keep all wiring in `cmd/sso-server` and `interfaces/admin` per DIRECTORY_MAP; document the plaintext-deprecation and the guard in `docs/config-reference.md` and `docs/deployment.md`.

**Acceptance check**:
- Startup tests (config-level, in `cmd/sso-server` or `test/`): (a) with `-grpc-listen` set and no TLS flags, server refuses plaintext or starts with the documented ephemeral-cert behavior — the default is never silently plaintext; (b) with `admin_destructive_actions.enabled=true` and `-grpc-listen` set, startup fails with an error naming the control until the gRPC governance wiring (improvements 1-2) is present.
- Existing e2e (`go test ./test/ -run TestE2E -v`) green with explicit `-tls-cert/-tls-key`; new e2e case asserts gRPC admin call over TLS succeeds and over plaintext (when explicitly permitted by the new knob) still enforces all governance checks.
- `make ci` passes; `docs/config-reference.md` documents every new knob and default change.

## Cross-cutting constraints (all improvements)

- Oracle safety: denial reasons for rate/quota/IP/confirm/idle stay indistinguishable per class; details only in audit (`EventAdminGRPCCalled` / existing audit reasons).
- No `layerExemptions`, no new top-level packages without classification in `architecture_layer_test.go`; `grpcadmin` fan-out ceiling (10 files) untouched — all changes land in `interfaces/admin` (shared gate), `interfaces/grpcserver`, and `cmd/sso-server`.
- Contract docs updated in the same change: `docs/config-reference.md`, `docs/error-codes.md` (new `Err*`), `docs/observability.md` (audit reasons), OpenAPI where the gateway surface is affected.
- Mandatory verification after every `.go` edit: `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; full `make ci` at handoff.
