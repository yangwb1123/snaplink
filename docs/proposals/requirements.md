All evidence verified against the codebase (grep across `.go` files confirms zero occurrences of `grpc_health_v1`/`healthpb`/`reflection.Register`/`otelgrpc`; grpc v1.80.0 already ships `health` and `reflection` packages in-module). Here is the specification.

---

# Requirements Specification — `interfaces/grpcserver`, Expansion Direction 3

**Direction (from `docs/auto/interfaces-grpcserver-analysis.md`):** *"gRPC 平面运维可观测性缺失：无健康检查、无 reflection、无 metrics/tracing 拦截器，TLS 可选"* — the gRPC plane is functionally complete (authz + discovery + admin services) but operationally invisible: nothing to probe, nothing to discover, nothing to measure, and a plaintext-by-default port. The HTTP plane (`/livez`, `/readyz`, `otelhttp`, `sso_http_*` metrics) has all four; the gRPC plane has none. Consumers include the ext-authz data plane (`AuthzService.Check`, `docs/feature-matrix.md:142`), SDK embedders (`interfaces/grpcserver/aliases.go`), and cluster deployments (`platform/registry` etcd backend).

## 1. Standard probe and discovery services: `grpc_health_v1` + reflection

**Problem:** No health service and no reflection. Load balancers and orchestrators cannot probe the gRPC port, `grpcurl`/`grpcreflect` tooling cannot enumerate the contract, and operators must grep source to know which services exist. The HTTP plane has `/readyz` with named per-dependency checks; the gRPC plane has no readiness signal at all — yet `platform/registry` (etcd backend, `docs/agent-os` cluster form) and the `AuthzService.Check` data-plane dependency make the gRPC listener a first-class production endpoint.

**Evidence:**
- `cmd/sso-server/main_servers.go:128` `newGRPCServer` registers exactly `authzv1.RegisterAuthorizerServer` (L134), `discoveryv1.RegisterDiscoveryServer` (L135), `registerAdminGRPCServices` (L137). No `healthpb.RegisterHealthServer`, no `reflection.Register`.
- Repository-wide grep: zero matches for `grpc_health_v1`, `healthpb`, or `reflection.Register` in any non-test `.go` file.
- HTTP parity exists: `interfaces/sso/server_routes.go:478` `mux.HandleFunc(PathReadyz, s.handleReadyz)`, handler at `interfaces/sso/server_health.go:97`; named checks via `sso.WithReadyCheck` (`interfaces/sso/options_misc.go:382`), `AddReadyCheck` (`interfaces/sso/accessors_handlers.go:181`), and `serverbuildsign.AppendReadyCheck` (`cmd/sso-server/serverbuildsign/build_readiness.go`). The readiness state is already exposed for reuse: `d.ReadyChecks = func() map[string]func(ctx) error` at `interfaces/sso/accessors_handlers.go:345`.
- `google.golang.org/grpc/health` and `google.golang.org/grpc/reflection` are part of the already-pinned grpc v1.80.0 module (confirmed in module cache) — zero new dependencies.
- Test infrastructure already assumes probe-ability: `test/admin_grpc_base_test.go` uses `bufconn` + `credentials/insecure`.

**Proposed behavior:**
1. Add a `grpcserver.RegisterObservability(s *grpc.Server, checks func() map[string]func(ctx) error)`-style helper (new file in `interfaces/grpcserver`, which has 6 non-test files against a 10-file budget) that registers `healthpb.HealthServer` backed by the standard `health.Server` and `reflection.Register`. The health server's `SERVING`/`NOT_SERVING` state is derived from the same `readyChecks` the `/readyz` handler uses (via the `d.ReadyChecks` accessor), preserving the degraded-readiness semantics documented in `docs/agent-os/`.
2. Wire it in `newGRPCServer` (`cmd/sso-server/main_servers.go`), so the standalone server and SDK consumers (per the `aliases.go` public-contract comment) get identical behavior. Health/reflection are intentionally unauthenticated (standard gRPC convention); plaintext exposure is mitigated by improvement 3's TLS default.
3. Surface both in `cmd/sso-server/log_endpoints.go:88` `logGRPCServices` so the startup banner lists them.

**Acceptance check:**
- New bufconn test in `interfaces/grpcserver` (following the `test/admin_grpc_base_test.go` pattern): `grpc_health_v1.Health.Check` returns `SERVING` when all checks pass; after an `AddReadyCheck`-registered check is made to fail, `Check` returns `NOT_SERVING` and flips back when it recovers; `Watch` streams the transition.
- E2E: `grpcurl -plaintext localhost:8081 list` enumerates `grpc.health.v1.Health`, `grpc.reflection.v1.ServerReflection`, `authz.v1.Authorizer`, `discovery.v1.Discovery`, and the admin services.
- Contract docs updated in the same change: `docs/observability.md` gains a gRPC health section; `docs/feature-matrix.md` gains a row.
- `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .` pass.

## 2. Per-RPC metrics and tracing interceptors on the gRPC plane

**Problem:** The gRPC plane is a black box. `grpcInterceptorOptions` (`cmd/sso-server/main_servers.go:195`) chains only `Recovery*ServerInterceptor` + adminMW; no RPC is ever counted, timed, or traced. The HTTP plane records `sso_http_requests_total`/`sso_http_request_duration_seconds` (bounded labels) and OpenTelemetry spans via `otelhttp`; the gRPC plane — including the data-plane `AuthzService.Check` calls every ext-authz request depends on — produces nothing. `docs/observability.md` contains zero occurrences of "grpc", so the observability contract is HTTP-only. There is no way to build latency/error SLOs or per-service dashboards for the plane that carries machine-to-machine traffic.

**Evidence:**
- `cmd/sso-server/main_servers.go:195-206` `grpcInterceptorOptions`: `unaryInts := []grpc.UnaryServerInterceptor{grpcserver.RecoveryUnaryServerInterceptor(logger)}` plus adminMW when wired — nothing else. The chain-order comment (L188-192) already establishes the invariant that Recovery must be outermost to protect everything beneath it.
- HTTP metric precedent: `platform/metrics/middleware.go` (`Middleware`, `sanitizeMethod`, `statusClass`) — bounded method set + 5-class status labels; vectors declared at `platform/metrics/metrics.go:39-40` and registered in `platform/metrics/metrics_ctor.go:63` `registerHTTPMetrics`. Bounded cardinality is a hard invariant: `docs/observability.md:9` "All metrics use bounded cardinality — **no per-path/per-user labels**".
- Tracing precedent: `platform/tracing/tracing.go:226` `Middleware(operation)` wraps handlers with `otelhttp.NewHandler`; `platform/tracing.Init` (L113) already installs an OTLP `TracerProvider`.
- `go.mod:21-26`: `otelhttp v0.68.0` present, no `go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc` (confirmed absent from module cache). grpc v1.80.0 in-module.

**Proposed behavior:**
1. New unary + stream interceptors in `interfaces/grpcserver` (e.g., `obs.go`/`metrics.go`): record RPC count and latency with strictly bounded labels — `rpc_service` (from `fullMethod` service prefix, collapsed to a bounded registered set; unknown → `"other"`, mirroring `sanitizeMethod`) and `code_class` (gRPC code families, mirroring `statusClass`). Never per-method/per-user labels.
2. Extend `platform/metrics.Metrics` with `GRPCRequestsTotal` / `GRPCRequestDuration` vectors registered in `metrics_ctor.go` beside `registerHTTPMetrics`; document both in the `docs/observability.md` metrics table.
3. Add `otelgrpc` (version-aligned with otel v1.43.0) and chain `otelgrpc.UnaryServerInterceptor`/`StreamServerInterceptor` for spans, consistent with `platform/tracing`; when tracing is unconfigured the noop `TracerProvider` makes the interceptor cost negligible, matching the existing HTTP behavior.
4. Chain order in `grpcInterceptorOptions`: observability interceptors outermost (so they observe errors produced by Recovery), Recovery next, adminMW innermost; the observability interceptors must be panic-safe (defensive recover) so they cannot crash the server.
5. New `platform/metrics`-style counters flow to the existing `/metrics` scrape (which is already served outside rate limiting per `docs/observability.md:99`).

**Acceptance check:**
- Unit test in `interfaces/grpcserver` with a bufconn server + prometheus test registry: successful and `PermissionDenied`-returning RPCs increment `sso_grpc_requests_total` with the correct `code_class` label and populate the duration histogram; a synthetic panic is recovered by `Recovery*ServerInterceptor` and still counted as 5xx-class (proves chain order).
- Cardinality test: sending RPCs with many distinct methods keeps label cardinality bounded (all unknown methods collapse to `"other"`).
- E2E: `make ci` passes with `-race`; a `go.mod` diff shows only the `otelgrpc` addition.
- Contract update: `docs/observability.md` metrics table gains the two `sso_grpc_*` rows; observability docs mention gRPC tracing.

## 3. Transport hardening: TLS required by default on the gRPC listener

**Problem:** The gRPC port is plaintext by default. `-grpc-listen` defaults to `:8081` (`cmd/sso-server/main_wiring.go:59`) — always on — but `grpcServerOptions` (`cmd/sso-server/main_servers.go:172-181`) only installs `grpc.Creds` when `tlsCert != "" && tlsKey != ""`. A stock `sso-server` run therefore binds a public, unauthenticated-by-TLS port carrying bearer-token admin traffic, ext-authz decisions, and discovery metadata, with no encryption and no config-documented way to require it. This makes improvements 1 and 2 (unauthenticated health/reflection) and the bearer-bearing admin plane trivially sniffable/replayable on the wire, and contradicts the security posture of the HTTP plane, where the same cert flags gate `ListenAndServeTLS` (`cmd/sso-server/main_servers.go:54`).

**Evidence:**
- `cmd/sso-server/main_servers.go:171-181`: `// Optional TLS for gRPC ... if tlsCert != "" && tlsKey != ""` — plaintext is the default configuration, not an explicit operator choice.
- `cmd/sso-server/main_wiring.go:59`: `flag.String("grpc-listen", ":8081", ...)` — the port is enabled by default.
- `docs/config-reference.md` documents `admin_destructive_actions.enabled` and HTTP TLS but has no gRPC TLS knob (grep for grpc TLS config yields nothing); `docs/feature-matrix.md` has no gRPC-transport row.
- Admin traffic over the gRPC plane carries `bearer` metadata authenticated by `authorizeGRPC` (`interfaces/admin/middleware.go:220`) — the very tokens improvement 1/2 tooling would now make discoverable; AGENTS.md §3 requires credential endpoints to use TLS-safe headers (`Cache-Control: no-store` etc.) on HTTP, an equivalent guarantee is absent on gRPC.
- Test harness connects with `credentials/insecure` (`test/admin_grpc_base_test.go`) — the only documented client pattern.

**Proposed behavior:**
1. Add dedicated `-grpc-tls-cert` / `-grpc-tls-key` flags (falling back to the shared `tlsCert`/`tlsKey` when set), consumed by `grpcServerOptions` instead of the implicit shared pair.
2. Fail-closed default: starting with `-grpc-listen` set and no TLS material is an explicit startup error **unless** the listen address is loopback-only (`127.0.0.1`/`::1`) or the operator passes an explicit `-grpc-insecure` opt-out. Plaintext becomes a deliberate, logged exception, not the default posture.
3. Update `docs/config-reference.md` (new gRPC TLS keys + the insecure opt-out) and `docs/feature-matrix.md` (transport row: TLS required by default, loopback/insecure exceptions); keep the `MinVersion: tls.VersionTLS12` floor already present at `main_servers.go:179`.
4. Keep `grpc.Creds` wiring in `grpcServerOptions` so SDK consumers embedding their own `grpc.Server` can reuse the same helper.

**Acceptance check:**
- CLI test: `sso-server -grpc-listen :8081` with no cert flags exits with a startup error naming the missing gRPC TLS material; `-grpc-listen 127.0.0.1:8081` and `-grpc-listen :8081 -grpc-insecure` start (plaintext logged); `-grpc-tls-cert/-grpc-tls-key` starts with `credentials.NewTLS` and rejects pre-TLS1.2 handshakes.
- Unit test for the option builder asserting the plaintext-refusal decision per (listen addr, flags) matrix.
- `docs/config-reference.md` golden check (the committed `docscheck` config-keys gate, per `docs/DECISIONS.md` M2) passes with the new keys.
- E2E: existing bufconn tests updated to exercise the TLS path once; `make ci` green including nested modules and config validation.

---

**Workflow compliance (AGENTS.md §5):** all three changes update contracts in the same change (observability doc, config reference, feature matrix); no new `Err*` codes are required (gRPC uses `status.Error(codes.*)`); the `grpcserver` directory stays within its 10-file budget (new files: ~1 observability-registration + ~1 metrics interceptor); `interfaces/sso` is untouched. Mandatory gates before handoff: `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, `go test ./... -race`, `go test ./test/ -run TestE2E -v`, then `make ci`.
