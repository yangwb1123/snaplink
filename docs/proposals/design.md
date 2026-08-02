Design doc written to `docs/design/grpcserver-observability-tls.md` (25303 bytes). All spec evidence was re-verified against the working tree first; every file/line reference in the doc is current.

## Design summary

**## Decision 1 — API surface**
`grpcserver.RegisterObservability(s *grpc.Server, checks func() map[string]func(ctx) error) (stop func())` in a new `interfaces/grpcserver/obs.go` (6→7 non-test files, within the 10-file budget). Registers the stock `health.Server` + `reflection.Register`; the `checks` func-value keeps `grpcserver` free of any `interfaces/sso` import (no new graph edges). cmd wires `a.server.BuildHandlerDeps().ReadyChecks` (verified at `accessors_handlers.go:343`). Per-service statuses derive from `s.GetServiceInfo()` each tick — no ordering constraint, no extra param.

**## Decision 2 — Health semantics**
Single poller goroutine: immediate first evaluation, then 5s interval; per-evaluation `recover` (panicking checks can't kill the poller — matches `/readyz`'s net/http survivability); 3s aggregate deadline mirroring `handleReadyz`. `stop()` cancels the poller + `health.Server.Shutdown()` so Watch clients see draining. Documented divergence: `WithReadyCheckTimeout` metadata is invisible through the accessor — gRPC health applies only the aggregate bound (not fixable without touching `interfaces/sso`, which is out of scope).

**## Decision 3 — Metrics**
`ss_grpc_requests_total` + `sso_grpc_request_duration_seconds` with labels `grpc_service` (memoized allowlist from `GetServiceInfo()`, unknown → `"other"`) and `code_class` (fixed `ok|client|server` table). Health/reflection RPCs are denylisted so LB probe traffic never dominates dashboards. Interceptors live in `interfaces/grpcserver/metrics.go`, vectors + registration in `platform/metrics` — same split as the HTTP pair. `a.metrics` is nil-safe (`main.go:274`).

**## Decision 4 — Tracing + chain order**
`otelgrpc v0.68.0` (exact contrib/otel alignment). New order: `metrics → otelgrpc → Recovery → adminMW`. This deliberately amends the documented "Recovery outermost" invariant — the comment is rewritten and the observability layer is panic-safe (defensive recover → Internal, never crashes the process). The panic-counted-as-server-class test is the regression lock.

**## Decision 5 — TLS fail-closed**
New `-grpc-tls-cert/-key` (fallback to shared pair) + `-grpc-insecure`. A pure decision function implements the 6-row matrix: non-loopback + no material → startup error; loopback or explicit opt-out → logged plaintext exceptions; cert+insecure → error. Flags stay runtime-only (no Config keys → docscheck gate unaffected). Verified no `test/` harness passes `-grpc-listen`, so the stock-run breaking change has no CI blast radius.

**## Decision 6 — Storage model**
No durable storage. In-memory only: health status map (a *projection* of the existing store-health check closures — no new probing), bounded prometheus vectors, one memoized allowlist per server, OTLP's bounded span queue.

**## Decision 7 — Failure modes**
11-row table: check panics/hangs, flapping, handler vs. observability-layer panics, exporter down, metrics disabled, cert failures, reflection-on-plaintext, poller leak (owned by `stop()`).

**## Decision 8 — What could break the design**
Nine risks with mitigations: chain-order regression (test-locked), otelgrpc missing from module cache (needs network fetch; minimal-diff criterion), `GetServiceInfo` fallback, stock-run startup break, unauthenticated health/reflection (accepted convention), cardinality growing with SDK-registered services, per-check-timeout divergence, flag/Config asymmetry, `health.Server.Shutdown()` availability (checked at implementation).

Contract updates and the full gate sequence (`go build/vet` → maintainability/architecture → `-race` → TestE2E → `make ci`) close the doc, per AGENTS.md §5.
