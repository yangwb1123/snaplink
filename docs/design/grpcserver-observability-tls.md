# Design: interfaces/grpcserver — 运维可观测性 + TLS 默认 (Direction 3)

Design for Direction 3 of
[`docs/auto/interfaces-grpcserver-analysis.md`](../auto/interfaces-grpcserver-analysis.md):
gRPC plane operational observability (health + reflection), per-RPC
metrics/tracing interceptors, and fail-closed TLS on the gRPC listener.

Every claim below was re-verified against the working tree before writing:

- `newGRPCServer` (`cmd/sso-server/main_servers.go:126-146`) registers only
  authz/discovery/admin; repository-wide grep finds zero non-test occurrences
  of `grpc_health_v1`, `healthpb`, or `reflection.Register`.
- `grpcInterceptorOptions` (`cmd/sso-server/main_servers.go:194-206`) chains
  only `Recovery*ServerInterceptor` + `adminMW`; its comment establishes the
  "Recovery outermost" invariant this design deliberately amends (Decision 4).
- `grpcServerOptions` (`cmd/sso-server/main_servers.go:170-183`) installs TLS
  only when `tlsCert != "" && tlsKey != ""`; `-grpc-listen` defaults to
  `:8081` (`cmd/sso-server/main_wiring.go:59`).
- grpc v1.80.0 (go.mod:30) ships `google.golang.org/grpc/health` and
  `google.golang.org/grpc/reflection` in-module (module cache confirmed) —
  zero new dependencies for Decision 1.
- `d.ReadyChecks = func() map[string]func(ctx) error` is set in
  `populateHandlerDepsCallbacks` (`interfaces/sso/accessors_handlers.go:343`),
  reachable from cmd via `s.BuildHandlerDeps().ReadyChecks`
  (`interfaces/sso/accessors_handlers.go:251`); `handler.ServerDeps.ReadyChecks`
  at `internal/handler/serverdeps.go:127`.
- `app.metrics *metrics.Metrics` (`cmd/sso-server/main.go:274`, nil when
  metrics disabled); vector registration pattern
  `registerHTTPMetrics` (`platform/metrics/metrics_ctor.go:63-83`);
  consts in `platform/metrics/consts.go`.
- `platform/tracing.Init` (`platform/tracing/tracing.go:113`) leaves the
  global no-op provider when unconfigured, so an always-wired otelgrpc
  interceptor costs ~nothing without an exporter.
- go.mod has `otelhttp v0.68.0` + `otel v1.43.0`; `otelgrpc` is absent from
  go.mod AND the module cache (first fetch requires network; see Decision 8).
- No `test/` harness passes `-grpc-listen`; bufconn tests
  (`test/admin_grpc_base_test.go`) bypass `startGRPCServer`, so the TLS
  default change has no test-harness blast radius.

**Scope.** Exactly the three improvements: (1) `grpc_health_v1` +
reflection, (2) per-RPC metrics + otelgrpc tracing interceptors, (3) TLS
required by default on the gRPC listener. No new proto, no new `Err*` codes
(gRPC errors use `status.Error(codes.*)`), `interfaces/sso` untouched,
`grpcadmin/` untouched (at its 10-file ceiling).

---

## Decision 1: API surface — `RegisterObservability` helper in `interfaces/grpcserver`

**What.** New file `interfaces/grpcserver/obs.go` (6 → 7 non-test files in
the directory; 10-file budget holds):

```go
// RegisterObservability registers grpc_health_v1.Health backed by the
// standard health.Server and grpc.reflection.v1.ServerReflection.
// checks (usually sso BuildHandlerDeps().ReadyChecks) is polled on an
// interval; nil or nil-returning checks evaluate to SERVING. Returns a
// stop func that cancels the poller and flips all services to
// NOT_SERVING (grpc-go health.Server.Shutdown, present since v1.60).
func RegisterObservability(s *grpc.Server,
    checks func() map[string]func(context.Context) error) (stop func())
```

Design points:

- **Function-value dependency injection.** The helper takes `checks` as a
  `func()` value instead of importing `interfaces/sso` or `internal/handler`.
  This keeps the import graph unchanged (`interfaces/grpcserver` imports no
  Snaplink package above its own layer, no new edges, no cycle) and lets SDK
  consumers pass their own check source. cmd wires it as
  `a.server.BuildHandlerDeps().ReadyChecks`.
- **Standard components only.** Register the stock `health.Server` and
  `reflection.Register` — no hand-rolled health protocol. The stock
  `health.Server` already implements `Watch` streaming with per-service
  status transitions, which the acceptance test requires.
- **Per-service statuses from server state, not a parameter.** The poller
  derives the service list from `s.GetServiceInfo()` on every evaluation, so
  it needs no `services []string` argument and no registration-order
  constraint. `GetServiceInfo` is concurrency-safe by construction — grpc's
  own reflection service calls it while serving.
- **Call site.** `newGRPCServer` calls it last, after every
  `RegisterXxxServer` call, so the first evaluation already sees the full
  service set. SDK consumers embedding their own `grpc.Server` (the
  `aliases.go` public-contract audience) get identical behavior by calling
  the same helper.
- **Startup banner.** `logGRPCServices` (`cmd/sso-server/log_endpoints.go:88`)
  gains two lines listing `grpc.health.v1.Health` and
  `grpc.reflection.v1.ServerReflection`, so the enumerated banner matches
  what `grpcurl list` returns.

**Rejected alternative.** A custom `HealthServer` that evaluates checks
synchronously inside `Check` gives fresher answers but forfeits the stock
`Watch` transition semantics and forces us to reimplement the protocol —
rejected. Polling latency (≤5 s, Decision 2) is the standard trade of every
kubelet-style probe anyway.

---

## Decision 2: Health evaluation semantics — background poller

**What.** One goroutine per registered server, created by
`RegisterObservability`:

1. Run an immediate first evaluation at registration, then every
   `HealthPollInterval = 5 * time.Second` (const in `obs.go`).
2. Each evaluation is wrapped in `recover` (a panicking check must not kill
   the poller — net/http's per-request recovery gives `/readyz` the same
   survivability; the gRPC poller must match).
3. Run all checks under a single 3-second aggregate deadline, mirroring
   `handleReadyz` (`interfaces/sso/server_health.go:97`). A hung check
   cannot wedge the poller: deadline expiry counts as failure.
4. All checks pass → `SetServingStatus("", SERVING)` and every service name
   from `GetServiceInfo()` → `SERVING`; any failure or panic →
   `NOT_SERVING` for the same set, with a warn log naming the failing check.
5. `checks == nil`, or a nil map, or an empty map (no ready checks
   registered) → SERVING. This matches `/readyz` returning 200 with an empty
   check list and keeps SDK consumers who never wired `WithReadyCheck` on a
   healthy default.
6. `stop()` cancels the poller context and calls `health.Server.Shutdown()`,
   which flips every service to NOT_SERVING and ends all `Watch` streams —
   load balancers see draining before `GracefulStop` completes.

**Documented divergence.** `d.ReadyChecks` exposes only
`map[string]func(ctx) error`; the per-check timeouts from
`WithReadyCheckTimeout` (`interfaces/sso/options_misc.go:407`) are **not**
visible through the accessor. gRPC health therefore applies only the
aggregate 3-second bound. This is a contract note for
`docs/observability.md`, not a gap: `/readyz` keeps its richer per-check
timeout semantics; the gRPC signal is a coarse readiness boolean.

**State flapping.** Two consecutive evaluations may disagree (a store
recovering mid-probe), producing SERVING↔NOT_SERVING transitions on Watch.
This is correct behavior — `/readyz` flaps identically — and
`health.Server` serializes `SetServingStatus` internally, so no data race.

---

## Decision 3: Metric vectors and bounded-cardinality label schema

**What.** Two new vectors on `platform/metrics.Metrics`, registered in
`platform/metrics/metrics_ctor.go` beside `registerHTTPMetrics`, plus
interceptors in new file `interfaces/grpcserver/metrics.go` (7 → 8 non-test
files in the directory).

| Const | Value | Labels |
|---|---|---|
| `NameGRPCRequestsTotal` | `sso_grpc_requests_total` | `grpc_service`, `code_class` |
| `NameGRPCRequestDuration` | `sso_grpc_request_duration_seconds` | `grpc_service`, `code_class` |

- **`grpc_service`** = the `fullMethod` service prefix (everything before
  the last `/`). Cardinality control: the interceptor lazily memoizes the
  registered-service set from
  `info.Server.(*grpc.Server).GetServiceInfo()` (first RPC per server
  instance; registration is closed before `Serve`, so the memo is stable).
  A service in that set keeps its real name; anything else — including a
  failed type assertion on `info.Server` — collapses to `"other"`, mirroring
  `sanitizeMethod` (`platform/metrics/middleware.go`). Label cardinality ==
  registered service count + 1, an operator-controlled bounded set, not a
  per-method/per-user set.
- **`code_class`**, three fixed values mirroring the 5-class spirit of
  `statusClass`: `ok` (nil error), `client`, `server`. The mapping is a
  `const` table in `metrics.go` and is reproduced verbatim in
  `docs/observability.md`:
  - `client`: InvalidArgument, FailedPrecondition, OutOfRange,
    Unauthenticated, PermissionDenied, NotFound, AlreadyExists, Aborted,
    ResourceExhausted, Canceled, Unimplemented.
  - `server`: Internal, Unavailable, DataLoss, DeadlineExceeded, Unknown.
- **Probe exclusion.** `grpc.health.v1.Health` and
  `grpc.reflection.v1.ServerReflection` are a const denylist: their RPCs are
  counted by neither vector. Load-balancer probes fire every few seconds per
  replica and would otherwise dominate every dashboard. The denylist is
  fixed and documented — same bounded-set philosophy as `sanitizeMethod`.
- **Streams.** A stream interceptor records one count + duration at stream
  completion (status from the completed stream), so `Watch`-style long-lived
  streams are accounted once, not per message.
- **Nil-safe.** `m == nil` (metrics disabled) → interceptor is a passthrough.
  The interceptors are constructed in `grpcInterceptorOptions` from
  `a.metrics`, which the app already holds (`main.go:274`).
- **Registration.** `registerGRPCMetrics` is unconditional in the metrics
  ctor (like every other `register*Metrics` call): zero traffic when no
  gRPC interceptor is wired, identical to the opt-in pattern of the other
  vectors. The existing `/metrics` scrape (outside rate limiting,
  `docs/observability.md:99`) picks them up with no new endpoint.

**Rejected alternative.** Putting the interceptors in `platform/metrics`
would place gRPC surface code in the shared kernel, forcing
`platform/metrics` to know about grpc internals (`GetServiceInfo`). The
interceptor belongs with the gRPC surface (`interfaces/grpcserver`, next to
`recovery.go`); `platform/metrics` only owns the vectors and registration,
exactly the existing HTTP split (`middleware.go` vs `metrics_ctor.go`).

---

## Decision 4: Tracing and interceptor chain order — observability outermost

**What.** Add
`go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc
v0.68.0` — the same contrib release as the pinned `otelhttp v0.68.0`,
aligned with `otel v1.43.0`. Chain `otelgrpc.UnaryServerInterceptor` and
`StreamServerInterceptor` in `grpcInterceptorOptions`.

**New chain order** (outermost → innermost):

```text
metrics (obs) → otelgrpc → Recovery → adminMW → handler
```

- Observability sits **outside** Recovery so it observes the
  `codes.Internal` error Recovery synthesizes from a panic — the acceptance
  test's "panic still counted as server-class" requirement. This **amends
  the documented invariant** at `main_servers.go:188-192` ("Recovery must be
  outermost"): the comment is rewritten to state that the observability
  layer is the new outermost shell, that it is panic-safe (below), and that
  Recovery still protects everything beneath it. The panic test in
  Decision 8's list is the regression lock on this order.
- **Panic-safety of the observability layer.** Both new interceptors wrap
  their body in `defer/recover`: on panic they log via the optional logger,
  record the RPC as `code_class=server`, and return a bare
  `codes.Internal` status (same oracle-safe "internal error" wording as
  `recovery.go`). Because handler/adminMW panics are caught by Recovery
  beneath them, this defensive recover can only fire for a panic inside the
  observability layer itself; converting it to Internal keeps the process
  alive instead of crashing every in-flight RPC. The trade (a panic in our
  own interceptor no longer crashes the process) is deliberate and
  documented — Recovery has always been the crash boundary, the
  observability shell simply extends that boundary upward.
- **otelgrpc with noop provider.** `tracing.Init` installs a provider only
  when an exporter resolves (`platform/tracing/tracing.go:113-130`); with
  the global noop provider the interceptor's span work is a few no-op calls.
  With an exporter, `BatchSpanProcessor` drops spans when its bounded queue
  is full — it never blocks the RPC path. Both behaviors match the existing
  `otelhttp` precedent, so gRPC tracing is "always wired, cheap when off".
- **Span naming.** otelgrpc names spans by full method
  (`/snaplink.authz.v1.Authorizer/Check`). This is tracing, not metrics —
  unbounded span names are the standard OTel contract and are sampled, so
  the bounded-cardinality invariant is untouched.

---

## Decision 5: Transport hardening — TLS required by default, fail closed

**What.** New runtime-only flags (declared in `parseRuntimeFlags`,
`cmd/sso-server/main_wiring.go:45-59`, alongside the existing
`grpc-listen`/`tls-cert`/`tls-key`):

| Flag | Semantics |
|---|---|
| `-grpc-tls-cert` | gRPC TLS cert; falls back to `-tls-cert` when unset |
| `-grpc-tls-key` | gRPC TLS key; falls back to `-tls-key` when unset |
| `-grpc-insecure` | explicit opt-out: allow plaintext on any address |

They stay runtime-only flags, not Config keys: they are deployment-time
per-node material paths, exactly like the HTTP TLS pair and `-grpc-listen`
today. This keeps the docscheck config-keys gate (`docs/DECISIONS.md` M2)
green by construction (no new Config fields) while the flags are still
documented in `docs/config-reference.md` (Decision 8, contract updates).

**Decision matrix** — implemented as a pure function in
`cmd/sso-server` (unit-testable, called from `grpcServerOptions`, which is
cmd-internal and reused by `startGRPCServer` only; SDK consumers building
their own `grpc.Server` keep full control of their own creds):

| Cert+key | `-grpc-insecure` | Listen host | Result |
|---|---|---|---|
| both set | any | any | TLS, `MinVersion: tls.VersionTLS12` (existing wiring, `main_servers.go:179`) |
| one of pair | any | any | startup error (asymmetric material) |
| unset | unset | loopback (`127.0.0.1`, `::1`, `localhost`) | plaintext allowed, info log |
| unset | unset | anything else (incl. `:8081`, `0.0.0.0`, `[::]`) | **startup error** naming the missing material and the escape hatches |
| unset | set | any | plaintext allowed, warn log "operator opt-out" |
| set | set | any | startup error (mutually exclusive) |

- Loopback detection via `net.SplitHostPort` on the listen address; an empty
  host (`:8081`) is *not* loopback. `-grpc-listen ''` continues to disable
  the listener entirely (existing escape hatch, unchanged).
- `grpc.Creds` wiring stays inside `grpcServerOptions` (`main_servers.go:170-183`),
  so the shared `MinVersion: TLS1.2` floor and keepalive/limits assembly
  remain one code path.
- `startGRPCServer`'s `"grpc listening"` log line gains the transport mode:
  `tls` / `plaintext (loopback)` / `plaintext (operator opt-out)` — the
  plaintext exceptions are logged, deliberate states per the spec.
- **Default-behavior change.** A stock `sso-server` run (no flags,
  `-grpc-listen :8081`) now fails fast with a startup error instead of
  binding a public plaintext port. This is the point of the change; the
  error message lists the three resolutions (provide `-grpc-tls-cert/-key`
  or the shared pair, switch to loopback, or pass `-grpc-insecure`). No
  `test/` harness passes `-grpc-listen` (verified), so CI blast radius is
  limited to the new unit test; any e2e that spins the binary will be
  audited during implementation.

---

## Decision 6: Storage model

No new durable storage. The complete state inventory is in-memory and
bounded:

1. **`health.Server` status map** — `service → SERVING/NOT_SERVING`, mutated
   only by the single poller goroutine, read by `Check`/`Watch`. Bounded by
   registered service count (≤ the services this server registers). The
   gRPC health state is a *projection* of store health: the same check
   closures that feed `/readyz` (postgres/redis/etcd/classifier probes wired
   via `WithReadyCheck`, e.g. `build_app_core.go:470`) run under the poller.
   No new probing, no new dependencies on any store.
2. **Prometheus vectors** — counter + histogram with fixed label sets
   (Decision 3). Memory is bounded by (registered services + `"other"`) × 3
   code classes × fixed buckets; no per-entity growth.
3. **Memoized service allowlist** — one map per interceptor instance (per
   `grpc.Server`), captured at first RPC.
4. **otelgrpc spans** — buffered in the SDK `BatchSpanProcessor`; bounded
   queue, drops when full, never blocks RPCs.

Relationships: `platform/registry` (etcd) and the ext-authz data plane are
*consumers* of the port (health probes, `AuthzService.Check`), not producers
of any state this change adds. The only lifecycle coupling is the poller
goroutine, owned by `RegisterObservability`'s returned stop func and
therefore by the server's shutdown path.

---

## Decision 7: Failure modes

| Failure | Behavior | Design response |
|---|---|---|
| A ready check panics | Poller recovers per evaluation, marks NOT_SERVING, warn-logs the check name | matches `/readyz` survivability; check closures already return errors, panic is the pathological case |
| A ready check hangs | 3 s aggregate deadline aborts the evaluation → NOT_SERVING | mirrors `handleReadyz`; poller can never wedge |
| `checks` nil / empty map | SERVING | matches `/readyz` empty-check 200; SDK consumers without `WithReadyCheck` stay healthy |
| Watch transition storms (flapping dependency) | SERVING↔NOT_SERVING per poll interval | correct; `health.Server` serializes; bounded at 1 transition per 5 s per service |
| Panic in a handler/adminMW | Recovery → `codes.Internal` → observed as `code_class=server` by the outer layer | chain order (Decision 4); acceptance test locks it |
| Panic inside the observability layer itself | defensive recover → Internal + log, process survives | documented amendment of the Recovery-outermost invariant |
| OTLP exporter down | spans dropped at the bounded queue; RPC path unaffected | identical to existing `otelhttp` behavior |
| Metrics disabled (`a.metrics == nil`) | interceptors are passthroughs; vectors exist but never increment | mirrors every other opt-in vector |
| TLS cert/key load failure | startup error (`grpc tls: ...`) | pre-existing fatal path, now also reachable via the gRPC-specific flags |
| Cert expiry/rotation | certs loaded once at startup; rotation requires restart | pre-existing limitation, unchanged, noted as out of scope |
| Reflection on a plaintext port | schema enumeration possible by anyone reachable | TLS-by-default; plaintext only via loopback or explicit opt-out; reflection never invokes RPCs and admin methods still require bearer authz via `adminMW` |
| Poller leak on shutdown | stop func cancels poller + `health.Server.Shutdown()` (NOT_SERVING + Watch clients notified) | wired into the server shutdown path next to `GracefulStop` |

---

## Decision 8: What could break the design

1. **Chain-order invariant reversal.** The existing comment
   (`main_servers.go:188-192`) is a documented contract ("Recovery goes
   first... so it also protects the admin middleware"). Moving observability
   outside it reverses that contract for future editors. Mitigations: the
   comment is rewritten with the rationale, the observability layer is
   panic-safe by construction, and the panic acceptance test fails loudly if
   the order regresses (a panic must still be counted server-class, which
   only holds with obs outside Recovery). Residual risk: a reviewer "fixing"
   the order back. Locked by the test.
2. **otelgrpc is not in the module cache.** First build requires
   `go get go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc@v0.68.0`
   (network). Version alignment is exact (contrib v0.68.0 ↔ otel v1.43.0 ↔
   the pinned otelhttp). The `go.mod` diff must be minimal — the acceptance
   criterion is "only the otelgrpc addition". `make ci` re-validates go.sum
   and nested modules (sso-mcp/sso-operator don't import the root module, so
   they are unaffected).
3. **`GetServiceInfo` reliance.** If `info.Server` is not a `*grpc.Server`
   (hypothetical alternative implementation), the interceptor falls back to
   `"other"` — no crash, worst case is label collapse. Memoization is safe
   because grpc forbids registration after `Serve` starts, so the first-RPC
   snapshot is final.
4. **Stock-run breaking change.** `sso-server` with no flags now exits with
   a TLS error instead of serving plaintext on `:8081`. Operators upgrading
   in place hit a hard stop. Mitigations: the error names all three
   resolutions, `docs/feature-matrix.md` gains a transport row, and the
   change is deliberate (fail-closed is the requested posture). Verified:
   no test/example harness depends on default-flag plaintext gRPC.
5. **Health/reflection are unauthenticated.** Standard gRPC convention, but
   on a TLS-enabled non-loopback port they remain anonymous: anyone with
   port access can probe and enumerate. This is the accepted trade of every
   gRPC deployment; the data-plane and admin RPCs themselves still enforce
   bearer authz, and Decision 5 removes the sniffing/replay angle that
   motivated the requirement. Documented in `docs/observability.md`.
6. **Cardinality grows with registered services.** The `grpc_service` label
   set equals the registered service count (plus `"other"`), which SDK
   embedders control. Bounded by construction (registration closes before
   `Serve`), consistent with the bounded-cardinality invariant — but an SDK
   that registers 50 services creates 50 label values. Documented as the
   contract; the denylist keeps probe noise out.
7. **Per-check timeout divergence.** `WithReadyCheckTimeout` is invisible to
   the gRPC poller (accessor exposes closures only). If an operator relies
   on a per-check timeout to keep `/readyz` fast, the gRPC poller still
   applies only the 3 s aggregate bound — a check that takes 2.9 s per
   evaluation delays the gRPC verdict the same way it delays `/readyz`.
   Documented; not fixable without touching `interfaces/sso` (out of scope
   by requirement).
8. **Flag/Config asymmetry.** The new knobs are flags while the rest of the
   operator surface is Config-file driven. Chosen for consistency with the
   existing transport flags and because cert paths are per-node deployment
   facts; the config-reference section documents them so operators find
   them. The docscheck config-keys gate is unaffected (no new Config keys).
9. **`health.Server.Shutdown()` availability.** Present in grpc v1.80 (added
   v1.60) — confirmed in-module at implementation time via `go doc`; if
   absent, stop() degrades to cancel-the-poller only (statuses stay at last
   value), a cosmetic gap.

---

## Contract updates (same change) and verification plan

**Docs:** `docs/observability.md` — gRPC health section (endpoint,
SERVING/NOT_SERVING mapping, 5 s poll, 3 s aggregate bound, unauthenticated
note, per-check-timeout divergence), two `sso_grpc_*` metric rows with the
`code_class` mapping table, gRPC tracing paragraph. `docs/feature-matrix.md`
— rows for health+reflection, metrics+tracing, TLS-by-default transport.
`docs/config-reference.md` — gRPC transport flags subsection. No
`docs/openapi.yaml` change (gRPC services are proto-defined; reflection is
self-describing). No new `Err*` codes. No new Config keys → docscheck gate
unaffected.

**Tests (beside the code):**
- `interfaces/grpcserver/obs_test.go` — bufconn server + faked check map
  (pattern of `test/admin_grpc_base_test.go`): SERVING when all pass;
  NOT_SERVING after a check fails; back to SERVING on recovery; `Watch`
  streams the transition; `stop()` flips to NOT_SERVING.
- `interfaces/grpcserver/metrics_test.go` — prometheus test registry: ok
  and PermissionDenied RPCs increment `sso_grpc_requests_total` with correct
  `code_class`, duration histogram populated; synthetic panic → server-class
  (proves chain order); many distinct unregistered methods all collapse to
  `"other"`; health/reflection RPCs excluded.
- `cmd/sso-server` — table test over the Decision 5 matrix (pure decision
  function); one bufconn TLS test with `credentials.NewTLS` against a
  self-signed cert exercising the `MinVersion: TLS1.2` path; CLI-level
  startup-error check if the existing test harness supports exec of the
  binary, else the matrix test + manual verification.

**Gates (AGENTS.md §5):** `go build ./... && go vet ./...`;
`go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`;
`go test ./test/ -run TestE2E -v`; `make ci` (nested modules, examples,
config, module validation — including the otelgrpc go.sum addition and the
`grpcurl -plaintext localhost:8081 list` enumeration).
