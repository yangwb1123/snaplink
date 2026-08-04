# Design: `interfaces/cors` execution observability — one observer, one counter, one audit event, one contract row

Design counterpart to `docs/auto/interfaces-cors-observability-spec.md` (direction 三:
被拒 origin 无指标无审计). Covers the API surface, storage model, failure
modes, and breakage risks for the shared observer mechanism and the three
improvements. Every citation below was re-verified against current source
before writing; where the spec left an ambiguity (registration-line budget,
PathOverrides × login-gate disagreement, audit classification bucket, observer
wiring shape), this document pins the exact behavior.

Layer map used throughout:

```text
composition (cmd/sso-server)                        ← unchanged
  → interfaces/sso (server_routes.go, origin_validation.go, server_login.go)
      │                                              ← wires observer; drops duplicate login-gate log
      ▼
  → interfaces/cors (cors.go)                       ← BlockObserver option fires on reject branch
  → platform/metrics (metrics.go, metrics_ctor.go, cors.go)   ← sso_cors_blocked_total
  → platform/audit (recorder_events.go, auditspi, auditreport) ← cors_origin_blocked
```

Non-negotiable constraints re-verified against source:

- `interfaces/cors/cors.go` is 242/500 lines and `cors_test.go` 205 — the
  option + observer split fits in the existing files with headroom; no new
  directory, no budget crossing.
- `platform/metrics/metrics_ctor.go` is 497/500 lines: the `registerCORSBlockedMetrics`
  call is exactly one added line (→ 498); the register function body lives in a
  NEW `platform/metrics/cors.go`, following the `conditional_access.go`
  precedent (register function extracted, called from `NewMetrics` at
  `metrics_ctor.go:54`).
- `interfaces/sso` is at its 60-file ceiling: no new file there. The observer
  implementation is a method on `*Server` in the existing
  `origin_validation.go`; the wiring is two lines in the existing
  `server_routes.go` `wrapInnerMiddlewares` (`:452`).
- Every observe site is nil-safe (`s.metrics == nil` / `s.auditor == nil` →
  no-op), so a build without `WithMetrics` / `WithAuditRecorder` stays
  behaviorally identical, including the wire.
- Audit `Event` has no first-class `method`/`path`/`origin` fields — those
  travel in `Metadata` via `audit.SetMeta` (the only legal metadata channel,
  AGENTS.md §4). Indexed dimensions (type/outcome/tenant/client/provider)
  stay bounded; raw values are stored, never indexed.

## Shared mechanism (prerequisite): `BlockObserver` option on `cors.Middleware`

### Problem restated

The reject branch of `Middleware` (`cors.go:185-188`) is a silent
`next.ServeHTTP(w, r)`: no headers, no counter, no log. The only signal in the
tree is the login-gate log at `server_login.go:174`, which covers `/auth/login`
only. Because CORS sits innermost (`server_routes.go:441-443`, just outside the
router), a hook at the reject branch observes every path by construction —
closing the coverage gap without touching any handler.

### API surface

```go
// interfaces/cors — package stays dependency-free (no prometheus, no audit).
type BlockObserver interface {
    // OriginBlocked reports a request whose Origin was rejected by the
    // resolved CORS policy. Called exactly once per rejected request,
    // before next.ServeHTTP. Not called for absent-Origin requests
    // (same-origin browsers / native clients are legitimate) or when
    // CORS is disabled (empty AllowedOrigins + no PathOverrides).
    OriginBlocked(origin, method, path string, preflight bool)
}

func Middleware(p Policy, opts ...Option) func(http.Handler) http.Handler
```

- `Option` is a private concrete type; the only constructor is
  `WithBlockObserver(o BlockObserver)`. Variadic keeps the ~10 existing call
  sites (`cors_test.go`, `server_routes.go:452`, `test/cors_e2e_test.go`)
  source-compatible — zero churn outside the change.
- `Middleware` splits the reject branch: `origin == ""` → forward untouched
  (no observer call); disallowed origin → fire observer, then forward.
- The `PathOverrides`-resolved config (`resolveCORSConfig`) decides: an origin
  allowed only by a `/.well-known/*` override is NOT blocked and the observer
  is NOT fired — the observer reports the decision of the policy that actually
  ran, not the default policy.
- `*sso.Server` implements `BlockObserver` (`OriginBlocked` method in
  `origin_validation.go`, beside `isOriginAllowed`). Wiring at
  `server_routes.go:452`:

  ```go
  if s.corsPolicy != nil {
      inner = cors.Middleware(*s.corsPolicy, cors.WithBlockObserver(s))(inner)
  }
  ```

  Always passing `s` is safe: the method nil-checks `s.metrics` / `s.auditor`
  and `s.logger` is a `NopLogger` by default, so an unwired server pays one
  interface call + nil checks on the cold reject path only. The reject path is
  the coldest code in the server — no hot-path cost.

### Storage model

None. The observer is a synchronous callback into the already-wired
metrics/audit plumbing; it introduces no state, no queue, no dedup table. State
lives in the consumers (decisions 1–2).

### Failure modes

| Mode | Behavior |
|---|---|
| Observer method panics | Would propagate and take down the request (no recover in `Middleware` — consistent with `metrics.Middleware`, which also never recovers). Made unreachable by construction: nil-checks before any `Inc`/`Record`; `Recorder.Record` swallows sink errors internally (fail-open). |
| No observer wired | `nil` option → observer skipped; byte-identical to today, including the identity short-circuit for empty policies (checked BEFORE the observer could ever fire, `cors.go:173-176`). |
| CORS disabled (`AllowedOrigins` empty, no overrides) | Identity middleware returned before the handler closure exists; observer cannot fire. Matches spec: "not called when CORS is disabled". |
| No-Origin request | Bypasses the observer — same-origin browsers and native clients are legitimate and must not flood the counter. |
| Preflight flood | Rate limiting already wraps CORS (`server_routes.go` chain order), bounding volume upstream; the observer is the signal, not the defense (spec non-goal). |

### What could break this design

1. **A future `Option`-shaped conflict.** `Middleware` gains variadic options;
   if direction 二 later adds config-surface options, `Option` is the shared
   seam — keep it a private type with exported constructors so the set stays
   closed and the identity fast-path stays intact.
2. **Observer-before-identity bug.** The empty-policy identity short-circuit
   must stay ahead of any observer firing. If someone moves the observer call
   above it, disabled-CORS deployments would emit events. The unit test pins
   this: empty policy → zero calls.
3. **Interface drift between `cors.BlockObserver` and `sso.Server`.** Adding a
   second method to the interface later would break `*Server` at compile time
   — good. Keep the interface single-method; a richer payload is a new
   observer interface, not a widened one.

## Decision 1: `sso_cors_blocked_total` counter at the reject branch

### Problem restated

A disallowed cross-origin request is counted by `metrics.Middleware`
(`middleware.go:16`) only as `sso_http_requests_total{method,status_class}` —
indistinguishable from a legitimate same-origin hit; a disallowed preflight is
counted as a 2xx. No origin dimension exists anywhere in Prometheus, so
"CORS config typo" is invisible until a browser console shows it.

### API surface

- New field on `platform/metrics.Metrics` (beside `CIBAPingTotal`,
  `metrics.go:190-196`):

  ```go
  // CORSBlockedTotal counts requests whose Origin was rejected by the
  // resolved CORS policy (incl. PathOverrides), by reason and preflight.
  // A blocked request is still forwarded and counted by HTTPRequestsTotal —
  // this vector is the only origin-sensitive signal. Alert on a rate that
  // is not explainable by known SPA origins: either a config typo or a
  // cross-origin probe. Zero traffic when CORS is disabled or no observer
  // is wired.
  CORSBlockedTotal *prometheus.CounterVec // labels: reason, preflight
  ```

- New consts: `NameCORSBlockedTotal = "sso_cors_blocked_total"` in
  `platform/metrics/consts.go` (beside `NameCIBAPingTotal`, `:46`);
  `LabelPreflight = "preflight"`; bounded reason values
  `CORSBlockReasonDisallowedOrigin = "disallowed_origin"` (consts, like the
  closed `AdoptionReason*` set at `consts.go:142`).
- `registerCORSBlockedMetrics(factory, m)` in NEW `platform/metrics/cors.go`,
  called from `NewMetrics` (`metrics_ctor.go:54`-area) — the one-line
  `metrics_ctor.go` addition keeps that file at 498/500.
- Labels, with the analysis's raw `{origin,path}` sketch explicitly rejected:
  - `reason` = `disallowed_origin` (closed vocabulary; a future `null_origin`
    decision from direction 一 would add a const, keeping cardinality ≤ 2).
  - `preflight` = `"true"` | `"false"` (`strconv.FormatBool`, `middleware.go`
    precedent of collapsing unbounded input).
  - Max cardinality 2 — honors `observability.md:7` and the `sanitizeMethod`
    precedent. Raw origin/path go to audit metadata and the log only.
- Increment exactly once per rejected request from the observer, before
  forwarding: `vec.WithLabelValues(CORSBlockReasonDisallowedOrigin,
  strconv.FormatBool(preflight)).Inc()` — nil-guarded by `s.metrics == nil ||
  s.metrics.CORSBlockedTotal == nil`.

### Storage model

In-memory Prometheus CounterVec, scraped at `/metrics` (served by the probe
mux OUTSIDE the middleware chain, so scrapes never self-inflate — verified
comment in `middleware.go:8-12`). No persistence, no histogram, no state
across replicas. Counter reset semantics are the standard scrape-domain ones.

### Failure modes

| Mode | Behavior |
|---|---|
| No `WithMetrics` | `s.metrics == nil` → no increment, no panic, no series on `/metrics` (spec acceptance: server without `WithMetrics` shows no series). |
| Counter vector nil (partial ctor) | Second nil-guard; same no-op. |
| Scrape of an unregistered name | Registering via `promauto` in `NewMetrics` means the vector exists iff the registry exists — no partial-registration drift. |
| Blocked request also counted by `HTTPRequestsTotal` | Expected and documented in the Help text: chain order is preserved (CORS inside metrics), so the block counter is the origin dimension ON TOP of the generic count, never a replacement. The E2E test asserts both move together. |

### What could break this design

1. **Cardinality creep.** The `reason` label is only bounded if new values are
   compile-time consts. The guard is the const declaration + review; the
   `preflight` label is structurally bounded by `FormatBool`. Never pass raw
   origin/path/method to `WithLabelValues` — a code-review invariant stated
   in the Help text and enforced by the unit test's accepted label set.
2. **Double increment.** Two observer call sites (middleware + login gate)
   would break the "exactly once" invariant. Decision 2 removes the login
   gate's signal; the middleware is the single emission point. Unit test
   asserts exactly-one per rejected request.
3. **`metrics_ctor.go` line budget.** 497/500 today; the registration call is
   +1 (→ 498). Any unrelated growth in that file before this lands would push
   it over — the register-function-in-new-file split keeps the marginal cost
   at one line, and the new file absorbs all future CORS-metric growth.
4. **Name collision with a future CORS allow/deny metric from directions 一/二.**
   `sso_cors_blocked_total` is rejection-only; direction 一's hot-reload work
   would add its own `sso_cors_*` names. Registering both through
   `registerCORSBlockedMetrics`-style functions in `platform/metrics/cors.go`
   keeps the naming namespace reviewable in one file.

## Decision 2: `cors_origin_blocked` audit event, single emission point

### Problem restated

The CORS boundary is a security enforcement point with no audit trail. The
sole signal is `server_login.go:174`'s `logger.Info("origin_blocked", ...)`:
log-only, `corsPolicy != nil`-gated, `/auth/login`-only, no W3C trace
correlation, no pipeline. A rejected probe against `/token` or
`/.well-known/jwks.json` leaves nothing for SOC review, while the platform
norm pairs counters with events (`RecordCIBAPingFailed`,
`recorder_events.go:139`).

### API surface

- New event type in `platform/audit/auditspi/event_types.go` (beside
  `EventCIBAPingFailed`, `:207`) and re-exported in
  `platform/audit/aliases_spi.go` (beside `:104`):

  ```go
  EventCORSOriginBlocked EventType = "cors_origin_blocked"
  ```

- New recorder helper in `platform/audit/recorder_events.go`, mirroring
  `RecordCIBAPingFailed` (`:139-154`) — nil-recorder no-op, plain
  `context.Context` (the observer runs in the request path where the trace
  middleware has already stamped `core.WithTraceID`, so the W3C ID rides the
  context), fail-open:

  ```go
  func RecordCORSOriginBlocked(rec *Recorder, ctx context.Context,
      origin, method, path string, preflight bool) {
      if rec == nil { return }
      e := &Event{
          Type:    EventCORSOriginBlocked,
          Outcome: OutcomeFailure,
          Reason:  CORSBlockReasonDisallowedOrigin, // mirrors the metric label
      }
      SetMeta(e, "origin", origin)
      SetMeta(e, "method", method)
      SetMeta(e, "path", path)
      SetMeta(e, "preflight", strconv.FormatBool(preflight))
      rec.Record(ctx, e)
  }
  ```

  `Reason` carries the bounded vocabulary (same const as the metric label —
  single source of truth via a shared string); `origin`/`path` are raw values
  in `Metadata` only — legal because audit indexed dimensions
  (type/outcome/tenant/client/provider, `observability.md` "Bounded
  dimensions") remain bounded; the JSON blob is stored, never indexed.
- `*Server.OriginBlocked` (observer, `origin_validation.go`) emits: counter
  (decision 1), `RecordCORSOriginBlocked(s.auditor, ctx, ...)`, and one
  structured log line (`s.logger.Info("origin_blocked", origin, method, path,
  preflight, client_ip, user_agent, trace_id)` — trace_id from
  `core.TraceIDFromContext`, which `metrics.Middleware`-adjacent tracing has
  already set by the time CORS runs).
- `rejectDisallowedLoginOrigin` (`server_login.go:158-178`) keeps its 403
  `authzErrorBody` (RFC 9207 §2 `iss` — unchanged) and drops only its bare
  `logger.Info("origin_blocked", ...)` at `:174`. The middleware observer
  covers the same request. Invariant: **one rejected request ⇒ exactly one
  counter increment, one audit event, one log line**.
- Classification in `platform/audit/auditreport`: add `EventCORSOriginBlocked`
  to the **CC6.1 "Access control"** bucket (`control_areas.go:50-66`, beside
  `EventClientAccess` / `EventPermissionQuery`). Rationale: it is an
  access-control rejection at an enforcement boundary, emitted for every
  disallowed origin — including benign misconfig traffic, which is not
  "anomaly" in the CC7.2 sense. The alternative (CC7.2, with
  `EventFAPIComplianceViolation`) is defensible for the probing signal but
  would mis-bucket the dominant misconfig case; the drift test requires an
  explicit decision either way (`drift_test.go:41` `wantUncategorizedEventTypes`
  would fail loudly if omitted).

### Storage model

Standard audit pipeline: `Recorder.Record` → sinks (async queue → multi →
retry → leaf; `MemorySink` in tests, SQLite sink in production). The event is
a row value, not a schema change — no migration, no new table, no new facet.
The hash chain (`PrevHash`/`Hash`) and W3C TraceID/SpanID ride along
unchanged. Volume note: one row per rejected origin request; the async sink's
drop counters (`sso_audit_async_drops_*`) already bound the blast radius if
the queue backs up.

### Failure modes

| Mode | Behavior |
|---|---|
| Recorder nil / not wired | `RecordCORSOriginBlocked` no-ops (mirror of `RecordCIBAPingFailed`). |
| Sink error | `Recorder.Record` swallows and logs internally — fail-open per AGENTS.md §3; the 403/forwarding is never affected by audit health. |
| Async queue full | Drop counters increment (`sso_audit_async_drops_queue_full_total`); the counter from decision 1 still fires (it is synchronous, before forwarding) — so metrics and audit can diverge under sink pressure, which is the designed trade-off (metric = always, audit = best-effort). |
| No trace middleware | `TraceIDFromContext` returns empty; event carries empty TraceID — same as every other event on paths outside tracing (probes are outside the chain but also outside CORS). |
| Login gate 403 with policies disagreeing | See breakage risk 3 below — the 403 still happens (the enforcement), but the telemetry point is the middleware's decision. |

### What could break this design

1. **Double emission on `/auth/login`.** If the login gate kept its log (or a
   future maintainer re-adds one), the invariant breaks: two log lines for one
   rejection, and a drift-prone "which one is authoritative" question. The
   removal is part of this change; the E2E case (decision 3) asserts exactly
   one event for disallowed-origin `/auth/login`, pinning the invariant.
2. **Metadata channel violation.** `e.Metadata = map{...}` would clobber
   enrichment (documented hard constraint in `observability.md` "Hard
   Constraints") — the helper must use `SetMeta` exclusively, as written.
3. **PathOverrides × login-gate policy disagreement (pre-existing asymmetry,
   must not widen).** `isOriginAllowed` (`origin_validation.go:103`) checks
   only `AllowedOrigins`/wildcard; the middleware checks the
   `PathOverrides`-resolved policy. If an operator ever configures a
   `PathOverrides` entry on `/auth/login` allowing an origin that the default
   policy denies, the middleware passes (observer silent) and the login gate
   403s with no telemetry — silent enforcement. Today this combination is
   unsupported/undefined (the gate was written before overrides existed), and
   this change must not make it worse: the observer fires on the middleware's
   decision, the gate remains a defense-in-depth 403. Guard: document in the
   E2E test file that `/auth/login` PathOverrides is out of scope; the
   unification of origin resolution is direction 二 territory (explicitly a
   non-goal here).
4. **auditreport drift.** Forgetting the CC6.1 (or explicit-uncategorized)
   entry fails `drift_test.go` at compile-time-test level — the test naming
   the gap is the guardrail, not a review comment.
5. **Classification flip-flop.** CC6.1 vs CC7.2 is a judgment call; once
   chosen, `soc2.go` output changes if it flips later. Pin it in this doc and
   the control-area comment.

## Decision 3: observability contract + cross-server E2E coverage

### Problem restated

AGENTS.md §5.5/§5.6 require contracts and cross-server tests to move with the
change. Today `docs/observability.md` documents the middleware order (`:100`)
and the metrics table (`:13` onward) with no CORS rejection row, no
`cors_origin_blocked` in the audit section, and `test/cors_e2e_test.go` covers
only header behavior — no rejection telemetry, no login-gate interaction. The
counter and event from decisions 1–2 would silently drift out of the operator
surface without a contract row, and the "exactly once" invariant could regress
unnoticed without an E2E pin.

### API surface

No code beyond decisions 1–2. This decision is the contract + proof layer:

1. `docs/observability.md`:
   - Metrics table: `| sso_cors_blocked_total | Counter | reason (disallowed_origin), preflight (true\|false) |`
   - Audit section: `cors_origin_blocked` listed with its metadata contract
     (origin, method, path, preflight; bounded `Reason`; one per rejected
     request).
   - Middleware-order note (`:100`): one sentence — rejected-origin requests
     are counted, audited, and logged before forwarding.
2. New `test/cors_observability_test.go` (`package ssotest`), built on
   `minServer` (`test/ops_test.go:30`) extended with `WithCORS` +
   `WithMetrics(m)` + `WithAuditRecorder(audit.New(sink))` — the
   `ciba_ping_test.go:182-183` wiring pattern. Cases:
   1. Disallowed-origin GET on a public path → no `Access-Control-Allow-Origin`
      header; `CORSBlockedTotal{disallowed_origin,false}` == 1; exactly one
      `cors_origin_blocked` event; `sso_http_requests_total` also moved.
   2. Disallowed-origin `POST /auth/login` → 403 with `iss`; counter +1; ONE
      audit event total (proves no double count between middleware and login
      gate after the `server_login.go:174` log removal).
   3. Allowed origin → headers present; counter unchanged; zero events.
   4. Origin denied by default policy but allowed by a `/.well-known/*`
      `PathOverrides` entry → headers present; counter unchanged; zero events
      (ties to direction 一's override semantics: the observer reports the
      resolved policy's decision).
   5. Server without `WithMetrics`/`WithAuditRecorder` → blocked request
      succeeds-or-forwards with zero panic, zero series (nil-safety).

### Storage model

None new. The E2E reads the in-memory `*metrics.Metrics` registry and
`MemorySink` directly (not the `/metrics` scrape — the probe mux is outside
the chain and the scrape path would add indirection without testing anything
new).

### Failure modes

| Mode | Behavior |
|---|---|
| E2E asserts exact counter values on a shared registry | `minServer` per-test instance ⇒ no cross-test pollution; the registry is created per test (mirror `ciba_ping_test.go`). |
| Preflight counter asserted via `/metrics` scrape | Not done — scrape requires the promhttp probe wiring and would be a second test surface; registry reads are authoritative for increments. |
| Test flakiness from async audit sink | Use `audit.New(sink)` with the synchronous `MemorySink` (the `recCtx`/`only` helpers in `recorder_events_test.go` pattern) — no async queue in the E2E. |

### What could break this design

1. **Chain-order regression.** If CORS ever moves outside `metrics.Middleware`,
   blocked requests would stop being counted by `sso_http_requests_total`
   while still being counted by the block counter — the E2E case 1 assertion
   (both move together) catches this. The comment at `server_routes.go:441-443`
   documents the ordering; the test enforces it.
2. **Doc drift.** The contract rows are only alive if `make ci` / the docs
   checks actually grep them. The spec's acceptance check greps
   `sso_cors_blocked_total` and `cors_origin_blocked` in `observability.md` —
   fold that into the change's verification, not a one-off.
3. **`minServer` helper growth.** `minServer` gains options per test; the
   observability test should construct its own server with the full option set
   rather than overloading `minServer` (which serves ops tests) — keeps the
   two test families independent.
4. **Over-asserting internal wiring.** The E2E must assert observable
   behavior (headers, counter deltas, event counts, 403+`iss`), not
   implementation shape — e.g., not asserting which file wired the observer.
   The unit tests in `interfaces/cors` and `platform/audit` own the
   shape-level guarantees.

## Cross-decision integration notes

- **Single emission point, three outputs.** The observer is the only code that
  increments the counter, records the event, and logs — one reject branch,
  three sinks, all fail-open, all nil-safe. The login gate keeps its 403 and
  loses its log; probes/metrics/ratelimits are untouched.
- **Non-goals honored.** No allow/deny semantics change (direction 一), no
  config surface (direction 二), no raw-origin/path Prometheus labels, no new
  `Err*`/endpoint/config knob (`error-codes.md`/`openapi.yaml`/
  `config-reference.md` untouched), no audit throttling (rate limit already
  wraps CORS).
- **Gates.** After `.go` edits: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`; before handoff:
  `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`. The
  `interfaces/sso` 60-file ceiling and the `metrics_ctor.go` 500-line budget
  are the two budget tripwires this design was shaped around.
