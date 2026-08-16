# Design: unified observability for `interfaces/middleware` (access log + single trace/audit source)

Status: committed (implemented scope: Decision 1 AccessLogger + Decision 2 slot + BodyLogPolicy + the capture/redaction/sampling machinery the BodyLogPolicy contract requires, plus the Decision 9 config surface. Decision 7 `Correlation` and Decision 8 span-first `EventFromRequest` — the "unified OTel correlation" half — are NOT implemented yet: the legacy `Tracing`/`RequestID` middleware and the header-parse audit path remain installed, so `request_id`/`trace_id` in the access record are populated by that legacy surface exactly as the Decision 1 field table describes ("empty when no correlation middleware installed"). Drift rulings vs this document: `interfaces/middleware` is at its 10-file ceiling, so `accesslog.go` does not exist — `AccessLogger`/`BodyLogPolicy`/redaction live in the existing `request_log.go`; `WithRequestLogging` is repurposed to the policy signature and `WithAccessLogging` is added, per Decision 3/9; the DEBUG `RequestLogger` and its `debugRequestLogging` fields are deleted, per Decision 2/3). Scope: `interfaces/middleware`, `interfaces/sso` (assembly),
`cmd/sso-server`, `cmd/sso-minimal`, `config`, `platform/tracing`,
`platform/audit`. Direction 3 of the middleware observability requirements:
replace "DEBUG-gated request logging + two independent propagation chains"
with "always-on low-cardinality structured access log (credentials structurally
impossible to log) + one OTel correlation source feeding both span tree and
audit events".

The three improvements are ordered by dependency: 1 and 2 are the log side
(2 depends on 1's capture stack), 3 is the correlation side. Decisions below
follow the same order.

## Decision 1: AccessLogger — always-on INFO access log

**API surface** (new file `interfaces/middleware/accesslog.go`):

```go
// AccessLogger returns an http.Handler middleware that emits exactly one
// INFO record per request with a fixed, low-cardinality field set. It is
// the always-on access log; policy controls only the OPTIONAL body capture
// (zero value = never capture bodies).
func AccessLogger(l spi.Logger, policy BodyLogPolicy) func(http.Handler) http.Handler
```

Fields (fixed set, always emitted; empty string when the value is absent):

| Field | Source | Notes |
|---|---|---|
| `method` | `r.Method` | |
| `path` | `r.URL.Path` | never `RawQuery` — query strings can carry `code`/`token` |
| `status` | captured status code | default 200 when handler never calls `WriteHeader` |
| `duration_ms` | wall-clock ms since middleware entry | includes rate-limit wait, matches operator intuition for "slow request" |
| `client_ip` | `peertrust.ClientIP(r)` | new shared helper, see below |
| `request_id` | `r.Header.Get(core.HeaderRequestID)` | populated by the correlation middleware (Decision 7); empty when no correlation middleware installed |
| `trace_id` | `core.TraceIDFromContext(r.Context())` | same source; empty when no OTel provider is active |

Message: `"access"` at INFO level via `l.Info(...)`. No `query`, no `user_agent`
(that lives on audit events), no body fields unless the policy allows them
(Decision 3). Message/fields are a new output only: no response, header, or
audit behavior changes.

`client_ip` must come from `peertrust.RequestInfoFrom` (the canonical
proxy-boundary result) with the documented fallback precedence
(X-Forwarded-For first hop → X-Real-IP → RemoteAddr). Today that precedence
lives in `audit.ClientIP`. Extract it once into
`shared/security/peertrust` as `ClientIP(r *http.Request) string` (peertrust
is the shared kernel; it already owns the trust decision) and make
`audit.ClientIP` delegate to it — byte-identical behavior, one implementation.
The access log then automatically records the real client IP when
trustedProxies runs, and the legacy first-hop fallback when it does not.

**Probe exemption**: `/livez`, `/readyz`, `/metrics` are served by
`buildProbeMux` outside the whole chain, so they bypass the access logger
with zero code — the existing exemption applies unchanged (verified:
`server_routes.go:475-486` routes probes before `inner`). Acceptance check 2
falls out of the current mux shape; no new probe-path logic.

## Decision 2: middleware slot and wiring

`buildMiddlewareChain` (`server_routes.go:364`) installs the access logger in
a fixed slot: immediately inside trustedProxies, immediately outside
rate limiting:

```go
if s.trustedProxies != nil {
    inner = s.trustedProxies.Middleware(inner)
}
if s.accessLogPolicy != nil {                       // new field, nil = not installed
    inner = middleware.AccessLogger(s.logger, *s.accessLogPolicy)(inner)
}
if s.rateLimitPolicy != nil {
    inner = ratelimit.DynamicMiddleware(s.rateLimitStore)(inner)
}
```

Rationale for this exact slot:

- Inside trustedProxies → `client_ip` is the validated real IP, not a
  forgeable raw XFF value (same invariant rate limiting already relies on).
- Outside rate limiting → 429 rejections are logged with their status; an
  incident where a flood gets rate-limited still leaves access evidence.
  This mirrors how the metrics recorder sits outside the limiter so 4xx
  statuses are counted.
- Inside the tracing/correlation wrapper (outermost) → `trace_id` is already
  on the context when the access record is emitted.
- Probe mux exemption is automatic (Decision 1).

**SDK default is off; sso-server default is on.** `NewServer` keeps
`accessLogPolicy == nil` unless the operator calls the option — byte-identical
SDK behavior, consistent with the repo's "option absent ⇒ byte-identical"
discipline (e.g. `FeatureGates`). `cmd/sso-server` enables it by default via
config (Decision 9): `cfg.ServerOptions()` appends
`sso.WithAccessLogging(...)` unless `logging.access_log.enabled: false`.
Requirement "default config produces access logs" is satisfied at the binary
level without changing SDK assembly semantics.

The old DEBUG-level install point (`wrapInnerMiddlewares`'s
`if s.debugRequestLogging { middleware.RequestLogger(...) }`,
`server_routes.go:445-446`) and the `debugRequestLogging`/
`debugRequestLogBodies` fields are removed; `middleware.RequestLogger` is
deleted (Decision 3 subsumes it). Operators who need DEBUG verbosity still
have `logging.level: debug` for the whole process; the access log is no longer
behind that switch.

## Decision 3: BodyLogPolicy replaces the boolean

**API surface** (in `interfaces/middleware/accesslog.go`, re-exported by
`interfaces/sso` via the existing `aliases.go` pattern — same as
`var TracingMiddleware = middleware.Tracing` today):

```go
// BodyLogPolicy controls OPTIONAL request/response body capture inside
// AccessLogger. The zero value disables body capture entirely — the
// default, and the only shape that makes credentials structurally
// impossible to log. Capturing bodies is a deliberate per-deployment
// debugging posture, not a log-level.
type BodyLogPolicy struct {
    // Paths is the allowlist of exact paths whose bodies may be captured.
    // Empty means no path is eligible (default).
    Paths []string
    // AllowAllPaths bypasses the allowlist. Deprecated escape hatch;
    // reproduces the old logBodies=true semantics. Never combine with
    // a populated Paths.
    AllowAllPaths bool
    // SampleRate is the fraction (0.0–1.0) of eligible requests whose
    // bodies are captured. 0 (default) means bodies are never captured;
    // body capture only exists when an operator explicitly sets > 0.
    SampleRate float64
    // MaxBodyBytes caps each captured body field (request and response).
    // 0 selects the default of 4096.
    MaxBodyBytes int64
}

// EnabledFor reports whether bodies may be captured for this path.
func (p BodyLogPolicy) EnabledFor(path string) bool
```

**Option change** (`options_httpstack.go`):

```go
// Deprecated: use the body policy on the always-on access log. The old
// logBodies=true behavior is BodyLogPolicy{AllowAllPaths: true} — logging
// every body on every path is a credential-exposure posture, not a debug
// flag, and is documented as such.
func WithRequestLogging(policy middleware.BodyLogPolicy) Option
```

The boolean signature is replaced (Go has no overloading; the name is kept,
the parameter type changes). Safe: the only call sites in the repo are
`request_logging_test.go` (verified — no production caller). `WithRequestLogging`
sets `s.accessLogPolicy = &policy`; `middleware.RequestLogger` and the
DEBUG-level "log everything when investigating" middle path are deleted. The
debug-only request/response body logging that existed is now expressed as
`WithRequestLogging(BodyLogPolicy{Paths: [...], SampleRate: ...})` — same
capture stack, but gated by allowlist, redaction, sampling, and a size cap.

## Decision 4: redaction engine

Implemented entirely in `interfaces/middleware` — no handler cooperation.
A captured body is parsed by content type and rewritten before it enters the
log record:

- `application/x-www-form-urlencoded`: parse with `url.ParseQuery`, redact
  listed keys, re-encode.
- `application/json`: decode into `map[string]any`, walk recursively
  (objects nested at any depth, including inside arrays), redact matching
  keys, re-encode. Unknown keys survive.
- any other content type: the raw bytes pass through, capped at
  `MaxBodyBytes` — documented limitation (see Decision 11), and the reason
  the allowlist defaults to empty.

**Secret key vocabulary** — exact-name match, case-insensitive, on a const
list in `consts.go` beside the path constants (no literal leaks), derived
from `shared/core/consts.go`'s existing naming and the grant surfaces:

```go
var bodyLogSecretKeys = []string{
    "password", "new_password", "current_password",
    "client_secret", "secret", "api_key", "apikey",
    "code", "authorization_code", "device_code", "otp", "totp",
    "mfa_code", "verification_code", "backup_code", "recovery_code", "answer",
    "token", "access_token", "refresh_token", "id_token", "id_token_hint",
    "assertion", "credential",
}
```

Two extra rules, both biased toward over-redaction (leak is the failure
mode, not over-redaction):

1. Suffix/substring heuristic: any key containing `secret`, `password`,
   `token`, `assertion`, or `code` (case-insensitive) is redacted even if
   not in the exact list — so a future endpoint that names a field
   `my_mfa_code` cannot silently leak.
2. Replacement literal is exactly `[redacted]` (no length-preserving
   padding — padding is a side channel for short secrets like TOTP codes).

Nested JSON keys are matched at any depth, so `{"data":{"password":"x"}}`
redacts. If the body is malformed for its declared content type, the raw
(capped) bytes are logged rather than dropped — a debugging aid that cannot
widen the leak: the cap still applies and the allowlist still gates entry.

## Decision 5: sampling

`SampleRate > 0` makes body capture a per-request Bernoulli decision
(`rand.Float64() < p`) evaluated once, before body read, at the same point
`EnabledFor` is checked. Sampling applies to body capture only — the fixed
access-log fields are never sampled (they are the always-on guarantee).
Default `0` = capture never happens even on allowlisted paths; there is no
implicit sampling, so "explicit config only" holds.

Sampling is intentionally independent of OTel head sampling: a sampled-out
trace may still have an access record and vice versa. The join key is
`trace_id` on the log line; independence is acceptable because the access
log's purpose (incident evidence) is served by the fixed fields regardless.

## Decision 6: shared capture stack

One capture implementation, used only when `policy.EnabledFor(path)` AND the
sample decision passes:

- **Request body**: read at most `MaxBodyBytes+1` bytes via `io.LimitReader`.
  Restore the FULL original body for downstream handlers with
  `io.NopCloser(io.MultiReader(bytes.NewReader(read), r.Body))` — the
  unread remainder stays readable, so the body-limit middleware and handlers
  see a byte-identical body. This differs from today's `RequestLogger`
  (which reads all and restores only what it read — broken for any
  downstream reader that expects the remainder).
- **Response body**: a buffered writer that captures up to `MaxBodyBytes`
  and write-throughs beyond the cap (never buffers unboundedly; never holds
  the response hostage). Status is captured by the same writer.
- Capture buffers are per-request, freed on return; a capture is skipped
  entirely when the policy denies the path — the zero-value policy allocates
  nothing (no `bytes.Buffer`, no body read), preserving the "zero overhead
  when off" property the old option documented.

The old `requestLogResponseWriter` in `request_log.go` is replaced by this
stack; `request_log.go` is deleted. Requirement 1's "default record has no
request_body/response_body fields" and requirement 2's "allowlist-gated
capture" share this single code path — there is no second logger that could
drift into logging bodies unredacted.

## Decision 7: single correlation point — OTel becomes the only propagation source

**API surface** (new `interfaces/middleware/correlation.go`; imports
`platform/tracing`, `shared/core`, `go.opentelemetry.io/otel/trace` —
allowed direction: interfaces → platform → shared):

```go
// Correlation is the ONE middleware that ties a request to a trace and a
// request ID. It wraps tracing.Middleware (the otelhttp span) and, from the
// live span context, stamps:
//   - request context: core.WithTraceID (error bodies keep their trace_id)
//   - response headers: X-Trace-Id (trace ID) and X-Request-Id
//   - request header: X-Request-Id (preserve incoming, else generate 32-hex)
//
// It no longer parses or rewrites Traceparent, and it does not build its
// own trace context — the OTel span is the only source of truth.
func Correlation(operation string) func(http.Handler) http.Handler
```

Implementation shape: the inner handler of `tracing.Middleware(operation)`
runs while the span is live, so the wrapper's inner `http.HandlerFunc` reads
`trace.SpanContextFromContext(r.Context())` before calling `next`:

```go
return tracing.Middleware(operation)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    reqID := r.Header.Get(core.HeaderRequestID)
    if reqID == "" {
        reqID = newRequestID() // moved from middleware.go; unchanged generator
        r.Header.Set(core.HeaderRequestID, reqID)
    }
    w.Header().Set(core.HeaderRequestID, reqID)
    if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() && sc.HasTraceID() {
        *r = *r.WithContext(core.WithTraceID(r.Context(), sc.TraceID().String()))
        w.Header().Set(core.HeaderTraceID, sc.TraceID().String())
    }
    next.ServeHTTP(w, r)
}))
```

Contract notes:

- `Traceparent` response header: otelhttp injects it itself (its configured
  propagator writes the response header after the inner handler). The
  integration test (acceptance 3a) must assert the header survives; if a
  Go-version/otel upgrade ever stops injecting it, the wrapper sets it
  explicitly from `sc` — the observability.md contract is a regression
  boundary either way.
- `X-Trace-Id` is emitted only when the span context is valid — i.e. only
  when a real TracerProvider is active (`tracing.Init` with an endpoint).
  With the SDK's no-op provider the header is absent and audit trace IDs are
  empty. This is a deliberate semantic change from the legacy middleware
  (which minted its own traceparent even without OTel) — see Decision 12.
- `WithTracing(operation)` is now THE switch: one option decides span tree,
  audit correlation, `X-Trace-Id`/`Traceparent` response headers, and
  `trace_id` in error bodies. `buildMiddlewareChain` replaces
  `tracing.Middleware(s.tracingOperation)` with
  `middleware.Correlation(s.tracingOperation)` in the same outermost slot.

**Removal list** (the legacy surface):

| Location | Today | After |
|---|---|---|
| `interfaces/middleware/middleware.go` | `Tracing()`, `RequestID()`, package `tracer = audit.NewTracer()`, traceparent parse/format/rewrite | deleted; `newRequestID` moves to `correlation.go` |
| `interfaces/sso/aliases.go:46` | `var TracingMiddleware = middleware.Tracing` | deleted |
| `interfaces/sso/options_security.go:484-497` | `WithTracingMiddleware`, `WithRequestIDMiddleware` | deleted |
| `interfaces/sso/sso_wiring.go:52` | `requestIDMW bool` | deleted |
| `interfaces/sso/server_routes.go:113` | `s.router.Use(TracingMiddleware())` in `mountMiddleware` | deleted |
| `cmd/sso-server/build_app_core.go:157` | `sso.WithTracingMiddleware()` | deleted (the `WithTracing("sso-server")` line beside it stays) |
| `cmd/sso-minimal/app.go:102` | `sso.WithTracingMiddleware()` under `edition.tracingEnabled()` | replaced by `sso.WithTracing("sso-minimal")` — the edition flag now gates the single switch |
| `docs/examples/basic/main.go:80` | `sso.WithTracingMiddleware()` | replaced by `sso.WithTracing("basic")` |

`platform/tracing.Middleware` itself is unchanged (still the pure otelhttp
wrapper); `platform/tracing`'s `StartSpan`/`ParentFromIDs` seams are
untouched — they already key off `Event.TraceID`/`SpanID`, which now
provably match the request span, so the async sub-span parenting
(`audit.sink.deliver`, etc.) links into the right trace without further
changes.

## Decision 8: audit `EventFromRequest` — span first, header fallback

`platform/audit/handler_helpers.go` changes:

```go
func EventFromRequest(ctx core.HandlerContext) *Event {
    r := ctx.Request()
    e := &Event{
        RequestID:    r.Header.Get(core.HeaderRequestID),
        ActorIP:      ClientIP(r),  // now delegates to peertrust.ClientIP
        UserAgent:    r.Header.Get("User-Agent"),
    }
    // OTel span is the single source of truth for trace correlation.
    // Header parsing remains only as a fallback for callers outside the
    // middleware chain (embedded SDK users who propagate manually).
    if sc := trace.SpanFromContext(r.Context()).SpanContext(); sc.IsValid() && sc.HasTraceID() {
        e.TraceID = sc.TraceID().String()
        e.SpanID = sc.SpanID().String()
        if parent := trace.SpanFromContext(r.Context()).Parent(); parent.IsValid() {
            e.ParentSpanID = parent.SpanID().String()
        }
    } else if tp := r.Header.Get(core.HeaderTraceparent); tp != "" {
        if tc, err := tracer.ParseTraceparent(tp); err == nil {
            e.TraceID, e.SpanID = tc.TraceID, tc.SpanID
        }
    }
    // EnrichTenant / EnrichGeo / EnrichRegion unchanged.
    return e
}
```

- `ParentSpanID` moves from the legacy `X-Parent-Span-Id` header to the
  span's actual parent — audit events now describe the real span tree, not
  the legacy middleware's reconstruction.
- The audit `tracer` var and `NewTracer` stay for the fallback path only;
  `interfaces/middleware` no longer imports them.
- Unsampled spans still carry valid IDs (sampling affects export, not
  identity), so audit correlation does not silently vanish under
  `tracing.WithSampleRate(0.1)`. The no-op provider case (no `tracing.Init`
  endpoint) yields invalid span context → empty TraceID, same as a
  deployment with no tracing at all — the honest state.
- Requirement 3's "两个开关合一" lands here: legacy middleware installed
  without OTel (span-less audit trace) and OTel installed without legacy
  (audit-less spans) are both impossible after this change, because there is
  only one middleware and it is the span.

## Decision 9: config surface

`config/config_server.go` — extend `LoggingConfig`:

```yaml
logging:
  level: info
  access_log:
    enabled: true        # default: on for sso-server; false explicitly disables
    body:
      paths: []          # exact-path allowlist; empty = no bodies ever
      allow_all_paths: false   # deprecated escape hatch (old logBodies=true)
      sample_rate: 0     # 0 = off; body capture requires explicit config
      max_body_bytes: 4096
```

- `enabled` uses a `*bool` (nil = default true) so "absent" is
  distinguishable from "explicitly off" — the same tri-state pattern
  `FeatureGates` uses. `cfg.ServerOptions()` appends
  `sso.WithAccessLogging(policy)` unless explicitly disabled. When `enabled`
  is false the middleware is not installed at all: zero added overhead on the
  chain (requirement 3's acceptance check).
- Body keys map 1:1 onto `BodyLogPolicy`; `sample_rate: 0` and empty
  `paths` keep the default posture (no bodies) while `enabled: true` gives
  the fixed access fields.
- Not hot-reloadable: `logging.access_log.*` goes into the
  `ignored_requires_restart` bucket of the SIGHUP reload table (middleware
  slots are fixed at boot, same as rate limiting's enabled flag). Documented
  in `docs/config-reference.md` next to the reload table.
- `docs/config-reference.md` and `docs/observability.md` both gain the
  access-log contract (field table, defaults, probe exemption, the
  `WithRequestLogging` deprecation note). `docs/observability.md`'s stack
  diagram becomes a single propagation point: `correlation → metrics →
  trustedProxies → access-log → ratelimit → bodyLimit → ... → router`.

## Storage model

No new durable state is introduced. Three layers, in order of permanence:

1. **Access log records** (the new output): emitted through the existing
   `spi.Logger` (slog), which the operator routes to stdout/file/SIEM as
   today. The log record IS the storage; nothing is buffered in-process
   beyond the per-request capture buffers (Decision 6), which are freed when
   the middleware returns. There is no queue, no retry, no persistence —
   access logging is deliberately fail-open and lossy-by-design (a wedged
   sink drops lines, never requests).
2. **Audit events**: unchanged durable records (SQLite/Postgres/sinks).
   The only delta is the provenance of `TraceID`/`SpanID`/`ParentSpanID`
   (span context instead of headers), and `RequestID` provenance moves from
   the legacy middleware to the correlation wrapper — same wire values,
   same schema, zero migration.
3. **Trace spans**: unchanged OTLP export path. The correlation wrapper adds
   no new storage.

Sampling state is intentionally stateless: a per-request Bernoulli draw, no
shared counter, no coordination. (A coordinated sampler would add state for
no benefit — the goal is volume control, not exact-rate guarantees; the
acceptance CI bounds the rate statistically over 1000 requests.)

## Failure modes

| Failure | Behavior | Why it is safe |
|---|---|---|
| Log sink wedged / slow | Access log lines drop; request path unaffected | `spi.Logger` is fire-and-forget; AGENTS.md "fail open with audit/logging" applies — logging failure must never degrade auth |
| Body capture panics (malformed content type, bad JSON) | Catch via the existing `Recover` middleware if it escapes; capture code prefers error → log capped raw bytes | Never fail the request for a log; capture is best-effort by construction |
| `io.ReadAll`-style body consumption | Impossible: LimitReader + MultiReader restore keeps the remainder readable; bodyLimit middleware downstream still sees the true body | Restore-before-forward is tested (a handler that reads the body twice gets identical bytes) |
| Operator allowlists a sensitive path with `allow_all_paths` | Credentials can be logged if a field name is not in the redaction vocabulary | Default is off; over-redaction heuristic (Decision 4); documented as explicit risk acceptance; audit events remain the credential-safe record |
| `logging.access_log.enabled: false` | No access records | Explicit operator choice; probes and audit still work |
| No OTLP endpoint configured | No spans, no `X-Trace-Id`, empty audit TraceID — but X-Request-Id and audit RequestID still work | The honest "no tracing" state (Decision 12) |
| Sample decision disagrees with OTel sampling | A request may have a span but no body log | Independent by design; `trace_id` joins them when both exist |
| High request rate | One INFO line per request into the operator's pipeline | Fixed 7-field schema, no query, no bodies by default, probes exempt; this is the point of the change (evidence during incidents) |
| Audit sink outage | Audit fail-open path unchanged (async wrap, error handler logs) | Existing invariant; correlation fields are just strings on the event |

## What could break the design

1. **The `X-Trace-Id`/error-body `trace_id` contract for OTel-less
   deployments.** Today the legacy middleware stamps `X-Trace-Id` and audit
   TraceID even when no OTLP exporter is configured. After the merge, a
   default `sso-server` without `OTEL_EXPORTER_OTLP_ENDPOINT` stops emitting
   those values (no-op provider → invalid span context). This is the
   requirement's intended "one switch" semantics, but it is a wire-visible
   behavior change for operators who never configured OTel. Mitigations:
   (a) boot-time warning in `cmd/sso-server` when `WithTracing` is active
   but the global provider is the no-op default ("tracing configured but no
   OTLP endpoint — X-Trace-Id and audit trace_id will be empty");
   (b) `docs/observability.md` states the new dependency explicitly;
   (c) `X-Request-Id`/audit `RequestID` keep working in all shapes.
   The regression boundary tests in `interfaces/sso` (`health_test.go`
   asserts `trace_id` in error bodies after tracing middleware runs) must
   run with a real (in-memory-exporter) provider, not the no-op default.

2. **otelhttp response-header injection.** The `Traceparent` response
   header currently comes from the legacy middleware; after the change it
   must come from otelhttp's own propagator injection. If a future otel
   upgrade stops injecting, the observability.md contract breaks silently.
   Guard: integration test asserts `Traceparent` + `X-Trace-Id` + `X-Request-Id`
   on one response; the wrapper sets `Traceparent` explicitly as a fallback
   only if the test proves otelhttp does not (prefer relying on otelhttp).

3. **`EventFromRequest` span-first precedence.** Handlers that construct
   `EventFromRequest` from a context that has a stale/dead span would get
   that span's IDs instead of the request's. In practice the request context
   is live during handlers; the fallback covers the no-span case. The unit
   test (acceptance 3b) must cover both: span present → span wins even with
   hostile headers; span absent → header parse.

4. **X-Request-Id provenance moves.** The correlation wrapper preserves an
   incoming `X-Request-Id` and generates one otherwise — same as legacy. But
   if the correlation middleware is not installed (no `WithTracing`), access
   log `request_id` and audit `RequestID` are empty. That is the correct
   one-switch semantics, but `request_logging_test` acceptance 1 asserts
   `request_id` on a full chain — the test server must install
   `WithTracing` (with an in-memory provider), matching the sso-server
   default shape.

5. **Redaction vocabulary drift.** A new grant/endpoint that introduces a
   credential field whose name contains none of the heuristic substrings
   (`secret|password|token|assertion|code`) could leak when an operator
   allowlists its path. The substring heuristic bounds this; the default
   empty allowlist makes the exposure require two explicit misconfigurations.
   Review gate: any new body-bearing endpoint in `interfaces/sso` adds its
   credential field names to `bodyLogSecretKeys` in the same change (mirror
   of the AGENTS.md "update contracts in the same change" rule).

6. **Capture-stack interaction with the body-limit middleware.** AccessLogger
   sits OUTSIDE bodyLimit; its LimitReader read of up to `MaxBodyBytes+1`
   runs before bodyLimit's own read. The MultiReader restore keeps bytes
   identical, so bodyLimit still enforces its cap correctly. The regression
   test must include a request whose body exceeds both caps (oversized body →
   bodyLimit 413, access log status 413, captured body truncated at
   `MaxBodyBytes`).

7. **`WithRequestLogging` signature change is source-breaking for SDK
   embedders.** No in-repo production callers, but external SDK users passing
   a bool stop compiling. Accepted per the requirement ("旧签名经
   `BodyLogPolicy{AllowAllPaths: true}` 兼容但标记 deprecated"); the option
   doc and changelog must call it out. `middleware.RequestLogger` deletion
   has the same note.

8. **Metrics/cardinality drift.** The access log's `path` is per-endpoint
   cardinality by nature — but it is a log record, not a metric; the metrics
   middleware is untouched and remains bounded-cardinality. No interaction.

9. **`feature_gate_hotreload_test.go` regression.** It asserts the
   `Use()`-registered middleware stamps `X-Request-Id`/`Traceparent`/
   `X-Trace-Id` before admin routes mount. The correlation middleware moves
   from `router.Use` to the outer chain (Decision 7 removal list) — the test
   must be updated to assert the same headers via the outer chain, proving
   the contract survives the move.

## Test plan (maps 1:1 to acceptance checks)

- **A1 (access log record):** `interfaces/middleware/accesslog_test.go` —
  full chain including trustedProxies + correlation: exactly one INFO
  `"access"` record with `status`, `duration_ms`, `client_ip` (validated
  real IP under XFF spoofing), `request_id`; zero-value policy ⇒ no
  `request_body`/`response_body` keys in the record.
- **A2 (probe exemption):** `interfaces/sso` server with default options +
  access log: `/token` produces a record; `/livez`, `/readyz`, `/metrics`
  produce none. Plus `enabled: false` ⇒ middleware not installed (chain
  identity check).
- **B1 (redaction):** table-driven — `password=topsecret` form body,
  `client_secret=xxx`, JSON `{"code":"123456"}`, nested JSON; log line
  contains only `[redacted]`; grep the entire record for the raw values
  (including the `[redacted]`-adjacent key) ⇒ absent.
- **B2 (allowlist + cap):** `/token` never logs bodies even with
  `AllowAllPaths: true`... (no — `/token` is only exempt when not
  allowlisted; the test asserts non-allowlisted path ⇒ no body fields,
  allowlisted path ⇒ body truncated at 4 KB).
- **B3 (sampling):** `SampleRate: 0.25` over 1000 requests ⇒ capture count
  inside the 99.9% binomial CI (≈ 250 ± 45).
- **A3 (single source):** `test/` `package ssotest` — server with only
  `WithTracing` + in-memory span exporter: (a) audit event `TraceID` ==
  request span trace ID; (b) `X-Trace-Id` response header and error-body
  `trace_id` from a failed request match. Unit test in `platform/audit`:
  `EventFromRequest` with zero headers but a live span context fills
  `TraceID`/`SpanID`/`ParentSpanID`.
- **Regression:** existing `interfaces/sso` tracing/health tests re-run with
  an in-memory exporter; `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  `make ci`.

## Migration steps (ordered)

1. Extract `peertrust.ClientIP`; `audit.ClientIP` delegates (no behavior
   change, existing tests green).
2. Add `BodyLogPolicy` + `AccessLogger` + capture stack to
   `interfaces/middleware`; delete `request_log.go`; rewrite
   `request_logging_test.go` for the policy shape.
3. Wire the slot in `buildMiddlewareChain`; add `WithAccessLogging` option +
   `accessLogPolicy` field; repurpose `WithRequestLogging(policy)`.
4. Add `Correlation` to `interfaces/middleware`; switch
   `buildMiddlewareChain` to it; delete the legacy `Tracing`/`RequestID`
   surface and its call sites (Decision 7 removal list).
5. Change `EventFromRequest` to span-first; update `handlers.go` comment.
6. Config: `logging.access_log.*`, defaulting, `ServerOptions` wiring,
   reload table entry; update `docs/config-reference.md` +
   `docs/observability.md` (stack diagram, field table, deprecation notes).
7. Full gate: `go build ./... && go vet ./...`,
   `go test -run 'TestMaintainability_|TestArchitecture_' .`, then
   `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.
