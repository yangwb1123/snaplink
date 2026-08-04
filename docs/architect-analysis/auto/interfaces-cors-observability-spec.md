# Requirements Spec: interfaces/cors — CORS execution observability

Source: `docs/auto/interfaces-cors-analysis.md`, direction 三 (被拒 origin 无指标无审计，跨域探测信号完全不可见).

Scope: `interfaces/cors` middleware execution boundary plus its two consumers
(`interfaces/sso` wiring, `platform/metrics`, `platform/audit`). Exactly three
improvements; each is independently shippable, all three share one hook
mechanism.

## Shared mechanism (prerequisite for all three decisions)

`cors.Middleware(p Policy)` gains a variadic option so the package stays
dependency-free and zero-overhead when unconfigured:

```go
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

The reject branch in `Middleware` (today a single silent `next.ServeHTTP(w, r)`)
splits into: no Origin → pass through untouched; disallowed Origin → fire
observer, then pass through. `interfaces/sso` wires one observer (holding
metrics + auditor + logger) at `server_routes.go:451-452` where
`cors.Middleware(*s.corsPolicy)` is mounted today. `nil` observer / no option
preserves current behavior exactly (identity for empty policies is unchanged).

Because CORS sits innermost in the chain (`server_routes.go:441-443`, CORS just
outside the router), the observer sees every path — closing the current gap
where only `/auth/login` produces any signal.

## 1. `sso_cors_blocked_total` counter at the reject branch

**Name**: Blocked-origin request counter (per-reason, per-preflight).

**Problem**: A disallowed cross-origin request is completely invisible in
Prometheus. `cors.Middleware`'s reject path writes no headers and forwards
silently (`next.ServeHTTP(w, r)` with zero counters, zero logs), so the request
is counted only by `metrics.Middleware` as an ordinary
`sso_http_requests_total{method,status_class}` — indistinguishable from a
legitimate same-origin hit. A disallowed preflight gets a 204 counted as 2xx
with no origin dimension. Operators cannot tell "CORS config typo (missing
staging domain)" from "cross-origin probe / CSRF attempt" without packet
capture. The only existing signal, `origin_blocked` in
`server_login.go:174`, is a log line that never bumps a metric and covers only
`/auth/login` when `corsPolicy != nil`.

**Evidence**:
- `interfaces/cors/cors.go` `Middleware()` — reject branch (`if origin == "" || !cfg.originAllowed(origin) { next.ServeHTTP(w, r); return }`): silent, no counters.
- `platform/metrics/middleware.go:16` `Middleware` — counts every request by `method, status_class` only; no origin dimension.
- Precedent: `platform/metrics/metrics_ctor.go:316` registers `CIBAPingTotal` (`NameCIBAPingTotal` in `platform/metrics/consts.go:46`); `docs/observability.md:32` documents `sso_ciba_ping_total` in the metrics table.
- Cardinality guardrail: `docs/observability.md:7` — "All metrics use bounded cardinality — no per-path/per-user labels"; `platform/metrics/middleware.go:29` `sanitizeMethod` collapses unbounded input onto a bounded set.

**Proposed behavior**:
- Add `CORSBlockedTotal *prometheus.CounterVec` to `platform/metrics.Metrics` (`metrics.go`, beside `CIBAPingTotal` at line 191), registered in `metrics_ctor.go` with `Name: "sso_cors_blocked_total"` and labels `reason` + `preflight`.
- Bounded label values: `reason` = `disallowed_origin` (extensible vocabulary, e.g. a future `null_origin` decision from direction 一); `preflight` = `true`|`false`. Max cardinality 2.
- Explicitly reject the analysis's raw `{origin,path}` label sketch: origin and path are attacker-controlled strings; per the `sanitizeMethod` precedent and the observability.md:7 invariant, they never become Prometheus labels. Raw values travel in the audit event and log only.
- Increment exactly once per rejected request, from the observer, before forwarding. No-Origin requests, allowed origins, and disabled CORS never increment. Zero traffic when `WithMetrics` is not wired (nil-safe, mirroring `metrics.Middleware(nil)` identity).
- Document the row in `docs/observability.md` metrics table.

**Acceptance check**:
- `interfaces/cors/cors_test.go`: with an observer wired, a disallowed-origin GET and a disallowed-origin preflight each fire the observer exactly once with the correct `preflight` flag; allowed-origin, no-Origin, and empty-policy requests fire zero times.
- sso-level test: blocked request increments `CORSBlockedTotal{reason="disallowed_origin", preflight="false"}` by 1; `sso_http_requests_total` also counts it (chain order preserved, CORS still inside metrics).
- `/metrics` scrape (server with `WithMetrics`) shows the series; a server without `WithMetrics` shows no series and no panic.

## 2. `cors_origin_blocked` audit event, single emission point

**Name**: Audit event + structured log for every rejected origin, unified across both enforcement points.

**Problem**: The CORS boundary — a security enforcement point — produces no
audit trail. The sole signal is `rejectDisallowedLoginOrigin`'s
`logger.Info("origin_blocked", ...)` in `interfaces/sso/server_login.go:174`,
which is (a) log-only, (b) gated on `corsPolicy != nil`, (c) reachable only for
`/auth/login`, and (d) not correlated with W3C trace IDs or the audit pipeline.
A rejected-origin probe against `/token`, `/.well-known/jwks.json`, or any
other path leaves nothing for SOC review. The platform norm is the opposite:
`deliverCIBAPing` pairs a counter with a `ciba_ping_failed` audit event
(`platform/audit/recorder_events.go:139` `RecordCIBAPingFailed`,
`auditspi/event_types.go:207`), and `docs/observability.md:100` documents CORS
as part of the middleware chain — a security decision point with zero
evidentiary output is the exception, not the baseline.

**Evidence**:
- `interfaces/sso/server_login.go:174` — `s.logger.Info("origin_blocked", ...)` is the only origin-block signal in the tree (grep `origin_blocked` matches this line and tests only); no metric, no audit event, no trace correlation.
- `platform/audit/recorder_events.go:139` — `RecordCIBAPingFailed` pattern: nil-recorder no-op, `audit.SetMeta` metadata, context-carried W3C trace ID, fail-open (recorder errors never fail the request).
- `platform/audit/auditspi/event_types.go:207` + `aliases_spi.go:104` — event type definition + re-export convention; `platform/audit/auditreport/drift_test.go:41` — every new event type must be classified (SOC2 area or explicit uncategorized) or the drift test fails.
- AGENTS.md §4 — "Audit metadata is added only through `audit.SetMeta`; new event types must be classified in `auditreport`".

**Proposed behavior**:
- New event type `cors_origin_blocked` (`auditspi/event_types.go`, re-exported in `aliases_spi.go`) with metadata `origin`, `method`, `path`, `preflight` set via `audit.SetMeta`; emitted by `RecordCORSOriginBlocked(rec, ctx, origin, method, path, preflight bool)` in `recorder_events.go`, mirroring `RecordCIBAPingFailed` (nil-recorder no-op; background-context helper for detached paths; trace ID from context).
- Classify the type in `auditreport` (SOC2 control area, or explicit uncategorized entry with rationale) so `drift_test.go` stays green.
- sso wires the observer to emit the audit event and the structured log (same fields, plus `client_ip`/`user_agent` on the log) for every rejected origin on every path. Fail-open: sink errors log, never affect the response.
- `rejectDisallowedLoginOrigin` (`server_login.go:158-178`) drops its bare `logger.Info("origin_blocked", ...)` — the middleware observer now covers the same request — keeping the 403 `authzErrorBody` (`iss` per RFC 9207 §2) unchanged. This establishes the invariant: **one rejected request ⇒ exactly one counter increment, one audit event, one log line**, regardless of which enforcement point observes it.

**Acceptance check**:
- `platform/audit/recorder_events_test.go` additions mirroring `TestRecordCIBAPingFailed_BackgroundContext` (line 154): event type, metadata fields, nil-recorder no-op, trace-ID preservation.
- `interfaces/sso/origin_validation_test.go` / login-gate test: disallowed-origin `POST /auth/login` → 403 with `iss`, exactly one `cors_origin_blocked` event; allowed origin → zero events; `corsPolicy == nil` → zero events.
- `platform/audit/auditreport/drift_test.go` updated: new type classified (not silently dropped into an unclassified bucket).
- `go test ./... -race` green.

## 3. Observability contract + cross-server integration coverage

**Name**: Contract documentation and end-to-end proof that both enforcement points emit the same signal.

**Problem**: AGENTS.md §5.6 requires contracts to move with the change, and
§5.5 requires cross-server integration to live in `test/` (`package ssotest`).
Neither exists for CORS observability today: `docs/observability.md` documents
the middleware order (`:100` `tracing → ratelimit → bodyLimit → metrics → CORS
→ router`) and the metrics table (`:32`) but nothing says rejections are
counted or audited; there is no `test/` case covering a rejected origin on any
route (the analysis's secondary note confirms the gap: cors unit tests cover
wildcards/credentials/preflight/path dispatch, but no integration test
exercises the CORS boundary together with the login CSRF gate). Without a
contract row, the counter/event added by decisions 1–2 will silently drift out
of the operator surface; without the E2E case, the "exactly once" invariant
could regress unnoticed.

**Evidence**:
- `docs/observability.md:100` — middleware order lists CORS but has no statement about rejection telemetry; metrics table (`:32` onward) has no CORS row; audit section lists event types with no `cors_origin_blocked`.
- `interfaces/cors/cors_test.go` — unit coverage exists for behavior but nothing exercises `PathOverrides` × login gate jointly (direction 一's secondary observation).
- `test/` directory (`package ssotest`, e.g. `account_lockout_test.go`) — established home for cross-server integration; AGENTS.md §5.5.
- AGENTS.md §5.6 — "Update contracts in the same change" (metric → `docs/observability.md`; audit event type → auditreport; no new `Err*`/endpoint/config, so `error-codes.md`/`openapi.yaml`/`config-reference.md` are untouched).

**Proposed behavior**:
- `docs/observability.md`: add `sso_cors_blocked_total | Counter | reason (disallowed_origin), preflight (true\|false)` to the metrics table; add `cors_origin_blocked` to the audit section; extend the middleware-order note (line 100) with one sentence: rejected-origin requests are counted, audited, and logged before forwarding.
- New `test/` E2E case (package `ssotest`) against a server wired with `WithCORS` + `WithMetrics` + auditor:
  1. disallowed-origin GET on a public path → no `Access-Control-Allow-Origin` header, counter +1, one audit event;
  2. disallowed-origin `POST /auth/login` → 403 with `iss`, counter +1, one audit event (proves no double count between middleware and login gate);
  3. allowed origin → headers present, counter unchanged, zero audit events;
  4. origin disallowed by default policy but allowed by a `/.well-known/*` `PathOverrides` entry → headers present, counter unchanged (ties decision 3 to direction 一's override semantics).
- No code changes beyond decisions 1–2; this decision is the contract + proof layer.

**Acceptance check**:
- `grep sso_cors_blocked_total docs/observability.md` and `grep cors_origin_blocked docs/observability.md` hit (contract rows present).
- New E2E case passes under `go test ./test/ -run TestE2E -v`; `go test ./... -race` and `make ci` green.
- `python cli.py` maintainability/architecture checks: no new package, no budget crossing (`interfaces/cors` stays < 500 lines, no new directory), `interfaces/sso` file count unchanged (observability wiring lives in existing files).

## Non-goals

- No change to allow/deny semantics (direction 一: hot reload + single origin
  truth source; direction 二: config surface) — out of scope here.
- No raw-origin/path Prometheus labels (bounded-cardinality invariant).
- No new `Err*`, endpoint, or config knob — no `openapi.yaml`/`config-reference.md`/`error-codes.md` changes.
- No audit throttling/dedup logic: rate limiting already wraps CORS
  (`server_routes.go` chain), so preflight floods are bounded upstream; the
  counter/event are the signal, not the defense.
