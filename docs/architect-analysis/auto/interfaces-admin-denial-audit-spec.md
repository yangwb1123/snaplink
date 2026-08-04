# Requirements specification — interfaces/admin, expansion direction 3: denial-path audit blind spots

**Source analysis:** `docs/auto/interfaces-admin-analysis.md` direction 3 ("管理面拒绝路径审计盲区：被拦截的访问不进审计").
**Module:** `interfaces/admin` (admin bearer gate: `middleware.go`, `governance.go`; audit taxonomy: `platform/audit/auditspi`, `platform/audit/auditreport`, `platform/audit/auditsink`).
**Contract discipline (AGENTS.md):** new event types must be classified in `auditreport`; audit metadata added only through `audit.SetMeta`; audit sink failures and recording must stay fail-open; W3C trace IDs preserved; `interfaces/admin` is at its 10 non-test files/directory ceiling and `governance.go` (483/500 lines) and `middleware.go` (492/500) are near their file budgets — all work lands inside existing files with a single compact helper, no new non-test file.

The management plane promises complete auditing (W3C trace IDs, event classification, realtime SSE stream), but every "request blocked" path on the HTTP side returns a silent error response. The gRPC side already records denials (`EventAdminGRPCCalled` + `OutcomeFailure`); the HTTP side records none. The following three decisions close that gap.

## Decision 1: Emit denial events from the four transport governance gates

**Name:** Governance-gate denial events (IP allowlist, admin-wide rate limit, destructive confirm, write quota).

**Problem:** `checkIPPolicy` (`interfaces/admin/governance.go:364`, 403 `admin_ip_denied`), `checkRateLimit` (`governance.go:306`, 429 `rate_limit_exceeded`), `checkDestructiveConfirm` (`governance.go:381`, 409 `destructive_confirmation_required`), and `checkWriteQuota` (`governance.go:408`, 429 `admin_write_quota_exceeded`) all end in `http.Error(...)` + `return false` with zero audit calls. The taxonomy is already half-built and dead: `EventAdminWriteQuotaExceeded` / `EventAdminIPDenied` are declared (`platform/audit/auditspi/event_types_admin.go:131-132`), aliased (`platform/audit/aliases_spi.go:50-51`), classified under the admin CC6 control area (`platform/audit/auditreport/control_areas.go:139-140`), and registered (`platform/audit/auditspi/event_types.go:305`) — but `grep` finds no production emitter anywhere in the tree. Meanwhile the gRPC interceptor records denials (`interfaces/admin/middleware.go:255-262`): `EventAdminGRPCCalled` + `OutcomeFailure` + reason `"<method>: denied"`. SOC therefore sees quota/allowlist/confirm rejections and admin brute-force probes only as absent events.

**Proposed behavior:**
- Consume the already-wired `Middleware.recorder` field (`SetAuditRecorder`, `middleware.go:141`) — today consumed only by the gRPC interceptor — in the HTTP gate path by converting the four free functions to `Middleware` methods (or threading `recorder *audit.Recorder` through them).
- On each denial, record via one compact helper (e.g. `recordAdminDenial(recorder, ctx, evtType, ip, reason, meta...)`) with: `Outcome: audit.OutcomeFailure`; `ActorIP` from `geo.DefaultIPExtractor(r)` — the same extractor `checkIPPolicy` already uses, no second IP logic; metadata (`audit.SetMeta` only): `method`, `path`, and `reason` = the wire error code. The write-quota event additionally stamps `actor_id`/`tenant_id` (available there: `checkWriteQuota` runs after auth with `claims.Subject` and `tenantHintFromClaims`).
- Event types: reuse `EventAdminIPDenied` / `EventAdminWriteQuotaExceeded`; add two new types `EventAdminRateLimited` (`admin_rate_limited`) and `EventAdminDestructiveConfirmRequired` (`admin_destructive_confirm_required`) in `event_types_admin.go`, registered in `event_types.go`, aliased in `aliases_spi.go`, classified in `control_areas.go` beside the two existing denial types, and mapped in `platform/audit/auditsink/cef.go` + `ocsf.go` (the conformance list at `platform/audit/auditsink/conformance_test.go:37` covers every type).
- Fail-open and byte-identical responses: `Recorder.Record` is nil-safe ("Safe to call on a nil Recorder (no-op)", `platform/audit/recorder.go:143`); the gates never consult the recorder's outcome, and the four error bodies/status codes are unchanged.

**Acceptance check:**
- New tests in `interfaces/admin/middleware_test.go` / `governance_test.go` (pattern: `TestHTTPMiddleware_IPAllowlistDenies`, `middleware_test.go:220`): with `SetAuditRecorder(audit.New(audit.NewMemorySink(...)))` wired, each gate's blocked request yields exactly one event of the expected type, `OutcomeFailure`, `ActorIP` populated, `method`/`path`/`reason` metadata set; response status/body byte-identical to today.
- Existing gate tests without a recorder pass unchanged (no event, no panic — nil-safety proven).
- `go test ./platform/audit/...` passes: the two new types are classified in `auditreport` and covered by CEF/OCSF conformance.

## Decision 2: Audit HTTP authentication failures for gRPC parity

**Name:** HTTP auth-failure denial events (401 missing/invalid/session-expired, 403 forbidden).

**Problem:** `authenticateHTTP` (`interfaces/admin/middleware.go:357`) writes 401 `missing_token`, 401 `invalid_token`, 403 `forbidden`, and `enforceIdleTimeout` (`middleware.go:395`) writes 401 `session_expired` — all with no audit call, and `HTTPMiddleware` (`middleware.go:317`) contains zero `Recorder` references on its full path. This is asymmetric by code fact, not by design: `UnaryServerInterceptor` records `EventAdminGRPCCalled` + `OutcomeFailure` on exactly this denial class (`middleware.go:255-262`). The most security-relevant signal — "an authenticated admin tried an operation their scope denies" (the 403 branch, where validated `claims` exist) — is the one that vanishes completely today.

**Proposed behavior:**
- New event type `EventAdminAuthDenied` (`admin_auth_denied`), registered/aliased/classified/mapped per Decision 1's contract steps; `Reason` carries the wire error code (`missing_token` / `invalid_token` / `forbidden` / `session_expired`), mirroring the gRPC `"<method>: denied"` reason convention.
- Emit from the four failure branches via the same `recordAdminDenial` helper; stamp `ActorID`/`ClientID` where claims parsed (403 `forbidden` branch has validated claims; `session_expired` has claims too), `ActorIP` always, metadata `method` + `path`. The 503 `admin_auth_not_configured` branch is excluded (server misconfiguration with no caller identity — operator-logged, not a per-request event).
- Response bytes, status codes, and `WWW-Authenticate` challenges unchanged; recording fail-open.

**Acceptance check:**
- One test per branch asserting a single `admin_auth_denied` event with the correct `reason` metadata and unchanged status code; the forbidden test (existing 403 assertion at `middleware_test.go:241`) additionally asserts `ActorID` equals the token's subject.
- Parity table test: same scenario (no token / invalid token / no scope) over HTTP vs gRPC now yields exactly one denial event on each transport — HTTP `admin_auth_denied`, gRPC `admin_grpc_called` failure.

## Decision 3: Correlation IDs on denial events + record streaming-interceptor denials

**Name:** Denial-event correlation (RequestID/TraceID/ActorIP) and gRPC stream-denial recording.

**Problem:** Two distinct gaps. (a) Denial events fire in the outermost pre-routing wrapper: `cmd/sso-server/build_http.go:87` applies `a.adminMW.HTTPMiddleware(base)` around `a.server.Handler()`, i.e. before the sso stack's `WithTracingMiddleware` ("installs TracingMiddleware ahead of all routes", `interfaces/sso/options_security.go:484`) stamps RequestID/TraceID into the context — so the `audit.Event` correlation fields (`RequestID`/`TraceID`, `platform/audit/auditspi/event.go:26-27`) would be empty exactly on the events SOC most needs to correlate; the realtime SSE stream (`WithSSEBroker` taps the recorder sink, `interfaces/sso/server_health.go:415-420`; `handleAdminEventsStream` at `interfaces/sso/server_admin_handlers.go:460`) and the audit query API inherit whatever the emitter recorded. (b) `StreamServerInterceptor` (`middleware.go:293`) denies with a bare `return err` and records nothing — unlike `UnaryServerInterceptor` — and the gated streams include `audit.v1.AuditWriter/StreamEvents` (bulk event ingestion, i.e. event forgery if open) and `netpolicy.v1.PolicyService/Watch`: a blocked stream attempt is currently silent on both transports.

**Proposed behavior:**
- Extend `recordAdminDenial` to stamp correlation from the raw request, since the admin wrapper runs ahead of the tracing middleware: `RequestID` from `core.HeaderRequestID` (`X-Request-Id`, `shared/core/consts_wire.go:21`); `TraceID` from the `traceparent` header via the existing `Tracer.ParseTraceparent` (`platform/audit/tracer.go:87-99`) when present. Pass-through only — no minted IDs for anonymous failures (bounded cardinality in the audit store). `ActorIP` via `geo.DefaultIPExtractor` as in Decision 1.
- gRPC: in `StreamServerInterceptor`'s denial path, record the same `EventAdminGRPCCalled` + `OutcomeFailure` event the unary interceptor emits, with correlation IDs pulled from incoming gRPC metadata (`x-request-id`, `traceparent`) and peer address via `grpc/peer.FromContext`; the unary denial branch (`middleware.go:255-262`) gains the same correlation stamping.
- No change to the SSE tap or audit query: denial events flow into the realtime stream and queries automatically once emitted.

**Acceptance check:**
- Test: a protected HTTP request blocked by the IP gate and carrying `X-Request-Id: <id>` (and optionally `traceparent`) yields a denial event with `RequestID == <id>` (and matching `TraceID`); without headers, empty correlation fields and no error.
- Test: `AuditWriter/StreamEvents` called without a bearer produces one `admin_grpc_called` failure event with peer address, matching the unary path.
- Test in `test/` (`package ssotest`): with a memory-sink recorder + `WithSSEBroker` wired, a blocked admin request appears in the SSE-projected stream.
