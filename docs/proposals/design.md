Design doc written to `docs/auto/interfaces-cors-observability-design.md` (docs-only change, no Go edits). Every citation was re-verified against source before writing.

**Structure** — five `##` sections:

- **## Shared mechanism** — `cors.BlockObserver` + variadic `Option` (private type, `WithBlockObserver` constructor so all ~10 existing call sites stay source-compatible); reject branch splits into no-Origin pass-through vs. observer-then-forward; observer reports the *PathOverrides-resolved* decision, not the default policy.
- **## Decision 1: `sso_cors_blocked_total`** — `CORSBlockedTotal` field beside `CIBAPingTotal` (`metrics.go:190`), registration in a **new `platform/metrics/cors.go`** because `metrics_ctor.go` is at 497/500 (the one-line call → 498 is the budget-shaped answer); `reason`/`preflight` closed vocabulary (max cardinality 2), raw `{origin,path}` explicitly rejected per `observability.md:7`.
- **## Decision 2: `cors_origin_blocked`** — `RecordCORSOriginBlocked` mirroring `RecordCIBAPingFailed` (`recorder_events.go:139`): nil-recorder no-op, `SetMeta`-only, W3C trace via context (tracing runs outside CORS, so it's already stamped); login gate keeps the 403 `authzErrorBody` and drops only the log at `server_login.go:174`; **classified in CC6.1 Access control** (not CC7.2 — the dominant case is benign misconfig, not anomaly), satisfying the `drift_test.go:41` guard.
- **## Decision 3: contract + E2E** — observability.md rows + middleware-order sentence, and a `test/cors_observability_test.go` with the five pinned cases (exactly-one on `/auth/login`, PathOverrides-allowed origins uncounted, nil-safety, counter+`sso_http_requests_total` moving together).

**Key findings beyond the spec** (each with API surface / storage model / failure modes / breakage risks):

1. **Pre-existing asymmetry surfaced**: `isOriginAllowed` (`origin_validation.go:103`) ignores `PathOverrides` while the middleware honors them — a hypothetical `/auth/login` override would 403 with zero telemetry after the log removal. Documented as a known limitation with the unification deferred to direction 二 (non-goal).
2. **Metrics/audit divergence is designed**: the counter is synchronous (always fires); the event is best-effort (async sink drops counted by `sso_audit_async_drops_*`) — the trade-off is stated explicitly.
3. **Two budget tripwires** shaped the design: `metrics_ctor.go` 500-line cap (new file split) and the `interfaces/sso` 60-file ceiling (observer is a `*Server` method in `origin_validation.go`, wiring is two lines in `server_routes.go:452`).
