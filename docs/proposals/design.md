Design doc written to `docs/design/middleware-observability-unified.md`. It grounds every decision in the code I verified (slot ordering in `server_routes.go:364-407`, `WithRequestLogging` having zero production callers, `peertrust.RequestInfoFrom` being the canonical IP source, otelhttp being the existing `Traceparent` injector, `tracing.Init` being a no-op without an endpoint).

## Key decisions

**Improvements 1–2 (log side)** — one middleware, one capture stack:
- `middleware.AccessLogger(l spi.Logger, policy BodyLogPolicy)` — INFO, fixed 7-field schema (`method`, `path`, `status`, `duration_ms`, `client_ip`, `request_id`, `trace_id`), no `query` (query strings can carry `code`/`token`). Installed in a fixed `buildMiddlewareChain` slot: inside trustedProxies (real client IP), outside ratelimit (429s are logged). Probes stay exempt for free via `buildProbeMux`.
- `BodyLogPolicy` (paths allowlist / `AllowAllPaths` deprecated escape hatch / `sample_rate` / 4 KB cap) replaces the boolean; `WithRequestLogging` keeps its name, changes its parameter. `middleware.RequestLogger` is deleted — its debug-level "log everything" shape becomes an explicit, redacted, sampled policy on the same middleware.
- Redaction: form + JSON parsed, keys matched exact + substring heuristic (`secret|password|token|assertion|code`), always over-redacting, nested JSON walked; non-structured content types pass capped-raw (documented limitation).
- SDK stays byte-identical (`accessLogPolicy == nil` by default); `cmd/sso-server` enables via `logging.access_log.enabled` (tri-state, default on) in the SIGHUP `ignored_requires_restart` bucket.

**Improvement 3 (correlation)** — one switch, one source:
- New `middleware.Correlation(operation)` wraps `tracing.Middleware`; from the live span context it stamps `core.WithTraceID`, `X-Trace-Id`, `X-Request-Id` (preserve-or-generate). `WithTracing` alone now decides span tree + audit correlation + error-body `trace_id`. Full removal list for the legacy surface (7 locations, including `cmd/sso-minimal` and `docs/examples/basic`).
- `EventFromRequest` reads `trace.SpanFromContext` first (span IDs + real parent), header parse demoted to external-caller fallback.
- `platform/tracing`'s `StartSpan`/`ParentFromIDs` seams need no changes — async audit sub-spans now provably link to the request span.

**Storage model**: no new durable state — the log record is the storage (fail-open, lossy by design), audit events keep their schema (only field provenance changes), sampling is stateless Bernoulli.

**Biggest break risks** (documented with mitigations): (1) `X-Trace-Id`/audit `trace_id` disappear for OTel-less deployments — the intended one-switch semantics but wire-visible, mitigated by a boot warning + doc change; (2) otelhttp's `Traceparent` response-header injection becomes load-bearing — pinned by an integration test; (3) `feature_gate_hotreload_test.go` asserts headers from the old `router.Use` location and must be moved to the outer chain.

One open point I flagged in the doc: acceptance B1's wording ("`/token` 即使策略开启也永不记录 body") only holds when `/token` isn't in the allowlist — the design treats the allowlist as the operator's explicit risk acceptance, which is what the policy requires.
