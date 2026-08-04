# SRE Review: `interfaces/cors` execution observability (direction 三)

Advisory review of `docs/auto/interfaces-cors-observability-design.md` (docs-only
stage; no Go changes landed). Evaluates whether operators can detect, withstand,
and recover from failures at the API backend's external frontend/proxy boundary,
plus the observability the design adds.

## Evidence standard

**What actually ran for this review** (`git rev 02bf30be`):
`go build ./...` (exit 0), `git status`/`git log` inspection, and targeted
reads of every file the design cites. Line citations below were re-verified
against source. The design is **not yet implemented** — no `BlockObserver`,
`sso_cors_blocked_total`, or `cors_origin_blocked` exists outside
`docs/{auto,proposals,architect-analysis}` (grep over `--include='*.go'`).
Worktree carries unrelated in-flight changes (`cmd/sso-server/*` CAP/worker
edits) that were preserved and are not part of this review.

**Design claims verified** (all **Verified**):
`cors.go:185-188` silent reject branch; `metrics_ctor.go` = 497/500 lines
(`wc -l`); `metrics.go:191` `CIBAPingTotal`; `consts.go:46`
`NameCIBAPingTotal`; `server_login.go:174` `logger.Info("origin_blocked", ...)`;
`server_routes.go:452` single production `cors.Middleware` call site + 9 in
`interfaces/cors/cors_test.go` (~10 total, so variadic `Option` churn is ~0);
`recorder_events.go:139` `RecordCIBAPingFailed`; `drift_test.go:41`
uncategorized-events guard (adds a compile-time-test failure if the CC6.1/CC7.2
classification is omitted); `control_areas.go:50-66` CC6.1 and `:158-168` CC7.2
buckets; `observability.md:7` bounded-cardinality invariant; rate limiting
wraps CORS (`buildMiddlewareChain`, `server_routes.go:363-390`); probes served
outside the chain (`buildProbeMux`); `core.WithTraceID`/`TraceIDFromContext`
exist (`shared/core/trace_context.go`); `sso_audit_async_drops_*` consts exist.

## 1. Service / dependency map and operational assumptions

### Topology (external boundary)

```
Browser SPA ──► OpenResty/Envoy ──► sso-server (Go, API-only)
                 │  local EdDSA JWT verify (JWKS, 60s cache)
                 │  /permissions/me caching, JSONL audit per request
                 │  NO CORS handling at the proxy (Verified: no CORS
                 │  directives in ops/deploy/openresty/nginx.conf)
                 └── sso-server is the SINGLE CORS enforcement point
Native clients ──────────────────────► sso-server (no Origin header)
```

- Probes `/livez`, `/readyz`, `/metrics` are served by `buildProbeMux`
  OUTSIDE middleware; they never pass CORS, rate limit, metrics, or tracing —
  a CORS misconfig can never take down probes. **Verified**.
- Inbound chain (outermost → innermost, from `buildMiddlewareChain` +
  `wrapInnerMiddlewares`): panicRecovery → tracing → metrics → trustedProxies
  → ratelimit → degradation gate → versioning → bodyLimit → compression →
  **CORS** → securityHeaders → requestLogger → router. The observer therefore
  sees every router-bound request not shed upstream (429, 503-degraded, 413).
- Dependencies: Redis/Postgres/SQLite (stores, per `WithReadyCheck` wiring in
  `cmd/sso-server/build_bootstrap.go:222,314`), etcd (cluster bus, signing-key
  registry, invalidation), KMS backends (nested modules), outbound IdPs
  (OIDC/SAML), audit sinks (webhook/kafka/SIEM), CIBA notifiers, CAEP
  receivers, federation. Default rate-limit backend is per-replica `memory`
  (`cmd/sso-server/config.yaml:715`).

### Operational assumptions the design relies on

1. Rate limiting bounds disallowed-origin volume upstream of CORS (so the
   observer is a signal, not a defense) — **Verified** for chain order; the
   default bucket covers all paths incl. OPTIONS.
2. Production audit pipeline is `Async → Multi → Retry → leaf`
   (`observability.md:68`), so the observer's synchronous `Record` costs one
   enqueue on the reject path; sink errors are fail-open.
3. Tracing stamps the W3C ID before CORS runs (tracing is outermost) —
   **Verified**; the event's `TraceID` rides the request context.
4. The frontend is a separate project; the stock binary serves no static UI
   (AGENTS.md §1) — so "blocked origin" telemetry is the only server-side
   signal the frontend team gets.
5. `security.cors.*` is **not** SIGHUP-reloadable (only `security.rate_limit.*`
   is, per `config/reload/reload.go:19-27`): fixing a CORS misconfig found via
   the new counter requires a restart/rollout today. Direction 二 is the
   planned config surface. **Verified**.

## 2. Readiness table

| Signal | Dependency | Failure behavior | Alert | Runbook |
|---|---|---|---|---|
| `/livez` | none (process) | 200 whenever handler runs | SSOInstanceDown (`alerts.yaml:110`) | k8s-prod probe config; pod restart |
| `/readyz` | redis, postgres, invalidation-bus, signing-key-aggregation, etcd registry, netpolicy-classifier, dr, saml-* (`build_bootstrap.go:222,314`, `build_app_cluster.go:161,237,249`, `build_http.go:67,408`) | 503; k8s `readinessProbe` tolerant (patch-deployment.yaml:53-59) so transient store blips don't drain fleet | SSOSigningKeyAggregationDegraded, SSOConnectionUnreachable | baremetal-ha RUNBOOK |
| `/metrics` | in-memory registry | scraped outside chain; never self-inflates | — | — |
| Degradation gate | `degradation.Manager` (readonly/authonly/localonly/maintenance) | 503 before CORS; `sso_degradation_mode` + `sso_degraded_rejections_total` | (none in alerts.yaml) | dr-framework.md |
| Audit pipeline | AsyncSink queue → sinks | drops counted `sso_audit_async_drops_{queue_full,closed,inner_error}_total`; fail-open | SSOAuditEventsDropped, SSOAuditQueueSaturated (gate-pinned by `alert_rules_test.go:60`) | alerts annotations |
| CORS reject branch (today) | none | silent forward; only `/auth/login` logs | **none** (the gap this design closes) | none |
| CORS reject branch (proposed) | observer → counter + event + log, all nil-safe | metric sync; event best-effort; log one line | **none yet — finding F2** | **none yet — finding F2** |

## 3. Findings (severity-sorted)

### F1 — High: log removal widens the acknowledged PathOverrides × login-gate edge into fully silent enforcement

- **Evidence**: `isOriginAllowed` (`origin_validation.go:103`) checks only
  `AllowedOrigins`; the middleware uses the `PathOverrides`-resolved config
  (`resolveCORSConfig`, `cors.go:229`). The design itself documents the
  mismatch and says "this change must not make it worse", then removes the
  login gate's `logger.Info("origin_blocked", ...)` (`server_login.go:174`).
- **Impact**: if an operator configures a `PathOverrides` entry on
  `/auth/login` (the pattern the middleware explicitly documents for
  `/.well-known/jwks.json`), the middleware allows → observer silent → gate
  still 403s → **zero counter, zero event, zero log**. Today that edge emits
  one log line; after this change it emits none. Telemetry is strictly
  worse on the exact edge the design promises not to widen, and the design's
  invariant "one rejected request ⇒ exactly one counter increment, one audit
  event, one log line" is false for any disagreement between the two layers.
  Production impact when hit: login breaks for the affected origin with no
  monitoring signal — an invisible availability incident.
- **Remediation (in scope, ~5 lines)**: in `rejectDisallowedLoginOrigin`,
  when the gate decides to 403, emit the same triple (counter + event + log)
  **only when the middleware did not reject** (i.e., the resolved config
  allowed the origin). Exactly-once holds for the agreeing case (E2E case 2
  unchanged); the disagreement edge regains a signal. Unifying resolution
  stays direction 二 (non-goal).
- **Recovery validation**: E2E case: PathOverrides allowing origin X on
  `/auth/login` + default policy denying X ⇒ 403 + exactly one event + one
  counter increment; the existing case-2 assertion still passes.

### F2 — Medium: the counter ships without an alert rule or runbook

- **Evidence**: decision 1's own Help text says "Alert on a rate that is not
  explainable by known SPA origins"; decision 3 adds only `observability.md`
  rows. `ops/deploy/grafana/alerts.yaml` has 11 alerts, none CORS-related
  (grep over the file); no runbook exists for CORS incidents (only
  `ops/deploy/baremetal-ha/RUNBOOK.md`).
- **Impact**: a metric without an alert is invisible until an operator
  happens to look. The design's whole value proposition — catching the
  "browser console shows it" misconfig server-side — is realized only when
  an alert pages someone.
- **Remediation**: add `SSOCORSBlockedRate` (e.g.
  `sum(rate(sso_cors_blocked_total[10m])) > 1` for 10m, severity warning) to
  `alerts.yaml` — the existing `alert_rules_test.go` gate validates
  conventions for all rules and cross-references metric-name constants, so
  adding a rule is gate-verified and cheap. Add a short runbook in the alert
  annotation: (1) query `cors_origin_blocked` events for the `origin`
  metadata (raw origin lives in audit metadata only — there is no Prometheus
  origin label by design); (2) distinguish config typo (blocked origins match
  a known SPA) from probing (unknown origins, preflight=true burst); (3)
  fix requires restart — `security.cors.*` is not SIGHUP-reloadable.
- **Operational nuance to document**: floods that trip the rate limiter
  (outside CORS) never reach the observer — the counter stays flat while
  `sso_rate_limit_hits_total` rises. The runbook must cross-reference both.

### F3 — Medium: `observability.md:100` middleware-order diagram is drift; decision 3 touches it without correcting it

- **Evidence**: the doc's `tracing → ratelimit → bodyLimit → metrics → CORS →
  router` contradicts the code (`buildMiddlewareChain`,
  `server_routes.go:350-395`): metrics is outside trustedProxies and ratelimit
  (so ratelimit does NOT sit between tracing and bodyLimit); bodyLimit and
  versioning sit inside CORS; trustedProxies, degradation gate, versioning,
  securityHeaders, and requestLogger are unlisted. The design's own phrase
  "CORS sits innermost, just outside the router" is likewise imprecise —
  requestLogger and securityHeaders are inside CORS.
- **Impact**: operators reason about preflight handling, body limits, and
  where the observer fires from this diagram; it is currently misleading.
  The design's load-bearing conclusions (ratelimit wraps CORS; metrics wraps
  CORS; probes outside) are all still true, so this is an operability-docs
  defect, not a design defect.
- **Remediation**: in decision 3's middleware-order edit, replace the diagram
  with the actual chain (one line each for panicRecovery, tracing, metrics,
  trustedProxies, ratelimit, degradation, versioning, bodyLimit, compression,
  CORS, securityHeaders, requestLogger) and add the rejected-origin sentence
  to it.

### F4 — Low: `cors_origin_blocked` semantics can mislead SOC triage

- **Evidence**: on every path except `/auth/login`, a "blocked" origin is
  **forwarded and fully executed** — only the response CORS headers are
  withheld (`cors.go:185-188` reject branch calls `next.ServeHTTP`). A
  valid `POST /token` from a disallowed origin still mints a token. The
  event name and `Outcome: Failure` imply server-side refusal.
- **Impact**: SIEM analysts may mis-triage the event as "request refused"
  when the accurate reading is "browser-enforced block; server processed
  the request" (with the `/auth/login` 403 as the one server-enforced
  exception).
- **Remediation**: state this explicitly in the `observability.md` audit row
  and the runbook; optionally set a metadata key (e.g. `enforced=true` only
  for the login gate path) so SIEM rules can distinguish.

### F5 — Low: log stream and volume change on rollout

- **Evidence**: today `origin_blocked` is login-path-only and
  `corsPolicy != nil`-gated; after the change it fires for every path and
  every disallowed origin, and the login-gate copy disappears. Log volume
  scales with disallowed-origin traffic (bounded upstream by rate limiting).
- **Impact**: operators with log-based grep alerts on "origin_blocked" or
  per-path log routing will see a one-time stream shift; a noisy bot with
  spoofed Origins produces a constant low-volume log+audit stream.
- **Remediation**: call out the log-stream change in the release notes and
  the E2E/design review; the async-drop counters already bound the audit
  side.

### F6 — Info: synchronous observer cost on the reject path is bounded, with one embedder caveat

- **Evidence**: production wiring is `AsyncSink` (enqueue only); nil-guards
  make unwired servers pay one interface call + nil checks on the reject
  path only. Allowed-origin and no-Origin hot paths gain one branch. The
  reject path is the coldest code in the server.
- **Caveat**: an embedder wiring a synchronous custom sink pays the sink's
  latency per rejected request. Fail-open covers errors, not latency. Worth
  one sentence in the observer's doc comment.

### F7 — Info: no committed gate enforces `observability.md` contract rows

- **Evidence**: no check in `CHECKS_REGISTRY.md`, `Makefile`, or `checks/`
  greps `observability.md` for metric names; only `alert_rules_test.go`
  cross-references `alerts.yaml`/dashboard against metric-name constants
  (compile-time). The design's decision-3 "fold the grep into the change's
  verification" is convention-only — the row can drift silently later.
- **Remediation (optional)**: follow the `alert_rules_test.go` precedent with
  a small committed test asserting the new metric name and event type appear
  in `observability.md`.

### Verified non-findings (design claims that hold up)

- Budget shaping is sound: `metrics_ctor.go` 497/500 → new `cors.go`;
  `interfaces/sso` 60-file ceiling respected; `cors.go` 242/500 has headroom.
- Nil-safety and fail-open semantics mirror the proven
  `RecordCIBAPingFailed` pattern; CC6.1 classification is defensible and the
  `drift_test.go` guard makes omission a test failure.
- Bounded cardinality holds: `reason`/`preflight` ≤ 2 combinations; raw
  origin/path correctly confined to audit metadata (no origin label anywhere
  in Prometheus — consistent with `observability.md:7`).
- Exactly-once emission is achievable and E2E case 2 pins it — **except** for
  the F1 disagreement edge.
- E2E plan is sound: per-test server + registry (no cross-test pollution),
  synchronous `MemorySink` (no flake), asserting observable behavior only.

## 4. Failure drills

1. **Outage** (replica dies mid-traffic): watch `/livez` fail → SSOInstanceDown
   → kubelet restarts; `/readyz`-gated rotation via PDB (`k8s-prod/pdb.yaml`)
   keeps quorum; verify a CORS-enabled deployment loses zero `sso_cors_*`
   series across the fleet on restart (registry is per-replica; counters reset
   — the alert must use `rate()`, not totals).
2. **Saturation** (preflight flood: OPTIONS + `Access-Control-Request-Method`
   + spoofed Origin): rate limiter 429s before CORS ⇒ observer silent, counter
   flat, `sso_rate_limit_hits_total` + `sso_http_requests_total{4xx}` rise;
   drill that the runbook cross-references these, and that audit volume is
   bounded by the async queue + drop counters.
3. **Bad rollout** (CORS config typo: staging origin missing): counter
   spikes `{reason=disallowed_origin,preflight=false}`; `cors_origin_blocked`
   events carry the origin in metadata; alert (F2) pages; fix requires
   **restart** (not SIGHUP-reloadable — Verified); rollback = revert config +
   restart, no data migration; canary via helm/kustomize values.
4. **Stale state** (PathOverrides on `/auth/login` + default-policy deny):
   today = 403 + one log; after design-as-written = 403 + zero telemetry (F1).
   Drill must assert the F1 fix emits exactly one event; also drill SIGHUP
   reload of `security.rate_limit.*` while CORS stays static to confirm
   `ignored_requires_restart` reporting.
5. **Restore** (audit SQLite lost/corrupt): `sso-ctl audit-verify` on the hash
   chain (`observability.md:68`) detects truncation; restore from snapshot,
   re-verify chain; DR cutover per `dr-framework.md` with `sso_dr_readiness`,
   RPO via `sso_dr_snapshot_replication_lag_seconds`; drill that restored
   replicas re-subscribe to the invalidation bus before `sso_dr_readiness`=1.

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers

- **F1 (High)** — the log removal makes the acknowledged disagreement edge
  fully silent, contradicting the design's own non-widening promise. Land the
  gate-side disagreement emission (or explicitly accept the regression as a
  documented residual risk in the design — the current text does neither).
  This is the only finding that changes the design's invariants.

### Required before promotion (not blockers)

- F2: alert rule + runbook for `sso_cors_blocked_total` — a counter with no
  alert is a telemetry gap, not observability.
- F3: correct the middleware-order diagram in the same edit decision 3 makes
  to it.

### Rollback triggers (during/after rollout)

- `sso_cors_blocked_total` rate unexplained by known SPA origins (typ or
  probe — per runbook);
- `cors_origin_blocked` event volume driving `sso_audit_async_drops_*` up;
- `/auth/login` 4xx rate rising (`sso_http_requests_total{status_class="4xx"}`)
  — the gate 403 must be the only new login-path behavior;
- E2E case-2 regression (double emission) — exactly-once invariant broken.

### Monitoring gaps (post-change)

- No Prometheus origin dimension (by design); origin identification requires
  the audit API — the runbook must include the query path (facets/event
  search by `cors_origin_blocked`).
- Rate-limited floods invisible to the new counter (documented, acceptable).
- No alert on `sso_degraded_rejections_total` or degradation-mode transitions
  (pre-existing gap, outside this design's scope).

### Residual risks

- PathOverrides × login-gate resolution asymmetry persists until direction 二
  (mitigated by F1's emission + E2E out-of-scope note).
- CORS misconfig fixes need a restart (no hot reload); the counter shortens
  time-to-detection but not time-to-fix.
- Observer is synchronous on the reject path; production latency bounded by
  the async enqueue, embedder sync sinks pay per-reject latency (F6).
- Counter is per-replica and reset on restart; all alerting must use rates.
