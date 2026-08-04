# Requirements Spec: Threat-response observability and feedback loop (metrics, execution history, real notification)

> Expansion direction 3 of `docs/auto/domains-threataction-analysis.md`:
> "响应可观测性与反馈闭环（指标、执行历史、真实通知）".
> Scope: `domains/threataction`, `platform/metrics`, `platform/lifecycle/notification`,
> `platform/audit/auditspi`, `cmd/sso-server/serverbuildplatform/build_governance.go`,
> `cmd/sso-server/serverbuildplatform/email_sender.go`, `docs/observability.md`,
> `docs/notifications.md`, `docs/openapi.yaml`, `docs/feature-matrix.md`.
> Each decision below is one independent, evidence-backed improvement.

Budget note: all touched production files are below their ceilings today
(`registry.go` 301 lines, `admin.go` 185, `build_governance.go` 430 with
`BuildThreatAction` at 32 lines — wiring for improvements 1-3 must be
folded into helper functions to stay under the 50-line function budget). `interfaces/sso` is at its frozen 60-file ceiling: all SSO-side
changes must extend existing files (`accessors_threat.go`,
`server_routes_admin.go`), never add new ones. No new `layerExemptions` entry
is needed: `domains/threataction` keeps its existing `platform/audit` +
`platform/cluster` edges and adds none.

## 1. Response metrics: `WithMetricsCallbacks` on `ThreatExecutors` + `sso_threat_*` counters

**Name**: Threat-response metrics callbacks wired to `platform/metrics`
(policy hits, action outcome, rate-limited, no-handler).

**Problem**: The package contract claims executions are "logged, metric'd"
but there is no metric outlet of any kind. `ThreatExecutors` has no metrics
field or option; the rate-limited, no-handler, and execution-failure paths
produce only a log line plus an audit event. Operators cannot answer the
three operational questions of a response subsystem — "did the response
happen", "did rate limiting swallow actions", "which policies fire and how
often". `platform/metrics` has zero threat counters and `docs/observability.md`
has no threat-response section.

**Evidence**:
- `domains/threataction/registry.go` — package doc: "it is logged, metric'd,
  and the next threat proceeds"; `ThreatExecutors` struct has only
  `policies/handlers/auditor/logger/defaultAct/mu/rateLimit`; the only
  options are `WithDefaultAction` and `WithLogger`; `Execute`'s
  rate-limit branch, no-handler branch, and failure branch each terminate
  in log + `recordAudit` (`recordAudit` is the sole observation outlet).
- `domains/anomaly/options.go` `WithMetricsCallbacks` and
  `domains/anomaly/runner.go` `metricsCallbacks` (line 238) — the
  established nil-safe callback pattern this package lacks; the
  composition-root wiring style is `cmd/sso-server/anomaly.go:195-203`
  (closures incrementing `m.AnomaliesDetectedTotal` etc.).
- `platform/metrics/metrics.go` lines 124-135 — `AnomaliesDetectedTotal`,
  `AnomalyDispatchedTotal`, `AnomalyDispatchDropsTotal`,
  `AnomalyInspectErrorsTotal`; repo-wide grep for threat counters in
  `platform/metrics` returns nothing (only an unrelated doc-comment
  "duration that threatens token-issuance latency").
- `platform/metrics/consts.go:25` — `NameAnomaliesDetectedTotal =
  "sso_anomalies_detected_total"`; no `sso_threat_*` names exist.
- `docs/observability.md` — grep "threat" → zero hits.

**Proposed behavior**:
- Add `WithMetricsCallbacks(matched func(policy, threatType, severity string),
  executed func(action, outcome string), rateLimited func(action string),
  noHandler func(action string))` to `ThreatExecutors`, stored in a nil-safe
  stub struct exactly like anomaly's `metricsCallbacks` (each callback may be
  nil; only set ones fire).
- Fire points inside `Execute`: `matched` after `matchPolicy` returns a
  non-nil policy; `rateLimited` in the rate-limit branch; `noHandler` in the
  missing-handler branch; `executed` after `handler.Execute` with outcome
  `success|failure` (bounded).
- Add to `platform/metrics/metrics.go` + a `registerThreatMetrics` in
  `platform/metrics/metrics_ctor.go` (zero-registration when metrics are off,
  mirroring the token-anomaly opt-in note at `metrics.go:369`):
  `ThreatActionsTotal *CounterVec{action, outcome}`
  (`sso_threat_actions_total`), `ThreatPolicyHitsTotal *CounterVec{policy,
  severity}` (`sso_threat_policy_hits_total`), `ThreatRateLimitedTotal
  *CounterVec{action}` (`sso_threat_rate_limited_total`), `ThreatNoHandlerTotal
  *CounterVec{action}` (`sso_threat_no_handler_total`); label cardinality
  bounded (action ∈ the 6 `Action` constants, severity ∈
  info/warn/critical, policy names admin/YAML-bounded — the same reasoning
  as the rate-limiter tenant label).
- Wire in `cmd/sso-server/serverbuildplatform/build_governance.go`
  `BuildThreatAction` (new `m *metrics.Metrics` parameter, nil-safe),
  following the `cmd/sso-server/anomaly.go:195` closure style; split a
  helper if `BuildThreatAction` crosses 50 lines.
- Add a "Threat response" section to `docs/observability.md` documenting the
  four counters and the failure modes they surface (rate-limit ratio,
  no-handler misconfiguration, silent executor failures).

**Acceptance check**:
- `domains/threataction/registry_test.go`: new tests assert each callback
  fires exactly once on its path (policy match, rate-limited, no-handler,
  exec success, exec failure) and that unset callbacks are a no-op (no
  panic).
- `platform/metrics/metrics_test.go`: vectors register under the exact
  `sso_threat_*` names with the expected label sets; nothing registers when
  metrics are disabled.
- `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` pass;
  `docs/observability.md` documents the counters.

## 2. Execution history: append-only `ExecutionHistoryStore` + admin read endpoint

**Name**: Durable, queryable threat-execution history
(`GET /api/v1/admin/threat-executions`) completing the feedback loop.

**Problem**: The admin surface exposes policy CRUD only; the sole trace of an
executed response is the `threat_action_executed` audit event scattered
through the generic audit stream, unqueryable by subject/action/type. There
is no answer to "what did the system do about subject X, when, and did it
succeed" — an operator investigating an incident must correlate logs by hand,
and the module cannot demonstrate its own efficacy.

**Evidence**:
- `domains/threataction/admin.go` — only `HandleAdminListPolicies`,
  `HandleAdminGetPolicy`, `HandleAdminPutPolicy`, `HandleAdminDeletePolicy`;
  no execution-history read.
- `domains/threataction/registry.go` `Execute`/`recordAudit` — every
  non-Noop action funnels through `recordAudit`, the single choke point
  where a history record can be appended; `Threat` (Type/Severity/SubjectID/
  ClientID/FamilyID/TenantID/TraceID) and `ActionResult` (Action/OK/Detail)
  (`domains/threataction/threataction.go`) plus `ThreatPolicy.Name` carry
  every recordable field.
- Precedent in-repo: `domains/tokenexchange/chainstore.go` — append-only,
  FAIL-OPEN `ChainStore.RecordHop` SPI with `domains/tokenexchange/memory`
  and `domains/tokenexchange/sqlite` implementations, admin read endpoint
  `interfaces/admin/lifecycle.go:109` `HandleTokenExchangeChain`, mounted
  only when a store is wired (`interfaces/sso/accessors_threat.go`
  `mountAdminTokenExchangeChainRoutes`). Same for the durable backend
  pattern in `domains/threataction/sqlite/policy_store.go` (`migrate` +
  full test suite).
- `docs/openapi.yaml:7405` — the threat surface is only
  `/api/v1/admin/threat-policies*`; no executions endpoint.

**Proposed behavior**:
- New `ExecutionRecord` (PolicyName, Action, OK, Detail, ThreatType,
  Severity, SubjectID, ClientID, TenantID, RateLimited, TraceID,
  RecordedAt) + `ExecutionHistoryStore` SPI in `domains/threataction`:
  `Record(ctx, ExecutionRecord) error` and `List(ctx, filter, limit)`
  (filter by subject/action/type, newest-first).
- `ThreatExecutors` gains `WithExecutionHistory(store)`; `Execute` records
  at the `recordAudit` choke point — FAIL-OPEN: a store error is logged but
  never changes the action result (mirror tokenexchange's
  `RecordHopFailOpen`).
- Implementations: `domains/threataction/memory` (dev/test) and
  `domains/threataction/sqlite` (durable, multi-replica, reusing
  `policy_store.go`'s migrate pattern).
- Admin read endpoint `GET /api/v1/admin/threat-executions` (admin:read),
  query params `subject`/`action`/`type`/`limit`, mounted only when a store
  is wired (mirror the token-exchange-chain gating in
  `interfaces/sso/server_routes_admin.go`; handler in
  `domains/threataction/admin.go` like the policy handlers).
- `BuildThreatAction` wires the store (`memory` default; `sqlite` via the
  direction-1 backend knob or an independent `threat_action.history.backend`,
  never coupling to direction 1's delivery).
- Contract updates: `docs/openapi.yaml` (endpoint), `docs/feature-matrix.md`
  row (add endpoint), `docs/observability.md` (history query).

**Acceptance check**:
- Unit tests: memory store round-trip, `List` filters, newest-first
  ordering; a failing store during `Record` leaves the action result
  unchanged (fail-open asserted in `registry_test.go`); sqlite store test
  (open/migrate/round-trip, mirroring `policy_store_test.go`).
- Handler test in the style of `interfaces/admin/tokenexchange_chains_test.go`.
- `go test ./... -race`; `make ci` validates the openapi addition;
  `docs/feature-matrix.md` row updated.

## 3. Real notification: honest `notify` action wired into the existing notification pipeline

**Name**: `NotifyExecutor` with a `Notifier` SPI + `threat_notify_executed`
routed to `security_event` via `notification.Router`.

**Problem**: `NotifyExecutor.Execute` fabricates success — it returns
`OK: true` with zero side effects, and its detail string "notification
recorded for threat ..." is false. The only artifact is the generic
`threat_action_executed` audit event that also fires for suspend/revoke/
step-up, so "admin was notified" is indistinguishable from "session was
suspended" in the audit trail. The platform's real delivery pipeline
(`notification.Router`) never sees threat events: `DefaultMappings` covers
`anomaly_detected` but has no entry for a threat event, and the threat event
type lives outside the canonical `auditspi` registry, so the router cannot
even reference it type-safely. A policy author who sets `notify` believes an
admin was alerted — misdirection in a security product.

**Evidence**:
- `domains/threataction/actions.go` `NotifyExecutor.Execute` — returns
  `ActionResult{Action: ActionNotify, OK: true, Detail: "notification
  recorded for threat " + ...}` with no side effect; its doc comment
  admits: "This executor is a pass-through — the registry handles audit
  recording".
- `domains/threataction/threataction.go:124` — `EventThreatActionExecuted =
  "threat_action_executed"` is a local string constant; grep of
  `platform/audit/auditspi/event_types.go` for it returns nothing — it is
  outside the canonical event-type registry that `notification.Router`'s
  mappings reference (cf. `EventAnomalyDetected EventType = "anomaly_detected"`
  at `auditspi/event_types.go:79`).
- `platform/lifecycle/notification/router.go:116-128` `DefaultMappings` —
  maps `audit.EventAnomalyDetected → core.NotificationSecurityEvent`; no
  threat entry; `router.go:100` falls back to `DefaultMappings()` when the
  composition root passes nil — and `cmd/sso-server/serverbuildplatform/
  email_sender.go:86` passes nil.
- `docs/notifications.md` event-mapping table — rows for `anomaly_detected`,
  `admin_*` events, etc.; none for threat actions.
- `shared/core/password_reset.go:146` — `NotificationSecurityEvent =
  "security_event"` already exists as the target type for anomaly events;
  `interfaces/sso/accessors_threat.go` `WithNotificationRouter`/
  `NotificationBroker` — the router handle is already available to the
  composition root.

**Proposed behavior**:
- `NotifyExecutor` becomes `NewNotifyExecutor(notifier Notifier)` with a
  local minimal interface (mirroring the `FamilyRevoker`/`SubjectRevoker`
  local-interface pattern in `actions.go`): `Notifier.Notify(ctx,
  Notification{Threat, Policy, Detail}) error`. Nil notifier → `Execute`
  returns `ActionResult{ActionNotify, OK: false, Detail: "notify action not
  wired"}` — audited as a failure, never a fabricated success. Notifier
  errors → `OK: false` + error, still FAIL-OPEN (never blocks sibling
  actions).
- New canonical event type `EventThreatNotifyExecuted EventType =
  "threat_notify_executed"` added to `platform/audit/auditspi/event_types.go`
  and classified in `platform/audit/auditreport` (AGENTS.md §4); the
  registry emits it for `ActionNotify` results (instead of the generic
  event) with a `threat.notify.channel` meta key, so notify delivery is
  independently observable and routable.
- `DefaultMappings()` (`router.go`) gains `audit.EventThreatNotifyExecuted →
  core.NotificationSecurityEvent` (severity warning; critical when the
  threat severity is critical), so the existing router delivers a real
  inbox + SSE (+ optional email) notification through the already-wired
  senders — no new delivery machinery. Update the `docs/notifications.md`
  mapping table.
- Composition root: `BuildThreatAction` receives the notification router
  (already built in `email_sender.go`) when `notifications.enabled` and
  passes a notifier that taps `notification.Router.Record` (public
  audit-sink method, `router.go:207`); otherwise nil (unwired notify is
  then audited as a failure, per above).

**Acceptance check**:
- `actions_test.go`/`registry_test.go`: nil notifier → `OK:false` with
  "notify action not wired" and an audit failure event; stub notifier
  success → `OK:true` + `EventThreatNotifyExecuted` emitted; failing stub →
  `OK:false`, no panic, sibling actions unaffected.
- `platform/lifecycle/notification/router_test.go`: `DefaultMappings()`
  contains `EventThreatNotifyExecuted` (extend the existing
  `TestDefaultMappingsCoverAdministrativeSecurityActions`-style coverage).
- Integration test in `test/` (package ssotest): with notifications enabled
  (memory store) and a notify policy, a triggered threat creates an inbox
  row + SSE event for the subject and the audit webhook sees
  `threat_notify_executed`.
- `go test ./... -race`; `make ci` (event-type registration + auditreport
  classification validated); `docs/notifications.md` + `docs/observability.md`
  updated.
