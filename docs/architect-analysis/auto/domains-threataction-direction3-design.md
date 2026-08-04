# Design: `domains/threataction` — threat-response observability and feedback loop (metrics, execution history, real notification)

Source: `docs/auto/domains-threataction-direction3-spec.md` (direction 3 of
`docs/auto/domains-threataction-analysis.md`). This doc fixes the three
decisions — `WithMetricsCallbacks` + `sso_threat_*` counters, an append-only
`ExecutionHistoryStore` + `GET /api/v1/admin/threat-executions`, and an
honest `NotifyExecutor` routed through `notification.Router` — down to API
surface, storage model, failure modes, and the distributed-systems
guarantees (state map, findings, scenario table, validation).

## Verification record

Every claim below was re-verified against the working tree at this revision
(`git rev-parse HEAD` = cde74c6c, working tree carries the uncommitted
direction-3 implementation work) by source inspection and line counting.
No Go gates were run in this pass; the verification is read-only. Corrections
against the previous draft of this doc:

| Claim in previous draft | Verified reality |
|---|---|
| `BuildNotifications` at `email_sender.go:51` / `email_sender.go:86` | `cmd/sso-server/serverbuildplatform/email_sender.go:51`; `NewRouter(nil, ...)` (nil mapping → `DefaultMappings()`) at line 81. Same file, corrected path |
| `BuildThreatAction` at `build_governance.go:310`, 32 lines | `cmd/sso-server/serverbuildplatform/build_governance.go:310–341`, 32 lines. Correct; the helper split is mandatory once +2 params and +1 return are added |
| `wireThreatAction` at `cmd/sso-server/anomaly.go:67` | Definition at `anomaly.go:54`; called by `wireDetectionResponse` (`anomaly.go:87`), which `finalize()` (`cmd/sso-server/build_app.go:238`) invokes at line 244 |
| `recordAudit` at `registry.go:240` | `domains/threataction/registry.go:241` |
| `applyAuditSinkTaps` at `sso.go:161` | `interfaces/sso/sso.go:143`; `auditor.AddSink(s.notificationRouter)` at 160–161, gated on `WithNotificationRouter` |
| `cooldown: 0` is an "explicit operator setting" | **Wrong.** `config/config_load.go:229–230` (`applyNotificationDefaults`) coerces `notifications.cooldown == 0` to the 5-minute default, and `validateNotifications` (line 259) rejects negatives. `cooldown: 0` is reachable ONLY via SDK embedding (`notification.WithCooldown(0)`, accepted because the guard is `value >= 0`, `router.go:51`). The duplicate-delivery edge is therefore an SDK-embedder config, not a stock-server operator setting. Finding F1 below is reworded accordingly |
| `domains/threataction/memory` has 2 non-test files (3 after) | **Wrong.** `memory/` has 1 non-test file (`policy_store.go`); 2 after the history store. `sqlite/` has 2 (`maxversions.go`, `policy_store.go`); 3 after. Both under the 10-file ceiling |
| `sso.go:161` router sink; `router.go:343` `suppressed`; `router.go:207` `Record`; `router.go:116` `DefaultMappings`; `metrics_ctor.go:45` eager `registerAnomalyMetrics`; `runner.go:238` nil-safe stub; `subject.go:19` `eventSubject`; `password_reset.go:146` `NotificationSecurityEvent`; `metrics_token.go:133` lazy `EnableTokenAnomalyMetrics`; `lifecycle.go:109` `HandleTokenExchangeChain`; `consts_wire.go:488` `PathAdminThreatPolicies`; `server_routes_admin.go:138` policy-CRUD block; `feature-matrix.md:69` threat row | All confirmed at the cited locations |

Other verified anchors used below: `domains/threataction` = 6 non-test files
(301-line `registry.go`, 334-line `actions.go`, 185-line `admin.go`,
136-line `threataction.go`, 243-line `policy.go`, 33-line `executor.go`);
`interfaces/sso` sits at exactly its frozen 60-file ceiling (so all
SSO-side additions extend `accessors_threat.go` + `server_routes_admin.go`);
`domains/threataction` imports only `platform/audit`, `platform/cluster`,
`shared/core`, `shared/spi` (architecture_layer_test.go classifies by
top-level directory; no `layerExemptions` entry is needed for the new
files, and `domains/threataction/sqlite` already imports `platform/migrate`);
`platform/migrate.Run(ctx, db, namespace, ...)` keeps a per-namespace
`schema_migrations_<namespace>` version table with `busy_timeout` +
`BEGIN IMMEDIATE` (`platform/migrate/migrate.go`), so a `threat_executions`
namespace cannot collide with `threat_policies` or
`tokenexchange_chain_hops` (`domains/tokenexchange/sqlite/chain_store.go:73`).

---

## Decision 1: response metrics — `WithMetricsCallbacks` on `ThreatExecutors` + `sso_threat_*` counters

### Problem restated

`ThreatExecutors.Execute` (`registry.go:77`) is the only observation outlet
for the response subsystem, and it has none: the package doc claims
executions are "logged, metric'd", but the rate-limited, no-handler, and
failure branches terminate in log + `recordAudit` (`registry.go:241`) and
nothing else. `platform/metrics` has zero threat counters (`metrics.go:124–135`
covers anomaly only; `consts.go` has no `sso_threat_*`), and
`docs/observability.md` has no threat section. The three operational
questions — "did the response happen", "did rate limiting swallow actions",
"which policies fire and how often" — are unanswerable today.

### API surface

`domains/threataction/registry.go` — new option, mirroring
`domains/anomaly/options.go:93–115` `WithMetricsCallbacks` and its nil-safe
`metricsCallbacks` stub with `record*` helpers (`domains/anomaly/runner.go:238`):

```go
// WithMetricsCallbacks wires the threat-response metric emitters. cmd builds
// these from its *metrics.Metrics; tests inject inline closures. Any
// callback may be nil — only set ones fire.
func WithMetricsCallbacks(
    matched     func(policy, threatType, severity string), // non-nil policy matched
    executed    func(action, outcome string),              // outcome: "success"|"failure"
    rateLimited func(action string),                       // rate-limit branch
    noHandler   func(action string),                       // missing-handler branch
) ThreatExecutorsOption
```

Stored as a `metricsCallbacks` struct on `ThreatExecutors` (exactly anomaly's
shape); each fire point is a `record*` helper with the nil-check guard. Fire
points inside `Execute`:

- `matched` — immediately after the `policy == nil` guard (line 97), before
  the `ActionNoop` early return (line 104), labeled with `policy.Name` (the
  `_default` fallback policy — used when `matchPolicy` errors, line 90 —
  counts too; observation-only policies must be visible). Not fired when no
  policy is configured at all (the `policy == nil` early return).
- `rateLimited` — in the rate-limit branch (line 109), before `recordAudit`
  (line 112).
- `noHandler` — in the missing-handler branch (line 118), before `recordAudit`
  (line 120).
- `executed` — after `handler.Execute` returns (line 124), with `outcome`
  derived from `result.OK` (bounded to `success|failure`, never from
  `result.Detail`).

`platform/metrics/metrics.go` — four new fields on `Metrics`
(zero traffic when no threat executor is wired — same property anomaly's
counters document):

```go
ThreatActionsTotal     *prometheus.CounterVec // labels: action, outcome
ThreatPolicyHitsTotal  *prometheus.CounterVec // labels: policy, severity
ThreatRateLimitedTotal *prometheus.CounterVec // labels: action
ThreatNoHandlerTotal   *prometheus.CounterVec // labels: action
```

`platform/metrics/consts.go` — four new names, all `sso_threat_*` wire
contract (renames are a major-version break):
`NameThreatActionsTotal = "sso_threat_actions_total"`,
`NameThreatPolicyHitsTotal = "sso_threat_policy_hits_total"`,
`NameThreatRateLimitedTotal = "sso_threat_rate_limited_total"`,
`NameThreatNoHandlerTotal = "sso_threat_no_handler_total"`, plus
`LabelAction`/`LabelOutcome`/`LabelPolicy` (reuse the existing
`LabelSeverity`, `consts.go:130`; `LabelAction` already exists at
`consts.go:126` with a CAP-verdict doc comment that must be widened to
"action (bounded per metric family)" — the label STRING is the same
`"action"`, which is the wire contract).

`platform/metrics/metrics_ctor.go` — `registerThreatMetrics(factory, m)` in
the same eager list as `registerAnomalyMetrics` (line 45). Eager, not lazy
like `EnableTokenAnomalyMetrics` (`metrics_token.go:133`): the vectors exist
whenever metrics are on and stay at zero without a threat executor. Spec's
"zero-registration when metrics are off" holds via the existing whole-
subsystem gate (metrics off ⇒ `m == nil` at the call site ⇒ all-nil
callbacks never fire).

Composition root — `BuildThreatAction`
(`cmd/sso-server/serverbuildplatform/build_governance.go:310`, currently 32
lines) gains a `m *metrics.Metrics` parameter (nil-safe). To hold the 50-line
function budget, the closure set is built by a helper (same shape as the
`if m != nil { opts = append(opts, anomaly.WithMetricsCallbacks(...)) }`
block at `cmd/sso-server/anomaly.go:197–204`):

```go
// threatMetricsCallbacks returns the four metric closures, or all-nil when
// m is nil. Mirrors cmd/sso-server/anomaly.go:197-204's closure style.
func threatMetricsCallbacks(m *metrics.Metrics) (func(string, string, string), func(string, string), func(string), func(string))
```

Call site `wireThreatAction` (`cmd/sso-server/anomaly.go:54`) passes
`b.metricsRegistry` (field at `cmd/sso-server/build_app.go:69`).

### Storage model and consistency

None — plain in-process Prometheus counters (volatile, per-replica, reset on
restart; scraped per replica). Cardinality is bounded by construction:

- `action` ∈ the 6 `Action` constants (`threataction.go:35–54`).
- `outcome` ∈ `{success, failure}`.
- `severity` ∈ the detector-emitted set: `domains/anomaly/types.go:145–147`
  (`info|warn|critical`) and `domains/tokenanomaly` (`warn|critical`,
  `detect.go:56–63`) — the callback labels `threat.Severity`, NEVER
  `policy.Severity`, precisely because policy severity strings are free-form
  (`"empty = any"`, `"warn+critical"` — `policy.go:35`, parsed by
  `MatchesSeverity` at `policy.go:158`). The closed set is a detector
  discipline, not an enforced type: a future detector that emits an
  unbounded severity string grows this label. Review gate: any new detector
  must keep severity in the closed set (see residual risks).
- `policy` is the one admin-controlled label: policy names come from
  `ThreatPolicyStore` (YAML seed + admin CRUD), the same trust level as the
  rate-limiter tenant label and webhook-name labels — bounded by admin
  access, not by the metric.

Counter increments happen on the replica that executed the action; a
multi-replica fleet scrapes each replica's registry, so sums must be
aggregated by `sum(rate(...))` across targets. There is no cross-replica
deduplication: the same threat executed independently on two replicas (see
F5) counts twice. That is correct behavior for a counter (it reflects two
executions) and must not be "fixed" by dedupe.

### Failure modes surfaced (and how to read them)

- `sso_threat_no_handler_total{action=...}` non-zero → misconfiguration: a
  policy references an action with no registered handler (previously only a
  log line). Alert on any non-zero rate.
- Rate-limit ratio = `sso_threat_rate_limited_total{action} /
  (sso_threat_actions_total{action} + sso_threat_rate_limited_total{action}
  + sso_threat_no_handler_total{action})` — high ratio = flapping detector
  or over-tight policy window; the operator sees actions being swallowed.
- `sso_threat_actions_total{outcome="failure"}` non-zero → silent executor
  failures (store down, notifier unwired) become visible.
- Executor/registry never wired → all four counters stay at zero; that
  itself is the "response subsystem not installed" signal.
- Counter reset on replica restart is visible as a rate drop; alerting must
  use `rate()` over windows longer than a rolling restart.

### What could break the design

- **`BuildThreatAction` budget**: +1 param, +4 closures, +1 notifier param
  (decision 3) push toward the 50-line cap; the `threatMetricsCallbacks`
  split is mandatory, not optional.
- **Callback panic safety**: nil-safe like anomaly, but NOT panic-safe — a
  mislabeled `WithLabelValues` (e.g. an unknown action string) panics the
  Prometheus client. `outcome` must be exactly `success|failure`; the
  `executed` helper derives it from `result.OK`, never from `result.Detail`.
- **Exact-once test brittleness**: `registry_test.go` assertions must pin
  each callback to its own path — the `noHandler` branch must not fire
  `executed`, the rate-limit branch must not fire `matched` twice, and a
  `noop` policy (early return, line 99) fires `matched` but nothing else.
  The test suite is the contract here.
- **Label drift**: `consts.go` names are wire contract; `metrics_test.go`
  must assert the exact `sso_threat_*` strings so a rename never slips
  through, and `docs/observability.md` gains a threat subsection in the same
  change (AGENTS.md §5).
- **Zero-registration expectation**: if a reviewer prefers strict opt-in
  (nothing registered until a threat executor exists), the lazy
  `EnableTokenAnomalyMetrics` pattern (`metrics_token.go:133`) is the
  alternative — but the anomaly precedent (eager, zero-traffic) is the one
  the spec cites, and switching mid-review costs nothing since the vectors
  are only ever incremented through the wired callbacks.

---

## Decision 2: execution history — append-only `ExecutionHistoryStore` + `GET /api/v1/admin/threat-executions`

### Problem restated

The admin surface is policy CRUD only (`admin.go` — 4 handlers); the sole
trace of an executed response is the `threat_action_executed` audit event
scattered through the generic audit stream, unqueryable by subject/action/
type. "What did the system do about subject X, when, and did it succeed"
requires hand-correlating logs. The in-repo precedent is
`domains/tokenexchange/chainstore.go` + `interfaces/admin/lifecycle.go:109`
(`HandleTokenExchangeChain`: nil store → 404, bad param → 400, store error →
500, empty chain → 404) + the gated mount pattern already used in
`interfaces/sso/accessors_threat.go`.

### API surface

`domains/threataction/history.go` (new file; package 6 → 7 non-test files,
ceiling 10):

```go
// ExecutionRecord is one flattened, queryable record of a threat-response
// attempt — the durable counterpart of the audit event recordAudit emits.
type ExecutionRecord struct {
    PolicyName  string    `json:"policy_name"`
    Action      Action    `json:"action"`
    OK          bool      `json:"ok"`
    Detail      string    `json:"detail"`       // human-readable result
    ThreatType  string    `json:"threat_type"`
    Severity    string    `json:"severity"`
    SubjectID   string    `json:"subject_id"`
    ClientID    string    `json:"client_id"`
    TenantID    string    `json:"tenant_id"`
    RateLimited bool      `json:"rate_limited"` // true = swallowed by rate limit, NOT executed
    TraceID     string    `json:"trace_id"`
    RecordedAt  time.Time `json:"recorded_at"`
}

// ExecutionHistoryStore is the OPTIONAL append-only threat-response history
// SPI. Nil (the default, unwired) is a complete no-op: nothing is recorded
// and the admin read endpoint is not mounted. PURE OBSERVABILITY — never a
// gate; Record is always fail-open at the call site (RecordExecutionFailOpen).
type ExecutionHistoryStore interface {
    Record(ctx context.Context, rec ExecutionRecord) error
    List(ctx context.Context, filter ExecutionFilter, limit int) ([]ExecutionRecord, error)
}

// ExecutionFilter selects history rows. Zero-value fields match everything.
type ExecutionFilter struct {
    SubjectID string
    Action    Action
    ThreatType string
}
```

`List` returns newest-first (by `RecordedAt` desc; ties broken by insertion
order) and honors a positive `limit`; `limit <= 0` means the caller wants the
store default (admin handler passes its own validated limit — same contract
as `ChainStore.GetDescendants`).

`domains/threataction/registry.go` — `WithExecutionHistory(store
ExecutionHistoryStore) ThreatExecutorsOption`; `Execute` records at the
`recordAudit` choke point. Concretely: `recordAudit` (`registry.go:241`)
gains a `rateLimited bool` parameter (3 internal call sites: rate-limit
branch `true` at line 112, no-handler branch `false` at line 121, executed
branch `false` at line 126) and, after emitting the audit event, writes the
history row via a package-level fail-open helper:

```go
// RecordExecutionFailOpen best-effort records rec. Never returns an error,
// never changes the action result: nil store is a no-op, any store error is
// logged and swallowed. Mirrors tokenexchange.RecordHopFailOpen
// (domains/tokenexchange/chainstore.go:99).
func RecordExecutionFailOpen(ctx context.Context, store ExecutionHistoryStore,
    rec ExecutionRecord, logf func(msg string, args ...any))
```

Rate-limited and no-handler attempts ARE recorded (with `RateLimited: true` /
`OK: false` + the branch's detail string): an operator investigating a
subject needs to see the attempts that were swallowed, not just the
successes — that is precisely the "did rate limiting swallow actions" answer
the metrics cannot give per-subject.

`domains/threataction/admin.go` — the read handler:

```go
// HandleAdminListThreatExecutions serves GET /api/v1/admin/threat-executions.
// Query params: subject, action, type, limit (default 100, max 1000).
// Admin-gated (admin:read) by the caller. Store nil (direct unit-test call)
// → 404, mirroring HandleTokenExchangeChain.
func HandleAdminListThreatExecutions(store ExecutionHistoryStore, log spi.Logger, ctx core.HandlerContext)
```

Response: `{"status":"ok","executions":[...],"total":n}`. A non-numeric,
negative, or >1000 `limit` is a 400 `ErrInvalidRequest`; a store error is a
500 `ErrInternal` (read path is fail-closed like every sibling admin
handler — only the WRITE is fail-open; the asymmetry is asserted in the
handler test).

`shared/core/consts_wire.go` — `PathAdminThreatExecutions =
"/admin/threat-executions"` (next to `PathAdminThreatPolicies`, line 488).

`interfaces/sso/accessors_threat.go` (existing file — 60-file ceiling) —
`threatState` gains `threatHistoryStore`; `WithThreatExecutionHistoryStore`
+ `ThreatExecutionHistoryStore()` accessor; the server adapter method
`handleAdminListThreatExecutions`. `interfaces/sso/server_routes_admin.go` —
one gated block beside the policy-CRUD block (line 138):

```go
if s.threatHistoryStore != nil {
    api.GET(PathAdminThreatExecutions, s.handleAdminListThreatExecutions)
}
```

Not mounted without a store — byte-identical to a build without the feature.

Composition root — `BuildThreatAction` also returns the history store
(signature becomes 4 returns:
`(*ThreatExecutors, ThreatPolicyStore, ExecutionHistoryStore, error)`) and
builds it from a new config knob: an independent
`threat_action.history.backend` (`""`|`memory`|`sqlite`) +
`threat_action.history.dsn`, NEVER coupled to the policy-backend knob or to
delivery — history is an observability concern and must be independently
toggleable. `memory` (the default) is the dev/test store; `sqlite` without
`dsn` fails loud at boot (the anomaly sqlite precedent). A helper
`buildThreatHistory(cfg, logger)` keeps `BuildThreatAction` under 50 lines.
`wireThreatAction` passes the returned store to
`sso.WithThreatExecutionHistoryStore`. `docs/config-reference.md` gains the
two rows in the same change (AGENTS.md §5 config-drift rule; `make ci`
validates).

### Storage model

- `domains/threataction/memory/execution_history_store.go` — append-only
  slice + `sync.RWMutex`; `Record` appends under a monotonic sequence for
  deterministic newest-first tie-breaks; `List` filters then truncates to
  `limit`. Dev/test only; unbounded growth is acceptable there (same as
  `domains/tokenexchange/memory/chain_store.go`). Package goes 1 → 2
  non-test files.
- `domains/threataction/sqlite/execution_history_store.go` — durable,
  multi-replica, reusing the `policy_store.go` migrate pattern
  (`migrate.Run(ctx, db, "threat_executions", ...)` — the per-namespace
  version table means this never touches the `threat_policies` stamp; the
  exact coexistence precedent is `tokenexchange/sqlite/chain_store.go:73`).
  `NewExecutionHistoryStore(dsn)` / `NewWithDB(db)` / `Close()`, plus
  `db.SetMaxOpenConns(1)` (WAL single-writer, the
  `infrastructure/defaultimpl/sqlite/account_lockout.go:55` precedent).
  Columns, not a JSON blob — every field is filterable/ordered (the same
  reasoning that drove `chain_store.go` to columns):

```sql
CREATE TABLE IF NOT EXISTS threat_executions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name  TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL DEFAULT '',
    ok           INTEGER NOT NULL DEFAULT 0,
    detail       TEXT NOT NULL DEFAULT '',
    threat_type  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    subject_id   TEXT NOT NULL DEFAULT '',
    client_id    TEXT NOT NULL DEFAULT '',
    tenant_id    TEXT NOT NULL DEFAULT '',
    rate_limited INTEGER NOT NULL DEFAULT 0,
    trace_id     TEXT NOT NULL DEFAULT '',
    recorded_at  INTEGER NOT NULL DEFAULT 0   -- unix millis
);
CREATE INDEX IF NOT EXISTS idx_threat_executions_subject ON threat_executions(subject_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_threat_executions_action  ON threat_executions(action, recorded_at);
CREATE INDEX IF NOT EXISTS idx_threat_executions_type    ON threat_executions(threat_type, recorded_at);
```

`recorded_at` is wall-clock unix millis (the request time, like
`ChainHop.RecordedAt` at `chainstore.go:56–58`, NOT a token claim).

### Consistency, ordering, durability

- **Append-only**: no update/delete API. A record is immutable once written;
  `id` (AUTOINCREMENT) is the insertion order, `recorded_at` the advertised
  order. `List` orders by `recorded_at DESC, id DESC`, so two records
  written in one millisecond still have a deterministic order.
- **Write atomicity**: each `Record` is one INSERT; SQLite serializes
  writers (`busy_timeout` + `SetMaxOpenConns(1)`). A crash mid-write leaves
  either the full row or nothing (single-statement transaction).
- **Read-your-writes**: within one store instance, `Record` then `List`
  sees the row. Across replicas sharing the sqlite file, a List on replica B
  may lag a Record on replica A by the filesystem/page-cache propagation —
  there is no read barrier; the admin endpoint is an operator tool, and
  eventually-consistent visibility across replicas is the stated contract.
- **Multi-replica clock skew**: `recorded_at` comes from each replica's
  wall clock. Skew reorders rows across replicas (ties are broken by `id`,
  which is insertion order, not causal order). This is acceptable for
  forensics but is explicitly NOT a total cross-replica order (see residual
  risks). Detector-emitted threats carry a `TraceID` (`threat.TraceID`,
  populated by the anomaly runner from `event.TraceID`) so an investigator
  can group rows across replicas by trace.

### Failure modes

- **Store down during Record** → `RecordExecutionFailOpen` logs and
  swallows; the action result and audit event are byte-identical to the
  no-store case. This is the design's core invariant and gets an explicit
  `registry_test.go` assertion (failing stub store ⇒ result unchanged).
- **History store down during List** → admin endpoint 500s (fail-closed
  read). Acceptable: reads are operator-facing and must not return partial
  data; the write path is where fail-open matters.
- **Unbounded append-only growth** → no retention in scope; the audit
  retention scheduler (`RunAuditRetention`,
  `cmd/sso-server/serverbuildstore/build_background.go:217`) is the eventual
  precedent, but wiring it here is explicitly follow-on. Mitigations shipped
  now: the admin `limit` cap (1000) bounds single reads; the sqlite index
  set keeps filtered reads cheap. Document the growth tradeoff in
  `docs/observability.md`.
- **Replica crash between action and Record** → the history row is lost
  (the write happens after the action, best-effort). The audit event has
  the same property (async sink). Recovery: none needed — history is
  observability, and the counters (decision 1) still show the action.

### What could break the design

- **`recordAudit` signature change** ripples to 3 call sites in `registry.go`
  and any test touching the private method (none today — verified). The
  `rateLimited` bool is the only way the choke point can distinguish
  swallowed attempts; forgetting it at a call site silently mislabels
  history rows.
- **"Executions" naming vs. recorded attempts**: the endpoint records
  rate-limited and no-handler ATTEMPTS too (deliberate — forensics on
  swallowed actions). An operator reading the endpoint naively sees
  `ok:false, rate_limited:true` rows as "executions"; the field + docs must
  make the distinction explicit, and `docs/openapi.yaml`'s schema
  description must say so.
- **Budgets**: `registry.go` grows ~120 lines (301 → ~420, under 500);
  `admin.go` grows ~60 (185 → ~245); `sqlite/` +1 non-test file (2 → 3);
  `memory/` +1 (1 → 2); `domains/threataction` +1 (6 → 7). All under
  ceilings; no new `layerExemptions`.
- **Config drift**: a new knob means `docs/config-reference.md` must gain
  the `threat_action.history.*` rows in the same change (AGENTS.md §5
  contract rule); `make ci` validates it.
- **Fail-open creep**: the 500-on-List read path must not "helpfully" become
  fail-open during review — a silent empty history is worse than an error
  for an incident investigator. The asymmetry (fail-open write, fail-closed
  read) is the design and should be asserted in the handler test.
- **Cross-replica ordering drift**: do not add an application-level sequence
  counter to "fix" cross-replica ordering — there is no total order across
  replicas without a consensus leader, and history does not need one.
  Per-replica `id` monotonicity within the shared sqlite file is guaranteed
  by AUTOINCREMENT.

---

## Decision 3: real notification — honest `NotifyExecutor` wired into the existing notification pipeline

### Problem restated

`NotifyExecutor.Execute` (`actions.go`, end of file) fabricates success —
`OK: true`, "notification recorded for threat ...", zero side effects — and
the only artifact is the generic `threat_action_executed` audit event that
also fires for suspend/revoke/step-up, so "admin was notified" is
indistinguishable from "session was suspended" in the audit trail. The
platform's real delivery pipeline never sees threat events: `DefaultMappings`
(`router.go:116–128`) has no threat entry, `BuildNotifications` passes a nil
mapping (`serverbuildplatform/email_sender.go:81`) which resolves to
`DefaultMappings()`, and the local `EventThreatActionExecuted` string
(`threataction.go:124`) lives outside the canonical `auditspi` registry. A
policy author who sets `notify` believes an admin was alerted — misdirection
in a security product.

### API surface

`domains/threataction/actions.go` — local-interface SPI in the established
`FamilyRevoker`/`SubjectRevoker` style (local interfaces precisely so the
domain layer never imports `platform/lifecycle/notification`; the
composition root adapts):

```go
// Notification is the payload handed to a Notifier for one notify action.
type Notification struct {
    Threat Threat
    Policy ThreatPolicy
    Detail string
}

// Notifier delivers one threat notification. Defined locally (not importing
// platform/lifecycle/notification) to keep the domain layer free of upward
// imports toward platform — the composition root adapts.
type Notifier interface {
    Notify(ctx context.Context, n Notification) error
}

func NewNotifyExecutor(notifier Notifier) *NotifyExecutor
```

`Execute` semantics (all FAIL-OPEN, never blocks sibling actions):

- nil notifier → `ActionResult{ActionNotify, OK: false, Detail: "notify
  action not wired"}`, nil error — audited as a FAILURE, never a fabricated
  success.
- `n.Threat.SubjectID == ""` → `OK: false`, "no subject for notification" —
  the router cannot deliver a per-user notification without a subject, and
  `OK:true` would be the old lie in a new costume.
- notifier error → `OK: false` + the error (returned like the other
  executors return store errors; the registry logs it).
- success → `OK: true`, detail as today.

`platform/audit/auditspi/event_types.go` — new canonical type (the local
string in `threataction.go:124` is outside this registry today, which is
exactly why the router cannot reference it type-safely):
`EventThreatNotifyExecuted EventType = "threat_notify_executed"`.
Classified in `platform/audit/auditreport/control_areas.go` under CC7.2
("Anomaly and lockout monitoring", lines 158–170, the control area that
already holds `EventAnomalyDetected` at line 165) — AGENTS.md §4 requires
the classification in the same change; `make ci` validates it. Adding the
type to the `KnownEventTypes` filter-aid map (event_types.go, line 247+) is
optional (it is a filter/UX aid only, never consulted on the record path)
but cheap and consistent.

`domains/threataction/registry.go` `recordAudit` — event-type selection at
the choke point:

```go
if result.Action == ActionNotify {
    e.Type = audit.EventThreatNotifyExecuted
} else {
    e.Type = EventThreatActionExecuted
}
```

plus two meta additions shared by all threat events:
`MetaKeyThreatSeverity = "threat.severity"` (new const — needed for the
critical presentation, finding F2) and, for notify events only,
`MetaKeyThreatNotifyChannel = "threat.notify.channel"`, sourced from a tiny
optional interface on the handler (`interface{ Channel() string }`,
implemented by the cmd router adapter as `"router"`; absent → key omitted).
The generic `threat_action_executed` event keeps firing for
suspend/revoke/step-up/challenge — only notify splits off, making delivery
independently observable and routable.

`platform/lifecycle/notification/router.go` — `DefaultMappings()` gains
`audit.EventThreatNotifyExecuted: core.NotificationSecurityEvent`
(`shared/core/password_reset.go:146` — the existing target type for
`anomaly_detected`). `platform/lifecycle/notification/presentation.go` —
`auditEventPresentation` (line 19) gains a case:

```go
case audit.EventThreatNotifyExecuted:
    severity := core.NotificationWarning
    if event.Metadata[MetaKeyThreatSeverity] == "critical" {
        severity = core.NotificationCritical
    }
    return "Security threat detected",
        "A security response was triggered for your account: " + event.Metadata[MetaKeyThreatDetail],
        severity, true
```

Recipient resolution needs no new work: `eventSubject` (`subject.go:19`)
checks metadata keys `subject_id`/`user_id`/`target_user_id` first, then
falls back to `event.ActorID`, which `recordAudit` already sets to
`threat.SubjectID`. (The `threat.subject` meta key is NOT in the metadata
key list — the ActorID fallback is the path that resolves.)

Composition root — `BuildNotifications` (`serverbuildplatform/email_sender.go:51`)
changes return to `([]sso.Option, *notification.Router, error)`;
`wireEmailSenders` (`build_app_selfservice.go:145`, called at line 65 in
build order) stores `b.notificationRouter` (new appBuilder field).
`wireThreatAction` (finalize, runs AFTER `wireEmailSenders` — finding F3)
passes a `routerNotifier{b.notificationRouter}` adapter (nil router → nil
notifier) into `BuildThreatAction`:

```go
// routerNotifier adapts notification.Router to threataction.Notifier.
// Notify enqueues a threat_notify_executed event on the router's queue
// (Router.Record — public audit-sink method, router.go:207). The registry's
// recordAudit emission ALSO reaches the router via the auditor sink
// (applyAuditSinkTaps, sso.go:143/160) — the router's per-(subject,type)
// cooldown dedupes the duplicate enqueue; see finding F1 for the cooldown:0
// edge (SDK embedders only).
func (n *routerNotifier) Notify(ctx context.Context, ntf threataction.Notification) error
```

The notifier enqueue carries the same `threat_notify_executed` event shape
(meta keys included) so the router's mapping + presentation handle it
identically. `docs/notifications.md` mapping table (row 32) gains the row;
`docs/feature-matrix.md` threat row (line 69) gains the endpoint;
`docs/openapi.yaml` gains the endpoint schema (beside `threat-policies`,
line 7405).

### Failure modes

- **Notifications disabled + policy action `notify`** → nil notifier →
  `OK:false "notify action not wired"` → failure audit event + failure
  history row + `sso_threat_actions_total{action="notify",outcome="failure"}`.
  The misconfiguration is now visible on every surface instead of a green
  lie.
- **Queue full** → `Router.Record` (router.go:207) drops silently (observe
  "queue", "dropped") and returns nil — `Notify` reports success for an
  enqueue that never happened. Accepted: delivery is asynchronous by design;
  drops surface on the router's existing delivery metrics
  (`sso_notifications_delivery_failed_total`, `platform/metrics/consts.go:15`,
  documented at `docs/observability.md:19`). Document that notify `OK:true`
  means "enqueued", not "delivered".
- **Double enqueue** (finding F1) → the event reaches the router twice when
  notifications are enabled (notifier tap + auditor sink). Default 5-minute
  per-(subject,type) cooldown (`suppressed`, router.go:343; stock default
  from `config_load.go:229–230`) suppresses the duplicate delivery;
  `cooldown: 0` produces duplicate inbox rows + SSE events, but is reachable
  only via SDK embedding (`WithCooldown(0)`, router.go:31 — the stock config
  coerces 0 to 5 minutes). Mitigation decision: keep the spec's notifier tap
  (it makes the side effect explicit and testable independent of auditor
  wiring) and pin the cooldown dependency in the `test/` integration test;
  document the SDK-embedder `cooldown: 0` consequence in
  `docs/notifications.md`.
- **Subject-less threats** → notifier returns `OK:false "no subject for
  notification"` (above); the audit event still records the attempt.
- **Email sender unwired** → router delivers in-app only; existing behavior,
  unchanged.
- **Multi-replica duplicate delivery** (finding F5) → per-replica detectors
  (each replica runs its own anomaly runner and tokenanomaly sweeps) can
  execute the same logical threat on two replicas; the cooldown map is
  per-replica, so the second delivery is not suppressed. Accept at-least-once
  semantics; document in `docs/notifications.md`.

### What could break the design

- **Event-type split is a wire-visible change**: audit consumers/webhook
  filters matching `threat_action_executed` stop seeing notify executions
  (they keep seeing suspend/revoke/etc.). This is the point of the split,
  but it must be called out in `docs/error-codes.md`/`docs/observability.md`
  as a contract change, and the webhook e2e assertion in the `test/` suite
  must expect the new type. Note the selection is by ACTION, not outcome:
  a rate-limited or no-handler ATTEMPT for a notify policy also emits
  `threat_notify_executed` (with `Outcome: failure`) — a consumer filtering
  on the type sees attempts, exactly as decision 2 records them.
- **Canonical-event registration is a hard gate**: adding
  `EventThreatNotifyExecuted` to `auditspi` + `auditreport` in the same
  change is AGENTS.md §4; `make ci` validates it. Missing the classification
  fails the gate.
- **`DefaultMappings` + presentation must ship atomically**: a mapping
  without the presentation case delivers the generic "Security activity
  detected" fallback (works but loses the critical-severity signal); the
  presentation without the mapping is dead code. One commit, one test
  (`router_test.go` mapping assertion + presentation unit test).
- **`recordAudit` chokepoint coupling**: decisions 2 and 3 both edit
  `recordAudit`. The severity meta (new), the notify event-type selection,
  and the history write must not reorder such that the history record sees a
  different event type than the audit event — the record's `RateLimited`/
  `OK` must stay the source of truth for both.
- **Cooldown=0 duplicate deliveries** (F1) — the one genuine edge; the
  integration test should run with the default cooldown and the unit tests
  should pin the `suppressed` behavior (including the `cooldown == 0` early
  return at router.go:344). If a future reviewer prefers no duplicates under
  any config, the single-path variant (notifier as wiring gate only,
  delivery via the existing auditor-sink fan-out) is a strictly smaller
  change — but it ties `Notify`'s honesty to `applyAuditSinkTaps`' wiring,
  which SDK embedders may not replicate.
- **Budgets**: `actions.go` 334 → ~390 (rewrite + SPI, under 500);
  `registry.go` shares decision 2's growth (~420 total, under 500);
  `router.go` 395 → ~400 (one mapping row); `presentation.go` 71 → ~90.
  `BuildThreatAction` gains the notifier param — the same helper split as
  decision 1 keeps it under 50 lines.

---

## Distributed-systems analysis

### State map

| State | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Rate-limit windows (`te.rateLimit`, keyed `subject\0type\0action`) | `ThreatExecutors` (per process) | in-memory map + `sync.Mutex` (`registry.go:187–218`) | volatile | linearizable within the process; per-window counters, opportunistic eviction at 1024 entries | none — replica-local windows | restart rebuilds empty ⇒ windows reset (fail-open: throttling is advisory response pacing, never an auth decision) |
| Threat policy set | `ThreatPolicyStore` (memory or sqlite) | memory: map+RWMutex (`memory/policy_store.go:17`); sqlite: `threat_policies` table | memory: volatile; sqlite: durable | read-after-write per instance; boot seed + admin CRUD (`admin.go`) | memory: replica-local; sqlite: shared file | restart re-seeds from config (memory) or persists (sqlite); lookup failure falls back to `_default` policy (`registry.go:90`) |
| Execution history (NEW) | `ExecutionHistoryStore` | memory: append-only slice + RWMutex; sqlite: `threat_executions` + 3 indexes | memory: volatile; sqlite: durable (single-statement INSERT) | append-only, immutable rows; `recorded_at DESC, id DESC` per replica; cross-replica eventual visibility | memory: replica-local; sqlite: shared file, serialized writers | write: fail-open (log+swallow, result unchanged); read: 500 on store error, 404 when unwired |
| Router cooldown map (`r.recent`, keyed `subject\0type`) | `notification.Router` (per process) | in-memory map + mutex | volatile | per-replica; wall-clock windows | none | restart empties map ⇒ one duplicate delivery right after restart (see F5/guarantees) |
| Router delivery queue | `notification.Router` | bounded channel (default 256, `router.go:70`) | volatile | FIFO per worker; drops when full (observe "queue","dropped", returns nil) | none | queue loss on crash = lost notifications; counters still show drops |
| Audit record path (`recordAudit` → `Recorder.Record`, `recorder.go:143`) | `audit.Recorder` → MultiSink → AsyncSink(s) + router tap | sqlite sink / memory + webhook/SSE/CAEP sub-sinks | durable at the sink, asynchronous | best-effort; drops on full async queue (fail-open) | per-replica sinks | audit loss does not affect the action result; `sso_threat_*` counters and history are independent channels |
| Session state (suspend/step-up targets) | `core.SessionManager` | durable store (sqlite/redis backends) | durable | per-session; cross-replica via `KindSessionSuspended` bus events (`actions.go:96–115`) | invalidation bus (`cluster.Bus`, `bus.go:224`; memory or etcd via `BuildInvalidationBus`, `build_ratelimit_cluster.go:183`) | store outage ⇒ executor returns error (fail-open, audited + metric'd); bus outage ⇒ peer caches stale until their own invalidation path |
| Refresh-token families (revoke targets) | `RefreshTokenStore` (`FamilyRevoker`/`SubjectRevoker`) | durable store | durable | atomic family/subject delete | `KindTokenRevoked` bus events (`actions.go:209–226`) | store outage ⇒ `revoke_family` failure (fail-open, visible); family reuse still fails closed at the token endpoint |
| SSE broker | per-router | in-memory subscriber map | volatile | per-replica | none | subscribers reconnect; in-app rows persist in the inbox store |
| Threat counters (NEW) | `platform/metrics.Metrics` | in-process Prometheus registry | volatile | per-replica monotonic | none (scraped per target; aggregate with `sum(rate(...))`) | restart resets; alert on rate over windows longer than rolling restart |
| `TraceID` correlation | detector-originated (`event.TraceID`) | audit event + history row | — | — | — | the only cross-replica grouping key for threat rows |

Ownership boundaries: the `ThreatExecutors` composite owns the rate limiter
and the audit/history emission choke point; handlers own their side effects;
the router owns delivery; metrics own counters. No state is shared across
processes except (a) the optional sqlite policy/history files and (b) the
cluster bus events. The design adds no new cross-replica state: history is
append-only observability and must never become a coordination channel
(no "did another replica already handle this" checks — that is F5's
accepted at-least-once).

### Findings

**F1 — Notifications are double-enqueued when enabled; the cooldown dedupes under the default, but `cooldown: 0` (SDK embedders only) duplicates inbox rows.** Severity: Medium.
- Evidence (Verified): `applyAuditSinkTaps` (`interfaces/sso/sso.go:143`) calls `auditor.AddSink(s.notificationRouter)` at 160–161 whenever `WithNotificationRouter` is set, which `BuildNotifications` returns whenever `notifications.enabled` (`serverbuildplatform/email_sender.go:92`). The proposed `routerNotifier.Notify` calls `Router.Record` directly — a second enqueue of the same event. `suppressed` (router.go:343) dedupes under the 5-minute default. `config/config_load.go:229–230` coerces config `cooldown: 0` to 5 minutes, so the duplicate path is reachable only via `notification.WithCooldown(0)` (guard `value >= 0`, router.go:31) from an embedding SDK user.
- Triggering failure: notifications enabled + policy with `notify` action; the registry's `recordAudit` fan-out and the notifier tap both enqueue.
- User impact: duplicate inbox rows + duplicate SSE events per threat when an embedder sets cooldown 0; none under stock config (default cooldown suppresses).
- Recovery: automatic under default cooldown; for cooldown 0, an operator can only restart with a positive cooldown — no runtime switch.
- Corrective pattern: keep the explicit tap (testable honesty), document the cooldown dependency in `docs/notifications.md`, pin `suppressed` behavior in unit tests, and run the `test/` integration with the default cooldown asserting exactly one delivery. The single-path variant (notifier as wiring gate only) is the escape hatch if duplicates under any config become unacceptable — but it couples executor honesty to server sink wiring.

**F2 — Threat severity is absent from audit metadata, blocking the severity-aware presentation.** Severity: Low.
- Evidence (Verified): `recordAudit` (`registry.go:241–262`) sets `threat.type/action/subject/detail` + bounded evidence but no severity; `auditEventPresentation` (`presentation.go:19`) has no threat case; `Threat.Severity` exists (`threataction.go:38`).
- Triggering failure: none today (no threat presentation exists); it blocks Decision 3's "critical when severity is critical" case.
- User impact: without the fix, critical threats would render as generic "Security activity detected" warning.
- Recovery: n/a (design prerequisite).
- Corrective pattern: new `MetaKeyThreatSeverity = "threat.severity"` const + one `SetMeta` line in `recordAudit`; presentation case reads it. Ship atomically with the mapping row.

**F3 — Wire order is safe: the router exists before `BuildThreatAction` runs; one `appBuilder` field is needed.** Severity: Info (verification finding).
- Evidence (Verified): `wireEmailSenders` runs in build order (`build_app_selfservice.go:65`, `BuildNotifications` at 156); `finalize()` (`build_app.go:238`) calls `wireDetectionResponse` → `wireThreatAction` (`anomaly.go:54/87`) at line 244, after the router exists. `BuildNotifications` currently returns only `[]sso.Option` — the router must be returned to be stored on `b` (new field).
- Triggering failure: none.
- Corrective pattern: `BuildNotifications` returns `([]sso.Option, *notification.Router, error)`; `routerNotifier` adapter wraps `b.notificationRouter` (nil → nil notifier → honest `OK:false`).

**F4 — `recordAudit` is the shared choke point of all three decisions.** Severity: Info (structural).
- Evidence (Verified): every non-Noop branch — rate-limited (line 112), no-handler (120), executed (127) — funnels through the single private method at `registry.go:241`; no tests touch it directly today.
- Corrective pattern: fold both changes in — one new `rateLimited bool` param + event-type selection + severity meta — rather than parallel call sites; the history write and audit emission must share the same `RateLimited`/`OK` truth (guarantee G2).

**F5 — Multi-replica execution can deliver the same notification twice; cooldown is per-replica.** Severity: Medium.
- Evidence (Verified): detectors are per-replica — the anomaly runner dispatches on each replica's workers (`domains/anomaly/runner.go:225`) and each replica's tokenanomaly sweeps (`detector.go:419`); the cooldown map (`r.recent`) is process-local (router.go:350). Two replicas can independently execute the same logical threat (e.g. the same token-behavior finding observed by two replicas' sweeps).
- Triggering failure: multi-replica fleet, tokenanomaly finding observed on two replicas within one cooldown window.
- User impact: duplicate inbox rows + duplicate SSE events per subject/type; no security-control degradation (notification is advisory).
- Recovery: none needed for correctness; operators dedupe by `TraceID` in history/audit.
- Corrective pattern: accept at-least-once and document it; do NOT add cross-replica dedupe (would require a consensus leader — out of scope). The router's `enabled`/preferences path is unchanged.

**F6 — Rate limiting is replica-local: N replicas multiply the effective action budget.** Severity: Low.
- Evidence (Verified): `te.rateLimit` is an in-memory map (`registry.go:141`); no cluster coordination; the bus carries only revocation/suspension events.
- Triggering failure: a flapping detector on a 3-replica fleet fires a policy with `rate_limit.max: 2`; each replica allows 2 → 6 actions in the window.
- User impact: response amplification (more suspensions/revocations than the policy author intended). Direction is toward over-response, not under-response — fail-safe for security, noisy for users.
- Recovery: adjust `rate_limit` for fleet size; no runtime switch.
- Corrective pattern: document in `docs/config-reference.md` that rate-limit windows are per-replica (same caveat the anomaly rate limiter already carries); cluster-coordinated rate limiting is explicitly out of scope.

**F7 — The design's time bases are wall clock everywhere; rollback is safe-direction, roll-forward is not.** Severity: Low.
- Evidence (Verified): rate-limit windows `time.Now()` (`registry.go:187`); cooldown `r.now()` injectable (`router.go:352`); history `recorded_at` unix millis; audit timestamps stamped in `Recorder.Record` (`recorder.go:143`, `e.Timestamp = r.now()` at 148).
- Triggering failure: NTP step-back on one replica extends rate-limit and cooldown windows (delays actions/notifications — safe); NTP step-forward shortens windows (allows earlier actions, weaker dedupe — duplicates possible, matching F5's at-least-once).
- User impact: bounded; no token/session state depends on these clocks (refresh rotation and JTI replay use their own stores, unaffected).
- Recovery: NTP discipline; no code change.
- Corrective pattern: keep wall clock for operator-facing timestamps (correct semantics for forensics); never use these clocks for security decisions; do not add a hybrid monotonic column (cross-replica comparability is the point of unix millis).

### Scenario table

| Scenario | Decision-1 (metrics) | Decision-2 (history) | Decision-3 (notification) | Existing state affected |
|---|---|---|---|---|
| **Partition** (replica isolated; store/bus unreachable) | counters increment locally (correct: the action ran) | `Record` fails → logged+swallowed; action result unchanged (G1) | router still delivers locally (per-replica); bus events dropped (peer caches stale until heal) | revoke/suspend bus events lost during partition — peers converge via their own invalidation paths; rate-limit windows diverge (F6) |
| **Replica crash** mid-`Execute` | counters since last scrape lost (in-process) | row lost if crash precedes INSERT; audit has same property | queued notification lost (volatile queue) | sessions/revocations already applied are durable; the response itself is not rolled back |
| **Replica crash** after INSERT, before `List` | — | row durable; no partial row (single-statement transaction) | — | — |
| **Retry / duplicate delivery** (two replicas execute same threat; or notifier tap + sink fan-out) | counted twice — correct reflection of two executions | two rows, distinguishable by `trace_id` | cooldown dedupes same-replica duplicates under default; cross-replica duplicates reach inbox (F5); `cooldown: 0` SDK embeds duplicate (F1) | revocation/suspension executors are idempotent (`DeleteFamily`/`Destroy`), so re-execution is safe |
| **Clock rollback** (NTP step-back) | — | `recorded_at` backdated; rows may sort older than causally-later rows; `id` tiebreak keeps per-replica order | cooldown window extends → suppression longer than intended (safe direction) | rate-limit windows extend (F7); refresh/session stores unaffected |
| **Clock roll-forward** (NTP step-forward) | — | `recorded_at` future-dated; sorts first | cooldown expires early → duplicate delivery possible (F5/F7) | rate-limit windows shorten → early action allowance (advisory only) |
| **Stale cache** (peer replica's session cache) | — | — | — | `KindSessionSuspended`/`KindTokenRevoked` bus events invalidate peer caches (`actions.go:96–115`, `209–226`); bus outage leaves peers stale until their own invalidation paths; threat responses are NOT cache-gated |
| **Dependency outage** — history sqlite down | counters still move (independent channel) | write fail-open (G1); admin read 500 (G3) | — | — |
| **Dependency outage** — session/refresh store down | `outcome="failure"` visible immediately | `OK:false` row recorded | — | executor returns error; registry logs; fail-open |
| **Dependency outage** — audit sink down (async queue full) | — | history still records (independent channel) | router still receives the notifier tap (direct enqueue) even though the sink fan-out dropped | audit loss does not alter actions |
| **Dependency outage** — notifications disabled/unwired | `action="notify",outcome="failure"` | `OK:false "notify action not wired"` row | honest failure on every surface (the old fabricated success is gone) | — |
| **Recovery sequencing** (store returns after outage) | counters continuous across outage | writes resume; no backfill (missed rows stay missed — documented) | queue drains; cooldown map intact | invalidation-bus recovery is the existing server contract (re-subscribe + cache flush + revocation reseed before clearing degraded readiness) — threat subsystem is not in that path and does not need to be |

### Stated guarantees

- **G1 (history write is fail-open and side-effect-free)**: `RecordExecutionFailOpen` never returns an error and never changes the action result, audit event, or sibling actions. Nil store is a no-op. Asserted in `registry_test.go` with a failing stub store.
- **G2 (single truth for attempt classification)**: the audit event's `Type`/`Outcome` and the history row's `RateLimited`/`OK` derive from the same `ActionResult` at the same choke point (`recordAudit`). A rate-limited attempt is never recorded as an execution and vice versa.
- **G3 (read path is fail-closed)**: `List` errors surface as 500; unwired store surfaces as an unmounted route (byte-identical to a build without the feature). No partial or empty-as-success reads.
- **G4 (append-only, immutable)**: history rows are never updated or deleted; ordering is `recorded_at DESC, id DESC` with deterministic per-replica ties.
- **G5 (notify honesty)**: `OK:true` means "accepted for enqueue", never "delivered"; unwired notifier, missing subject, and notifier errors are all `OK:false` with a reason, and are visible on every surface (audit, history, metrics).
- **G6 (event-type split is per-action, not per-outcome)**: `threat_notify_executed` covers notify attempts (including rate-limited/no-handler attempts on notify policies); `threat_action_executed` continues for all other actions.
- **G7 (label cardinality bounded by construction)**: `action`/`outcome` closed sets; `severity` from detector-closed sets only; `policy` bounded by admin access.
- **G8 (fail-open boundary preserved)**: nothing in these three decisions becomes an authentication/authorization gate; response execution remains advisory-to-enforced per policy, and observability never decides an action (mirrors the anomaly "fail-open advisory" invariant).

### Unsupported topologies

- **Shared-file sqlite history over filesystems without POSIX advisory locking** (e.g. NFS without lockd, SMB): serialized-writer assumptions break. Supported: local disk, or a filesystem with reliable locking; otherwise use per-replica sqlite or memory.
- **Cross-replica rate-limit coordination**: not provided; per-replica windows (F6).
- **Cross-replica notification dedupe**: not provided; at-least-once delivery (F5).
- **`cooldown: 0` via stock config**: impossible by design (`config_load.go:229` defaults it); only SDK embedding can express it.
- **Cross-replica total ordering of history rows**: not provided and not needed; grouping is by `trace_id`.
- **History as a coordination channel**: explicitly unsupported; the store has no "did another replica handle this" query and must never gain one (would silently reintroduce a distributed decision point without consensus).
- **Retention**: not shipped in this change; unbounded growth is documented (audit-retention scheduler is the follow-on precedent).

### Validation tests

- `domains/threataction/registry_test.go`: each metric callback fires only on its own path (noHandler branch does not fire `executed`; rate-limit branch fires `rateLimited` once; `noop` policy fires `matched` only); nil-safe callbacks; `outcome` derived from `result.OK`; severity label from `threat.Severity`, not `policy.Severity`; failing history stub ⇒ action result unchanged (G1); `rateLimited` param correctness across the three call sites (G2); concurrent `Execute` from two goroutines under `-race` (anomaly + tokenanomaly call-shape) with `-count=10+`.
- `platform/metrics/metrics_test.go`: exact `sso_threat_*` wire strings; eager registration via `registerThreatMetrics` in the ctor list; zero-traffic without an executor.
- `domains/threataction/history_test.go` (new): memory store append/order/filter/limit; sqlite store roundtrip, filters, ordering ties, `SetMaxOpenConns(1)` single-writer; migrate-namespace isolation (`schema_migrations_threat_executions` separate from `threat_policies`); `List` with `limit <= 0`.
- `domains/threataction/admin_test.go`: nil store → 404; invalid `limit` → 400; store error → 500 (read fail-closed, G3); response shape.
- `platform/lifecycle/notification/router_test.go`: `DefaultMappings` contains `EventThreatNotifyExecuted`; presentation case returns `NotificationCritical` only when `threat.severity == "critical"`; `suppressed` pinned for default cooldown and for `cooldown == 0` (router.go:346).
- `test/` (package `ssotest`): notify e2e with default cooldown asserting exactly one inbox row + one SSE event (F1 pin); webhook e2e expecting `threat_notify_executed` for notify and `threat_action_executed` for suspend (G6, wire-visible split).
- Gates: `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .` after every `.go` edit; `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci` (validates `auditspi`/`auditreport` classification, config-reference rows, openapi, and module validation).

### Residual risks

- **Existing notify policies change meaning**: policies that assigned `notify` today produced a fabricated `OK:true`; after this change they produce honest `OK:false` until the stock binary wires the router (notifications enabled) or the embedder supplies a notifier. Existing audit history for those rows is not rewritten. Documented as the point of the change; operators with `notify` policies and notifications disabled will see failure counters immediately after upgrade.
- **`severity` label cardinality depends on detector discipline** (closed sets today: anomaly `info|warn|critical`, tokenanomaly `warn|critical`). A future detector emitting free-form severity grows the label; the review gate is the new detector's severity constants, enforced by the metrics test's bounded-label comment.
- **At-least-once notification delivery** across replicas and after restart (F1/F5): duplicate inbox rows are possible under embedder `cooldown: 0` and under multi-replica execution. No correctness impact; documented.
- **History gaps during store outage / crash window** (G1 recovery): missed rows are never backfilled; the counters are the completeness check.
- **Wall-clock dependence** (F7): roll-forward weakens dedupe and ordering; roll-back backdates rows. Bounded and safe-direction for security controls.
- **Unbounded growth** of memory (dev) and sqlite history: no retention in this change; `limit` caps reads; follow-on wiring to the audit retention scheduler.
- **`notify` success ≠ delivery** (queue drops are silent by design): operators must graph `sso_notifications_delivery_failed_total` alongside `sso_threat_actions_total{action="notify"}` to see the true delivery rate.
