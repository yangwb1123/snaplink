Design doc written to `docs/auto/domains-threataction-direction3-design.md`. All evidence re-verified against the tree before writing.

## What the doc contains

**`## Decision 1: response metrics`** — `WithMetricsCallbacks(matched, executed, rateLimited, noHandler)` on `ThreatExecutors` (anomaly's nil-safe stub pattern), four `sso_threat_*` counter vecs registered eagerly via `registerThreatMetrics`, `BuildThreatAction` gains a nil-safe `*metrics.Metrics` param with a mandatory helper split (32→50-line budget). Label cardinality bounded by construction: `severity` labeled from `threat.Severity` (detector-closed set), never `policy.Severity` (free-form).

**`## Decision 2: execution history`** — `ExecutionRecord` + `ExecutionHistoryStore` SPI (`Record`/`List` with subject/action/type filter), `WithExecutionHistory` option, fail-open `RecordExecutionFailOpen` mirroring `RecordHopFailOpen`. Storage model: memory (append-only slice) + sqlite with its own `migrate` namespace (`threat_executions` version table), columnar DDL + 3 `(field, recorded_at)` indexes, wall-clock unix-millis timestamps. Admin endpoint `GET /api/v1/admin/threat-executions` gated on store wiring, mounted beside the policy-CRUD block in `server_routes_admin.go`, independent `threat_action.history.backend/dsn` config knob.

**`## Decision 3: real notification`** — local `Notifier` SPI with `NewNotifyExecutor(notifier)` (nil → honest `OK:false "notify action not wired"`), canonical `EventThreatNotifyExecuted` in `auditspi` + CC7.2 classification in `auditreport`, one `DefaultMappings` row → `security_event`, a severity-aware presentation case, and a `routerNotifier` adapter at the composition root.

## Four design-level findings surfaced during verification

1. **The router is already an auditor sink** (`applyAuditSinkTaps`, `sso.go:161`) — the notifier tap plus registry emission double-enqueues; the 5-minute cooldown dedupes, but `cooldown: 0` yields duplicate inbox rows. Resolved explicitly with a documented edge + test pinning.
2. **Threat severity is absent from audit metadata today** — the "critical when severity is critical" presentation requires a new `threat.severity` meta key.
3. **Wire order is safe**: `BuildNotifications` runs before `wireThreatAction` in `finalize`, so one new `appBuilder` field carries the router.
4. **`recordAudit` is the shared choke point of all three decisions** — both history and event-type selection fold into it (one new bool param) rather than parallel call sites.

Each decision covers API surface, storage model, failure modes (including how to read the new counters), and what could break the design (budgets, wire-visible event-type split, fail-open creep on reads, cooldown edge, config-drift contract rules).
