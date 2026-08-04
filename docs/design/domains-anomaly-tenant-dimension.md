# Design: domains/anomaly — Tenant Dimension

Design for `docs/requirements/domains-anomaly-tenant-dimension.md`. All file/line
references were verified against executable code before writing. Scope is the
three improvements (dispatch + event model, tenant-scoped history stores, audit
sink + threat-executor bridge) plus the review-driven closures in this revision:
tenant-scoped trust-scorer reads (DB review High-1), the **wired retention loop**
(High-2 — the spec's direction #3 was a non-goal; the review closure supersedes
it), the guard truth table and executor/rate-limit tenant-scoping (security
F1/F3, DS F3), ctx-tenant-first dispatch resolution (security F2), and the
additive refusal callback (DB Medium-5). Direction #2 (dead
`detect/`/`signature/`/`fingerprint/` removal) remains a non-goal, but the dead
`detect/` package still compiles against the changed interfaces and must be
updated mechanically (see "What could break the design").

Data flow after the change:

```text
/auth/login → recordLoginFailure/Success
  → dispatchLoginAnomaly(ctx, tenantID, …)   # tenant resolved or best-effort
  → Runner.Dispatch(LoginEvent{TenantID})    # async, bounded queue
  → Detector.Inspect(ctx, event)             # queries stores with event.TenantID
  → Signal{TenantID}                          # runner backfills from event
  → Sink.Record (audit event stamped with tenant.id)
  → ThreatExecutor.Execute(Threat{TenantID}) # truth table: execute iff
                                              #   event.TenantID != "" && a.TenantID == event.TenantID
```

---

## Decision: `TenantID` on `LoginEvent` and `Signal`

**What.** Add `TenantID string` to `LoginEvent` (`domains/anomaly/types.go`) and
to `Signal`. Empty = tenant-less/legacy embedder, explicitly documented; detectors
skip tenant-scoped checks exactly as they do for empty `SubjectID` today.

**Why.** Tenant is structurally unreachable downstream today: `LoginEvent` carries
no tenant, so neither detectors, nor the sink, nor the threat bridge can be
tenant-aware without guessing. The event model is the one missing link for
*labeling* — audit, stores, and the `Threat.TenantID` field. It is **not** a
missing link for *executor scoping*: `threataction.Threat.TenantID`
(`domains/threataction/threataction.go:50-51`) is defined but read by **no**
executor today — `SuspendSessionExecutor` calls `sessions.ListByUser(ctx,
threat.SubjectID)` and `RevokeFamilyExecutor` calls
`DeleteAllForSubject(ctx, threat.SubjectID, threat.ClientID)`, both subject-
scoped (verified: the only `TenantID` mentions in `domains/threataction/` are
the struct field and its comment). This design therefore delivers
**tenant-correct labels and guarded execution**, not tenant-scoped actions;
the action-layer gap is the accepted residual in the threat-bridge decision
below (gate finding SEC-F1).

**Surface.**

```go
type LoginEvent struct {
    TenantID string // empty = tenant-less/legacy embedder
    // … existing fields unchanged
}
type Signal struct {
    TenantID string // detector-resolved; empty → runner backfills from event
    // … existing fields unchanged
}
```

**Backfill rule (single point).** In `Runner.inspect` (`domains/anomaly/runner.go`),
before sink and threat bridge: `if a.TenantID == "" { a.TenantID = event.TenantID }`.
`a` is a per-inspection range copy, so mutation is race-free (runner already runs
`-race` clean). Backfilling once at the runner boundary means sink and executor
always observe the same value; `NewRecorderSink` additionally falls back to
`event.TenantID` when stamping (mirror of the existing `ActorID` fallback in
`sink.go`), so a custom Sink that bypasses the runner never loses the event's
tenant either.

`Runner.Dispatch` and `Detector.Inspect` signatures are unchanged — the tenant
rides the event. No new option knobs.

**Acceptance.** Event with tenant "t1" through the runner reaches detectors and
sink with `TenantID == "t1"`; a detector leaving `Signal.TenantID` empty gets it
backfilled.

---

## Decision: `dispatchLoginAnomaly` gains a tenant param; failure paths resolve best-effort

**What.** Change `dispatchLoginAnomaly(ctx, subjectID, clientID, provider, outcome,
failureReason)` (`interfaces/sso/server_helpers.go:298`) to
`dispatchLoginAnomaly(ctx, tenantID, subjectID, clientID, provider, outcome,
failureReason)`. The two callers:

- Success: `recordLoginSuccess` gains a `tenantID string` param. Two of its
  four call sites hold the resolved `*Client` and pass `client.TenantID`:
  `mintAndRecordDirectLogin` (`server_login_client.go:397`) and
  `recordCodeFlowSuccess` (`server_finish_login.go:434`). The other two have
  only `clientID` and pass `""`, falling through to the same best-effort
  resolution as the failure path: the exported SDK accessor
  `Server.RecordLoginSuccess` (`accessors_handlers.go:177`, silent renewal /
  CIBA / device grants), and the `BuildHandlerDeps` closure
  `d.RecordLoginSuccess` (`accessors_handlers.go:330`; the field is declared
  as `handler.ServerDeps.RecordLoginSuccess` at `internal/handler/serverdeps.go:153`
  and has no in-repo callers today — see DS finding F2).
- Failure: `recordLoginFailure` signature stays unchanged (~30 call sites, many
  where client resolution itself failed). It passes `""`; `dispatchLoginAnomaly`
  resolves best-effort in priority order (gate finding SEC-F2):
  1. **Ctx-resolved tenant first** — `TenantFromHandlerContext(ctx)` (the tenant
     middleware's `*Resolved{Tenant, Domain}` stashed on `HandlerContext`,
     `domains/tenant/middleware.go:36-45`). This is the authoritative isolation
     boundary: garbage/unknown-`client_id` sprays — the traffic
     `BruteForceShadowDetector` exists for — stay in the *routed* tenant's
     partition instead of aggregating in the shared `""` partition, and no
     store read is needed on tenant-routed deployments.
  2. **`clientStore.Get` fallback** when no ctx tenant — via
     `s.clientStore.Get(ctx.Request().Context(), clientID)` → `client.TenantID`
     (note: `HandlerContext` is a value bag, not a `context.Context`; the read
     uses the request context, so a client disconnect mid-resolution cancels
     it — fail-open to `""`, accepted). This mirrors the existing
     `tenantLabel(ctx, clientID)` resolution on the exact same paths
     (`interfaces/sso/server_tenant.go:437-449`), which is the in-repo
     precedent for client-side resolution; the two should eventually be
     unified (out of scope).
  3. `""` when both are absent. Nil/error → tenant stays `""`, anomaly still
     dispatched.
  The mismatch risk between (1) and (2) is nil: handlers already reject flows
  whose routed tenant differs from the client's tenant (`ErrTenantMismatch`).

**Why.** Success paths have the resolved `*Client` in scope; plumbing `TenantID`
through 30 failure call sites is churn and several of those sites fail *because*
client resolution failed, so they have nothing to pass. One resolution point
inside `dispatchLoginAnomaly` (after the `s.anomalyRunner == nil` short-circuit, so
no store read when no runner is wired) is uniformly correct and keeps the failure
path fail-open: a store outage degrades to tenant-less dispatch, never a dropped
anomaly and never an error surfaced to the login response.

**Cost note.** Zero store reads on tenant-routed deployments (ctx tenant wins);
one `clientStore.Get` per failed login only on deployments *without* the tenant
middleware, plus per success event from the two clientID-only success paths
(the exported `RecordLoginSuccess` accessor and the `BuildHandlerDeps`
closure), on runner-wired servers. All are single indexed PK reads on
already-heavy paths; direct-mint and code-flow successes pass the resolved
client's tenant for free. The closure is currently dead in-repo (no callers of
`deps.RecordLoginSuccess` in `internal/handler`), so today the accessor is the
only live clientID-only success path. If this ever shows up in profiles, the
resolution can move into the runner's worker goroutine, but that would move
the store dependency off the dispatch site — not done now.

**Acceptance.** Unit test at `interfaces/sso`: events from
`recordLoginSuccess`/`recordLoginFailure` carry the resolved client's tenant;
tenant-less client → empty, no panic; runner-less server → no store read.

---

## Decision: `RecentLoginStore` becomes tenant-scoped

**What.** Change `domains/anomaly/recent_login.go`:

```go
type RecentLoginStore interface {
    Append(ctx context.Context, entry *LoginEntry) error              // unchanged
    Recent(ctx context.Context, tenantID, subjectID string, since time.Time, limit int) ([]*LoginEntry, error)
    PruneOlder(ctx context.Context, cutoff time.Time) (int64, error)  // unchanged (global retention)
}
type LoginEntry struct {
    TenantID string
    // … existing fields unchanged
}
```

`Append` validation unchanged: empty `SubjectID` still rejected with
`ErrInvalidLoginEntry`; empty `TenantID` allowed (the `""` partition, see the
empty-tenant decision).

**Why.** `Recent`/`Append` are keyed by `SubjectID` alone (`recent_login.go:69`,
SQLite index `(subject_id, ts_unix_ns DESC)`), and failure-path `SubjectID` is the
*attempted* identifier — same-name users in different tenants share one key space
today. Tenant must be part of the key, not a filter applied after the fact.

**Detector updates (live).** `infrastructure/defaultimpl/detectors/`
`impossible_travel.go:159,179`, `new_baseline.go:114,209`, `velocity.go:116` pass
`event.TenantID` into `Recent` and set `entry.TenantID = event.TenantID` on
`Append`. `domains/anomaly/detect/velocity.go:67` (dead code, must compile) gets
the same mechanical change.

---

## Decision: `IPFailureCounter` becomes tenant-scoped

**What.** Change `domains/anomaly/ip_failure_counter.go`:

```go
type IPFailureCounter interface {
    Record(ctx context.Context, tenantID, ipHash, subjectID string, ts time.Time) error
    Count(ctx context.Context, tenantID, ipHash string, since time.Time) (total int, distinct int, err error)
    PruneOlder(ctx context.Context, cutoff time.Time) (int64, error)  // unchanged
}
```

`Record` keeps its empty-`ipHash` no-op. Detector update:
`brute_force_shadow.go:124,132` passes `event.TenantID`; dead-code
`detect/credential_stuffing.go:56` gets the mechanical change.

**Why.** The counter aggregates by `ipHash` alone — one egress IP shared by two
tenants (NAT, hosted attacker) contaminates both tenants' spray baselines. The
`ip_failure_counter.go` doc comment already admits counters are IP-keyed; tenant
partitioning sits above the hash.

**Salt scheme unchanged.** The per-deployment salt already scopes the hash space
to one deployment; tenant partitioning happens above the hash, so no salt
change and no re-hash of existing rows.

---

## Decision: SQLite storage model — `tenant_id` column, tenant-leading indexes, v2 migration

**What.** `infrastructure/defaultimpl/sqlite/recent_login.go` and
`ip_failure_counter.go`:

```sql
-- recent_logins: add
tenant_id TEXT NOT NULL DEFAULT ''
-- replace idx_recent_logins_subject_ts (subject_id, ts_unix_ns DESC) with
idx_recent_logins_tenant_subject_ts (tenant_id, subject_id, ts_unix_ns DESC)
-- keep idx_recent_logins_ts (ts_unix_ns) for PruneOlder

-- ip_failures: add
tenant_id TEXT NOT NULL DEFAULT ''
-- replace idx_ip_failures_ip_ts (ip_hash, ts_unix_ns) with
idx_ip_failures_tenant_ip_ts (tenant_id, ip_hash, ts_unix_ns)
-- keep idx_ip_failures_ts (ts_unix_ns) for PruneOlder
```

Queries become `WHERE tenant_id = ? AND subject_id = ? [AND ts_unix_ns >= ?]
ORDER BY ts_unix_ns DESC LIMIT ?` (and the `COUNT`/`COUNT(DISTINCT …)` analog for
`ip_failures`). Scans add `tenant_id` to SELECT/INSERT/column lists.

**Migration mechanics.** Convert both stores from `ensureSchema` (one-shot v1
baseline) to an explicit `migrate.Run` with a migration slice, following the
`refresh_tokens` precedent (`refresh_tokens_schema.go` v3–v7: backfill
`Func` migrations that no-op on fresh DBs whose baseline DDL already carries
the columns): v1 baseline DDL
*already contains* the new column + indexes (fresh DBs skip the backfill), and a
v2 `Func` migration (`addRecentLoginTenantColumn`, `addIPFailureTenantColumn`)
does the idempotent work for pre-existing DBs:

- `ALTER TABLE … ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''` guarded by a
  `PRAGMA table_info` presence check (SQLite has no `ADD COLUMN IF NOT EXISTS`);
- `CREATE INDEX IF NOT EXISTS` for the new tenant-leading indexes;
- `DROP INDEX IF EXISTS` for the old cross-tenant indexes, after the new indexes
  exist (create-then-drop means the table is never without a usable index).

**Boot-time version check (spec gap — required).** `RecentLoginMaxVersion()` and
`IPFailureCounterMaxVersion()` (`infrastructure/defaultimpl/sqlite/maxversions.go`)
currently hardcode `1` and feed `CheckSQLiteSchema` at boot
(`cmd/sso-server/build_app_selfservice.go:432,439`). They must return
`migrate.MaxVersion(recentLoginMigrations)` / `migrate.MaxVersion(ipFailureMigrations)`
(= 2) in the same change, or a forward-migrated DB fails `ErrSchemaTooNew` against
the new binary. Namespace strings (`"recent_login"`, `"ip_failure_counter"`) stay
identical so the existing `schema_migrations_*` version rows are honored.

**PruneOlder stays global.** Retention is per-store, not per-tenant — the spec
explicitly keeps `PruneOlder(ctx, cutoff)` and both ts indexes. This is accepted:
retention windows are deployment policy, and a global sweep is strictly simpler
than per-tenant sweeps for no correctness benefit (old rows are dead in every
tenant). The scheduler that calls it is wired in this revision (see the
retention decision).

**Acceptance.** `EXPLAIN QUERY PLAN` for the `Recent` shape selects the
tenant-subject index (backward scan); an upgrade test constructs the pre-migration
schema (old DDL + v1 stamp), opens the store, and proves the column + indexes
exist and old rows default to `tenant_id = ''`.

---

## Decision: Memory storage model — composite keys

**What.** `infrastructure/defaultimpl/memorystorecredential/memory_recent_login.go`
and `memory_ip_failure_counter.go` switch from `map[subjectID]…` / `map[ipHash]…`
to composite keys `tenantID + "\x00" + subjectID` / `tenantID + "\x00" + ipHash`.
`PruneOlder` iteration is unchanged (walks all buckets, drops empty ones).

**Why.** A composite key string with a NUL separator is the in-repo precedent
(`threataction.RateLimitKey`: `subject + "\x00" + type + "\x00" + action`) and
avoids nested-map allocation on every Append. `"\x00"` cannot appear in tenant IDs
(they come from `core.Client.TenantID` / domain identifiers), so the key space is
collision-free. Empty tenant becomes its own `""` partition.

---

## Decision: empty `TenantID` is a first-class "tenant-less" partition

**What.** Everywhere a tenant can be empty — event, entry, store query, audit
event — empty is a documented, valid mode: single-tenant embedders and tests keep
byte-identical behavior. In both stores it is simply the `""` partition: entries
written with `""` are only read back by queries with `""`.

**Why.** The spec's backwards-compatibility clause. Multi-tenant correctness must
not regress single-tenant deployments; partitioning (not rejection) of empty
tenants is the only design that satisfies both. This is *not* a fail-open hole:
cross-tenant leakage requires two *different* tenant IDs, and the stores never
coalesce `""` with a non-empty tenant.

---

## Decision: trust-scorer lookups become tenant-scoped (composition root)

**What.** Thread the tenant through the trust pipeline (gate finding DB-H1,
missed by the security and distributed reviews — the design's compile-break
inventory listed live detectors and the dead `detect/` package but not the
composition-root adapters). Three coordinated changes:

- `shared/trust.TrustSignals` gains `TenantID string`; `buildTrustSignals`
  (`interfaces/sso/server_login_client.go:327`) populates it with the **same
  priority order as dispatch** (SEC-F2): routed ctx tenant first
  (`TenantFromHandlerContext`), then `client.TenantID`, then `""`. All three
  `Score` call sites (`server_login_client.go:298,368` and the passkey-risk
  site `accessors_feature_gates.go:208`) share this builder, so one population
  point covers them — no new resolution is needed. Client-first would reopen
  the cold-start hole: a tenant-less client (`Client.TenantID == ""`) on a
  tenant-routed deployment writes events under the ctx tenant (dispatch
  SEC-F2) but would make trust read the `""` partition — the exact
  `no_signal` regression this decision closes.
- `trust.IPFailureLookup.CountFailures(ctx, tenantID, ip, since)` and
  `trust.LoginHistoryLookup.History(ctx, tenantID, subjectID, limit)` gain a
  tenant parameter.
- The two adapters in `cmd/sso-server/serverbuildplatform/build_trust.go`
  (`:189` `a.counter.Count(...)`, `:215` `a.store.Recent(...)`) pass it
  through; the in-package memory test doubles gain the param too.

**Why.** Without this, the change is a **silent tenant-blind regression** on
multi-tenant deployments: the adapters receive bare `ctx.Request().Context()`
(the tenant middleware stashes `*Resolved` on `HandlerContext`, not on
`r.Context()`), so after the store change they can only read the `""` partition
— which on a tenant-routed deployment receives zero writes. The `ip_reputation`
and `behavior` scorers would cold-start to `no_signal` on every login, and since
trust feeds enforced conditional access (`access_policies.enforce`), that
silently changes authorization behavior. It is also a plain compile break.

**Acceptance.** Regression test: t1 events never yield a t2 or `""`-partition
trust read (recording lookup doubles asserting the tenant argument).

## Decision: audit sink stamps tenant from the event

**What.** `NewRecorderSink` (`domains/anomaly/sink.go`) sets
`e.TenantID = a.TenantID` (fallback `event.TenantID`) and
`audit.SetMeta(e, "tenant.id", …)` when non-empty, mirroring
`EnrichTenant`'s metadata vocabulary (`platform/audit/handler_helpers.go:62-69`)
minus the keys that are unreachable off-path (`tenant.slug` and `tenant.domain`
both need the tenant middleware's routing result; the runner runs on
`context.Background()`).
Empty tenant → no tenant fields, byte-identical to today.

**Why.** Anomaly events are async and off the request path, so the canonical
ctx-routing enrichment (`EnrichTenant`) can never run for them; the sink is the
only place the tenant can be stamped, and it must come from the event itself.
Without this, cross-tenant false positives land in the wrong tenant's audit trail
and the existing `tenant_id` audit query filter silently misses them.

---

## Decision: threat-executor bridge copies `TenantID` and refuses empty/mismatched execution

**What.** In `Runner.inspect`, the `threataction.Threat` construction
(`runner.go:216-227`) gains `TenantID: a.TenantID` (post-backfill). Guard before
`Execute`, defined as an explicit truth table (gate finding SEC-F3):

| event tenant | signal tenant (post-backfill) | action | reason |
|---|---|---|---|
| `"t1"` | `"t1"` | **execute** | — |
| `"t1"` | `"t2"` | refuse | `tenant_mismatch` |
| `""` | `""` | refuse | `empty_tenant` |
| `""` | `"t2"` | refuse | `empty_tenant` |

i.e. **execute ⟺ `event.TenantID != ""` ∧ `a.TenantID == event.TenantID`**
(post-backfill). The fourth cell — a detector-claimed tenant on a tenant-less
event — is refused, not executed: the design's rationale (an unsupported
tenant claim is how a wrong-tenant action slips through) covers it, the metric
reasons already cover it (`empty_tenant`), and no in-tree detector resolves
its own tenant, so nothing legitimate loses execution. The signal still
reaches the sink in every cell — the guard gates the *response*, never the
*report*. `WithThreatExecutor`'s option comment documents that threat
execution is guarded by `Signal.TenantID`.

**Why.** Executors are **subject-scoped, not tenant-scoped** (verified — see
the first decision's Why): `SuspendSessionExecutor` → `sessions.ListByUser(
ctx, threat.SubjectID)` (SQLite filters only `user_id`, `revoked`, `expires_at`;
`ListByTenant` exists but is unused), `RevokeFamilyExecutor` →
`DeleteAllForSubject(ctx, threat.SubjectID, threat.ClientID)`
(`refresh_tokens` has **no `tenant_id` column**), and
`StepUpMFAExecutor`/`ChallengeExecutor` are subject-only too. The guard is
therefore a **label-integrity control**: it prevents execution under an empty
or unsupported tenant claim, and it surfaces routing regressions via the
metric. It does **not** make a correctly-resolved execution tenant-isolated —
see the accepted residual below.

**Deliberate behavior change.** Today the runner executes with `Threat.TenantID`
always `""`. After this change, a legacy single-tenant embedder whose events carry
no tenant gets audit-only behavior (no executor invocation). The spec accepts
this ("fail-open audit-only for legacy embedders"); document it in the option
comment and release notes. Any embedder wanting automated response must now
provide tenant context — which tenant-routed `sso.Server` deployments do
automatically via the dispatch change.

**Accepted residual (gate finding SEC-F1).** The design's original premise —
"executors are already tenant-scoped" — is **false**, and the original
cross-tenant test ("t1 spray never yields `Threat.TenantID == "t2"`") asserts
only the threat's *label*, not the action's *target*. Executor action remains
subject-scoped: a correctly-resolved t1 anomaly on a subject shared with tenant
t2 (email/phone-derived subject IDs make this routine) still suspends/revokes
that subject in **every** tenant. No regression versus today (executors were
always subject-scoped), but the guard does not provide cross-tenant action
isolation in the normal resolved case. Blast-radius note: failure-path threats
carry `SubjectID == ""` (`recordLoginFailure` passes `""` at
`server_helpers.go:286`, and `BruteForceShadowDetector` copies `event.SubjectID`
into the signal), and the executors no-op on empty subjects (`ListByUser("")`
returns no rows; `DeleteAllForSubject("")` early-returns) — so the residual is
reachable only via success-path detectors (impossible travel, velocity,
new-baseline). **Disposition:** accept and document, with mitigations (a)
tenant-qualified subject IDs in multi-tenant deployments, and (b) executor-layer
tenant scoping as a follow-up change: the sessions half is cheap (`ListByTenant`
already exists — intersect or add `ListByUserTenant`), but the refresh-family
half requires adding `tenant_id` to `refresh_tokens` (a central OAuth table with
its own migration and wire-contract review — deliberately out of scope here).
The follow-up's acceptance test: t1 spray on a subject shared with t2 → **zero**
t2 sessions destroyed and **zero** t2 refresh tokens deleted, via recording
`SessionManager`/`FamilyRevoker` doubles.

---

## Decision: refusal is observable — warn log + bounded metric

**What.** Add an additive option `WithThreatSkippedCallback(func(reason string))`
(gate finding DB-M5) that arms a `threatSkipped` callback on `metricsCallbacks`
(`runner.go`); the existing `WithMetricsCallbacks` signature is **unchanged**
(avoiding a 5th-param SDK break for embedders — the repo's additive-option
pattern, e.g. `WithClientStoreCache`, `interfaces/sso/options.go:290`). Wire a
new counter `sso_anomaly_threat_skipped_total{reason}` with `reason ∈
{empty_tenant, tenant_mismatch}` in `platform/metrics/` (consts, ctor, struct)
and `anomalyRunnerOptions` (`cmd/sso-server/anomaly.go`, the function that
begins at line 175).

**Why.** A silent refusal would hide misconfigurations (e.g., a tenant-routing
regression that empties every event's tenant would silently disarm all automated
response). Two bounded label values keep cardinality in line with the package's
other anomaly counters. The first refusal per reason should also log at
error level (not just warn) so the tripwire is visible even where the metric is
not watched.

---

## Decision: anomaly retention scheduler is wired (DB review High-2)

**What.** `config.AnomalyRetentionConfig` (`config/config_anomaly.go:88-93`)
and `anomaly.retention.*` (`cmd/sso-server/config.yaml:1767-1773`) currently
have **zero consumers** — `rt.recentLoginAge`/`rt.ipFailureAge`
(`cmd/sso-server/anomaly.go:37-38`) are written and never read, no goroutine
calls `PruneOlder` on either store, and the memory stores' docs promise
eviction "on the next PruneOlder" that never comes. Both stores grow unbounded
(every success *and* failure row; subject-count-unbounded memory maps). The
final gate accepted this as a residual with a follow-up; this revision
**resolves** it (the requirement: wire pruning or fail loud on
`anomaly.retention.enabled` — wiring is the option that leaves no dead knob
and no unbounded store):

- In `buildAnomaly`, when `cfg.Retention.Enabled`, start a prune loop mirroring
  `startAuditRetention` (`cmd/sso-server/build_app_core.go:315`): a ticker
  goroutine at `interval` (0 → 1h) that calls `PruneOlder(ctx, now-age)` on
  **both** stores — `rt.recentStore` and `rt.ipFailCounter`, memory or SQLite
  (both backends implement `PruneOlder`; unlike audit's sqlite-only sink, no
  backend assert is needed). Ages: `recent_login_age` 0 → 90d, `ip_failure_age`
  0 → 2h — the defaults the config comments already document. A prune error is
  logged and the loop continues — fail-open: retention must never take down
  detection.
- Lifecycle: `anomalyRuntime` gains `retentionCancel`/`retentionDone`;
  `rt.close` (`cmd/sso-server/anomaly.go`, called at `main_shutdown.go:165`)
  cancels and joins the loop in the order **runner → retention → SQLite
  handles**, so a prune can never race the store teardown.
- Opt-in (`enabled: false` in the shipped config) — default deployments are
  byte-identical; the knob stops lying. `docs/config-reference.md` gains the
  `anomaly.retention.*` knobs in the same change (currently undocumented —
  config/code drift per AGENTS.md §1).

**Why.** Unbounded growth on exactly the stores this design partitions is an
ops defect, and the scaffolding already presupposes the loop: the runtime's
`recentLoginAge`/`ipFailureAge` fields are commented "for retention
scheduler", and both ts indexes are kept "for PruneOlder". Wiring also makes
the failure-mode table's `PruneOlder` rows real instead of hypothetical.

**Acceptance.** Loop test with a ~10ms interval prunes expired rows from both
stores (memory + SQLite) and exits cleanly on cancel; `retention.enabled=true`
with default ages boots; `close` joins the goroutine (`-race -count=10`, no
leak). Encoded as T13.

---

## Failure modes

| Failure | Behavior | Class |
|---|---|---|
| `clientStore.Get` errors on the failure path | Tenant `""`, anomaly still dispatched, no error to caller | fail-open (spec: best-effort) |
| Tenant-routing regression empties event tenants | All signals audit-only; `sso_anomaly_threat_skipped_total{reason="empty_tenant"}` rises — the metric is the tripwire | fail-closed on action, observable |
| Buggy detector sets a tenant different from the event | Threat refused (warn + `tenant_mismatch`); signal still audited | fail-closed on action |
| SQLite migration fails (disk, lock) | Store constructor error → `wireAnomaly` error → boot fails, same as every other store; no partial serving | fail-closed at boot |
| Old binary boots against forward-migrated DB | `CheckSchema` → `ErrSchemaTooNew` (only if the max-version funcs were bumped; see the gap above) | fail-closed, intended canary-rollback guard |
| Concurrent replicas start against one DB | `migrate.Run`'s single `BEGIN IMMEDIATE` transaction serializes; the *version-stamp* race loses and no-ops on `busy_timeout`; an **in-progress v2 index build** on a large table can exceed `busy_timeout` and fail that replica's boot (gate finding DS-F4) — retryable, idempotent, fail-closed | safe; prefer rolling replica restarts on migration day |
| Replica clock skew (pre-existing, gate finding DS-F5) | A fast-clock replica's entries get future timestamps that `since` windows exclude (missed signals), and a fast-clock global `PruneOlder` can delete rows lagging replicas still need (truncated history) | fail-open; NTP discipline; unchanged by the tenant dimension |
| Store outage mid-detection | Detector error → warn + `inspect_errors_total`, event dropped, login path untouched | fail-open (existing contract) |
| Upgrade transition on multi-tenant deployments (gate finding DB-M4) | Legacy rows stay in the `""` partition (no backfill possible — cross-DB client join); ≤1h lost spray volume, up to 90d lost baseline → transient fresh-signals up to the 7d bootstrap grace | accepted, release-noted |
| `PruneOlder` during tenant migration | Index create-then-drop ordering keeps a usable index at every instant; retention is tenant-blind by design; the wired scheduler (retention decision) and a migration are independent | safe |
| Retention prune loop fails | Prune error logged, loop continues; growth resumes until the next successful prune | fail-open (retention never gates detection) |
| Cross-tenant subject-scoped action (gate finding SEC-F1, accepted residual) | A correctly-resolved t1 anomaly on a subject shared with t2 still acts on the subject in every tenant (executors are subject-scoped); guarded refusal only covers empty/mismatched labels. Success-path detectors only (failure threats carry empty subject → executor no-op) | pre-existing behavior, documented + release-noted; follow-up = executor tenant scoping |
| Hash collision between tenants | Impossible by construction: partition key is the tenant ID itself, not a hash of it | safe |

## What could break the design

1. **Embedder interface break (wire contract).** `RecentLoginStore.Recent` and
   `IPFailureCounter.Record/Count` change signatures; `WithMetricsCallbacks` is
   **unchanged** (the threat-skip metric uses the additive
   `WithThreatSkippedCallback` option instead — gate finding DB-M5). In-repo
   implementations, tests, and the **composition-root trust adapters**
   (`cmd/sso-server/serverbuildplatform/build_trust.go:189,215` — gate finding
   DB-H1) are all updated in one commit per AGENTS.md §5; embedder-facing SPI
   docs (package comments) must be updated in the same change. `PruneOlder`
   unchanged everywhere limits the blast radius.
2. **Dead `domains/anomaly/detect/` still compiles.** `detect/velocity.go`,
   `detect/credential_stuffing.go` call the changed interfaces. They are dead
   code (removal is a non-goal) but `go build ./...` fails if they're missed —
   they must get the same mechanical tenant-threading as the live detectors.
3. **Missed max-version bump.** Forgetting `RecentLoginMaxVersion()` /
   `IPFailureCounterMaxVersion()` (both currently hardcoded `1`) makes the new
   binary refuse its own forward-migrated DB at boot. This is the one integration
   the requirements spec does not mention.
4. **`recordLoginSuccess` param churn.** Four call sites: two with the resolved
   `*Client` (pass `client.TenantID`), plus the exported SDK accessor
   `RecordLoginSuccess` and the `BuildHandlerDeps` closure `d.RecordLoginSuccess`
   (both clientID-only, both relying on dispatch-side best-effort resolution).
   Both clientID-only paths must stay wire-compatible; future success paths must
   pass the tenant — compile-time enforced, and the param ordering (tenant first)
   must stay consistent with `dispatchLoginAnomaly`.
5. **Failure-path resolution cost.** Zero store reads on tenant-routed
   deployments (ctx tenant wins); one `clientStore.Get` per failed login only
   without the tenant middleware, on runner-wired servers. Negligible today;
   the dispatch decision documents the fallback (resolve in the worker) if it
   ever shows up in profiles.
6. **Detector tenant override.** A detector that resolves its own tenant (from a
   lookup, not from the event) is refused by the guard truth table when the
   event carries no tenant (`empty_tenant`) or a different one
   (`tenant_mismatch`) — fail closed on the action, signal still reaches audit,
   warn log names the detector. Custom detectors must therefore derive their
   `Signal.TenantID` from the event.
7. **EXPLAIN QUERY PLAN test fragility.** SQLite's planner may choose the ts
   index for extreme `tenant_id=''` queries if table stats are odd; the test
   should assert the tenant-subject index for the canonical query shape and use
   plan-text containment, not exact match. The `ORDER BY ts DESC` matches the
   index's `DESC` declaration, so a backward scan is expected.
8. **Audit event shape change.** Multi-tenant deployments get `tenant.id` meta +
   first-class `TenantID` on anomaly events — additive; OCSF projection and
   `tenant_id` query filter already exist (`platform/audit/handlers.go`).
9. **Retention loop lifecycle (new).** The wired scheduler (retention decision)
   adds a goroutine + `retentionCancel`/`retentionDone` to `anomalyRuntime`;
   the `close` order (runner → retention → SQLite handles) matters, and
   `docs/config-reference.md` must document the now-live `anomaly.retention.*`
   knobs in the same change (currently undocumented).

## Verification and contract updates

Every regression test below is tied to a review finding (Sec = security review,
DS = distributed-systems review, DB = database-architect review, design =
"What could break the design" item) and to the mandatory gates. The
"Pre-remediation" column is the test's expected status against the tree
*before* the remediated code lands: red is the executable form of the finding,
green-after is the fix. The requirements spec's label-only acceptance test
(assert `Threat.TenantID == "t1"` on the threat) is insufficient because no
code reads `Threat.TenantID` — the executors act on `SubjectID` alone. Under
the SEC-F1 disposition (accepted residual), the label-level regression stays
in this change (T2/T10) and the side-effect assertions (zero t2 sessions /
refresh tokens destroyed) become the executor-scoping follow-up's acceptance
test (T1, deliberately not in this change's green set).

Gate legend:

| Gate | Command | When |
|---|---|---|
| G1 | `go build ./... && go vet ./...` | after every `.go` edit (AGENTS.md §2) |
| G2 | `go test -run 'TestMaintainability_|TestArchitecture_' .` | after every `.go` edit |
| G3 | `go test ./domains/anomaly/ ./domains/threataction/ ./domains/tenant/ ./interfaces/sso/ ./infrastructure/defaultimpl/... ./cmd/sso-server/serverbuildplatform/ -race -count=1` | after every `.go` edit touching these packages |
| G4 | `go test ./... -race` | handoff |
| G5 | `go test ./test/ -run TestE2E -v` | handoff (mandatory integration gate; no new e2e test — anomaly behavior is server-internal and the existing `test/` login-flow coverage stays the integration surface) |
| G6 | `make ci` | handoff (fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract capabilities-check sdk-surface-check profiles-evidence) |

| ID | Finding | Regression test — assertion | Pre-remediation | Location | Gates |
|---|---|---|---|---|---|
| T1 | Sec-F1 (High) — **accepted residual + follow-up** | **Executor side-effect cross-tenant (follow-up acceptance).** The SEC-F1 disposition for this change is remediation (c): fix the false tenant-scoped-executor claim, ship the guard as a label-integrity control, and document the residual — executors act on `SubjectID` alone (`sessions.go:246` `ListByUser` has no tenant predicate; `refresh_tokens.go:242` `DeleteAllForSubject`; `refresh_tokens` has no `tenant_id` column), so a correctly-resolved t1 anomaly on a subject shared with t2 still acts cross-tenant. The side-effect assertion (t1 spray on a shared subject → zero t2 sessions destroyed, zero t2 refresh tokens deleted) is the **executor-scoping follow-up's** red-before-green test and is deliberately **not** in this change's green set. This change's label-level regression (t1 spray never yields `Threat.TenantID == "t2"`; guard refuses empty/mismatch) is covered by T2/T10. | N/A for this change (follow-up); label-level tests green after implementation | `domains/threataction/executor_test.go` (follow-up); `domains/anomaly/runner_test.go` (guard, this change) | G1–G4, G6 |
| T2 | Sec-F3 (Medium) | **Guard truth table.** Table-driven: (event, signal) ∈ {("t1","t1")→execute, ("t1","t2")→refuse + `tenant_mismatch` metric, ("","")→refuse + `empty_tenant` metric, ("","t2")→refuse + `empty_tenant` metric}; the signal still reaches the sink in every refusal cell. Encodes the Sec-F3 truth table: `execute ⟺ event.TenantID != "" ∧ a.TenantID == event.TenantID`. | **FAILS** cell ("","t2") — executes on the detector-claimed tenant as the design stands; amend the guard decision when adopting | `domains/anomaly/runner_test.go` | G1–G4, G6 |
| T3 | Sec-F2 (Medium) | **ctx-tenant resolution.** HandlerContext carrying `*tenant.Resolved{Tenant}` + a `clientStore` that errors/returns unknown → the dispatched event's `TenantID ==` the ctx tenant, not `""`; garbage-client sprays stay in the routed tenant's partition. Encodes the Sec-F2 priority order: ctx-resolved tenant → `clientStore.Get` fallback → `""`. | **FAILS** — the design resolves `""` when `clientStore.Get` errors | `interfaces/sso/` (new `server_anomaly_dispatch_test.go`, or an existing login-pipeline test) | G1–G4, G6 |
| T4 | Sec-F4 (Low) | **NUL-collision.** Memory stores: tenant `"a\x00b"`/subject `"x"` and tenant `"a"`/subject `"b\x00x"` must not alias; `Tenant.Validate` rejects NUL in IDs (defense-in-depth key-builder guard on the stores). | **FAILS** — composite keys alias; `Tenant.Validate` (`tenant.go:137`) accepts NUL | `infrastructure/defaultimpl/memorystorecredential/` store tests; `domains/tenant/tenant_test.go` | G1–G4, G6 |
| T5 | design break #3; DS-F1; Sec-F6 | **Max-version self-consistency + v2 boot smoke.** `RecentLoginMaxVersion() == migrate.MaxVersion(recentLoginMigrations)` and the same for `IPFailureCounterMaxVersion()`; store-constructor smoke against a v2-stamped DB succeeds (forward-migrated acceptance; the old binary's `ErrSchemaTooNew` is the intended canary-rollback guard). | **FAILS** — both hardcode `1` (`maxversions.go:86,90`) | `infrastructure/defaultimpl/sqlite/maxversions_test.go` + sqlite store tests | G1–G4, G6 |
| T6 | design SQLite decision; design break #7; DB-arch §3–4 | **Upgrade path + EXPLAIN QUERY PLAN.** Construct the pre-migration schema (old DDL + v1 stamp) → open the store → `tenant_id` column and tenant-leading indexes exist, old cross-tenant indexes dropped, legacy rows default `tenant_id = ''`; `EXPLAIN QUERY PLAN` for the canonical `Recent` shape contains the tenant-subject index (plan-text containment, backward scan — not exact match). | N/A — encodes target behavior; red until the migration lands | `infrastructure/defaultimpl/sqlite/recent_login_test.go`, `ip_failure_counter_test.go` | G1–G4, G6 |
| T7 | design sink decision; Sec-F6 | **Sink byte-identity.** Empty tenant → audit event JSON-encoding byte-identical to today (no `TenantID` field, no `tenant.id` meta); t1 → `TenantID == "t1"` + `tenant.id` meta; never `tenant.slug`/`tenant.domain` (unreachable off-path). | N/A — encodes target behavior | `domains/anomaly/sink_test.go` (new) | G1–G4, G6 |
| T8 | DB-High-1 | **Trust-scorer tenant-read.** A t1-routed login's `ip_reputation`/`behavior` evaluation reads the t1 partition — t1 events never yield a t2 or `""` trust read; the composition-root adapters (`build_trust.go:189,215`) must thread the resolved tenant per the DB-High-1 remediation (populate `TrustSignals.TenantID` at the `Score` call sites, or a ctx value set on `r.Context()`). | **FAILS to compile** on the interface change; a naive `""`-passing patch compiles but silently cold-starts the scorers (permanent `no_signal`, enforced conditional access) | `cmd/sso-server/serverbuildplatform/build_trust_test.go` | G1 (compile), G3, G4, G6 |
| T9 | design store decisions; DS-F5 | **Store isolation + prune/clock semantics.** Same `SubjectID` in t1/t2 → `Recent` returns only the queried tenant's rows; same `ipHash` across tenants → independent `Count` totals; `PruneOlder` stays global; entries with `ts` beyond `since` are excluded; prune with an arbitrary cutoff does not error on skewed data. | FAILS for the isolation half (status quo leakage); N/A for the prune half | memory + sqlite store tests | G1–G4, G6 |
| T10 | design decisions 1–2; DS-F2 | **Runner round-trip/backfill + dispatch units.** t1 event reaches detectors and sink with `TenantID == "t1"`; detector-empty `Signal` backfilled from the event; `recordLoginSuccess`/`recordLoginFailure` events carry the resolved client's tenant (tenant-less → empty, no panic; runner-less → no store read); both clientID-only success paths (exported accessor `accessors_handlers.go:177`, `BuildHandlerDeps` closure `accessors_handlers.go:330`) resolve via `dispatchLoginAnomaly`. | N/A — encodes target behavior | `domains/anomaly/runner_test.go`; `interfaces/sso/` | G1–G4, G6 |
| T11 | DS-F4 | **Migration idempotency/concurrency.** Two stores opening one DB concurrently → `BEGIN IMMEDIATE` serializes; a forced mid-migration failure leaves no partial DDL; the second attempt no-ops. Note: the failure-mode table's "loser no-ops" covers only the version-stamp race — an in-progress index build can exceed `busy_timeout` and fail boot (documented in DS-F4). | N/A — encodes target behavior | `infrastructure/defaultimpl/sqlite/` migration tests | G1–G4, G6 |
| T12 | DS-F3 (Medium) — **adopted, unconditional** | **Throttle independence.** Same subject/type/action in two tenants, `RateLimitPolicy{Max:1}` → tenant B's action is not suppressed by tenant A's. The registry's throttle map keys on `RateLimitKey(subjectID, type, action)` (`threataction.go:134-137`, `registry.go:191`) with no tenant component; the fix prefixes the internal map key with `threat.TenantID` in `registry.Execute` (the exported `RateLimitKey` signature stays — no SPI break). | **FAILS** — `RateLimitKey` has no tenant component | `domains/threataction/registry_test.go` | G1–G4, G6 |
| T13 | DB-H2 | **Retention loop.** `anomaly.retention.enabled=true` boots with the documented defaults (90d/2h); a ~10ms-interval loop prunes expired rows from both stores (memory + SQLite) and stops on `close` without racing store teardown (no leak under `-race`). | **FAILS** — no scheduler calls `PruneOlder` today (`anomaly.go` writes the ages, never reads them; both stores grow unbounded) | `cmd/sso-server/` (new `anomaly_retention_test.go` mirroring `audit_retention_test.go`) | G1–G4, G6 |

Gate mapping notes: G1/G2 run after every `.go` edit and are subsumed by G6;
G3 is the fast targeted race set and contains every package above (it extends the
design's original targeted set with `./domains/tenant/` for T4 and
`./cmd/sso-server/serverbuildplatform/` for T8); G4/G6 execute every row at
handoff. T2–T5, T8, T12, and T13 are the red-before-green regressions for **this**
change: write them first, observe the failure against the pre-change tree (that
failure is the finding), then land the remediation with the test turning green.
T1 is the executor-scoping follow-up's red-before-green test (SEC-F1
disposition: accepted residual here). T2 additionally required amending the
guard decision to the Sec-F3 truth table — done in this revision.

- Contract updates in the same change: SPI package comments (`recent_login.go`,
  `ip_failure_counter.go`, `runner.go`, `sink.go`, `shared/trust` lookup
  interfaces), `WithThreatExecutor` and `WithThreatSkippedCallback` option
  docs (new), `WithMetricsCallbacks` docs (unchanged signature), and the
  metric const/help text. OpenAPI is unaffected; `docs/config-reference.md`
  gains the `anomaly.retention.*` knobs in the same change (currently
  undocumented — they become live with the wired scheduler).

---

## Distributed-systems review

Independent review pass (distributed-systems engineer). All claims below were
verified against the working tree at HEAD `fb85964c` by reading the cited
files/symbols and by `go build ./...` (exit 0, so the dead `detect/` package
compiles against current interfaces today — item 2 of "What could break the
design" is a *future* break, not present drift). No test runs were executed in
this pass; gate runs are listed in "Verification and contract updates" for the
implementation commit. Every finding is labeled per the evidence standard.

### State map

| State | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| In-flight `LoginEvent` | `sso.Server` dispatch → `Runner` bounded channel (`runner.go:130-155`) | in-process channel, `drop_newest` default | none — dropped on overflow/Close/ctx-cancel, counted | per-event; no cross-event ordering (worker pool) | none | new replica starts with an empty queue; drops are metric-visible |
| `recent_logins` | `RecentLoginStore` SPI; SQLite impl | shared SQLite file, `SetMaxOpenConns(1)` (`sqlite/recent_login.go:61`) | per SQLite sync pragma (WAL); advisory — loss degrades detection, never login | per-partition (tenant, subject) ordering by `ts`; read-your-writes is approximate (workers interleave Append/Recent) | cluster-shared single file (impl doc comment) | replica restart reopens same file; migration is version-stamped |
| `ip_failures` | `IPFailureCounter` SPI; SQLite impl | shared SQLite file, `SetMaxOpenConns(1)` | same as above | COUNT/DISTINCT are point-in-time aggregates; single-writer serialization | shared file | same |
| Memory store variants | `MemoryRecentLoginStore` / `MemoryIPFailureCounter` | process map | none — lost on restart | per-process | none — replica histories are disjoint | rebuilt empty |
| Anomaly audit rows | `NewRecorderSink` → `audit.Recorder` | configured audit sinks | per audit contract (sink errors fail open) | append-only, per event | per audit topology | per audit topology |
| Threat rate-limit map | `ThreatExecutors.rateLimit` (`threataction/registry.go:29`) | process map, `te.mu`-guarded | none | mutex-serialized | none | throttle resets on restart (fail-open: actions re-eligible) |
| Threat actions (suspend / family revoke) | `SuspendSessionExecutor` / `RevokeFamilyExecutor` (`threataction/actions.go:58,135`) | session store / family store + cluster bus | per those stores | per those stores | bus publishes cross-replica (`publishRevoked`) | per those stores |

### Findings

**F1 — High (Verified) — max-version bump is a release blocker if missed.**
*Evidence:* `RecentLoginMaxVersion()` and `IPFailureCounterMaxVersion()` both
hardcode `1` (`infrastructure/defaultimpl/sqlite/maxversions.go:86,90`), and
`build_app_selfservice.go:432,439` feeds them to `CheckSQLiteSchema` at boot;
`platform/migrate/migrate.go:350-364` returns `ErrSchemaTooNew` when the live
version exceeds the binary's max, and `migrate_test.go:386-404` proves the
failure mode. *Triggering failure:* v2 migration stamps the DB at 2; a binary
still returning 1 refuses its own forward-migrated DB at boot. *User impact:*
total boot failure on the canary; the rollback guard works exactly as designed
(the old binary also refuses). *Recovery:* fix the funcs to return
`migrate.MaxVersion(recentLoginMigrations)` / `ipFailureMigrations`; no data
repair needed. *Corrective pattern:* implement in the same change as the v2
migration (the design already mandates this — the review confirms it is the
single integration the requirements spec missed); add a unit test asserting
`RecentLoginMaxVersion() == migrate.MaxVersion(recentLoginMigrations)` so the
two cannot drift again.

**F2 — Medium (Verified) — `recordLoginSuccess` has four call sites, not three.**
*Evidence:* `interfaces/sso/server_login_client.go:397`,
`server_finish_login.go:434`, `accessors_handlers.go:177` (exported accessor),
and `accessors_handlers.go:330` (the `BuildHandlerDeps` closure assigning
`handler.ServerDeps.RecordLoginSuccess`, declared at
`internal/handler/serverdeps.go:153`). The closure has no in-repo callers today
(grep of `internal/handler` finds only the declaration), but it is exported
surface and its body calls `recordLoginSuccess`, so the compiler will force the
update — the risk is not a silent break but a wrong patch plan and a wrong cost
note ("only the accessor path does it on success"). *Triggering failure:*
implementer follows the design's three-site list and misses that two
clientID-only success paths rely on dispatch-side resolution. *User impact:*
none at runtime; acceptance coverage gap for the Deps path. *Recovery:* n/a.
*Corrective pattern:* the body of this doc is corrected; add a unit test that
drives both clientID-only paths (accessor + closure) through
`dispatchLoginAnomaly`.

**F3 — Medium (Verified) — threat rate-limit key is not tenant-scoped.**
*Evidence:* `RateLimitKey(subjectID, threatType, action)` at
`threataction/threataction.go:134-137` has no tenant component;
`registry.go:191` keys the throttle by it; a denied action is audit-recorded
with `OK:false, Detail:"rate-limited"` (`registry.go:109-113`). *Triggering
failure:* two tenants with the same subject identifier (common across tenants)
trip the same `(subject, type, action)` bucket; tenant A's offender exhausts
tenant B's action budget for the same username. *User impact:* tenant B's
automated suspend/revoke is silently (Info-log + audit row) skipped until the
window expires — a defense-availability degradation; the action
layer is subject-scoped regardless (SEC-F1), so the throttle collision is an
additional availability coupling on top of that residual. *Recovery:* next
window re-enables; manual response in the interim. *Corrective pattern:* include
`TenantID` in the throttle key (prefix the map key in `registry.Execute`;
keeping the exported `RateLimitKey` signature avoids an SPI break); the tenant
dimension is exactly the scope that makes this collision newly consequential.
**Adopted in the final gate** (blind spot — missed by the security and
database reviews; T12 is unconditional). *Validation:* unit test — same
subject/type/action, two tenants, `RateLimitPolicy{Max:1}`: tenant B's action
must not be suppressed by tenant A's.

**F4 — Medium (Verified) — v2 index build holds the shared-file write lock for
O(table size).** *Evidence:* `migrate.Run` pins one connection and runs
`BEGIN IMMEDIATE` with `busy_timeout` (`platform/migrate/migrate.go:161-203`);
both stores use `SetMaxOpenConns(1)`; v2 `CREATE INDEX` scans all rows.
*Triggering failure:* a large `recent_logins` (30-90 day retention of full
rows) makes the v2 migration take minutes; replicas booting concurrently either
wait on `busy_timeout` or fail boot and retry. *User impact:* extended boot /
boot retries on migration day; the login path is unaffected (these stores are
written off-path by the runner); fail-closed at boot is the designed behavior.
*Recovery:* restart; the migration is idempotent and the second attempt no-ops.
*Corrective pattern:* the design's failure-mode table says the migration loser
"no-ops on busy_timeout" — refine that row: the *version-stamp* race no-ops,
but an in-progress index build on a large table can exceed `busy_timeout` and
fail the boot instead. Accepted risk; document the window and prefer rolling
replica restarts on migration day.

**F5 — Low (Verified) — global `PruneOlder` × replica clock skew.**
*Evidence:* `PruneOlder` is global and tenant-blind by design; `Timestamp` is
`time.Now()` at dispatch (`server_helpers.go:311`), i.e. the *writing replica's*
clock; the SQLite file is shared. *Triggering failure:* a replica with a fast
clock prunes rows younger than lagging replicas' windows still need, or writes
entries with future timestamps that `since` windows (local clock) exclude.
*User impact:* truncated history → missed/under-counted velocity and
brute-force-shadow signals; impossible-travel (limit=1) is mostly immune;
fail-open, no wrong actions. *Recovery:* NTP discipline; self-heals as events
append. *Corrective pattern:* none required — pre-existing and accepted; state
it in the failure-mode table so the tenant change doesn't inherit it silently.
The tenant dimension does not alter it (retention is per-store).

**F6 — Low (Verified) — audit stamping exclusion list omits `tenant.domain`.**
*Evidence:* `EnrichTenant` sets `tenant.id`, `tenant.slug`, and `tenant.domain`
(`platform/audit/handler_helpers.go:67-72`); the design's sink decision excludes
only `tenant.slug`. `tenant.domain` needs the same routing result and is equally
unreachable off-path. *Corrective pattern:* body corrected; no runtime impact.

**F7 — Low (Verified) — reference drift in the design.** `refresh_tokens`
migrations run v1–v7 (`refresh_tokens_schema.go:78-121`), not v3–v6;
`WithMetricsCallbacks` is wired at `cmd/sso-server/anomaly.go:195` (175 is the
`anomalyRunnerOptions` body). Body corrected; no design impact.

**F8 — Info (Verified) — crash between `sink.Record` and threat `Execute`
loses the action.** *Evidence:* `runner.go:206-226` sequence record → execute;
no re-queue or retry anywhere in the pipeline (dispatch is at-most-once).
*User impact:* anomaly audited, automated response never executed, no replay.
Accepted under the fail-open contract; audit-before-action is the safe order
(never action-without-audit). Note the mirror case: on recorder outage the
threat still executes while the audit row is lost — visible via existing
metrics; accept and document.

**F9 — Info (Verified) — memory stores are process-local; cross-replica
detection requires the SQLite backend.** *Evidence:*
`memorystorecredential/memory_recent_login.go:26` (process map); SQLite impl
doc comment: "Cluster-shared: detectors on replica B see entries appended by
replica A." *User impact:* with memory stores, an attacker LB-splitting across
replicas evades per-replica windows entirely (N×M failures where each replica
sees M < threshold). Pre-existing; unchanged by the tenant dimension. Must be
listed under unsupported topologies.

**F10 — Info (Verified) — no retries, no backoff, no fencing tokens; that is
consistent.** The pipeline is at-most-once with load-shedding; the only
mutual-exclusion primitive is SQLite `BEGIN IMMEDIATE` (no distributed state
machine, so no fencing/quorum machinery is needed); `inspectTimeout` (5s
default) bounds detector sweeps. All consistent with the documented fail-open
boundary — the review finds no missing timeout/backoff/fencing assumption in
the design's own additions.

### Scenario table

| Scenario | Behavior after the change | Verdict |
|---|---|---|
| Partition between replica and shared SQLite file | Append/Recent error → detector error → warn + `inspect_errors_total`; event dropped; login path untouched | fail-open, accepted; no replay on heal |
| Partition with memory stores | Disjoint per-replica histories by construction (F9) | unsupported topology, documented |
| Replica crash mid-inspect | `inspectSafe` recover drops only the current event; process crash loses in-flight queue (bounded by queue size); restart resumes | at-most-once, accepted |
| Crash between sink and Execute | F8 — audit row exists, action lost, no replay | accepted, documented |
| Retry | None anywhere: dispatch, queue, inspect, execute are at-most-once; executor actions deduped by the rate-limit map (idempotency at the action layer, F3) | consistent; do not add retries (they would duplicate actions, not events) |
| Clock rollback on a replica | New entries get past timestamps → `since` windows exclude them; threat rate-limit windows (`time.Now()`, `registry.go:194-203`) extend (fewer actions suppressed); prune unaffected (uses cutoff, not now) | detection-fidelity degradation only; fail-open |
| Clock step forward | Entries with future `ts`; global prune (fast clock) can delete rows lagging replicas still need (F5) | fail-open; NTP |
| Stale client-cache read at dispatch resolution | Failure-path attribution to an outdated tenant → wrong-tenant audit rows and a wrong-tenant threat *label*; the executor action itself is subject-scoped and unchanged (SEC-F1 residual). Bounded by client-store semantics the sync path already trusts; unknown-client failures resolve to `""` anyway | Low; attribution-only, no new oracle |
| Dependency outage: client store | Tenant `""`, anomaly still dispatched, no error to caller; `empty_tenant` tripwire rises | fail-open, designed |
| Dependency outage: audit recorder | Sink error logged; `recordDetected` still bumps; threat still executes (action-without-audit on recorder outage) | accepted (F8); metric-visible |
| Concurrent replica boot against one DB | `migrate.Run` `BEGIN IMMEDIATE` serializes; loser waits/no-ops on the version stamp, or fails boot if an index build exceeds `busy_timeout` (F4) | fail-closed at boot, retryable |
| Canary rollback | Old binary vs v2 DB → `ErrSchemaTooNew` at boot | intended guard (F1) |
| Recovery sequencing | Boot: `migrate.Run` (v1+v2) → `CheckSQLiteSchema` → ready checks registered (`build_app_selfservice.go:434-438`: `sqlite-anomaly-recent-logins`, `sqlite-anomaly-ip-failures`) → serving; a broken anomaly store drains the replica via /readyz but never fails login | verified wiring |

### Interactions with OAuth/session/revocation state

- Threat actions are the only OAuth/session touchpoint and are unchanged by
  this design except invocation gating: `SuspendSessionExecutor` and
  `RevokeFamilyExecutor` are **subject-scoped** (they do not read
  `Threat.TenantID` — SEC-F1; this change sets the field but only the guard
  consumes it) and publish invalidation-bus events
  (`actions.go:188 publishRevoked`); the guard prevents empty/mismatched-
  labeled invocation. Refresh-family rotation, JTI replay, revocation
  reseeding, and invalidation-bus recovery are untouched — this design adds no
  cache that needs invalidation and no store that participates in the bus.
- Readiness: the two stores are already registered as ready checks and storage
  health sources; the v2 migration adds a boot-time dependency (fail-closed)
  but no runtime readiness change.
- The anomaly stores sit outside the invalidation bus by design: SQLite is a
  shared file (no per-replica caches), memory stores are process-local (nothing
  to invalidate).

### Stated guarantees (post-change)

1. Partition isolation: an entry written under tenant X is readable only via
   queries with tenant X; `""` is a distinct partition; cross-tenant leakage is
   impossible by construction (the partition key is the tenant ID itself, never
   a hash of it).
2. Guarded execution: execution requires `event.TenantID != ""` ∧
   `a.TenantID == event.TenantID` (post-backfill); empty or mismatched tenant →
   refuse with warn + bounded metric, signal still audited (fail-closed on
   action, fail-open on reporting). This is a **label-integrity** guarantee,
   not cross-tenant action isolation: executors are subject-scoped, so a
   correctly-resolved execution still acts on the subject in every tenant
   (SEC-F1 accepted residual; executor tenant-scoping is the documented
   follow-up with T1 as its acceptance test).
3. Fail-open boundaries preserved: detector/store/audit/tenant-resolution
   errors never surface to the login response; a tenant-routing regression
   degrades to audit-only and is observable via
   `sso_anomaly_threat_skipped_total{reason="empty_tenant"}`.
4. At-most-once delivery per event; no retries; load-shedding by drop policy.
5. Migration atomicity and boot-time version checks: single `BEGIN IMMEDIATE`
   transaction, idempotent v2, `ErrSchemaTooNew` canary-rollback guard (only
   if F1 is implemented).
6. Byte-identical behavior for single-tenant embedders (empty-tenant partition,
   no audit meta when tenant empty).

### Unsupported topologies and accepted limitations

- Multi-replica fleets using the memory stores (per-replica histories; F9).
- Large fleets on one SQLite file: single-writer (`SetMaxOpenConns(1)`), WAN
  latency, and the v2 index-build window (F4) cap scale; this is the
  pre-existing SQLite topology, not a regression.
- Cross-tenant throttle isolation: **adopted** in this change (DS-F3 — the
  throttle map key is tenant-prefixed in `registry.Execute`), so this line no
  longer applies.
- Cross-tenant *action* isolation: not provided by this change (SEC-F1
  residual); follow-up threads `TenantID` into the executors (sessions half is
  cheap via `ListByTenant`; refresh-family half needs a `refresh_tokens`
  `tenant_id` column + its own migration/OAuth contract review).
- Cross-replica ordering: no global event order; detectors see an
  approximately ordered per-partition history only.

### Validation tests (DS additions to the design's list)

Consolidated into the verification matrix above — no separate list: DS-F1 →
T5, DS-F2 → T10, DS-F3 → T12 (adopted, unconditional), DS-F4 → T11, clock-skew
semantics + cross-tenant store isolation → T9, cross-tenant regression → T1
(side-effect assertions replace the label-only `Threat.TenantID == "t2"`
form), DB-H2 → T13.

### Residual risks (final-gate state)

- **SEC-F1**: cross-tenant subject-scoped executor action (accepted; success-
  path detectors only — failure threats carry empty subject and no-op at the
  executors). Mitigation: tenant-qualified subject IDs; follow-up = executor
  tenant scoping (T1 is its acceptance test).
- **DB-H2**: **resolved in this revision** — the retention scheduler is wired
  (retention decision, T13): opt-in loop calling `PruneOlder` on both stores at
  `anomaly.retention.interval` with the documented age defaults (90d/2h),
  close-joined in `rt.close`; default deployments are unchanged
  (`enabled: false`). No residual remains.
- **DB-M4**: multi-tenant upgrade cold-start (≤1h spray volume, up to 90d
  baseline lost; release-noted).
- F8 action loss on crash between audit and execute (no replay).
- F5 clock-skew-dependent detection fidelity (pre-existing, accepted).
- Legacy tenant-less embedders lose automated response by design (deliberate,
  flagged for release notes); the tripwire metric only helps if operators
  actually alert on it — document the alert rule with the metric.
- Detection-evasion tradeoff inherent to partitioning: an attacker with a
  legit account in one tenant can spray another tenant from the same egress
  IP without tripping that tenant's counter (accepted; the `""`-partition
  contamination is closed by the ctx-tenant-first resolution, SEC-F2).

---

## Final gate: arbitration record, blind-spot probes, sign-off

Gate run over the revised design plus the three specialist reviews (security,
database architect, distributed systems). Every finding below was re-verified
against the working tree during the gate (not taken on the reviewers' word):
`Threat.TenantID` has no readers in `domains/threataction/` (only the field and
its comment); `build_trust.go:189,215` call the two changing SPIs with bare
`ctx.Request().Context()`; `RateLimitKey(subjectID, threatType, action)` has no
tenant component (`threataction.go:134-137`, `registry.go:191`);
`recordLoginFailure` → `dispatchLoginAnomaly(ctx, "", clientID, ...)`
(`server_helpers.go:286`) — failure events carry no subject;
`WithMetricsCallbacks` is a 4-param func (`options.go:101-113`); both
max-version funcs hardcode `1` (`maxversions.go:86,90`); `AnomalyRetentionConfig`
has zero consumers; `recordTenantLoginAttempt`/`tenantLabel`
(`server_tenant.go:437-458`) already resolve tenant via `clientStore.Get` on
these exact paths. The focused build (`go build ./...` for every package this
design touches) exits 0; a full-tree `go build ./...` currently fails in
`cmd/sso-server/build_app_oidc.go:110` (`undefined: context`) — pre-existing
unrelated working-tree drift (BCL rework), reported per AGENTS.md §5.

### Disposition table — every finding resolved or explicitly accepted

| ID | Severity | Disposition | Recorded in |
|---|---|---|---|
| SEC-F1 | High | **Accepted residual** (remediation c: false claims corrected; residual declared with mitigation + follow-up defined). The claim "executors act on `Threat.TenantID`'s state" was false — no code reads it; executors are subject-scoped. | threat-bridge decision (accepted residual), decision 1 Why, failure-mode row, DS guarantee 2, T1 |
| SEC-F2 | Medium | **Resolved**: ctx-tenant-first resolution order (`TenantFromHandlerContext` → `clientStore.Get` → `""`). | dispatch decision, break-item 5, T3 |
| SEC-F3 | Medium | **Resolved** (arbitrated — see conflicts): guard truth table `execute ⟺ event.TenantID != "" ∧ a.TenantID == event.TenantID`. | threat-bridge decision, break-item 6, T2 |
| SEC-F4 | Low | **Resolved**: NUL rejection in `Tenant.Validate` + memory key-builder guard. | memory decision, T4 |
| SEC-F5 | Info | **Resolved**: four `recordLoginSuccess` call sites (was three) + accessor-site comments + dispatch coverage of both clientID-only paths. | dispatch decision, break-item 4, T10 |
| SEC-F6 | Info | **Resolved** (positive confirmation): max-version catch is real and slightly worse than stated (new binary also refuses its own fresh DB without the bump). | SQLite decision, T5 |
| DB-H1 | High | **Resolved**: new trust-scorer decision — `TrustSignals.TenantID` + tenant param on `IPFailureLookup.CountFailures`/`LoginHistoryLookup.History` + `build_trust.go` adapters. | trust-scorer decision, T8 |
| DB-H2 | High | **Resolved in this revision**: retention scheduler wired (prune loop mirroring `startAuditRetention`; opt-in `anomaly.retention.enabled`; defaults 90d/2h/1h; close-joined); `docs/config-reference.md` gains the knobs. | retention decision, failure-mode row, T13 |
| DB-M3 | Medium | **Resolved**: four call sites; `ctx.Request().Context()` precision + disconnect-cancel note. | dispatch decision, T10 |
| DB-M4 | Medium | **Resolved as documentation**: multi-tenant upgrade cold-start, release-noted. | SQLite decision, failure-mode row |
| DB-M5 | Medium | **Resolved** (arbitrated — see conflicts): additive `WithThreatSkippedCallback`; `WithMetricsCallbacks` unchanged. | refusal decision, break-item 1, T12 |
| DS-F1 | High | **Resolved**: max-version bump mandated + drift-proof consistency test. | SQLite decision, T5 |
| DS-F2 | Medium | **Resolved**: four call sites; Deps-closure path covered. | dispatch decision, T10 |
| DS-F3 | Medium | **Resolved (adopted)**: throttle map key tenant-prefixed in `registry.Execute` (exported `RateLimitKey` unchanged). | T12, unsupported topologies |
| DS-F4 | Medium | **Resolved as documentation**: index-build lock window refined in failure-mode row. | failure-mode row, T11 |
| DS-F5 | Low | **Resolved as documentation**: clock-skew row added. | failure-mode row, T9 |
| DS-F6 | Low | **Resolved**: `tenant.domain` added to sink exclusion list. | sink decision |
| DS-F7 | Low | **Resolved**: `refresh_tokens` precedent is v3–v7; `anomaly.go:175` names `anomalyRunnerOptions` (accurate as a function reference). | SQLite decision, refusal decision |
| DS-F8 | Info | **Accepted**, documented (crash between sink and Execute loses the action; audit-before-action is the safe order). | DS scenario table |
| DS-F9 | Info | **Accepted**, documented (memory stores are process-local; unsupported topology). | DS state map, unsupported topologies |
| DS-F10 | Info | **Accepted**, documented (at-most-once pipeline is consistent; no retries/backoff/fencing needed). | DS F10 |

### Conflicts arbitrated

1. **SEC-F3 (refuse the `("", "t2")` cell) vs the design's appended "deliberate"
   carve-out (allow it).** Refuse wins. The carve-out was never justified — it
   fell out of the backfill asymmetry, contradicted the guard's own rationale
   (empty/mismatched labels are how wrong-tenant actions slip through), and no
   in-tree detector resolves its own tenant, so nothing legitimate loses
   execution. Both refusal cells map onto the existing metric reasons.
2. **DB-M5 (additive `WithThreatSkippedCallback`) vs the design's
   `WithMetricsCallbacks` signature change.** Additive wins: the signature
   change is an avoidable SDK break; the repo's additive-option pattern
   (`WithClientStoreCache`) is established; wiring cost is identical.
3. **SEC-F1 remediation (a) thread tenant into executors vs (c) accept
   residual.** (c) wins for this change, with (a) defined as the follow-up: the
   sessions half is cheap (`ListByTenant` exists) but the refresh-family half
   requires adding `tenant_id` to `refresh_tokens` — a central OAuth table —
   with its own migration and wire-contract review that belongs in a separate
   design. (b) (gate wiring) was rejected: it only protects embedders; the
   stock `sso-server` still wires subject-scoped executors.
4. **DS-F3 adoption vs "residual risk" listing.** Adopted: the tenant dimension
   makes the throttle collision newly consequential, the fix is internal to
   `registry.Execute` (no SPI break), and the design's own goal is
   tenant-scoped response.

### Cross-review blind-spot probes

1. **Trust-scorer composition-root adapters (DB-H1)** — missed by the security
   and distributed reviews. Verified: `build_trust.go:189,215` break at compile
   time *and* would silently cold-start `ip_reputation`/`behavior` to
   `no_signal` on tenant-routed deployments (they receive bare
   `ctx.Request().Context()`; the tenant middleware stashes `*Resolved` on
   `HandlerContext`, not `r.Context()`), changing enforced conditional-access
   outcomes. Now a design decision + T8.
2. **Threat rate-limit key (DS-F3)** — missed by the security and database
   reviews. Verified: `RateLimitKey` has no tenant component. Adopted with an
   internal key prefix; T12.
3. **NEW: `tenantLabel` precedent.** `interfaces/sso/server_tenant.go:437-458`
   already resolves tenant via `clientStore.Get` on the exact same
   failure/success paths (`recordTenantLoginAttempt`). The design's
   client-store fallback has in-repo precedent; the ctx-tenant-first priority
   (SEC-F2) is still strictly better (authoritative boundary, zero extra reads
   on routed deploys). Follow-up: unify `tenantLabel` and dispatch resolution.
4. **NEW: failure-path threats are executor no-ops.** Failure events carry
   `SubjectID == ""` and `BruteForceShadowDetector` copies it into the signal;
   the executors no-op on empty subjects (`ListByUser("")` returns nothing,
   `DeleteAllForSubject("")` early-returns). This narrows the SEC-F1 residual's
   blast radius to success-path detectors and is now recorded in the
   threat-bridge residual.
5. **NEW: design-internal contradiction.** The appended DS residual's
   "detector-set tenant on empty event is deliberate" carve-out contradicted
   the threat-bridge decision's own rationale — this is the substance of
   SEC-F3; arbitrated to the truth table.

### Sign-off

Not sign-off-ready at first review: SEC-F1 and DB-H1 were open Highs, SEC-F2/3
and DB-M5 were unresolved design decisions, and two cross-review blind spots
(DB-H1, DS-F3) were entirely absent from the design. **After this gate, every
finding is resolved or explicitly accepted with a documented residual** (see
the disposition table; residuals are itemized in the DS residual-risks
section and the threat-bridge/SQLite decisions). One gate residual has since
been closed: DB-H2 (dead retention knob) is **wired** in this revision — see
the retention decision and T13. Remaining gates are
implementation-time: G1–G6 and the T1–T13 matrix (red-before-green for
T2–T5, T8, T12, T13; T1 is the executor-scoping follow-up's acceptance test).
Pre-existing unrelated tree state to report separately: `go build ./...` fails
in `cmd/sso-server/build_app_oidc.go:110` (uncommitted BCL rework), and
`TestArchitecture_DirectorySubdirFanout` flags `docs` (documented temporary
drift).
