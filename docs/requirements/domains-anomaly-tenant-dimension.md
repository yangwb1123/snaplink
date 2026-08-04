# Requirements Spec: domains/anomaly — Tenant Dimension

> Expansion direction (from `docs/architect-analysis/auto/domains-anomaly-analysis.md` #1):
> 为 anomaly 数据模型补齐 Tenant 维度（多租户隔离是正确性缺陷，不是增强）。
> Exactly three evidence-backed improvements; scope is the tenant-isolation
> contract only. Directions #2 (dead `detect/`/`signature/`/`fingerprint/`
> convergence) and #3 (unwired retention loop) are explicit non-goals here.

Problem class: Snaplink is multi-tenant end to end (`core.Client.TenantID`,
`domains/tenant`, per-tenant token strategy, `threataction.Threat.TenantID`,
tenant-scoped audit), but the anomaly chain is tenant-blind: dispatch, event
model, both history stores, the audit sink, and the threat-executor bridge.
Failure-path `SubjectID` is the *attempted* identifier (username/phone/email),
which is inherently ambiguous across tenants, so same-name users in different
tenants collide today. Cross-tenant aggregation both leaks signal (tenant A's
spray raises tenant B's counters and baselines) and dilutes the true signal —
and can drive wrong-tenant automated responses (session suspend / refresh
family revoke), which are already tenant-aware on the execution side.

## 1. Thread TenantID through the dispatch point and the event/signal model

**Name**: Tenant-aware `LoginEvent` / `Signal` and tenant-carrying dispatch.

**Problem**: `dispatchLoginAnomaly` has no tenant parameter and the two
structs every detector and every sink consume carry no tenant, so tenant
context is structurally unreachable downstream even though it exists at every
call site.

**Evidence**:
- `interfaces/sso/server_helpers.go:298` — `func (s *Server) dispatchLoginAnomaly(ctx HandlerContext, subjectID, clientID, provider, outcome, failureReason string)`; no tenant, called from `recordLoginFailure` (line 286) and `recordLoginSuccess` (line 338).
- Tenant IS available at those sites: `interfaces/sso/server_login_client.go:397` passes the resolved `client` (its `TenantID` at `shared/core/types.go:47`) into `recordLoginSuccess`; the failure path has `req.ClientID` and the canonical resolve-then-gate pattern exists at `interfaces/sso/server_tenant_residency.go:22-25` (`s.clientStore.Get(ctx, claims.ClientID)` → `client.TenantID`).
- `domains/anomaly/types.go:60` — `LoginEvent` has no `TenantID`; `Signal` (types.go, `SubjectID` field) has no `TenantID`.
- Same-server precedent for tenant-keyed behavior at the dispatch boundary: `interfaces/sso/server_helpers.go:39` `s.tenantTokenStrategies[c.TenantID]`.

**Proposed behavior**:
- Add `TenantID string` to `LoginEvent` (documented: empty = tenant-less/legacy embedder; detectors skip tenant-scoped checks exactly as they do for empty `SubjectID`). Add `TenantID string` to `Signal`, populated by the runner from `LoginEvent.TenantID` when the detector leaves it empty (mirror of the existing `SubjectID` fallback in `NewRecorderSink`).
- Change `dispatchLoginAnomaly` to accept `tenantID`; success paths pass `client.TenantID`; failure paths resolve best-effort via `s.clientStore.Get(ctx, clientID)` (nil/error → empty, anomaly still dispatched — fail-open, consistent with the runner's non-blocking contract).
- `Runner.Dispatch` and `Detector.Inspect` signatures are unchanged (tenant rides the event); no new option knobs.

**Acceptance check**:
- `LoginEvent`/`Signal` carry `TenantID`; unit test: an event with tenant "t1" dispatched through the runner reaches detectors and the sink with `TenantID == "t1"`; a detector that leaves `Signal.TenantID` empty gets it backfilled from the event.
- Unit test at `interfaces/sso`: `recordLoginSuccess`/`recordLoginFailure` produce events whose `TenantID` equals the resolved client's tenant (tenant-less client → empty, no panic).
- `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, `go test ./domains/anomaly/ ./interfaces/sso/ -race` green.

## 2. Tenant-scope both history stores: keys, SQLite schema/indexes, memory maps

**Name**: Tenant-partitioned `RecentLoginStore` + `IPFailureCounter` storage.

**Problem**: Both stores are keyed tenant-blind, so entries from different
tenants share one key space: `Recent`/`Append` key by `SubjectID` alone and the
IP counter by `ipHash` alone. A tenant A attacker spraying the same username
or egress IP contaminates tenant B's new-device/new-country baselines,
impossible-travel "last location", and credential-stuffing counts.

**Evidence**:
- `domains/anomaly/recent_login.go` — `RecentLoginStore.Recent(ctx, subjectID string, since, limit)`; `LoginEntry` (line 69) has no `TenantID`; `Append` validates only `SubjectID` non-empty (`ErrInvalidLoginEntry`).
- `domains/anomaly/ip_failure_counter.go` — `Record(ctx, ipHash, subjectID, ts)` / `Count(ctx, ipHash, since)`: ipHash-only aggregation; the doc comment itself says counters are IP-keyed, and the failure-path `SubjectID` is an attempted identifier (ambiguous across tenants).
- SQLite: `infrastructure/defaultimpl/sqlite/recent_login.go:14-31` — `recentLoginSchema` has `subject_id` but no `tenant_id`; `idx_recent_logins_subject_ts ON recent_logins(subject_id, ts_unix_ns DESC)` is a cross-tenant index. `infrastructure/defaultimpl/sqlite/ip_failure_counter.go` likewise.
- Memory: `infrastructure/defaultimpl/memorystorecredential/memory_recent_login.go:37` — `entries map[string][]*anomaly.LoginEntry` keyed by `SubjectID` alone; the IP counter mirrors this shape.
- Asymmetry reference: execution side is already tenant-aware — `domains/threataction/threataction.go:50-51` `Threat.TenantID`.

**Proposed behavior**:
- Add `TenantID string` to `LoginEntry`. Extend the interface signatures to `Recent(ctx, tenantID, subjectID, since, limit)` and `Append` validation unchanged (empty `SubjectID` still rejected; empty `TenantID` allowed for legacy embedders but scoped as its own partition). `IPFailureCounter` becomes `Record(ctx, tenantID, ipHash, subjectID, ts)` / `Count(ctx, tenantID, ipHash, since)`. This is a deliberate interface contract change; bump it in one commit with all in-repo implementations (memory + sqlite) and embedder-facing docs, per AGENTS.md wire-contract discipline.
- SQLite: add `tenant_id TEXT NOT NULL DEFAULT ''` column; replace the indexes with `(tenant_id, subject_id, ts_unix_ns DESC)` and `(tenant_id, ip_hash, ts_unix_ns)`; existing tables migrated at construction (CREATE TABLE IF NOT EXISTS + additive column/index migration, same style as current schema bootstrap).
- Memory: composite keys `(tenantID, subjectID)` / `(tenantID, ipHash)`.
- Keep the existing per-deployment salt scheme unchanged (hash space already deployment-scoped; tenant partitioning happens above the hash).

**Acceptance check**:
- Unit tests: same `SubjectID` in tenants "t1"/"t2" never shares entries (`Recent` returns only the queried tenant's rows) and same `ipHash` across tenants produces independent `Count` totals; `PruneOlder` remains global (retention is per-store, unaffected).
- SQLite test: after migration, `EXPLAIN QUERY PLAN` for `Recent` uses the new `(tenant_id, subject_id, ts)` index; old-table upgrade path covered by a test constructing the pre-migration schema then opening the store.
- Both memory and sqlite implementations pass the shared store behavior suite; `go test ./... -race` green.

## 3. Tenant-stamp the audit sink and gate the threat-executor bridge

**Name**: Tenant-correct audit events and cross-tenant threat-response guard.

**Problem**: Anomalies surface as audit events and — via
`WithThreatExecutor` — as automated responses (session suspend, refresh
family revoke). Today the sink writes no tenant on the event, and the runner
invokes the tenant-aware executor with a signal that carries no tenant, so a
cross-tenant false positive can land in the wrong tenant's audit trail and
trigger actions against the wrong tenant's sessions/families.

**Evidence**:
- `domains/anomaly/sink.go` — `NewRecorderSink` builds `audit.Event` (Type `audit.EventAnomalyDetected`, `Reason: a.Type`) with no `TenantID` and no `tenant.id` metadata.
- The canonical tenant-stamping pattern for audit events already exists: `platform/audit/handler_helpers.go:62-69` `EnrichTenant` sets `Event.TenantID` + `SetMeta("tenant.id"/"tenant.slug")`; the anomaly runner is async (off the request path), so it cannot rely on ctx routing — the sink must stamp tenant from the event itself.
- `domains/anomaly/runner.go:77,216-227` — `threatExec threataction.ThreatExecutor` executed on signals with `threataction.ThreatPolicy{}`; `Threat` already carries `TenantID` (`domains/threataction/threataction.go:50-51`) and `domains/threataction/actions.go` (`SuspendSessionExecutor` line 49, `RevokeFamilyExecutor`) act on that tenant's state.
- Tenant-scoped login audit precedent on the same dispatch path: `interfaces/sso/server_helpers.go:39-40` `recordTenantLoginAttempt` keys by `c.TenantID`.

**Proposed behavior**:
- `NewRecorderSink`: set `Event.TenantID = event.TenantID` and `audit.SetMeta(e, "tenant.id", ...)` when non-empty, mirroring `EnrichTenant`'s metadata vocabulary.
- Runner threat bridge: when building the `threataction.Threat` from a `Signal`, copy `TenantID` from the event/signal (populated per improvement 1); add a guard — a signal whose tenant differs from... (no ambient tenant exists off-path, so the guard is: empty or mismatched tenant on the threat) — refuse execution with a warn-level log + `anomaly` metric, never act on an unknown/empty tenant. This preserves the existing fail-open audit-only behavior for tenant-less embedders while making the cross-tenant case impossible.
- Document in the `WithThreatExecutor` option comment that threat execution is tenant-scoped by `Signal.TenantID`.

**Acceptance check**:
- Unit test (sink): event with tenant "t1" produces an audit event with `TenantID == "t1"` and `tenant.id` meta; empty tenant produces no tenant fields (byte-identical to today).
- Unit test (runner): a detector signal for tenant "t1" with a mock `ThreatExecutor` recording `Threat.TenantID` — assert the executor receives `TenantID == "t1"`; a signal with empty `TenantID` does not execute (audit-only fallback) and is logged.
- Cross-tenant regression test (side-effect assertions, not labels): tenant
  "t1" spray on a subject shared with tenant "t2" must leave t2 untouched —
  assert zero t2 sessions destroyed and zero t2 refresh tokens deleted via
  recording session/refresh-family mocks. A label-only assertion
  (`Threat.TenantID == "t1"`) is insufficient: no code reads
  `Threat.TenantID` (the executors act on `SubjectID`: `sessions.go:246-257`
  `ListByUser` has no tenant predicate; `refresh_tokens.go:242-265`
  `DeleteAllForSubject`; `refresh_tokens` has no `tenant_id` column), so
  tenant enforcement must be asserted on the action's side effects. The test
  must fail against the pre-change tree (design verification matrix, T1).
- `go build ./... && go vet ./...`, architecture gate, and `go test ./domains/anomaly/ ./domains/threataction/ -race -count=1` green.

---

## Cross-cutting notes

- Contract updates in the same change (AGENTS.md §5): interface signature changes in `RecentLoginStore`/`IPFailureCounter` are wire-visible — update `docs/` (OpenAPI/config unaffected; the anomaly SPI docs live in package comments) and any embedder-facing references.
- Non-goals: dead `domains/anomaly/{detect,signature,fingerprint}` removal, `runner.go` package-comment fix (points at nonexistent `infrastructure/defaultimpl/anomaly`), and the unwired `anomaly.retention` loop — separate specs.
- Backwards compatibility: empty `TenantID` must remain a valid, explicitly documented "tenant-less" mode (single-tenant embedders, tests) that behaves byte-identically to today.
