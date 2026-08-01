Spec written to `docs/requirements/domains-anomaly-tenant-dimension.md`. All claims were verified against executable code before writing:

**Verification performed**
- `dispatchLoginAnomaly` (`interfaces/sso/server_helpers.go:298`) has no tenant param; tenant is available at every call site (resolved `client.TenantID` at `server_login_client.go:397`; `clientStore.Get` pattern at `server_tenant_residency.go:22-25`)
- `LoginEvent`/`Signal` (`domains/anomaly/types.go`) and `LoginEntry` (`recent_login.go:69`) carry no `TenantID`; `Recent`/`Count` are keyed by `SubjectID`/`ipHash` alone
- SQLite schema (`infrastructure/defaultimpl/sqlite/recent_login.go:14-31`) has no `tenant_id` column and a cross-tenant `(subject_id, ts)` index; memory store keyed by `SubjectID` only (`memorystorecredential/memory_recent_login.go:37`)
- Audit sink (`domains/anomaly/sink.go`) writes no tenant despite the canonical `EnrichTenant` pattern (`platform/audit/handler_helpers.go:62-69`); runner invokes tenant-aware `ThreatExecutor` (`runner.go:216-227`) with a tenant-less signal, while `Threat.TenantID` already exists (`threataction.go:50-51`)

**The three improvements** (scope fixed to direction #1, tenant dimension)

## 1. Thread TenantID through dispatch + event/signal model
`LoginEvent.TenantID`/`Signal.TenantID` added; `dispatchLoginAnomaly` gains a tenant param (success paths pass `client.TenantID`, failure paths resolve best-effort). Acceptance: tenant round-trips through runner to sink; tenant-less clients stay empty.

## 2. Tenant-scope both history stores
`LoginEntry.TenantID`, `Recent(ctx, tenantID, subjectID, …)` and `Record/Count(ctx, tenantID, ipHash, …)` interface changes; SQLite gains `tenant_id` column + `(tenant_id, subject_id, ts DESC)` / `(tenant_id, ip_hash, ts)` indexes with migration; memory uses composite keys. Acceptance: same subject/IP in t1 vs t2 never share state; EXPLAIN QUERY PLAN shows new index.

## 3. Tenant-stamp audit sink + gate threat-executor bridge
`NewRecorderSink` sets `Event.TenantID`/`tenant.id` meta; runner copies `TenantID` onto the `Threat` and refuses execution on empty/mismatched tenant with warn+metric (fail-open audit-only for legacy embedders). Acceptance: executor receives `Threat.TenantID == "t1"`; cross-tenant regression test proves t1 spray never acts on t2.

Each section lists file/symbol evidence and a concrete acceptance check; cross-cutting notes cover the AGENTS.md contract-update obligation and explicitly scope out analysis directions #2 (dead code) and #3 (retention loop).
