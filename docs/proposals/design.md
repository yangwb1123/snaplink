Design doc written to `docs/design/domains-anomaly-tenant-dimension.md`. I verified every claim in the requirements spec against the code before writing, and found one integration the spec misses.

## Design decisions (## headings, one per decision)

**API surface**
1. `TenantID` on `LoginEvent`/`Signal` — backfilled once at the `Runner.inspect` boundary (per-inspection range copy, race-free); `Dispatch`/`Inspect` signatures unchanged, tenant rides the event.
2. `dispatchLoginAnomaly` gains a tenant param — success paths pass the resolved `client.TenantID`, failure paths (all ~30 `recordLoginFailure` sites unchanged) resolve best-effort inside dispatch, *after* the nil-runner short-circuit, so no store read when no runner is wired.
3. `RecentLoginStore.Recent(ctx, tenantID, subjectID, …)` + `LoginEntry.TenantID`; `Append`/`PruneOlder` unchanged.
4. `IPFailureCounter.Record/Count(ctx, tenantID, …)`; salt scheme untouched (partitioning is above the hash).
5. `NewRecorderSink` stamps `Event.TenantID` + `tenant.id` meta only when non-empty (byte-identical otherwise); `tenant.slug` is unreachable off-path, so it's excluded.
6. Threat bridge: `Threat.TenantID = a.TenantID` post-backfill, refused on empty or event-mismatch (warn + new `sso_anomaly_threat_skipped_total{reason}` metric) — signal still reaches audit. This is a deliberate behavior change for legacy tenant-less embedders (audit-only), which I flag for the option comment/release notes.
7. `recordLoginSuccess` gains the param — **three** call sites, not one as the spec implies: `mintAndRecordDirectLogin` and `recordCodeFlowSuccess` pass `client.TenantID`; the exported SDK accessor `Server.RecordLoginSuccess` keeps its signature and relies on dispatch-side resolution.

**Storage model**
8. SQLite: `tenant_id TEXT NOT NULL DEFAULT ''`, tenant-leading indexes `(tenant_id, subject_id, ts DESC)` / `(tenant_id, ip_hash, ts)`, converted from `ensureSchema` to explicit `migrate.Run` v2 `Func` migrations (refresh_tokens precedent; create-new-index-then-drop-old ordering).
9. Memory: composite keys `tenantID + "\x00" + key` (`threataction.RateLimitKey` precedent).
10. Empty tenant = first-class `""` partition: byte-identical for single-tenant embedders, and cross-tenant leakage is impossible by construction (partition key is the tenant ID itself).

**Failure modes** — table covering store-outage fail-open, tenant-routing regression (the metric is the tripwire), detector tenant override (fail-closed on action), migration failure (fail-closed at boot), concurrent-replica serialization, and the canary-rollback guard.

**What could break the design** — 8 items, including the one the spec missed: `RecentLoginMaxVersion()`/`IPFailureCounterMaxVersion()` in `maxversions.go` hardcode `1` and feed `CheckSQLiteSchema` at boot (`build_app_selfservice.go:432,439`) — if they aren't bumped to 2 alongside the v2 migration, the new binary refuses its own forward-migrated DB. Also: the dead `domains/anomaly/detect/` package still compiles against the changed interfaces and must be mechanically updated, or `go build ./...` fails.
