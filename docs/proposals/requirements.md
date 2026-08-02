I have verified the analysis against the code. All claims in direction 2 check out: `memory/store.go` is the sole `FindingStore` implementation (FIFO cap 1024, `mergeFinding` severity-escalation-only), `Finding`/`FindingQuery` carry no status/tenant/pagination, `Detector.obs` is process-local with no TenantID capture, `BuildTokenAnomaly` hardcodes the memory store with no backend knob, and the sqlite/migrate precedent exists in `threataction/sqlite` and `BuildConfigAuditStore`. The spec follows.

---

## Decision 1: Durable FindingStore with a config-selectable sqlite backend (fixes restart loss + multi-replica convergence)

**Name**: Durable finding persistence — `token_anomaly.backend` = `memory | sqlite`

**Problem**: `FindingStore` has exactly one implementation, `domains/tokenanomaly/memory` (bounded at 1024, FIFO eviction), so every detected anomaly vanishes on process restart — the suspicious-token list is a rolling in-process view that cannot serve audit/re-triage after a redeploy. Worse, under multi-replica deployment the whole findings chain breaks: each replica runs its own `Analyze` sweep (`cmd/sso-server/build_app_security.go:startTokenAnomalySweep` → `interfaces/sso/sso.go:RunTokenAnomalyDetection`) writing to its own process-local store, so the admin API on replica A never sees findings produced by replica B's sweep. There is no way to point the store at a shared durable backend: `TokenAnomalyConfig` (`config/config_snapshot.go:429`) has no backend/DSN fields, and `BuildTokenAnomaly` (`cmd/sso-server/serverbuildplatform/build_governance.go`) unconditionally constructs `tokenanomalymemory.NewFindingStore(findingStoreOptions(cfg)...)`.

**Evidence**:
- `domains/tokenanomaly/memory/store.go:22-60` — sole implementation; doc comment states "rolling operational view, not an archive".
- `cmd/sso-server/serverbuildplatform/build_governance.go` — `BuildTokenAnomaly` hardcodes `tokenanomalymemory.NewFindingStore`; `findingStoreOptions` maps only `MaxFindings`.
- `config/config_snapshot.go:429-457` — `TokenAnomalyConfig` has no `Backend`/`Sqlite.DSN`; `docs/config-reference.md:657` documents `max_findings` as "Bound on the in-memory finding store".
- Precedent for the missing pattern: `domains/threataction/sqlite/policy_store.go` (schema + `migrate.Run`, `NewWithDB`, `Close`, `Ping`, doc: "shared across replicas pointed at the same database file") and `BuildConfigAuditStore`'s `config_audit.backend` switch.

**Proposed behavior**:
1. Extend `FindingStore` semantics to remain `Add`/`List`-compatible; keep the `DedupKey` UPSERT contract (a cross-replica sweep re-running the same finding must be idempotent).
2. New package `domains/tokenanomaly/sqlite` (classified as `infrastructure` in `architecture_layer_test.go` `layerName()`): single `token_anomaly_findings` table keyed by `dedup_key`, JSON/columns for the `Finding` fields, `ON CONFLICT(dedup_key) DO UPDATE` merge with the same merge rules as `memory.mergeFinding` (earliest `FirstSeen`, latest `LastSeen`, severity only escalates), `migrate.Run` baseline migration v1, `New(dsn)`/`NewWithDB`/`Close`/`Ping`/`DB()` mirroring `threataction/sqlite`.
3. Config: `token_anomaly.backend` (`memory` default, `sqlite`) + `token_anomaly.sqlite.dsn` (required when backend=sqlite, fails loud otherwise — same contract as `config_audit`); `BuildTokenAnomaly` switches on it. A returned store implementing `io.Closer` is closed at shutdown like `BuildConfigAuditStore`.
4. The durable backend drops FIFO cap-eviction (an audit record must not be silently evicted); boundedness moves to the retention lifecycle of Decision 2. Document this divergence in `docs/config-reference.md`.
5. Multi-replica: each replica keeps its own sweep, but all upsert into the shared store; `Detector.obs` dilution (geo cardinality split across replicas) is a detection-side gap owned by direction 1 and is explicitly out of scope here — this decision fixes the persist/surface half of the chain only.

**Acceptance check**:
- New `domains/tokenanomaly/sqlite` package with migration v1; parity test: identical `Add`/`List` results and merge semantics (FirstSeen/LastSeen/severity-escalation) between `memory` and `sqlite` for the same scripted sweep sequence.
- Restart-retention test: write findings, `Close`, reopen same DSN, `List` returns them unchanged; `Ping`/`DB()` wired for storage-health readiness like `threataction/sqlite`.
- Two-detector convergence test: two `Detector`s (simulating replicas) share one sqlite store; each `Analyze`s disjoint observations; the store ends with the union, no duplicate `DedupKey` rows, no lost upsert.
- `config/config_snapshot.go` + `docs/config-reference.md` document `token_anomaly.backend`/`sqlite.dsn`; boot fails loud when `backend=sqlite` without DSN; `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, and `make ci` pass.

## Decision 2: Triage lifecycle state machine with auto-resolution and retention expiry (fixes no-triage + stale-finding noise)

**Name**: Finding status lifecycle — `open → acknowledged → resolved`, auto-close on signal loss, retention purge

**Problem**: `Finding` carries no triage state, so a SOC cannot distinguish "handled" from "pending" and the store never stops reporting. Two compounding defects: (a) `memory.mergeFinding` (`domains/tokenanomaly/memory/store.go:46-57`) only escalates severity and refreshes `LastSeen` — a token that was revoked or went quiet keeps its row until capacity eviction, i.e. permanent noise with no closed state; (b) the detector has an add-only lifecycle: `Detector.Analyze` (`detector.go`) emits findings but no sweep pass ever resolves the ones whose signal disappeared (`detectGeoVelocity` already skips observations quieter than `window`, yet the stored row lingers), and a re-detected anomaly after resolution would clobber the admin's triage state under today's unconditional merge.

**Evidence**:
- `domains/tokenanomaly/tokenanomaly.go:38-80` — `Finding` struct: `Type/Severity/Thumbprint/ClientID/SubjectID/Geos/Detail/Count/FirstSeen/LastSeen`; no status field.
- `domains/tokenanomaly/tokenanomaly.go:91-97` — `FindingQuery` only `Type/Severity/Limit`.
- `domains/tokenanomaly/memory/store.go:46-57` — `mergeFinding`: "Severity only escalates", no resolution path; eviction is the only removal mechanism.
- `domains/tokenanomaly/detector.go:186-206` — `Analyze` only adds findings; `domains/tokenanomaly/detect.go:31-39` — stale observations are filtered (`o.last.Before(cutoff)`), proving signal-absence is observable yet unused for closing rows.
- `domains/tokenanomaly/admin.go:20-45` — read-only handler, no state transitions.

**Proposed behavior**:
1. Add `Status` to `Finding` (bounded wire strings: `open | acknowledged | resolved`, default `open`) and `ResolvedAt`/`ResolvedReason` fields; `FindingQuery.Status` filter.
2. Extend `FindingStore` with `UpdateStatus(ctx, dedupKey, status, reason)` and a `ResolveStale(ctx, cutoff, reason)` bulk pass; `memory` implementation adds both with the same merge rules (a re-detection `Add` after `resolved` reopens the row to `open` and clears `ResolvedAt` — the admin's acknowledgement is the only state a re-detection preserves).
3. Add an auto-resolution pass to `Detector.Analyze`: after emitting, resolve every stored `open`/`acknowledged` finding whose `LastSeen` is older than `window` and that was not re-detected this sweep, with `ResolvedReason="signal_stale"`. This makes the sweep a true lifecycle: emit → refresh → close.
4. Retention: config knob `token_anomaly.retention` (default e.g. 30d, `<=0` = keep forever); `ResolveStale` (or a lazy prune in `List`) deletes `resolved` rows older than retention. This replaces FIFO eviction as the boundedness mechanism of Decision 1's durable store.
5. Admin transitions (extend `domains/tokenanomaly/admin.go`, thin `Server` wrappers in existing `interfaces/sso` files — no new `interfaces/sso` files; that package is at its 60-file ceiling): `PATCH /api/v1/admin/tokens/suspicious/:key` with `{status, reason}` (`admin:write`), `GET` gains `status` filter; invalid transitions (e.g. `resolved → acknowledged` without reopen, or unknown status) are `400` with a documented `error_description`. Triage state changes are governance mutations: `audit.SetMeta` event (new classified event type in `auditreport`), never an auth decision.
6. Contract updates in the same change: `docs/openapi.yaml` (`/api/v1/admin/tokens/suspicious` schema + new PATCH), `docs/config-reference.md` (`retention`, status field), `docs/feature-matrix.md`, `docs/error-codes.md` if new `Err*` sentinels are added.

**Acceptance check**:
- State-machine unit tests in `domains/tokenanomaly`: `open→acknowledged→resolved` succeeds; `open→resolved` direct transition allowed; unknown status / `resolved→acknowledged` rejected with `400`; re-detection `Add` on a `resolved` row reopens to `open` and preserves `acknowledged` only if it was not already `resolved`.
- Sweep lifecycle test with a fixed clock: finding emitted at T, no re-detection at T+window → row auto-resolved with `signal_stale`; re-detected within window → stays `open` with refreshed `LastSeen`.
- Retention test: `resolved` rows older than `retention` are pruned; `open` rows are never pruned by retention.
- Admin API tests: PATCH transition persists across `List`, `status` filter returns only matching rows; audit event recorded with `audit.SetMeta`; gate suite (`go test ./... -race`, `make ci`) green.

## Decision 3: Cursor pagination and tenant dimension on the query surface (fixes unbounded responses + cross-tenant pooling)

**Name**: Tenant-scoped, cursor-paginated finding query surface

**Problem**: The suspicious-token read API returns every matching row in one response — `HandleAdminSuspicious` (`domains/tokenanomaly/admin.go:20-45`) supports only `type`/`severity`/`limit`, and `FindingStore.List` (`memory/store.go:59-90`) is a full scan sorted in memory with `limit` applied last. Two consequences: (a) once Decision 1 makes the store durable and cross-replica, the list grows to archive scale and a single response is unbounded (a 1024-cap hid this; a retained store cannot); (b) `metering.Event` already carries `TenantID` (`domains/metering/token_usage.go:69`) but the observation table drops it (`observation` struct, `detector.go:31-42`, has no tenant field), `Finding` has no `TenantID`, and the handler has no tenant filter — in a multi-tenant deployment every tenant's findings are pooled into one unpartitioned list, which is both a governance and a privacy problem (subject IDs from tenant A leak into a tenant-B-scoped query) and blocks per-tenant rate limiting/chargeback on detection volume.

**Evidence**:
- `domains/tokenanomaly/admin.go:13-18` — `paramType/paramSeverity/paramLimit` only; response `"total": len(findings)` is the page size, not the match count.
- `domains/tokenanomaly/tokenanomaly.go:82-97` — `FindingQuery{Type, Severity, Limit}`; no tenant, no cursor.
- `domains/tokenanomaly/memory/store.go:61-90` — `List` scan + in-memory sort + truncate.
- `domains/tokenanomaly/detector.go:31-42` — `observation` has `clientID/subjectID/geos` but no `TenantID`, so the tenant is lost before a finding is built (`detect.go:57-78` `geoFinding`, `detect.go:123-136` `spikeForClient`).
- `domains/metering/token_usage.go:69` — `Event.TenantID` exists upstream and is already the wave-1 telemetry dimension; `domains/tokenanomaly/detector.go:115-131` `recordObservation` copies `ClientID`/`SubjectID` but not `TenantID`.

**Proposed behavior**:
1. Carry the tenant through the chain: `observation.TenantID` set from `ev.TenantID` in `recordObservation`; `Finding.TenantID` populated by `geoFinding`/`spikeForClient` (empty when unknown — same omission semantics as `SubjectID`). `DedupKey` is unchanged (thumbprint is a SHA-256 of a globally unique jti; per-client spike keys are globally unique client ids), so dedup identity does not need tenant scoping — but every row records its tenant.
2. Extend `FindingQuery` with `TenantID` (exact match) and a cursor: `Cursor` encoding `(LastSeen, DedupKey)` of the last returned row; `List` returns `(findings, nextCursor, error)` — keyset pagination over the `(last_seen DESC, dedup_key)` ordering, so pages are stable under concurrent upserts (no offset drift). `total` in the response becomes the match count for the filter (computed with the same predicates) or is dropped in favor of `has_more`/`next_cursor`.
3. Handler: `GET /api/v1/admin/tokens/suspicious` gains `tenant_id` and `cursor` params, returns `next_cursor` (omitted when exhausted); `limit` stays, now defaulted to a bounded page size when absent. New admin param names and the response shape go into `docs/openapi.yaml` in the same change; existing consumers keep working (new fields are additive, `cursor` optional).
4. Durable store: index on `(tenant_id, last_seen)` for the paginated query path; `memory` store implements the same cursor semantics so both backends pass the same conformance tests (add a small shared test suite or mirror tests, since `tokenanomaly` has no `*test` conformance package today).
5. Tenant semantics follow the repository's contract: findings for a tenant are queryable only with that tenant's filter; the admin endpoint remains admin-scoped (tenant filtering is a query dimension, not an authz boundary — admin:read gating is unchanged, consistent with the existing per-tenant usage read API).

**Acceptance check**:
- Pagination test: insert 250 findings (mixed types/tenants), page size 50, walk `next_cursor` to exhaustion — union equals the full ordered set with no duplicates/misses, order stable while rows are concurrently upserted mid-walk (keyset, no offset).
- Tenant test: findings from tenants A and B; `tenant_id=A` returns only A rows; `tenant_id` filter combined with `type`/`severity`/`status`/`cursor` composes correctly; empty-tenant findings (e.g. `rate_spike` with unknown tenant) are returned only when no `tenant_id` filter is set.
- Wire test: `next_cursor` omitted on the last page; malformed cursor → `400` with documented `error_description`; `limit` absent → bounded default page.
- Backend parity: identical pagination results for `memory` and `sqlite` implementations on the same dataset; `docs/openapi.yaml` updated for the new params/response fields; `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, `make ci` all pass (new `domains/tokenanomaly/sqlite` package classified in `layerName()`).

---

**Cross-cutting constraints honored**: no new `interfaces/sso` files (60-file ceiling — handlers live in `domains/tokenanomaly/admin.go` with thin wrappers in existing files); new `Err*` → `docs/error-codes.md`; new config knobs → `docs/config-reference.md`; new audit event type classified in `auditreport`; detection/reporting-only contract preserved (no finding ever feeds an auth decision); sqlite store follows the `migrate` + `NewWithDB`/`Close`/`Ping` peer pattern; no `layerExemptions` additions.
