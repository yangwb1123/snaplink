# domains/tenant — 方向 3 需求规格：B2B 跨租户协作「内存-only + 零管理面」→ 持久化后端 + 运营/审计表面

Scope: expansion direction 3 from `docs/auto/domains-tenant-analysis.md` —
「B2B 跨租户协作"内存-only + 零管理面"——补齐持久化后端与运营/审计表面」.
Today the cross-tenant B2B collaboration feature (`GuestRecord` pointers +
`TenantCollaboration` trust edges) has exactly ONE implementation — the
in-process `memory` store — and no management surface of any kind: no HTTP or
gRPC admin CRUD/list, no snapshot/backup coverage, no config-driven
provisioning. A restart destroys the entire trust graph and guest roster; an
operator cannot audit "who trusts whom", cannot revoke a single guest, and
cannot discover a bad trust edge without restarting the process or editing
code. Meanwhile every other tenant resource (tenants, domains, branding,
membership) ships the full "SPI + reference implementation + admin CRUD +
audit + snapshot" stack.

This spec contains exactly three evidence-backed improvements:

1. Durable SPI backends — sqlite + postgres implementations of
   `ExternalUserStore` and `CollaborationStore`.
2. Management + audit surface — a `CollaborationAdminService` (gRPC + HTTP
   gateway, `admin:read`/`admin:write`) with classified admin audit events.
3. Snapshot v2 backup coverage + provisioning wiring — the two stores join
   the disaster-recovery export/restore and the `cmd/sso-server` build.

## Preserved invariants (non-negotiable)

- Gate semantics are NOT touched. `tokExEnforceTenantCollaboration` /
  `tokExAuthorizeGuestHop` (`internal/handler/tokengrant/token_exchange.go`)
  keep their fail-closed oracle collapse: a backend error, a missing trust
  row, and a missing registration all still land on the SAME `invalid_grant`.
  A durable backend must never synthesize trust, never return
  `IsTrusted=true` on a read/parse failure, and must keep
  `Get` returning the `ErrNoGuestRecord` sentinel for absent rows.
- Zero-value byte-identity: unwired stores (the default) remain a complete
  no-op — `WithExternalUserStore(nil)` / `WithTenantCollaborationStore(nil)`
  or an unwired admin service behaves byte-identically to today. The memory
  stores stay the reference implementation and the existing
  `test/cross_tenant_collaboration_test.go` E2E matrix stays green unchanged.
- No new subdirectories anywhere: `domains/` sits at its frozen subdir
  ceiling (`directory_fanout_test.go`, 15/16 — the reason
  `tenant_collab.go` lives in the root package), `interfaces/grpcserver/
  grpcadmin` is at the 10-file fan-out ceiling, `interfaces/snapshot` is at
  its frozen 14-file exemption ceiling, and `interfaces/sso` is at its
  60-file ceiling. All additions extend EXISTING files or packages; the
  permissionstest-style conformance suite is realized in-place in
  `domains/tenant/memory` (see Improvement 1).
- Admin surface rules from AGENTS.md §4 apply: `admin:read` for
  list/get, `admin:write` for mutations, HTTP 401 identifies
  `Bearer realm="admin"`, and audit metadata is added only through
  `audit.SetMeta`. New event types are classified in `auditreport` and
  mapped in the audit sinks (CEF/OCSF), preserving bounded cardinality and
  W3C trace IDs.
- The stores are tenant-boundary data, not credentials: the new admin
  endpoints are operator surfaces behind `admin:*` scopes and never feed
  the login/token path; the token-exchange gate's read pattern
  (`IsTrusted` + `Get` per hop) is unchanged.
- Budgets: `domains/tenant/sqlite` grows 5 → 7 non-test files (ceiling 10);
  `domains/tenant` root stays at 4 files (ceiling 10);
  `interfaces/grpcserver/grpcadmin/admin_domains.go` grows 171 → ~470 lines
  (ceiling 500; `admin_tenants.go` at 461 lines has no headroom — see
  Improvement 2); `interfaces/snapshot` stays at 14 files (frozen ceiling).

## Improvement 1: Durable SPI backends — sqlite + postgres implementations

**Problem**: The two collaboration SPIs have exactly one implementation, the
in-process `memory` store, which is explicitly single-replica. Production
deployments on sqlite or postgres tenant backends cannot persist a single
trust edge or guest registration: every restart silently resets the B2B
feature to "no trust, no guests" (fail-closed, so nothing breaks — but the
operator's entire collaboration topology vanishes). The SPI doc itself
promises durable backends, and the memory doc points at them as the intended
production path; neither is implemented, and no conformance suite exists to
keep future backends honest (the `permissionstest.ConformanceSuite`
discipline from AGENTS.md §4 has no tenant-collaboration equivalent).

**Evidence**:

- `domains/tenant/tenant_collab.go:37–39` — SPI doc: "memory.ExternalUserStore
  + memory.CollaborationStore are the in-process reference implementations;
  any Store backend a deployment needs (sqlite, etcd, ...) implements the
  same two interfaces." The SPIs themselves: `ExternalUserStore`
  (Add/Remove/Get/ListByGuestTenant, :109) and `CollaborationStore`
  (Put/Remove/IsTrusted/ListByGuestTenant, :178); `ErrNoGuestRecord` :135.
- `domains/tenant/memory/collab_store.go:5–8` — "Single-replica only — a
  multi-replica deployment wanting cluster-shared guest registrations/trust
  rows should back these interfaces with a durable store instead." The
  `ExternalUserStore` (:24) and `CollaborationStore` (:91) are the ONLY
  implementations in the tree.
- `test/cross_tenant_collaboration_test.go:73–74` and
  `domains/tenant/memory/collab_store_test.go` — the only construction sites
  of the stores anywhere; no sqlite/postgres counterpart exists.
- `domains/tenant/sqlite/sqlite.go:29–58` — the ordered `migrations` list
  (v1 baseline → v4 `tenant_branding_resource`) and `New(dsn)`/`NewWithDB`
  constructors (:96, :120) the collab tables must join; `maxversions.go`
  `TenantMaxVersion()` derives from the same list.
- `infrastructure/postgres/tenant.go:35–57` — the `tenantSchema` baseline
  (`CREATE TABLE IF NOT EXISTS tenants/tenant_domains` + `idx_tenant_domains_tenant_id`)
  and `NewTenantStoreWithDB(db, dialect)` (:91) pattern to mirror.
- `interfaces/sso/options_grants.go:195–219` — `WithExternalUserStore` /
  `WithTenantCollaborationStore`: the only wiring surface; nothing in
  `cmd/sso-server` constructs a durable implementation to pass in.

**Proposed behavior**:

1. `domains/tenant/sqlite/collab.go` — two store types in the existing
   `sqlite` package implementing the same interfaces with the same
   contracts as `memory`:
   - Migration v5 appended to the ordered `migrations` list:
     `tenant_collaborations(guest_tenant_id, home_tenant_id, created_at,
     PRIMARY KEY(guest_tenant_id, home_tenant_id))` and
     `guest_records(guest_tenant_id, external_subject_id, home_tenant_id,
     roles_json, attributes_json, created_at, PRIMARY KEY(guest_tenant_id,
     external_subject_id))` plus
     `CREATE INDEX idx_guest_records_guest_tenant ON guest_records(guest_tenant_id)`
     (the `ListByGuestTenant` scan column). No `FOREIGN KEY` to `tenants`:
     the SPIs accept opaque tenant IDs and the token-exchange gate must keep
     working with memory-only tenant stores; deletion cascades are an admin
     concern handled by Improvement 2, not the schema.
   - `NewExternalUserStore(db *sql.DB)` / `NewCollaborationStore(db *sql.DB)`
     (or one combined constructor), mirroring `NewWithDB`; `TenantMaxVersion`
     automatically covers v5 via `migrate.MaxVersion(migrations)`.
   - Semantics copied from `memory`, not relaxed: `Validate()`-before-write;
     upsert (`INSERT ... ON CONFLICT DO UPDATE`) for `Add`/`Put`; idempotent
     `Remove` (0 rows deleted is nil, no existence oracle); `Get` returns
     `tenant.ErrNoGuestRecord` on missing row; `IsTrusted` returns
     `(false, nil)` on missing row and a non-nil error on a backend failure
     (fail-closed, never `(true, nil)` from a parse error).
2. `infrastructure/postgres/collab.go` — same two tables added to the
   postgres baseline schema (extending `tenantSchema`'s ensure path) and the
   same two store types behind `NewExternalUserStoreWithDB(db, dialect)` /
   `NewCollaborationStoreWithDB(db, dialect)`, matching
   `NewTenantStoreWithDB`. Postgres FKs ARE enforced (per `tenantSchema`
   doc), so no cross-table FK is added here either.
3. `domains/tenant/memory/conformance.go` — the shared suite, realized
   in-place because `domains/` cannot gain subdirectories
   (`directory_fanout_test.go`; the `permissionstest` pattern cannot be
   repeated under `domains/tenant`). Exports
   `ConformanceSuite(t *testing.T, ext tenant.ExternalUserStore, collab
   tenant.CollaborationStore)` covering: upsert-replaces, idempotent remove,
   `ErrNoGuestRecord` sentinel, validation rejection (empty/matching
   guest==home IDs), `IsTrusted` false-default, `ListByGuestTenant`
   filtering, and defensive-copy semantics. `collab_store_test.go` is
   refactored onto it; sqlite/postgres tests import it.
4. `cmd/sso-server` provisioning (with Improvement 3's wiring): when the
   tenant backend is sqlite/postgres, build the corresponding collab stores
   and pass them to `sso.WithExternalUserStore` /
   `sso.WithTenantCollaborationStore`; memory/absent tenant backend keeps
   them nil (byte-identical no-op). The existing
   `test/cross_tenant_collaboration_test.go` matrix is additionally run
   against a server wired with the sqlite backends (same expected
   200/400 outcomes).

**Acceptance check**:

- `ConformanceSuite` passes against memory, sqlite, and postgres
  implementations (`go test ./domains/tenant/... ./infrastructure/postgres/
  -run Collab`).
- Durability proof: a sqlite test seeds a trust row + guest record, closes
  the DB, reopens the same file via `NewWithDB`, and asserts
  `IsTrusted=true` and `Get` returns the record (restart survival, not just
  in-process behavior). Same round trip for postgres against a test DB.
- Fail-closed proof: with the underlying `*sql.DB` closed, `IsTrusted`
  returns `(false, err)` and `Get` returns a non-nil error — the
  token-exchange gate collapses both to the same `invalid_grant` (no new
  oracle); `Add`/`Put` reject invalid records with the same
  `ErrInvalidGuestRecord`/`ErrInvalidCollaboration` as memory.
- Migration proof: a v4 sqlite DB applies v5 cleanly (`migration_test.go`
  pattern) and `TenantMaxVersion()` returns 5;
  `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` green (fan-out
  ceilings untouched).

## Improvement 2: Management + audit surface — `CollaborationAdminService`

**Problem**: The feature has zero operations surface. There is no way to
list trust edges or guest registrations, no way to revoke a single guest or
a single trust row, and no audit trail for who changed the trust graph —
the only mutation paths are direct store calls in test code
(`test/cross_tenant_collaboration_test.go:73–74`). The module's own
fail-closed trust model (AGENTS.md §3: "a tenant must EXPLICITLY collaborate
with another before anything crosses the boundary") is an allow-list that
grows over time; without a list/revoke surface, the response to a discovered
bad edge is "restart with empty stores or write code". Every sibling tenant
resource (tenants, domains, branding, members) has full
gRPC `TenantAdminService` CRUD plus HTTP admin handlers; the B2B feature is
the sole gap, and its security-sensitivity (trust topology) makes the gap
worst there.

**Evidence**:

- `interfaces/grpcserver/grpcadmin/admin_tenants.go:19–75` — the
  `TenantAdminService` pattern to mirror: nil-store → `FailedPrecondition`,
  nil-safe optional callbacks, audit recorder on every mutation,
  list/get/create/update/delete/status RPCs.
- `proto/admin/v1/tenants.proto:21–75` — the RPC surface shape
  (`ListTenants`/`GetTenant`/.../`ListDomains`/`CreateDomain`/
  `UpdateDomain`/`DeleteDomain` + page-token pagination) that a
  collaboration service should parallel.
- `interfaces/admin/tenants.go:62–80` — the HTTP admin handler convention
  (`HandleAdminListTenantMembers`, `admin:read` gate, JSON shapes) and the
  `/api/v1/admin/tenants/{id}/members` route family (`docs/openapi.yaml:
  9433`) the collab routes would join.
- `platform/audit/auditspi/event_types_admin.go:60` —
  `EventAdminTenantCreated = "admin_tenant_created"`; the event-naming
  pattern for new `admin_*` mutation events. `platform/audit/auditreport/
  control_areas.go:34,109–120` — classification is a manual, counted list
  ("This count is a manual…"); `platform/audit/auditsink/cef.go` +
  `ocsf.go` map each admin event into the sink formats.
- `cmd/sso-server/build_http.go:451` — `RegisterTenantAdminServiceHandlerServer`
  gateway mount that turns the gRPC service into the HTTP admin API with
  `admin:*` scopes.
- Budget constraint: `interfaces/grpcserver/grpcadmin` holds exactly 10
  non-test files (`maxGoFilesPerDir=10`), and `admin_tenants.go` is at 461
  lines (500 cap) — the new RPCs must extend `admin_domains.go` (171
  lines), the natural home for tenant-boundary resources, staying under 500.

**Proposed behavior**:

1. `proto/admin/v1/collaborations.proto` — new service
   `CollaborationAdminService`:
   - Trust edges: `ListCollaborations(ListCollaborationsRequest)` (filter
     by guest/home tenant, page-token pagination per `admin_paginate.go`
     conventions), `PutCollaboration` (upsert, idempotent),
     `RemoveCollaboration` (idempotent revoke — the "cut a bad edge"
     operation).
   - Guest pointers: `ListGuestRecords(ListGuestRecordsRequest)` (filter by
     guest tenant and/or home tenant), `AddGuestRecord` (upsert, carries
     Roles/Attributes),
     `RemoveGuestRecord` (idempotent — the "revoke a single guest"
     operation).
   - Regenerate (`python cli.py` proto flow) into `gen/proto/admin/v1/`.
2. `interfaces/grpcserver/grpcadmin/admin_domains.go` — implement the RPCs
   in this existing file (see budget note in Evidence): nil-store →
   `codes.FailedPrecondition` ("collaboration store not configured"),
   mirroring `TenantAdminService`; `admin:read`-scoped list/get and
   `admin:write`-scoped mutations enforced by the existing admin gateway
   interceptor (no per-RPC reimplementation); `Validate()` before write
   (400-style `codes.InvalidArgument` wrapping `ErrInvalidGuestRecord`/
   `ErrInvalidCollaboration`); every mutation records an audit event via
   the same `audit.Recorder` the tenant service uses.
3. Audit events — new `EventType`s in
   `platform/audit/auditspi/event_types_admin.go` following the
   `admin_tenant_*` naming: `admin_collaboration_created`,
   `admin_collaboration_removed`, `admin_guest_record_added`,
   `admin_guest_record_removed`; alias them in
   `platform/audit/aliases_spi.go`; classify ALL four in
   `platform/audit/auditreport/control_areas.go` (tenant-governance area,
   beside `EventAdminTenant*` — the manual count comment at :34 must be
   updated); map them in `platform/audit/auditsink/cef.go` and
   `platform/audit/auditsink/ocsf.go` like every other admin event.
   Mutations also carry `audit.SetMeta` context (`guest_tenant_id`,
   `home_tenant_id`, `external_subject_id` — the existing wire keys in
   `shared/core/consts_wire.go:237–238`) so a SIEM can reconstruct the
   exact edge changed. No `EventCrossTenantTokenExchange` changes.
4. Mount + docs: register the service in `cmd/sso-server/build_http.go`
   beside `RegisterTenantAdminServiceHandlerServer` (:451) so the HTTP
   admin API gains `/api/v1/admin/collaborations*` and
   `/api/v1/admin/guest-records*` routes; document the routes in
   `docs/openapi.yaml` (alongside `/api/v1/admin/tenants/{id}/members`).
   No new wire error codes: admin failures reuse the existing
   `FailedPrecondition`/`InvalidArgument`/`Internal` mapping of
   `TenantAdminService` (docs/error-codes.md unchanged).
5. Optional-but-wired revocation callback: `RemoveGuestRecord` /
   `RemoveCollaboration` take a nil-safe callback (the
   `invalidateSuspensionCache` pattern, `admin_tenants.go:29–34`) so a
   future cache of trust verdicts can be evicted; today the callbacks stay
   nil in every deployment (no behavior change, pattern established).

**Acceptance check**:

- Bufconn test in `interfaces/grpcserver` (the documented gRPC test flow):
  empty list → `PutCollaboration` → list shows the edge → `RemoveCollaboration`
  → list empty; same for guest records; double-remove and double-put are
  idempotent; invalid records get `InvalidArgument`; nil-store service
  returns `FailedPrecondition` for every RPC.
- Audit assertion: each mutation emits exactly one classified event with the
  expected meta keys; `auditreport` drift test green (classification is
  complete and counted); CEF/OCSF conformance tests green.
- Gateway E2E (`cmd/sso-server` admin-gateway pattern): HTTP routes respond
  `401` with `Bearer realm="admin"` unauthenticated, `403` for an
  `admin:read`-only caller hitting a mutation, and the tenant-wiring tests
  stay green.
- `test/cross_tenant_collaboration_test.go` unchanged and green — the gate
  surface is untouched; `go test ./... -race` and `make ci` green.

## Improvement 3: Snapshot v2 backup coverage + provisioning wiring

**Problem**: Snapshot v2 exports/restores tenants and tenant domains
(`CategoryTenants`, `CategoryTenantDomains`) but nothing else from this
module — a DR backup that restores tenants and domains silently produces a
server with ZERO trust edges and ZERO guest registrations, i.e. the B2B
feature is quietly disabled after every restore. And on the provisioning
side, the durable backends from Improvement 1 have no config surface:
`cmd/sso-server` constructs the sqlite/postgres tenant store but nothing
that would hand the server a durable collab store, and
`docs/config-reference.md` documents no collaboration knobs — so even with
backends implemented, an operator cannot turn them on without writing code.

**Evidence**:

- `interfaces/snapshot/snapshotter.go:162–188` — `exportTenants` marks
  exactly `CategoryTenants` and `CategoryTenantDomains`; the `Snapshotter`
  struct (:28) has `Tenants tenant.Store` (optional, nil = category
  excluded) — the field pattern the collab stores must join.
- `interfaces/snapshot/snapshot.go:103–104,119` — `CategoryTenants` /
  `CategoryTenantDomains` consts and the default category list that must
  gain the new categories.
- `interfaces/snapshot/restorer.go:177–178` — the category → restore-func
  dispatch table (`restoreTenants`, `restoreTenantDomains`) that must gain
  two arms.
- `interfaces/snapshot/snapshot_v2_test.go:17–20,37–48` — the round-trip
  test covers tenants + domains only; `categories_test.go` pins the default
  category set.
- `cmd/sso-server/build_stores.go:142–160` — `buildSnapshotterRestorer`
  constructs the `snapshot.Snapshotter`/`Restorer` with `Tenants:
  b.tenantStore` — the single construction point for the new fields.
- `cmd/sso-server/build_app_oauth.go:67` + `:43` — `wireTenantStoreOptions`
  (`sso.WithTenantStore(tenantStore)`) and the sqlite/postgres tenant
  backend switch (`cfg.Tenant.Backend != "postgres"`) — the provisioning
  decision point the collab stores must follow.
- `docs/config-reference.md` — no collaboration/guest knobs; the feature is
  documented only in `docs/observability.md:278` as an opt-in gate.
- Budget: `interfaces/snapshot` is at its frozen 14-file ceiling — every
  change extends an existing file; no new files.

**Proposed behavior**:

1. New categories `CategoryCollaborations = "collaborations"` and
   `CategoryGuestRecords = "guest_records"` in
   `interfaces/snapshot/snapshot.go` (consts + default list, beside the
   tenant categories).
2. `interfaces/snapshot/snapshotter.go` — `Snapshotter` gains optional
   `Collaborations tenant.CollaborationStore` and
   `GuestRecords tenant.ExternalUserStore` fields (nil ⇒ category excluded,
   same contract as `Tenants`). `exportTenants` (or a new
   `exportCollaborations`) lists the collab rows per tenant: iterate
   `ListTenants` and call `ListByGuestTenant(tenantID)` on each store —
   the SPI has no global list, and the tenant scan is already in hand in
   `exportTenants` — then mark the categories and store the rows on the
   snapshot (order unspecified, matching the memory stores' contract).
3. `interfaces/snapshot/restorer.go` — two dispatch arms:
   `restoreCollaborations`/`restoreGuestRecords` replay rows via
   `Put`/`Add` (idempotent upserts, so re-restores converge); the
   `Restorer` struct gains the same two optional fields.
4. `cmd/sso-server/build_stores.go:142–160` — `buildSnapshotterRestorer`
   passes the wired collab stores into both structs (nil when unwired ⇒
   categories never marked ⇒ byte-identical snapshots for memory/absent
   deployments).
5. Provisioning wiring: in `build_app_oauth.go`'s tenant-backend switch,
   construct the sqlite or postgres collab stores (Improvement 1) whenever
   the tenant store is durable, pass them to
   `sso.WithExternalUserStore`/`sso.WithTenantCollaborationStore` AND into
   the snapshotter/restorer; memory backend ⇒ nil everywhere (no-op).
   Document the surface in `docs/config-reference.md` (a `tenant.collab`
   enablement note tied to the existing `tenant.backend` knob) and extend
   `docs/observability.md`'s cross-tenant section with the admin events and
   snapshot categories; `docs/feature-matrix.md` B2B row gains
   backend/admin/snapshot completeness.
6. No `interfaces/sso` file changes (60-file frozen ceiling): the options
   `WithExternalUserStore`/`WithTenantCollaborationStore` already exist
   (`options_grants.go:195–219`) and carry the stores into the server;
   only `cmd/sso-server` and `interfaces/snapshot` change.

**Acceptance check**:

- Snapshot round trip (extend `snapshot_v2_test.go`): seed sqlite collab
  stores with 2 edges + 2 guest records → snapshot (manifest lists the new
  categories) → restore into fresh stores → `ListByGuestTenant` returns
  identical rows; `Exclude`-listing either category omits it and its
  restore arm no-ops.
- Byte-identity for unwired builds: snapshot of a memory/absent-collab
  server marks NO new categories (existing snapshot tests green unchanged).
- `categories_test.go` asserts the two new categories are in the default
  set; `go test ./interfaces/snapshot/... -race` green.
- Provisioning test (the `cmd/sso-server/tenant_wiring_test.go` pattern):
  `cfg.Tenant.Backend=sqlite|postgres` ⇒ collab stores constructed and
  wired into server options AND snapshotter/restorer; `memory` ⇒ all nil.
- `make ci` green; `go test ./test/ -run TestE2E -v` green (gate behavior
  untouched).

## Files

### Create

```text
domains/tenant/sqlite/collab.go — migration v5 tables + ExternalUserStore/CollaborationStore impls
domains/tenant/sqlite/collab_test.go — conformance + durability + fail-closed tests
infrastructure/postgres/collab.go — postgres baseline tables + both store impls
infrastructure/postgres/collab_test.go — conformance + fail-closed tests
domains/tenant/memory/conformance.go — shared ConformanceSuite (permissionstest pattern, in-place)
proto/admin/v1/collaborations.proto — CollaborationAdminService RPCs + messages
gen/proto/admin/v1/… — regenerated bindings
interfaces/grpcserver/grpcadmin/admin_collab_test.go — bufconn RPC + audit tests (test files don't count toward fan-out)
```

### Modify

```text
domains/tenant/memory/collab_store_test.go — refactor onto ConformanceSuite
interfaces/grpcserver/grpcadmin/admin_domains.go — CollaborationAdminService impl (171 → ~470 lines, under 500)
platform/audit/auditspi/event_types_admin.go — 4 new admin_* event consts
platform/audit/aliases_spi.go — aliases for the 4 events
platform/audit/auditreport/control_areas.go — classify the 4 events (update the manual count)
platform/audit/auditsink/cef.go, platform/audit/auditsink/ocsf.go — sink mappings
cmd/sso-server/build_http.go — register CollaborationAdminService gateway handler
cmd/sso-server/build_app_oauth.go — durable collab-store construction + wiring in the tenant-backend switch
cmd/sso-server/build_stores.go — pass collab stores into Snapshotter/Restorer
interfaces/snapshot/snapshot.go — 2 new category consts + default list
interfaces/snapshot/snapshotter.go — 2 optional store fields + export arm
interfaces/snapshot/restorer.go — 2 optional store fields + restore arms
interfaces/snapshot/snapshot_v2_test.go, categories_test.go — round-trip + category-set coverage
docs/openapi.yaml — /api/v1/admin/collaborations* and /api/v1/admin/guest-records* routes
docs/config-reference.md — tenant collaboration backend knob
docs/observability.md — admin events + snapshot categories for the cross-tenant section
docs/feature-matrix.md — B2B collaboration completeness row
```

### Do not modify

```text
domains/tenant/tenant_collab.go — SPI definitions, sentinels, Validate (contract, not implementation)
domains/tenant/memory/collab_store.go — reference implementation semantics (only add the conformance file beside it)
internal/handler/tokengrant/token_exchange.go — the gate (tokExEnforceTenantCollaboration / tokExAuthorizeGuestHop) is frozen
interfaces/sso/options_grants.go — WithExternalUserStore/WithTenantCollaborationStore signatures (already carry stores)
test/cross_tenant_collaboration_test.go — existing E2E matrix stays as the wire-behavior pin
domains/tenant/tenant.go, interfaces/grpcserver/grpcadmin/admin_tenants.go — tenant CRUD untouched
```

## Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./domains/tenant/... -race
go test ./infrastructure/postgres/ -run Collab -race
go test ./interfaces/snapshot/... -race
go test ./interfaces/grpcserver/ -run 'TestCollab|TestAdmin' -race
go test ./platform/audit/... -run 'Drift|Conformance' -race
go test ./test/ -run 'TestCrossTenant|TestE2E' -v
make ci
```
