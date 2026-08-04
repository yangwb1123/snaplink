# Design: `domains/tenant` — B2B cross-tenant collaboration「内存-only + 零管理面」→ 持久化后端 + 运营/审计表面

Source: `docs/auto/domains-tenant-direction3-spec.md` (direction 3 of
`docs/auto/domains-tenant-analysis.md`). This doc fixes the three decisions —
durable SPI backends, a `CollaborationAdminService`, and snapshot v2 +
provisioning coverage — down to API surface, storage model, failure modes,
and the failure modes of the design itself. Three spec corrections surfaced
during design (each flagged inline):

1. **Postgres needs a NEW migration version, not a baseline-string edit.**
   The versioned runner (`infrastructure/postgres/migrate.go` `applyPending`)
   never re-applies an already-stamped migration. Extending the `tenantSchema`
   v1 baseline (the spec's "extending tenantSchema's ensure path") would leave
   every EXISTING postgres deployment without the collab tables, and the first
   `IsTrusted`/`Get` would fail at runtime. The tables must ship as a v2
   migration in `tenantMigrations` (fresh DBs get them via v1+v2; existing DBs
   via v2 alone).
2. **The audit meta keys are not all "existing wire keys".**
   `shared/core/consts_wire.go` has `KeyGuestTenantID = "guest_tenant_id"` but
   no `home_tenant_id`/`external_subject_id` consts (the strings exist only as
   JSON tags on the domain structs). Two new consts must be added; the spec's
   "Do not modify" list does not include `shared/core/consts_wire.go`, so this
   is additive and allowed.
3. **`admin_domains.go` headroom is ~30 lines, not ~330.** 6 RPCs +
   converters + service struct land at ~530 lines if everything goes in one
   file. The design splits: RPC methods in `admin_domains.go`, message
   converters + filter helpers in `admin_paginate.go` (331 lines, ~169 of
   headroom).

All budget claims below were re-verified against the tree: `grpcadmin` has
exactly 10 non-test files, `interfaces/snapshot` 14 (frozen exemption),
`domains/tenant/sqlite` 5, `domains/tenant` root 4, `interfaces/sso` 60
(frozen exemption). `infrastructure/postgres` (26 non-test files) is skipped
by the file/fan-out gates via `skipDirs` (pre-existing drift vs AGENTS.md's
"root-module package" wording — noted, not fixed here; adding `collab.go` is
gate-safe either way).

---

## Decision 1: durable SPI backends — migration v5 + sqlite/postgres stores + an in-place conformance suite

### Problem restated

`tenant.ExternalUserStore` and `tenant.CollaborationStore`
(`domains/tenant/tenant_collab.go:109,178`) have exactly one implementation,
the single-replica in-process `memory` pair (`domains/tenant/memory/
collab_store.go:5–8` explicitly names a durable store as the production
path). The SPI doc promises "any Store backend a deployment needs (sqlite,
etcd, ...) implements the same two interfaces" — none does. A restart
silently resets the entire trust graph and guest roster to the fail-closed
zero state; the operator cannot even tell the difference without probing.

### API surface

New file `domains/tenant/sqlite/collab.go` — two types in the existing
`sqlite` package, both implementing the domain interfaces:

```go
func NewExternalUserStore(db *sql.DB) (*ExternalUserStore, error)
func NewCollaborationStore(db *sql.DB) (*CollaborationStore, error)
```

- Constructors mirror `Store.NewWithDB` (caller owns the `*sql.DB`; the
  stores never close it, expose no `Close`/`Ping`/`DB`). Both run
  `migrate.Run(ctx, db, "tenant", migrations)` — the SAME list and the SAME
  namespace as the tenant store. Running it twice is a versioned no-op
  (idempotent by design); a collab-only open of an old DB converges it to
  head. `PRAGMA foreign_keys = ON` is set for parity with `NewWithDB`
  (irrelevant today — no FKs — but keeps the constructor pattern uniform).
- **The single-list rule is a hard invariant**: v5 is appended to the
  existing ordered `migrations` slice in `sqlite.go`. A second slice with
  version 5 in the same namespace would double-claim the version table.
  Because the list is shared, opening the tenant store already migrates to
  v5; `TenantMaxVersion()` returns 5 automatically and the cmd boot gate
  (`serverbuildsign.CheckSQLiteSchema`) then correctly refuses an older
  binary against a v5 DB.
- Semantics are copied from `memory`, not relaxed:
  - `Add`/`Put`: `Validate()` first, then single-statement
    `INSERT ... ON CONFLICT(...) DO UPDATE` (full replace, including
    `created_at` — matches memory's copy-the-struct semantics; no
    created-at preservation like `PutTenant`).
  - `Remove`: `DELETE`; 0 rows affected is nil — no existence oracle.
  - `Get`: missing row → `tenant.ErrNoGuestRecord` (via `sql.ErrNoRows`,
    never via a fall-through); any other error is wrapped, never mapped to
    the sentinel.
  - `IsTrusted`: missing row → `(false, nil)`; backend error → `(false, err)`.
    A parse/scan error can never produce `(true, nil)`.
- Zero-value parity: `roles_json`/`attributes_json` are stored as the raw
  `json.Marshal` output. Go's `json.Marshal` of a nil slice/map is `null`,
  and unmarshalling `null` yields nil — so nil ↔ `null` round-trips exactly
  and the sqlite/postgres stores return the same nil-vs-empty shapes as
  memory. No normalization code required; the conformance suite pins it.

New file `infrastructure/postgres/collab.go` — `NewExternalUserStoreWithDB(db,
*database/sql.DB, dialect Dialect)` and `NewCollaborationStoreWithDB(db,
dialect)`, mirroring `NewTenantStoreWithDB` and running
`Run(ctx, db, "tenant", tenantMigrations, dialect)`.

New file `domains/tenant/memory/conformance.go` — the shared suite, realized
in-place because `domains/` is at its frozen subdir ceiling and
`permissionstest`-style packages cannot be added under it:

```go
func ConformanceSuite(t *testing.T, ext tenant.ExternalUserStore, collab tenant.CollaborationStore)
```

Coverage (all asserted behaviorally, never on pointer identity): upsert-
replaces (same key, record count stable); idempotent remove (twice → nil);
`ErrNoGuestRecord` via `errors.Is`; validation rejection with
`ErrInvalidGuestRecord`/`ErrInvalidCollaboration` (empty fields, guest==home);
`IsTrusted` false-default `(false, nil)`; `Put` → `IsTrusted` true;
`ListByGuestTenant` filters to the guest tenant (order unspecified);
defensive-copy semantics (mutating a returned record or the passed-in record
does not change the store); nil-vs-empty JSON round-trip. `memory/
collab_store_test.go` is refactored onto it; `sqlite/collab_test.go` and
`postgres/collab_test.go` import it and add backend-specific tests (durability
round trip, fail-closed on closed DB).

### Storage model

Migration v5 (appended to `sqlite.go` `migrations`; `BIGINT`/`INTEGER`
Unix-nanosecond `created_at` matching the `tenants` tables; `TEXT` JSON
columns matching the `settings_json` pattern):

```sql
CREATE TABLE tenant_collaborations (
    guest_tenant_id TEXT    NOT NULL,
    home_tenant_id  TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (guest_tenant_id, home_tenant_id)
);

CREATE TABLE guest_records (
    guest_tenant_id     TEXT    NOT NULL,
    external_subject_id TEXT    NOT NULL,
    home_tenant_id      TEXT    NOT NULL,
    roles_json          TEXT    NOT NULL DEFAULT '[]',
    attributes_json     TEXT    NOT NULL DEFAULT '{}',
    created_at          INTEGER NOT NULL,
    PRIMARY KEY (guest_tenant_id, external_subject_id)
);

CREATE INDEX IF NOT EXISTS idx_guest_records_guest_tenant
    ON guest_records(guest_tenant_id);
```

Postgres v2 migration in `tenantMigrations` (same DDL, `BIGINT`; multi-
statement strings are fine — `postgres.Run` splits on `;`):

```sql
CREATE TABLE IF NOT EXISTS tenant_collaborations ( ... PRIMARY KEY (guest_tenant_id, home_tenant_id) );
CREATE TABLE IF NOT EXISTS guest_records ( ... PRIMARY KEY (guest_tenant_id, external_subject_id) );
CREATE INDEX IF NOT EXISTS idx_guest_records_guest_tenant ON guest_records(guest_tenant_id);
```

Decisions pinned here:

- **No `FOREIGN KEY` to `tenants`** on either backend. The SPIs accept
  opaque tenant IDs (no charset constraint — see `tenant.Validate`), the
  token-exchange gate must keep working with a memory-only tenant store, and
  a tenant deletion must not silently cascade the trust graph away. Deleting
  a tenant's edges/guests is an operator decision through the admin surface
  (Decision 2), not a schema side effect. (Postgres enforces FKs always, so
  this is doubly mandatory there.)
- **`idx_guest_records_guest_tenant` is technically redundant** — the PK's
  leftmost column already serves `WHERE guest_tenant_id = ?` — but it is
  pinned by the spec, costs nothing, and survives a future PK change.
  `tenant_collaborations` needs no extra index: the PK prefix covers
  `ListByGuestTenant`.
- **Rows are tenant-boundary data, not credentials** — no redaction
  interaction (Decision 3), no no-store headers (these are admin endpoints,
  not credential endpoints).
- **Shared `*sql.DB`, no second pool**: the sqlite collab stores wrap
  `tenantStore.DB()`; postgres wraps `b.pgDB`. One migration history, one
  connection pool, and the tenant store's existing storage-health source
  already covers the DB — no duplicate health registration.

### Failure modes

| Failure | Behavior |
|---|---|
| Backend down / `*sql.DB` closed | `IsTrusted` → `(false, err)`, `Get` → wrapped error (NOT `ErrNoGuestRecord`); the token-exchange gate collapses both to the same `invalid_grant` — oracle intact |
| Corrupt `roles_json`/`attributes_json` row | Scan returns a wrapped error; never a synthesized record with nil roles (fail-closed, same collapse) |
| Migration failure at boot | Constructor error propagates; cmd boot fails loud (same shape as `BuildTenantStore`) |
| `SQLITE_BUSY` on a collab write | Single-statement upserts are short; a busy error surfaces as a wrapped error (admin mutation → `Internal`; gate unaffected — writes never sit on the gate path). Bounded-busy handling (the `domainClaimBusyTimeoutMS` pattern) is NOT added: it exists for PutDomain's read-modify-write claim, which collab writes do not have. Documented limitation, consistent with the tenant store's own single-statement writes. |
| Validation failure | Same `ErrInvalidGuestRecord`/`ErrInvalidCollaboration` as memory, before any SQL |

### What could break the design

- **The postgres baseline-string edit (spec's original wording) is a silent
  runtime break** for existing deployments — this design's correction to a v2
  migration is mandatory, and the postgres `collab_test.go` must include an
  upgrade test (apply v1, stamp, then run the full list, assert tables exist)
  so the trap cannot regress.
- **A second migrations list** in the `tenant` namespace (e.g. someone
  extracting the collab DDL into its own slice with version 1) would either
  collide with the stamped versions or leave the version table ambiguous —
  the single shared list is enforced by the `migration_test.go` pattern
  (head version = `len(migrations)`-derived `TenantMaxVersion()`, v4 → v5
  upgrade test).
- **Nil-vs-empty drift**: if the JSON scan used `DEFAULT`-fallback
  normalization instead of the `null` round-trip, `Get` would return non-nil
  empty `Roles` where memory returns nil. The conformance suite's zero-value
  parity case pins this; the E2E matrix (`test/cross_tenant_collaboration_
  test.go`, unchanged) pins the gate behavior on top.
- **FK temptation**: adding `REFERENCES tenants(id)` would break opaque-ID
  and memory-tenant-store deployments and silently delete trust rows on
  tenant deletion. Guarded by the no-FK test in the conformance suite
  (add rows for tenant IDs that do not exist in the tenants table — must
  succeed).
- **`IsTrusted` error-path mapping**: mapping a closed-DB error to
  `ErrNoGuestRecord` would create a "backend down reads as no-trust" oracle —
  harmless for the gate (same `invalid_grant`) but wrong for the admin list
  surface (would show an empty trust graph during an outage). The fail-closed
  test (closed DB → non-nil error, not the sentinel) pins this.

---

## Decision 2: management + audit surface — `CollaborationAdminService`

### Problem restated

The B2B feature has zero operations surface: no list, no revoke, no audit
trail; the only mutation paths are direct store calls in test code. Every
sibling tenant resource has full `TenantAdminService` CRUD plus classified
audit events. The trust graph is the security-sensitivity worst case (an
allow-list that only grows), so the gap matters most here.

### API surface

New file `proto/admin/v1/collaborations.proto` — service
`CollaborationAdminService` (regenerated via the `python cli.py` proto flow
into `gen/proto/admin/v1/`; `gen/` is outside all fan-out gates):

```proto
service CollaborationAdminService {
  rpc ListCollaborations(ListCollaborationsRequest) returns (ListCollaborationsResponse) {
    option (google.api.http) = { get: "/api/v1/admin/collaborations" };
  }
  rpc PutCollaboration(PutCollaborationRequest) returns (PutCollaborationResponse) {
    option (google.api.http) = { put: "/api/v1/admin/collaborations", body: "collaboration" };
  }
  rpc RemoveCollaboration(RemoveCollaborationRequest) returns (RemoveCollaborationResponse) {
    option (google.api.http) = { delete: "/api/v1/admin/collaborations/{guest_tenant_id}" };
  }
  rpc ListGuestRecords(ListGuestRecordsRequest) returns (ListGuestRecordsResponse) {
    option (google.api.http) = { get: "/api/v1/admin/guest-records" };
  }
  rpc AddGuestRecord(AddGuestRecordRequest) returns (AddGuestRecordResponse) {
    option (google.api.http) = { put: "/api/v1/admin/guest-records", body: "guest_record" };
  }
  rpc RemoveGuestRecord(RemoveGuestRecordRequest) returns (RemoveGuestRecordResponse) {
    option (google.api.http) = { delete: "/api/v1/admin/guest-records/{guest_tenant_id}" };
  }
}
```

Message shapes mirror `tenants.proto` + the domain structs, with the repo's
`int64 *_unix` (seconds) time convention:

```proto
message Collaboration { string guest_tenant_id = 1; string home_tenant_id = 2; int64 created_at_unix = 3; }
message GuestRecord {
  string guest_tenant_id = 1; string external_subject_id = 2; string home_tenant_id = 3;
  repeated string roles = 4; map<string, string> attributes = 5; int64 created_at_unix = 6;
}
message ListCollaborationsRequest {
  string guest_tenant_id = 1;  // REQUIRED
  string home_tenant_id  = 2;  // optional narrowing
  string page_token = 3; int32 page_size = 4;
}
message ListGuestRecordsRequest {
  string guest_tenant_id = 1;  // REQUIRED
  string home_tenant_id = 2; string external_subject_id = 3;  // optional narrowing
  string page_token = 4; int32 page_size = 5;
}
// RemoveCollaborationRequest { guest_tenant_id, home_tenant_id }
// RemoveGuestRecordRequest { guest_tenant_id, external_subject_id }
```

Decisions pinned here:

- **`guest_tenant_id` is REQUIRED on both list RPCs** (else
  `InvalidArgument`). Rationale: the SPIs enumerate per guest tenant
  (`ListByGuestTenant`); there is no global list. An unfiltered list would
  force the admin service to depend on a `tenant.Store` (coupling the
  collab surface to tenant-store availability) or to do an O(all edges)
  cross-tenant scan. Full-inventory export is the snapshot category's job
  (Decision 3), which already holds the tenant store. `home_tenant_id` /
  `external_subject_id` narrow in memory after the per-guest scan.
  Pagination reuses `decodeOffset`/`pageBounds`/`clampPageSize` from
  `admin_paginate.go` (bounds the response, not the server-side
  materialization — same as `ListDomains`).
- **Second key as a query parameter, not a second path segment**: tenant
  IDs and external subject IDs are opaque non-empty strings with no charset
  constraint (`tenant.Validate`), and raw subject IDs in particular may
  contain `/`. `DELETE /api/v1/admin/collaborations/{guest_tenant_id}?home_
  tenant_id=...` keeps the path segment safe; the gateway maps the non-path
  field to a query parameter automatically (no body). `page_token` already
  establishes query params on admin GETs.
- **No `AlreadyExists` preflight** (contrast `CreateDomain`): `Put`/`Add`
  are upserts by contract, so there is no read-modify-write race and no
  existence check to leak. `Remove` is idempotent and returns success for an
  absent row — no revocation oracle (matches the store contracts).
- **Error mapping** (identical vocabulary to `TenantAdminService`, no new
  wire error codes): nil store → `codes.FailedPrecondition` ("collaboration
  store not configured"); missing required field → `InvalidArgument`;
  `Validate()` failure (`ErrInvalidGuestRecord`/`ErrInvalidCollaboration`) →
  `InvalidArgument` wrapping the sentinel; backend error → `Internal`; the
  `ErrNoGuestRecord` sentinel is NOT surfaced (Remove is idempotent; Get
  doesn't exist as an RPC).
- **AuthZ**: nothing per-RPC — the existing admin gateway interceptor
  enforces `admin:read` on lists and `admin:write` on mutations, and the
  existing admin HTTP middleware issues the `401 Bearer realm="admin"`
  challenge. Stores are tenant-boundary data, not credentials: these
  endpoints never feed the login/token path.
- **Audit**: four new event consts in
  `platform/audit/auditspi/event_types_admin.go` —
  `admin_collaboration_created`, `admin_collaboration_removed`,
  `admin_guest_record_added`, `admin_guest_record_removed`; aliases in
  `platform/audit/aliases_spi.go`; all four classified in `auditreport/
  control_areas.go` CC6.3 (Privileged and administrative actions, beside
  `EventAdminTenant*`) with the manual count comment updated (60 → 64);
  mappings added in `auditsink/cef.go` + `auditsink/ocsf.go`. Mutations
  record via `recordAdminMeta` with `guest_tenant_id` (`core.KeyGuestTenantID`),
  plus TWO NEW consts `KeyHomeTenantID = "home_tenant_id"` and
  `KeyExternalSubjectID = "external_subject_id"` added to
  `shared/core/consts_wire.go` (correction 2 — the spec claims these are
  existing wire keys; only `guest_tenant_id` is). `EventCrossTenantTokenExchange`
  is untouched.
- **Optional revocation callbacks**: `NewCollaborationAdminService(ext,
  collab, recorder, onEdgeRemoved, onGuestRemoved)` with nil-defaulting (the
  `invalidateSuspensionCache` pattern) — today every deployment passes nil;
  the seam exists so a future trust-verdict cache can evict on revoke.
- **File placement** (correction 3): RPC methods land in
  `interfaces/grpcserver/grpcadmin/admin_domains.go` (171 → ~420 lines,
  under 500); the service struct/constructor, proto converters
  (`collaborationToProto`/`protoToCollaboration`/`guestRecordToProto`/
  `protoToGuestRecord`), and the in-memory narrow/filter helpers land in
  `admin_paginate.go` (331 → ~430 lines, under 500). This keeps both files
  under the 500-line budget with headroom; the spec's single-file plan does
  not fit.
- **Mounting**: `cmd/sso-server/build_http.go` registers
  `RegisterCollaborationAdminServiceHandlerServer` beside the tenant service
  (with a `grpcserver` alias in `interfaces/grpcserver/aliases.go`), gated on
  at least one collab store being wired (nil stores still mount — every RPC
  returns `FailedPrecondition`, mirroring how the tenant service behaves
  without a store). Routes documented in `docs/openapi.yaml`.

### Storage model

No new storage. The service is a thin operator surface over the two SPIs:
writes are the same upserts/removes the gate reads, so an admin revoke is
immediately visible to `tokExEnforceTenantCollaboration`/`tokExAuthorizeGuestHop`
(no cache to invalidate today; the callbacks are the future seam). Record
`CreatedAt` is carried on the wire (`created_at_unix`, seconds) so an
operator can see when an edge was granted.

### Failure modes

| Failure | Behavior |
|---|---|
| Store nil (unwired deployment) | Every RPC → `FailedPrecondition` — byte-identical behavior to today (no surface exists) |
| Store backend error (DB down) | Lists → `Internal`; mutations fail before write. The gate path is unaffected (it reads the same stores but collapses errors to `invalid_grant`) |
| Invalid record | `InvalidArgument` wrapping the domain sentinel — same code vocabulary as tenant/domain RPCs |
| Audit sink failure | Fail-open per AGENTS.md §3 — `recordAdminMeta` never fails the RPC; nil recorder is a no-op |
| Double-remove / double-put | Idempotent by store contract — success, one audit event each (event emitted per RPC, not per row changed) |

### What could break the design

- **File budget**: the 10-file ceiling on `grpcadmin` forbids a new file;
  the 500-line budget on both candidate files is the binding constraint.
  The RPCs-in-`admin_domains.go` / helpers-in-`admin_paginate.go` split is
  what makes it fit; if the bufconn tests push either file over 500, the
  fallback is shrinking the RPC bodies (the filter/narrow helpers are the
  only movable part left) — never a new file, never touching
  `admin_tenants.go` (461 lines).
- **Proto regeneration drift**: `gen/proto/admin/v1` bindings must be
  committed in the same change; a stale regenerate fails the build.
- **Audit drift tests**: `auditreport`'s drift test fails CI the moment a
  new `EventType` is unclassified; CEF/OCSF conformance tests pin the sink
  mappings. Forgetting any of the four consts' classification/alias/sink
  work breaks `make ci` — this is the most likely accidental break in this
  decision.
- **Query-parameter binding**: the gateway's automatic query mapping for
  the second key depends on the request message having no body binding; a
  later edit adding `body: "*"` would silently move the key into the body
  and break the HTTP contract. The bufconn + gateway E2E tests (401/403
  scoping, mutation via query param) pin this.
- **The E2E matrix**: `test/cross_tenant_collaboration_test.go` must stay
  green unchanged — the admin surface must not alter gate behavior. The
  gateway E2E asserting 401/403 on the new routes is additive.

---

## Decision 3: snapshot v2 backup coverage + provisioning wiring

### Problem restated

Snapshot v2 exports/restores tenants and tenant domains but nothing else
from this module; a DR restore silently produces a server with zero trust
edges and zero guest registrations — the B2B feature is quietly disabled
after every restore. And `cmd/sso-server` has no way to construct the
durable collab stores (Improvement 1) or hand them to the server/snapshotter.

### API surface

All changes extend EXISTING files — `interfaces/snapshot` is at its frozen
14-file exemption ceiling; no new files there.

- `interfaces/snapshot/snapshot.go`: two consts
  `CategoryCollaborations = "collaborations"` and
  `CategoryGuestRecords = "guest_records"` (beside `CategoryTenantDomains`),
  both added to `AllCategories()`; `Resources` gains
  `Collaborations []*tenant.TenantCollaboration` and
  `GuestRecords []*tenant.GuestRecord` (`json:"collaborations,omitempty"` /
  `json:"guest_records,omitempty"`).
- `interfaces/snapshot/snapshotter.go`: `Snapshotter` gains optional
  `Collaborations tenant.CollaborationStore` and
  `GuestRecords tenant.ExternalUserStore` fields (nil ⇒ category never
  marked — same contract as `Tenants`). `exportTenants` already returns the
  tenant-ID list; a new `exportCollaborations(ctx, snap, opts, tenantIDs)`
  runs after it: for each tenant ID, `ListByGuestTenant(id)` on each wired
  store, append rows, `markCategory`. When `s.Tenants` is nil there is no
  tenant list and the categories are skipped even if the collab stores are
  wired (same dependence `exportConnections` already has on `tenantIDs`).
- `interfaces/snapshot/restorer.go`: `Restorer` gains the same two optional
  fields; `restorePlan` gains two arms after `CategoryTenantDomains`.
  Per-row semantics mirror `restoreTenants`: `Merge` skips rows whose key
  already exists (`IsTrusted`/`Get`); `Overwrite` and `Replace` upsert via
  `Put`/`Add` (idempotent — re-restores converge). `Replace` additionally
  prunes rows absent from the snapshot: iterate `r.Tenants.ListTenants()` ×
  `ListByGuestTenant` × `Remove` for rows not in the wanted set. If
  `r.Tenants` is nil, Replace returns `ErrUnsupportedRestore` for these
  categories (the `prunePairwise` precedent) — there is no global list on
  the SPIs.
- `cmd/sso-server/build_stores.go` `buildSnapshotterRestorer`: pass
  `b.collabTrustStore`/`b.collabExtStore` into both structs (nil when
  unwired ⇒ categories never marked ⇒ byte-identical snapshots for
  memory/absent deployments).
- `cmd/sso-server/build_app_oauth.go` `wireTenant`: after
  `wireTenantStoreOptions`, switch on the tenant backend:
  - `sqlite`: assert `tenantStore.(*tenantsqlite.Store)`, build
    `tenantsqlite.NewExternalUserStore(ts.DB())` +
    `tenantsqlite.NewCollaborationStore(ts.DB())` (shared pool, shared
    migration history — see Decision 1).
  - `postgres`: `postgresbackend.NewExternalUserStoreWithDB(b.pgDB,
    b.pgDialect)` + `NewCollaborationStoreWithDB` (requires
    `tenant.enabled` + postgres backend, as today).
  - `memory`/absent: both nil.
  Store both on the builder for the snapshotter/restorer, append
  `sso.WithExternalUserStore`/`sso.WithTenantCollaborationStore` (the
  options already exist in `options_grants.go` — NO `interfaces/sso`
  change, 60-file ceiling respected).
- **No new config knob**: enablement derives from `tenant.backend`
  durability. `docs/config-reference.md` gains a `tenant.collab` note tied
  to the existing `tenant.backend` row (durable ⇒ collab shares the backend;
  memory ⇒ in-process, single-replica); `docs/observability.md` gains the
  admin events + snapshot categories in the cross-tenant section;
  `docs/feature-matrix.md` B2B row gains backend/admin/snapshot
  completeness. A separate knob would create a "durable tenants + volatile
  trust" configuration that helps nobody and silently reintroduces the
  restart-loss failure mode.

### Storage model

Wire format: two additive `omitempty` JSON fields on `Resources`; the
envelope keeps `SchemaVersion = "2"` — old snapshots lack the fields (nil →
category not marked → restore no-op), and old binaries restoring a new
snapshot ignore the unknown fields and skip the unknown category strings in
the manifest (`IncludesCategory` is a string-containment check). Rows are
exported as plain domain structs (order unspecified, matching the memory
stores' contract); no redaction interaction — collab rows carry pointers and
guest-scoped roles, no credentials, and `applyRedaction` only copies the
fields it knows.

### Failure modes

| Failure | Behavior |
|---|---|
| Collab store backend fails during export | Export fails all-or-nothing (existing contract — partial snapshots are never returned) |
| Collab store nil on restore | Category silently skipped (existing optional-backend contract) |
| `Exclude` lists a category | Not marked on export; restore arm skipped |
| Replace mode without `r.Tenants` | `ErrUnsupportedRestore` for the two categories (pairwise precedent) |
| Re-restore of the same snapshot | Converges — upserts are idempotent; Merge skips existing rows |
| Restore target on a different backend | Rows replay through the SPI — sqlite→postgres restore works (both implement the same interfaces; no dialect coupling in the snapshot format) |

### What could break the design

- **`categories_test.go` pins the default category set** — both new
  categories must be added there or the gate fails; the round-trip test in
  `snapshot_v2_test.go` must seed + restore both stores.
- **Byte-identity regression**: an unwired build must not mark the new
  categories. The nil-store early-return pattern (mirroring every other
  `export*`/`restore*` arm) guards this; the existing snapshot tests
  (unchanged) pin it.
- **The postgres v2-migration trap (correction 1) interacts here**: a
  postgres deployment that restores collab categories before the v2
  migration exists would fail every `Put`/`Add` with a "no such table"
  error. Restore ordering (tenants/domains first) does not fix schema
  absence — the migration lands in the same change as the restore arms, and
  the upgrade-path test pins it.
- **Replace-prune enumeration cost**: O(tenants × rows) on the admin path —
  acceptable for operator-scale trust graphs; documented, not optimized.
- **Provisioning test** (the `tenant_wiring_test.go` pattern) must assert
  the three-way matrix: sqlite → stores constructed + wired into options AND
  snapshotter/restorer; postgres → same; memory → all nil. This is what
  stops a future backend switch from silently dropping the wiring.

---

## Sequencing, gate compliance, and what could break the design overall

Implementation order (each step leaves `go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .` green):

1. **Conformance suite first** (`domains/tenant/memory/conformance.go`) +
   refactor `collab_store_test.go` onto it — establishes the contract before
   any backend exists.
2. **SQLite backend** (`sqlite/collab.go`, migration v5, `collab_test.go`
   with conformance + durability + fail-closed + v4→v5 upgrade tests).
3. **Postgres backend** (`postgres/collab.go`, v2 migration in
   `tenantMigrations`, `collab_test.go` incl. the v1→v2 upgrade-path test).
4. **Admin surface** (proto → regenerate → `grpcadmin` RPCs + helpers →
   audit consts/aliases/classification/sinks → gateway mount → bufconn +
   gateway E2E + openapi docs). The audit classification and sink mapping
   land in the SAME change as the event consts — the drift test fails
   otherwise.
5. **Snapshot + provisioning** (categories, export/restore arms, cmd
   wiring, snapshot/provisioning tests, docs).
6. **E2E + full gates**: `go test ./test/ -run 'TestCrossTenant|TestE2E' -v`
   (existing matrix unchanged), the new sqlite-wired variant,
   `go test ./... -race`, `make ci`. Independent review after.

Budget compliance (re-verified):

| Location | Before | After | Cap |
|---|---|---|---|
| `domains/tenant/sqlite` | 5 files | 7 files | 10 (not exempt) |
| `domains/tenant` root | 4 files | 4 files | 10 |
| `infrastructure/postgres` | 26 files | 27 files | gate-skipped (pre-existing `skipDirs` drift) |
| `domains/tenant/memory` | 2 files | 3 files | 10 |
| `interfaces/grpcserver/grpcadmin` | 10 files | 10 files | 10 (at ceiling — extend-only) |
| `interfaces/grpcserver/grpcadmin/admin_domains.go` | 171 lines | ~420 | 500 |
| `interfaces/grpcserver/grpcadmin/admin_paginate.go` | 331 lines | ~430 | 500 |
| `interfaces/snapshot` | 14 files | 14 files | 14 (frozen exemption — extend-only) |
| `interfaces/sso` | 60 files | 60 files | 60 (frozen — no changes) |
| `cmd/sso-server` | 24 files | 24 files | 24 (frozen — modify-only) |

Cross-cutting risks ranked:

1. **Postgres upgrade path** (correction 1): the single most likely silent
   production break — mitigated by the v2-migration design + upgrade-path
   test.
2. **File budgets in `grpcadmin`**: the only hard ceiling the design
   brushes against; the two-file split is pre-committed, and the RPC bodies
   are the designed pressure valve.
3. **Audit classification completeness**: mechanical (drift test catches
   it), but the most likely CI break — the 4 consts, 4 aliases, 4
   classifications, and 8 sink mappings must ship atomically.
4. **Oracle safety**: every backend error path is designed to land on the
   same `invalid_grant` the gate already returns; the fail-closed tests
   (closed DB, corrupt JSON) are what keep a future backend honest.
5. **Byte-identity**: unwired deployments must stay byte-identical — nil
   stores everywhere (options, admin service, snapshotter/restorer) and the
   unchanged E2E matrix pin this.

Verification plan per the spec: `go build ./... && go vet ./...`; `go test
-run 'TestMaintainability_|TestArchitecture_' .`; `go test
./domains/tenant/... -race`; `go test ./infrastructure/postgres/ -run
Collab -race`; `go test ./interfaces/snapshot/... -race`; `go test
./interfaces/grpcserver/ -run 'TestCollab|TestAdmin' -race`; `go test
./platform/audit/... -run 'Drift|Conformance' -race`; `go test ./test/ -run
'TestCrossTenant|TestE2E' -v`; `make ci`.
