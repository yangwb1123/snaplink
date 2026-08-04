# Design: wiring the permissions resource catalog into enforcement, persistence, and management

Status: proposed. Scope: Direction 1 of the analysis — the three improvements
(resource-aware `Check`, durable catalog backend + conformance, admin CRUD +
RAR enforcement). Each section is a decision with API surface, semantics,
failure modes, and risks. Line numbers cited were verified against the tree at
writing time.

## ## 1. Resource-aware decision at the authz `Check` point

### Decision 1.1: Extend `CheckRequest` additively (authz/v1 is STABLE)

`proto/authz/v1/authz.proto` — append three fields, never renumber or touch
existing ones (ADR-0008: "Fields may be added but never removed or change
type"):

```proto
message CheckRequest {
  string subject_id = 1;
  string client_id  = 2; // app scope; empty = global
  string permission = 3; // permission code being requested

  // Resource-aware lookup (optional). When resource_type is non-empty the
  // decision is made against the resource catalog (see ResourceDecision in
  // the permissions domain); otherwise the legacy flat-code path runs.
  string            resource_type = 4; // e.g. "http_api"
  string            tenant_id     = 5; // empty = no-tenant bucket
  map<string,string> attributes    = 6; // type-specific match keys (method/path/...)
}
```

Presence detection: `resource_type != ""` means "lookup present". This is
safe because no registered resource can have an empty `Type`
(`Resource.Validate()` rejects it) and proto3 zero-values are the only way
old callers can look — old callers send none of these fields and get
byte-identical behavior.

Regenerate with `cd proto && buf generate` and commit `gen/` in the same
change. `make proto-breaking` is an optional extra check, not in `make ci`.

### Decision 1.2: One exported decision helper in the domain

New exported function in **`domains/permissions/resources.go`** — the
package root directory is exactly at its 10 non-test-file ceiling, so this
goes into an existing file, not a new one (see §7 risk R1):

```go
// CheckResource decides a resource-aware authorization request.
//   - lookup == nil        → legacy: flat Matches (byte-identical to today).
//   - provider lacks the ResourceProvider extension → error (fail closed;
//     silently ignoring a requested resource check is an authorization hole).
//   - ResolveResource Found=false → legacy flat Matches fallback (spec:
//     existing callers' semantics stay byte-identical).
//   - Found=true → gate by the projected policy:
//       !RequiresAuth                    → allowed (public resource)
//       no RequiredPermissions           → allowed (auth gate only)
//       RequireMode all                  → every code via Matches
//       RequireMode any (default)        → at least one code via Matches
func CheckResource(rp ResourceProvider, lookup *ResourceLookup, subjectPerms []Permission, want string) (bool, error)
```

`RequireMode` resolution reuses `EffectiveRequireMode()` (empty → `any`),
so the domain stays the single source of truth. The `RequiresAuth=false`
branch means "no permission gate" — the calling sidecar still decides
whether an unauthenticated request may reach the resource; `Check` itself
only ever sees a subject identity and its permission set. A subject with no
role mapping (`ErrUserNotFound` → empty perms) passes an auth-only
resource; document this in the helper's comment.

### Decision 1.3: Thin adapter in `interfaces/grpcserver/authz.go`

`AuthzService.Check` gains, after the existing `Permissions` lookup:

```go
if in.ResourceType != "" {
    rp, ok := s.provider.(permissions.ResourceProvider)
    if !ok {
        return nil, status.Error(codes.FailedPrecondition,
            "resource lookup requested but permission provider has no resource catalog")
    }
    allowed, err := permissions.CheckResource(rp, &permissions.ResourceLookup{
        TenantID: in.TenantId, ClientID: in.ClientId,
        Type: permissions.ResourceType(in.ResourceType), Match: in.Attributes,
    }, perms, in.Permission)
    if err != nil { return nil, status.Errorf(codes.Internal, "resource check: %v", err) }
    return &authzv1.CheckResponse{Allowed: allowed}, nil
}
// existing flat path unchanged
```

Hexagonal boundary preserved: domain owns the decision, gRPC owns the wire.

### Decision 1.4: Failure modes

| Case | Behavior |
|---|---|
| No `resource_type` | Flat `Matches` — byte-identical, old servers ignore new fields during rolling deploys (same flat result) |
| Lookup + non-`ResourceProvider` backend (postgres today) | `FailedPrecondition` — fail closed, audible misconfiguration |
| Lookup + `Found=false` | Flat `Matches` fallback (spec-mandated). Security note: see §7 R2 |
| `ResolveResource` store error | `Internal` — fail closed |
| Subject unknown | Empty perms (existing `ErrUserNotFound` tolerance), then the same decision table |

### Decision 1.5: Acceptance mapping

grpcserver-level test (bufconn, new `interfaces/grpcserver/authz_resource_test.go`):
register `http_api` `{method: POST, path: /api/v1/users/:id, require_mode: all,
required_permissions: [billing:write, audit:read]}` on a memory provider;
`Check` with matching lookup + one code → `allowed=false`; both codes →
`allowed=true`; lookup with no catalog entry → exactly the flat result;
empty `require_mode` → `any` semantics. `go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .` must pass.

## ## 2. Durable resource catalog backend + conformance suite

### Decision 2.1: Migration v2 — `permissions_resources`

Append to the `migrations` slice in `domains/permissions/sqlite/sqlite.go`
(v1 untouched; `migrate.Run(ctx, db, "permissions", migrations)` applies it
to v1-stamped DBs automatically; `PermissionsMaxVersion()` picks it up with
no code change — the boot schema gate in `build_app_core.go` follows):

```sql
CREATE TABLE IF NOT EXISTS permissions_resources (
    id                        TEXT PRIMARY KEY,
    tenant_id                 TEXT NOT NULL DEFAULT '',
    client_id                 TEXT NOT NULL DEFAULT '',
    type                      TEXT NOT NULL,
    name                      TEXT NOT NULL,
    requires_auth             INTEGER NOT NULL DEFAULT 1,
    description               TEXT NOT NULL DEFAULT '',
    attributes_json           TEXT NOT NULL DEFAULT '{}',
    required_permissions_json TEXT NOT NULL DEFAULT '[]',
    require_mode              TEXT NOT NULL DEFAULT '',
    created_at                TEXT NOT NULL,   -- RFC3339Nano UTC
    updated_at                TEXT NOT NULL,
    -- provider-maintained dispatch columns (Decision 2.2)
    dispatch_key              TEXT NOT NULL DEFAULT '',
    dispatch_method           TEXT NOT NULL DEFAULT '',
    dispatch_segments         INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, client_id, type, name)
);

CREATE INDEX idx_permissions_resources_exact
    ON permissions_resources(tenant_id, client_id, type, dispatch_key);
CREATE INDEX idx_permissions_resources_http
    ON permissions_resources(tenant_id, client_id, dispatch_method, dispatch_segments);
```

Design choices:

- **Plain columns, not JSON1 expression indexes.** `attributes_json` stays
  opaque TEXT; the provider maintains `dispatch_*` columns in Go at write
  time. This avoids depending on `modernc.org/sqlite`'s JSON function
  surface for correctness and keeps lookup SQL portable.
- **Timestamps as RFC3339Nano TEXT** — matches `Resource.CreatedAt`/
  `UpdatedAt` `time.Time` round-tripping without driver timestamp quirks.
- **`require_mode` default `''`** so `EffectiveRequireMode()` (empty →
  `any`) is the single source of truth and the wire value round-trips
  unmodified.
- v2 must be append-only: no ALTER/DROP on the three v1 tables; the
  restart-persistence and v1→v2 upgrade tests (§2.5) pin this.

### Decision 2.2: Dispatch index semantics (per-type, not a scan)

`ResolveResource` on the sqlite provider dispatches per `Type`:

| Type | Dispatch | Lookup strategy |
|---|---|---|
| `grpc_api` | `dispatch_key = service + "\x00" + method` | exact index hit |
| `page` | `dispatch_key = route` | exact index hit |
| `graphql_api` | `dispatch_key = op + "\x00" + field` | exact index hit |
| `js_fn` | `dispatch_key = route + "\x00" + symbol` | exact index hit |
| `ui_element` | `dispatch_key = selector` (page_id compared in Go when both set) | exact index hit + Go check |
| `http_api` | `dispatch_method = method`, `dispatch_segments = len(split(path))` | index narrows to same method + same segment count, then `matchPath` in Go |
| custom types | full scan | exact-match keys are unsound for custom types (lookup may carry a subset of registered keys; `matchCustomAttributes` semantics); catalog is small, documented |

Why `http_api` gets the narrowing index instead of an exact key: registered
patterns contain `:param` wildcards (`/api/v1/users/:id`), so an exact
`method+path` key can never hit a runtime lookup (`/api/v1/users/42`), and
enumerating wildcard expansions of the lookup path is exponential in segment
count. `matchPath` requires equal segment counts, so
`(tenant, client, method, segments)` is a sound narrowing; the remaining
candidates (a handful) are filtered with the existing exported-in-package
`matchPath`/`matchAttributes` logic — never trust the index to decide a
wildcard match. Segment counting must use the same split rule as
`matchPath` (`strings.Split(strings.TrimPrefix(path, "/"), "/")`).

`ResolveResource` returns `Decision{Found:false}` on no row — never an
error, matching the memory peer and the `ResourceDecision` contract.

### Decision 2.3: Write semantics — upsert, tuple conflict, idempotency

`RegisterResource` runs inside one transaction (the provider already pins
`SetMaxOpenConns(1)`, so the tx serializes all writers):

1. `SELECT id FROM permissions_resources WHERE tenant_id=? AND client_id=? AND type=? AND name=?`
2. owner found and `!= r.ID` → `ErrResourceExists` (real tuple conflict)
3. `INSERT ... ON CONFLICT(tenant_id, client_id, type, name) DO UPDATE SET
   requires_auth=excluded.requires_auth, description=excluded.description,
   attributes_json=excluded.attributes_json,
   required_permissions_json=excluded.required_permissions_json,
   require_mode=excluded.require_mode, updated_at=excluded.updated_at,
   dispatch_key=excluded.dispatch_key, dispatch_method=excluded.dispatch_method,
   dispatch_segments=excluded.dispatch_segments,
   created_at=COALESCE(permissions_resources.created_at, excluded.created_at)`
   — same-ID re-register updates in place (idempotent), preserving
   `created_at`.

The explicit SELECT (rather than relying on `RowsAffected` of the upsert,
which is ambiguous for no-op value updates) mirrors the memory peer's
lock-then-check semantics. `Validate()` runs before the tx — the same
`ErrInvalidResource` contract as the memory peer. `DeleteResource` is
`DELETE ... WHERE id=?`, nil on zero rows (idempotent). `GetResource` by
PK, `ErrResourceNotFound` on zero rows. `ListResources` filters
`tenant_id = ? AND client_id = ?` (empty strings match the no-tenant /
no-client buckets exactly as documented on the interface).

New file **`domains/permissions/sqlite/resources.go`** (sqlite dir has 6
non-test files; room to spare). Add
`_ permissions.ResourceProvider = (*Provider)(nil)` to the existing
compile-time assertions in `sqlite.go`.

### Decision 2.4: `ResourceConformanceSuite` in `permissionstest`

New file **`domains/permissions/permissionstest/resource_conformance.go`**
(2 non-test files today, room to spare):

```go
type ResourceConformanceSuite struct {
    // Factory returns a fresh ResourceProvider per subtest — instances
    // MUST NOT be shared across subtests (state leakage masks bugs).
    Factory func(*testing.T) permissions.ResourceProvider
    // SkipReason, when non-empty, skips every subtest with this reason.
    // Backends with a known gap (postgres, redis) invoke the suite with
    // an honest skip; memory and sqlite must pass with SkipReason == "".
    SkipReason string
}
```

Coverage (each a subtest): register/get/list/delete round-trip;
`ErrResourceNotFound` on unknown ID; tuple-conflict with a different ID →
`ErrResourceExists`; same-ID re-register is an idempotent update (fields
replaced, `created_at` preserved); tenant/client scoping (empty = no-tenant /
no-client bucket, and cross-bucket rows never leak into each other's
`ListResources`/`ResolveResource`); `RequireMode` projection (`any` default
via `EffectiveRequireMode`, `all` preserved); `:param` path matching
(`/api/v1/users/:id` matches `/api/v1/users/42`, not `/api/v1/users/42/x`);
`Found=false` on no match (and `Found=true` on the documented attribute
keys). Reuses the `type-assert + skip` honesty pattern from
`sod_conformance.go` where an extension is involved; here the suite IS the
extension test, so skips only occur via `SkipReason`.

### Decision 2.5: Acceptance mapping

- `permissionstest.ResourceConformanceSuite{Factory: memoryFactory}.Run(t)`
  appended to `domains/permissions/memory_conformance_test.go` and a new
  `TestSQLiteProvider_ResourceConformance` in
  `domains/permissions/sqlite/` — zero skips for both.
- Restart-persistence test in `domains/permissions/sqlite/`: write through
  one `permsqlite.New(dsn)`, `Close()`, reopen the same DSN, assert
  `GetResource`/`ResolveResource` return identical data (this also proves
  the JSON columns round-trip).
- Migration test: extend `migration_test.go` — stamp a v1 DB, `NewWithDB`,
  assert `migrate.CurrentVersion == 2`, v1 tables untouched, resource rows
  survive reopen.

## ## 3. Management plane + RFC 9396 `authorization_details` enforcement

### Decision 3.1: Admin resource CRUD — proto

`proto/admin/v1/permissions.proto` — four additive RPCs on
`PermissionAdminService` (new messages; no existing message touched):

```proto
rpc RegisterResource(RegisterResourceRequest) returns (RegisterResourceResponse) {
  option (google.api.http) = { post: "/api/v1/admin/permissions/{client_id}/resources" body: "resource" };
}
rpc GetResource(GetResourceRequest) returns (GetResourceResponse) {
  option (google.api.http) = { get: "/api/v1/admin/permissions/{client_id}/resources/{id}" };
}
rpc ListResources(ListResourcesRequest) returns (ListResourcesResponse) {
  option (google.api.http) = { get: "/api/v1/admin/permissions/{client_id}/resources" };
}
rpc DeleteResource(DeleteResourceRequest) returns (DeleteResourceResponse) {
  option (google.api.http) = { delete: "/api/v1/admin/permissions/{client_id}/resources/{id}" };
}

message Resource {
  string id = 1;              // required, client-supplied
  string tenant_id = 2;       // empty = no-tenant bucket
  string client_id = 3;
  string type = 4;            // http_api | grpc_api | graphql_api | page | ui_element | js_fn | custom
  string name = 5;
  bool   requires_auth = 6;   // default true
  string description = 7;
  map<string,string> attributes = 8;
  repeated string required_permissions = 9;
  string require_mode = 10;   // "any" (default) | "all"
  string created_at = 11;     // RFC3339, server-stamped, read-only
  string updated_at = 12;     // RFC3339, server-stamped, read-only
}
message RegisterResourceRequest { string client_id = 1; string tenant_id = 2; Resource resource = 3; }
message RegisterResourceResponse { Resource resource = 1; }
message GetResourceRequest    { string client_id = 1; string tenant_id = 2; string id = 3; }
message GetResourceResponse   { Resource resource = 1; }
message ListResourcesRequest  { string client_id = 1; string tenant_id = 2; string page_token = 3; int32 page_size = 4; }
message ListResourcesResponse { string next_page_token = 1; int32 total_size = 2; repeated Resource resources = 3; }
message DeleteResourceRequest { string client_id = 1; string tenant_id = 2; string id = 3; }
message DeleteResourceResponse {}
```

`id` is client-supplied (matches `Resource.Validate()` and the `Role.Code`
required-field precedent); `type` is an open string so custom types stay
possible, validated by `Resource.Validate()`. `ListResources` needs the
`tenant_id` filter because the storage contract buckets on
`(tenant_id, client_id)` — unlike roles, resources are not client-only
scoped.

### Decision 3.2: Service methods — placement, mapping, audit, invalidation

Implement in **`interfaces/grpcserver/grpcadmin/admin_permissions.go`**
(the `grpcadmin` directory is exactly at its 10 non-test-file ceiling — a
new file would break `make ci`; the existing file is 264 lines, well under
the 500-line budget after adding ~170):

- `RegisterResource`: validate `in.Resource != nil && in.Resource.Id != ""`
  → else `InvalidArgument`; map `ErrResourceExists` → `AlreadyExists`,
  `ErrInvalidResource` → `InvalidArgument`, else `Internal` — the exact
  `admin_permissions.go` pattern. Audit `EventAdminResourceRegistered`
  (`recordAdmin`, clientID + "/" + type + "/" + name). Fire
  `invalidateAuthzPolicy(ctx, clientID)` — catalog changes must invalidate
  authz-policy bundles exactly like role mutations.
- `GetResource`: `ErrResourceNotFound` → `NotFound`.
- `ListResources`: sort by `(type, name)` for deterministic paging, reuse
  `decodeOffset`/`pageBounds`/`clampPageSize`/`encodeOffset` from
  `admin_paginate.go` (same rationale as `ListRoles`: map/sqlite row order
  is nondeterministic without a fixed sort).
- `DeleteResource`: idempotent — provider returns nil for missing IDs, so
  re-delete returns success (spec acceptance). Audit
  `EventAdminResourceRemoved`; fire `invalidateAuthzPolicy`.

New audit events go through `auditspi` aliases and MUST be classified in
`platform/audit/auditreport/control_areas.go` next to the existing
`EventAdminRole*` entries (AGENTS.md §4: bounded cardinality, no new
cardinality dimension — these are fixed enumerants).

### Decision 3.3: PAR catalog check — config gate + accessor

Config knob `security.rar_catalog_check.enabled` (bool, default false),
documented in `docs/config-reference.md` beside `security.rar_limits.*`;
mapped by a new `sso.WithRARCatalogCheck()` option storing the flag on
`*sso.Server`.

`PARDeps` gains one method (the only implementer is `*sso.Server`; the
single test fake `parDeps` in `protocols/oauth/handle_par_test.go` is
updated in the same change):

```go
// ResourceCatalog returns the ResourceProvider for RFC 9396 catalog
// enforcement, or nil when the check is disabled or the wired provider
// doesn't implement ResourceProvider (shape-only mode).
ResourceCatalog() permissions.ResourceProvider
```

`*sso.Server` implements it as: flag set AND `s.permissions` type-asserts to
`permissions.ResourceProvider` → return it; else nil. No `cmd/` wiring
changes — the provider instance already flows through
`WithPermissionProvider`.

### Decision 3.4: Enforcement in the PAR flow

After the existing shape validation at `protocols/oauth/handle_par.go:222`
(`ValidateAuthorizationDetails`), inside `validatePARRequestParams`:

```go
if rp := d.ResourceCatalog(); rp != nil {
    if err := oauthvalidate.ValidateAuthorizationDetailsCatalog(
        req.AuthorizationDetails, rp, client.TenantID, client.ID); err != nil {
        ctx.JSON(http.StatusBadRequest,
            core.ErrorBodyDesc(ErrInvalidAuthorizationDetails, err.Error()))
        return false
    }
}
```

New pure function in **`protocols/oauth/oauthvalidate/rar.go`** (extends the
internal element struct with the catalog keys; re-exported through
`protocols/oauth/aliases.go` like the existing RAR symbols):

```go
// ValidateAuthorizationDetailsCatalog resolves every element whose type is
// one of the catalog-verifiable types (http_api, grpc_api, graphql_api)
// against rp via ResolveResource. Element match keys:
//   http_api    → {method, path}
//   grpc_api    → {service, method}
//   graphql_api → {op, field}
// A verifiable-type element that resolves to Found=false (unknown resource
// or attribute mismatch) fails with an error mapped to
// invalid_authorization_details (RFC 9396 §6). Other types pass through
// shape-only. Callers without a provider never call this — behavior is
// byte-identical to today.
func ValidateAuthorizationDetailsCatalog(raw json.RawMessage, rp permissions.ResourceProvider, tenantID, clientID string) error
```

Lookup scoping: `TenantID = client.TenantID` (empty in single-tenant
deployments = no-tenant bucket), `ClientID = client.ID` — the catalog
entries the requesting client's own resources were registered under.
`ResolveResource` store errors fail closed with the same
`invalid_authorization_details` code (an outage must not mint tokens with
unverifiable resource claims).

Semantics note: the PAR check validates verifiability (the resource exists
and the element's attributes match the catalog entry), NOT whether the
client holds the entry's `required_permissions` — the resource server
enforces the permission half later via the §1 `Check` path. This split
matches the requirement ("tokens never carry unverifiable resource claims")
and keeps PAR client-side (the resource server's audience, not the client's
entitlement).

### Decision 3.5: Failure modes (management + RAR)

| Surface | Failure | Behavior |
|---|---|---|
| RegisterResource | tuple owned by different ID | `AlreadyExists` (wire `already_exists`) |
| RegisterResource | missing id / bad type attrs | `InvalidArgument` |
| GetResource unknown | | `NotFound` |
| DeleteResource missing | | `200` success (idempotent) |
| ListResources | store error | `Internal` |
| PAR with provider, element unknown/mismatched | | `400 invalid_authorization_details`, PAR not issued |
| PAR with provider, `ResolveResource` errors | | `400 invalid_authorization_details` (fail closed) |
| PAR without provider / flag off | | shape-only, byte-identical (backward compatible) |
| Catalog deleted after PAR | | enforcement happens later at `Check` (Found=false → flat fallback; see R2) |

### Decision 3.6: Contract updates in the same change (AGENTS.md §5)

- `docs/error-codes.md`: add `ErrResourceNotFound` → `NotFound` mapping and
  `ErrResourceExists` → `AlreadyExists` rows (admin plane); extend the
  `invalid_authorization_details` row with the catalog-enforcement clause.
- `docs/openapi.yaml`: four new admin paths under the permissions section
  (the gRPC gateway registers them automatically after `buf generate`).
- `docs/config-reference.md`: `security.rar_catalog_check.enabled`.

## ## 4. Failure modes (cross-cutting)

- **Decision store errors**: `Check` and PAR catalog resolution fail
  closed (`Internal` / `invalid_authorization_details`); admin reads fail
  with `Internal`. The permission decision is a security control — never
  fail open on a store outage.
- **Provider missing the extension**: `Check` with a lookup →
  `FailedPrecondition` (audible, fail closed); PAR → shape-only (per spec,
  backward compatible). The asymmetry is deliberate: `Check` is a live
  authorization query where silent ignore is a vuln; PAR is a client-facing
  validation step with a documented catalog-less mode.
- **Idempotency**: re-register same ID = update; re-delete = success;
  concurrent duplicate registers serialize on the single sqlite conn and
  return `ErrResourceExists` for the loser, matching the memory peer under
  its mutex.
- **Cache coherence**: catalog mutations fire `invalidateAuthzPolicy`, so
  sidecar policy bundles and the invalidation bus (cross-replica
  invalidation covers "client/authz-policy changes" per AGENTS.md §4)
  converge after admin writes. The `Check` path itself reads the provider
  directly — no additional cache to poison.

## ## 5. What could break the design

- **R1 — File-budget traps (verified, contradicts the requirement's
  assumption).** `domains/permissions/` root and
  `interfaces/grpcserver/grpcadmin/` each have exactly 10 non-test .go
  files — the ceiling. Any new file in either directory fails
  `TestMaintainability_`. Mitigation baked in: `CheckResource` → existing
  `resources.go`; admin RPCs → existing `admin_permissions.go` (stays under
  500 lines). Only `sqlite/` and `permissionstest/` get new files. If the
  maintainability gate counts differently in CI, the placement still holds —
  it costs nothing.
- **R2 — `Found=false` flat fallback inverts deny-by-default.** A
  deployment that registers a catalog intending "no entry = deny" gets the
  legacy flat-code allow instead whenever the lookup misses (e.g. a typo'd
  path, or a resource deleted after PAR). The spec mandates the fallback for
  byte-identical behavior, so the design ships it — but this is a
  documented, deliberate allow-inversion window. Follow-up (out of scope
  here): an explicit `CheckRequest.deny_by_default` / config mode.
- **R3 — `RequiresAuth` cannot be fully enforced at `Check`.** `Check`
  knows a subject's permissions, not its authentication state; a
  `requires_auth=true` resource with no `required_permissions` allows a
  subject with zero role mappings. The sidecar remains responsible for the
  authentication gate. Documented in the helper; do not "fix" by failing
  `ErrUserNotFound` subjects — that would change legacy `Check` semantics.
- **R4 — Rolling-deploy skew.** Old servers ignore the new
  `CheckRequest` fields → flat decisions for the new lookup (same as
  `Found=false` fallback); new servers reject lookups from a deploy whose
  provider was downgraded to a non-resource backend. Both are fail-safe or
  spec-fallback, but the operator should land the sqlite/backend migration
  before rolling out catalog-dependent callers.
- **R5 — `gen/` drift.** `buf generate` output must be committed in the
  same change; a CI build without regeneration fails to compile, so this is
  self-policing, but `make proto-breaking` is not in `make ci` — run it
  once against main to prove wire compatibility.
- **R6 — Migration/version pins.** `PermissionsMaxVersion()` auto-bumps to
  2 and the boot schema gate follows, but `cmd/sso-server/schema_guard_test.go`
  and any pinned-version assertions must be checked during implementation —
  if a test hard-codes v1, it breaks the change (verify, don't assume).
- **R7 — RAR element schema drift.** The catalog check reads
  `method`/`path`/`service`/`op`/`field` off each element; RFC 9396 leaves
  type-specific fields to the ecosystem. If a client uses different keys
  for the same type, PAR rejects it (fail closed) — correct per spec, but
  the first-party key contract must be documented in
  `docs/config-reference.md` and the `Resource` attribute contract.
- **R8 — PAR-only enforcement gap.** `/auth/login` also accepts
  `authorization_details` (limits already apply there per
  `docs/config-reference.md`); the catalog check per the requirement is
  PAR-only, so a non-PAR login can still mint a token whose details were
  never catalog-verified. Acceptable for this increment (PAR is the
  documented upstream validation point), but a follow-up should extend
  `validateLoginRequestParams` symmetrically.
- **R9 — SQLite hot-path contention.** `SetMaxOpenConns(1)` serializes
  `ResolveResource` reads behind any write. Catalog reads are on the authz
  hot path; acceptable at current scale (the memory peer is the documented
  fast path for single-replica), but a dedicated read conn (or a
  catalog-shaped cache invalidated via the bus) is future work — do not
  build it in this change.
- **R10 — `Permission.Resource` stays unpopulated.** Improvement 1 makes
  `Check` resource-aware, but `MemoryProvider.Permissions` still emits
  `Permission{Code: code}` only (verified at `memory.go:283`); the wire
  field remains dead for `ListPermissions`. Out of scope per the
  requirement, but callers must not start reading it expecting values.

## ## 6. Delivery order and verification

1. §2 first (sqlite backend + suite) — §1 and §3 both consume it.
2. §1 (domain helper + grpcserver adapter + proto fields) — runtime surface.
3. §3 (admin RPCs, then PAR gate) — management + validation surface.
4. Full gates: `go build ./... && go vet ./...`,
   `go test -run 'TestMaintainability_|TestArchitecture_' .`,
   `go test ./domains/permissions/... -race`,
   `cd proto && buf generate` + `make proto-breaking`,
   `go test ./test/ -run TestE2E`, `python cli.py checks` (or targeted),
   `make ci` at handoff.

Each step leaves the tree green; the sqlite migration and the proto changes
are the only cross-cutting artifacts and land first so later steps build on
a stable base.
