# Design: `domains/permissions` — resource enforcement, operable SoD, decision-plane observability

Design counterpart to `docs/architect-analysis/auto/domains-permissions-spec.md`. Covers the API
surface, storage model, failure modes, and breakage risks for the three
improvements. Every decision below was checked against current code and the
AGENTS.md budgets; where the spec proposed a location that would breach a gate
(the grpcadmin file fan-out), this document says so and relocates.

Layer map used throughout:

```text
composition (cmd/sso-server, interfaces/sso)
  → interfaces (grpcserver, grpcadmin)
  → protocols (oauth/oauthvalidate)
  → domains (permissions)
  → platform, shared
```

## Decision: enforce the resource catalog through the provider seam, not a new subsystem

### Problem restated

`ResourceProvider` (`domains/permissions/resources.go`) is complete and tested
but has zero consumers, no durable backend, and no admin surface. The wire
already anticipates it (`Permission.resource` in `authz.proto`, RFC 9396
`authorization_details` pass-through). The fix is wiring, not redesign.

### API surface

**1. Shared match semantics move into the domain (free function).**
`ResolveResource` is currently per-provider (memory has its own matcher). If
sqlite/redis/postgres each reimplement matching, the conformance suite cannot
pin one semantic. Extract the matching algorithm from
`domains/permissions/memory_resources.go` into a domain free function —
`MatchResource(catalog []*Resource, lookup ResourceLookup) *ResourceDecision`
— and have every backend call it over its (tenant, client)-scoped catalog
rows. Matching rules, pinned by the new conformance suite:

- `http_api`: exact `method` match + path match where `:param` segments are
  wildcards (`/api/v1/users/:id` matches `/api/v1/users/42`); `*` segments
  are not introduced (not in today's contract — do not invent syntax).
- `grpc_api`/`graphql_api`/`page`/`js_fn`/`ui_element`: exact attribute
  equality on the documented keys (`resources.go` `requiredAttrRules`).
- Multiple catalog entries matching one lookup: most-specific wins (fewest
  wildcard segments), then lexicographic by `Name` for determinism. The
  suite locks this so backends cannot diverge.
- `Found=false` remains NOT an error. Empty `TenantID`/`ClientID` in the
  lookup match the empty-bucket rows, exactly as `ResourceLookup` documents.

Because `domains/permissions` is at the 10-non-test-file ceiling, the matcher
folds into `resources.go` (it is resource-domain logic; do not add a file).

**2. `ResourceConformanceSuite` in `permissionstest`.**
Mirror `ConformanceSuite{Factory}` (`permissionstest/conformance.go`): a new
`ResourceConformanceSuite{Factory func(*testing.T) permissions.Provider}` with
subtests for register/idempotent-re-register/tuple-conflict, get, list
scoping, delete idempotency, per-type attribute validation, `RequireMode`
defaulting, and a full `ResolveResource` matrix (hit, miss, specificity,
empty buckets, wildcard permissions). Unlike `SoDProvider`, resource support
is NOT optional for first-party backends: `sqlite_conformance_test.go` and
the redis/postgres peers wire the suite with no skip branches, making the
catalog part of the base conformance contract. This is what converts the
"invested but idle" memory tests into a backend contract.

**3. Admin gRPC services — relocated out of `grpcadmin`.**
The spec proposed implementing new RPCs in
`interfaces/grpcserver/grpcadmin/admin_permissions.go`. That file is ~340
lines, `grpcadmin/` has exactly 10 non-test files (the ceiling), and
`grpcadmin/resources/` would breach directory depth 3. So:

- New proto service `ResourceAdminService` in
  `proto/admin/v1/permissions.proto` (same file, additive service — proto
  packages are stable per ADR-0008; adding a service is not breaking):

```proto
service ResourceAdminService {
  rpc RegisterResource(RegisterResourceRequest) returns (RegisterResourceResponse);
  rpc GetResource(GetResourceRequest) returns (GetResourceResponse);
  rpc ListResources(ListResourcesRequest) returns (ListResourcesResponse);
  rpc DeleteResource(DeleteResourceRequest) returns (DeleteResourceResponse);
}
```

  with `google.api.http` annotations under `/api/v1/admin/permissions/{client_id}/resources`
  so the grpc-gateway mux (`cmd/sso-server/build_http.go:437` pattern) serves
  REST for free, following the existing `/me/*`-adjacent admin conventions.
- Implementation lives in new files `interfaces/grpcserver/resource_admin.go`
  and `interfaces/grpcserver/sod_admin.go` (grpcserver is at 6/10 non-test
  files — the only legal home). It reuses `interfaces/grpcserver/audit.go`
  helpers and receives the same `invalidateAuthzPolicy` callback pattern as
  `grpcadmin.NewPermissionAdminService`; `cmd/sso-server/main_servers.go`
  registers the new services.
- Error mapping: `ErrResourceNotFound` → `codes.NotFound`,
  `ErrResourceExists` → `codes.AlreadyExists`,
  `ErrInvalidResource` → `codes.InvalidArgument` (mirrors
  `admin_permissions.go` role mapping). Every successful mutation fires
  `invalidateAuthzPolicy(ctx, clientID)` — resource changes alter the bundle
  (decision 3), so the existing cross-replica invalidation bus
  (`KindAuthzPolicyChange`, `server_discovery.go:135`) applies unchanged.

**4. `Check` becomes resource-aware, additively.**
`authz.proto` is ADR-0008 STABLE; only additive fields:

```proto
message CheckRequest {
  string subject_id = 1;
  string client_id  = 2;
  string permission = 3;
  string tenant_id  = 4;              // NEW: scope for resource resolution
  ResourceLookup resource = 5;        // NEW: optional resource-gated check
  string session_id = 6;              // NEW: DSoD scope (decision 2)
}
message ResourceLookup {
  string type = 1;
  map<string, string> match = 2;      // method/path, service/method, ...
}
message CheckResponse {
  bool allowed = 1;
  bool requires_auth = 2;             // NEW: informational, mirrors resource
}
```

`Check` semantics in `interfaces/grpcserver/authz.go`:

- `resource` absent → current flat `permissions.Matches(perms, in.Permission)`
  behavior, byte-identical for existing callers (sidecars included).
- `resource` present → `ResolveResource`; `Found=false` → flat `Matches`
  fallback (documented fail-open default);
  `Found=true` → `RequireMode` semantics: `RequireAny` = any of
  `RequiredPermissions` matches via `Matches` (wildcards `*`/`domain:*` keep
  working); `RequireAll` = every one matches. `RequiresAuth` is enforced by
  the gate, not `Check` (see 5). `ResolveResource` returning an error →
  `codes.Internal`, same as today's provider-lookup failure — a decision must
  never silently flip to allow because the catalog store is down.

**5. `RequiresAuth` is a gate concern; `Check` stays a permission oracle.**
`Check` has no notion of caller anonymity (it requires `subject_id`). The
acceptance "`RequiresAuth` blocks anonymous callers" is enforced where
anonymity is known: the HTTP/gRPC authorization gate resolves the resource
once, rejects anonymous callers when `RequiresAuth` is set, and otherwise
calls `Check` with the resolved lookup. The OPA sidecar gets `RequiresAuth`
from the bundle (decision 3), so server and sidecar agree without `Check`
growing an auth-state input. `CheckResponse.requires_auth` is informational
for callers that want it without a second resolve.

**6. RAR validation — composition root, not `oauthvalidate`.**
`oauthvalidate` is deliberately shape-only ("type-specific extensions don't
need to model their schema in this SDK") and has no provider access. The
spec's "in oauthvalidate" is therefore relocated: a domain free function
`permissions.ValidateRARResources(ctx, resolver ResourceProvider, tenantID,
clientID string, details []json.RawMessage) (matched []Resource, err error)`
in `resources.go`, invoked from the `interfaces/sso` issuance/exchange path
where both the provider and the parsed details are in hand. Semantics:

- RAR element resolves when `type` equals a `ResourceType` and its fields
  match that resource's attributes (e.g. `type: "http_api"`, fields
  `method`/`path`). Custom RAR types never resolve → pass through unchanged
  (fail-open preserved; client `authorizationDetailTypes` allowlist still
  gates first, as today).
- At least one element resolves → the subject must satisfy the union of the
  resolved resources' `RequiredPermissions` (any-of per resource, `Matches`
  semantics), else the exchange fails with the existing
  `invalid_authorization_details` wire error (RFC 9396 §6) and details go to
  audit only. The issued token's embedded permissions are narrowed to the
  union of the resolved resources' required permissions — "carries only the
  permissions that resource requires". Zero resolved elements → token
  permissions unchanged (byte-identical issuance).
- This is the one place the spec's literal wording is deviated from; the
  acceptance check ("token issued after RAR names a registered resource
  carries only that resource's permissions; unregistered types pass through")
  is met either way, and the deviation is what keeps `oauthvalidate` pure.

### Storage model

Append one migration to `domains/permissions/sqlite/sqlite.go` `migrations`
(the versioned `platform/migrate` scheme) — four tables:

```sql
CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT '',
  client_id TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  requires_auth INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  attributes TEXT NOT NULL DEFAULT '{}',          -- JSON map
  required_permissions TEXT NOT NULL DEFAULT '[]', -- JSON array
  require_mode TEXT NOT NULL DEFAULT '',          -- '' | 'any' | 'all'
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT '',
  UNIQUE (tenant_id, client_id, type, name)
);
CREATE INDEX IF NOT EXISTS idx_resources_scope ON resources (tenant_id, client_id);
```

`ResolveResource` loads the (tenant, client)-scoped rows and runs the shared
`MatchResource` (catalog sizes are operator-managed, dozens to hundreds of
rows; O(n) per resolve is fine — no trie, no per-type index, one semantic in
one place). `RegisterResource` implements the memory semantics exactly
(`resourceTupleKey` conflict → `ErrResourceExists`, same-ID overwrite
idempotent, timestamps stamped) inside one transaction.

- Redis peer: hash `perm:res:{tenant}:{client}` field
  `{type}\x00{name}` → JSON resource; resolve = `HGETALL` + `MatchResource`.
- Postgres peer: same relational schema as sqlite (root-module package).

### Failure modes

- **Catalog store down during `Check`**: `ResolveResource` error →
  `codes.Internal`, no decision. Consistent with today's provider-failure
  behavior; never silently allow or deny.
- **Catalog store down during RAR exchange**: fail open with audit (issuance
  availability wins; same family as audit-sink and geo fail-open per
  AGENTS.md §3). The token is issued with unchanged permissions and the
  event is recorded so a compliance review can see the degradation window.
- **`Found=false`**: fail-open flat match, per the existing contract.
  High-security deployments wanting deny-on-miss get a future gate knob;
  it is explicitly out of scope here because flipping the default silently
  would change existing deployments' behavior.
- **Tuple collision on register**: `ErrResourceExists` → `AlreadyExists`;
  admin UI must treat this as a conflict, not a retry.

### What could break the design

- `grpcadmin` fan-out is the binding constraint (10/10 non-test files). Any
  attempt to follow the spec's literal placement fails the architecture
  gate; the grpcserver relocation is mandatory, and adding both new service
  files keeps grpcserver at 8/10 — still under, but no room for a third.
- `domains/permissions` is at 10/10 files: the shared matcher and the RAR
  validator must fold into `resources.go` (currently 216 lines; the additions
  keep it under 500). A separate `resource_match.go` would breach the fan-out
  gate.
- Matching-semantics drift between backends is the classic failure; the
  conformance suite plus the single shared `MatchResource` closes it.
- `authz.proto` additions must stay additive (new fields 4-6, new message).
  Adding a field to an existing message is permitted by ADR-0008; renumbering
  or changing `CheckResponse` semantics is not.
- The narrowing rule ("token carries only the resource's permissions") is a
  behavior change for RAR-issuance when a resource matches. It is gated
  behind "at least one element resolves", so today's deployments (no
  registered resources) see zero change — but the conformance fixtures must
  include the zero-match case to prove it.

## Decision: make SoD operable end-to-end (durable, configurable, enforced)

### Problem restated

`SoDProvider`/`SessionRoleActivator` (`domains/permissions/sod.go`) exist only
in memory, have no admin surface, and no decision point reads `ActiveRoles`.
The conformance suite itself skips everything via type-asserts. The fix is a
complete vertical slice: admin RPCs, durable tables, and `Check` consumption.

### API surface

**1. New proto service `SoDAdminService`** (same file as
`ResourceAdminService`, same grpcserver implementation home):

```proto
service SoDAdminService {
  rpc SetConflictSets(SetConflictSetsRequest) returns (SetConflictSetsResponse);         // SSoD
  rpc ListConflictSets(ListConflictSetsRequest) returns (ListConflictSetsResponse);
  rpc SetActivationConflictSets(SetActivationConflictSetsRequest)
      returns (SetActivationConflictSetsResponse);                                        // DSoD
  rpc ListActivationConflictSets(ListActivationConflictSetsRequest)
      returns (ListActivationConflictSetsResponse);
  rpc ActivateRoles(ActivateRolesRequest) returns (ActivateRolesResponse);
  rpc ListActiveRoles(ListActiveRolesRequest) returns (ListActiveRolesResponse);
  rpc DeactivateSession(DeactivateSessionRequest) returns (DeactivateSessionResponse);
}
```

REST via `google.api.http` under `/api/v1/admin/permissions/{client_id}/conflicts`
and `/.../sessions/{session_id}`. Error mapping: `ErrInvalidConflictSet` →
`InvalidArgument` (malformed declaration); `ErrRoleNotAssigned` →
`FailedPrecondition` (state of the world: the role is not held);
`ErrRoleConflict` → `FailedPrecondition` with the `ConflictError` codes and
set in the status message (never in a distinct error code — SoD violations
are oracle-safe: same code for any conflicting pair, details only in the
`mfa_failure`-style audit trail).

**2. Conflict-declaration semantics** follow `sod.go` exactly: SET semantics
(whole-table replace), validate-before-write (a bad set is a no-op), `nil`
clears. Both tables are checked by `ActivateRoles` (SSoD union DSoD), as the
memory implementation already does via `findConflict`.

**3. `Check` consumption of the active set.**
`CheckRequest.session_id` (field 6, decision 1) is the DSoD scope; it maps to
the OIDC `sid` claim so login/logout lifecycle can drive it. Decision matrix
in `authz.go`:

| `session_id` | provider implements `SessionRoleActivator` | evaluation set |
|---|---|---|
| absent | any | full assigned set (today's behavior, backward compatible) |
| present | no | full assigned set (documented fallback; no error) |
| present | yes | `ActiveRoles` projected permissions; empty active set = deny |

The last row is fail-closed by design: a caller that opted into session
scoping gets exactly the active subset — an empty activation means nothing is
in effect, and a permission held only by a deactivated role is denied
(the acceptance check). Activation itself is explicit via admin RPC (an
operator picks the per-session subset); logout calls `DeactivateSession`
through the session-lifecycle hook in `interfaces/sso`. `ActivateRoles`
already rejects unassigned roles and both conflict tables, so the DSoD
"pick one per session" workflow is enforced at activation time and again at
decision time.

**4. Conformance-suite skip removal.** `sod_conformance.go` keeps its
type-assert pattern (the suite stays valid for hypothetical minimal
backends), but the first-party sqlite/redis/postgres factories now satisfy
both interfaces, so the skip branches are dead in the actual test matrix —
the spec's "skip branches are gone" acceptance means the subtests RUN for
those backends, not that the pattern is deleted.

### Storage model

Same migration as decision 1, three more tables:

```sql
CREATE TABLE IF NOT EXISTS sod_conflicts (
  client_id TEXT PRIMARY KEY,
  sets TEXT NOT NULL DEFAULT '[]'          -- JSON [][]string
);
CREATE TABLE IF NOT EXISTS activation_conflicts (
  client_id TEXT PRIMARY KEY,
  sets TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS active_sessions (
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  roles TEXT NOT NULL DEFAULT '[]',        -- JSON []string
  activated_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (user_id, client_id, session_id)
);
```

- Redis: `perm:sod:{client}`, `perm:dsod:{client}` (JSON), and per-session
  `perm:active:{user}:{client}:{session}` (JSON roles, with a TTL aligned to
  the OIDC session lifetime). Postgres: same relational schema.
- **Atomicity is the design's sharp edge**: "assign two conflicting roles
  fails with `ErrRoleConflict`" must be race-safe. sqlite: check+write inside
  one `BEGIN IMMEDIATE` transaction (SSoD check reads `sod_conflicts` in the
  same txn as the assignment write). Postgres: same in a serializable txn.
  Redis: a Lua script (read sets, `findConflict` logic in the script, write)
  so check-and-act is atomic. Memory already has the single mutex.
- `active_sessions` grows unbounded if `DeactivateSession` is never called.
  Mitigation: the logout hook deactivates; redis TTL matches session expiry;
  for sqlite/postgres a documented sweep (delete rows whose `activated_at` is
  older than the OIDC session TTL) runs with the same cadence as existing
  maintenance. This is a retention decision, not a correctness one —
  stale rows only ever produce an empty active set (deny), never a grant.
- Conflict-set mutations change the exported bundle (decision 3), so
  `SetConflictSets`/`SetActivationConflictSets` fire `invalidateAuthzPolicy`.
  Activation/deactivation do NOT (they are per-subject state, never in the
  bundle; the bundle cache is untouched).

### Failure modes

- **SoD store down during `AssignRoles`/`ActivateRoles`**: fail closed —
  the mutation returns an error. Assignments are writes; silently skipping a
  compliance check on a write is worse than refusing it.
- **Store down during `Check` with `session_id`**: `ActiveRoles` lookup
  error → `codes.Internal` (same rule as decision 1: no decision on store
  failure). The no-`session_id` path is unaffected.
- **Conflict check without atomicity** would let two concurrent
  `AssignRoles` calls both pass the check and interleave the writes — this
  is why the transactional/Lua design above is a requirement, not an
  optimization.
- **Logout without deactivate**: session row lingers; effect is deny-only
  (empty or stale subset), and the sweep reclaims it. Fail-safe direction.
- **`ErrRoleConflict` details in gRPC status**: the `ConflictError` fields
  (which roles, which set) are useful for the admin UI but must not become
  distinguishable error codes on the wire — the row in the table above pins
  one code for every conflicting pair.

### What could break the design

- **`Check` semantic split** (assigned vs active) is the riskiest behavioral
  change: any existing caller that starts sending `session_id` gets stricter
  answers. The mitigation is the matrix: behavior changes only when
  `session_id` is present AND the provider implements the activator, and the
  OIDC `sid` is only populated by the new session lifecycle — old callers
  are byte-identical.
- **Concurrency on the conflict check** is where a "works on memory, breaks
  on sqlite" bug lives; the conformance suite must include a parallel
  `AssignRoles` subtest to lock the transactional behavior.
- **Session-key hygiene**: the memory `sessionKey` is NUL-separated
  (`sod.go`); the sqlite PK triple and redis key must use the same
  collision-free framing (NUL cannot appear in IDs — keep that invariant in
  the durable keys too).
- **`SetConflictSets` not retroactive** is a documented semantic
  (`sod.go` doc comment): a set declared after a conflicting assignment
  exists only blocks the NEXT mutation. Admin UI copy must say so, or
  operators will believe existing assignments are safe.
- **Feature-matrix/error-code sync**: `ErrRoleConflict`,
  `ErrRoleNotAssigned`, `ErrInvalidConflictSet` rows in
  `docs/error-codes.md`, an SoD row in `docs/feature-matrix.md` — the docs
  gates treat a missing entry as drift.

## Decision: observability at the decision plane and a complete, drift-checked policy export

### Problem restated

`Check` is a silent black box (no audit event, no counters — while `/me/*`
queries emit `EventPermissionQuery`), and `PolicyBundle` v1 exports only
"the role-definition half" (`server_health.go:40`'s own words), so the OPA
sidecar cannot reproduce resource-gated or SoD-aware decisions.

### API surface

**1. `audit.EventPermissionCheck` + decision counters.**
- New event type declared in `auditspi` (event_types file), aliased in
  `platform/audit/aliases_spi.go` beside `EventPermissionQuery`, and
  classified in `auditreport/control_areas.go` (same control area as
  `EventPermissionQuery`, line 51 region) — the `auditreport` drift test
  FAILS until classification exists, which is the gate doing its job.
  Meta via `audit.SetMeta` only: `subject_id`, `client_id`, `permission`,
  `resource_type`, `resource_id`, `decision` (allow|deny), `session_id`
  (when present), `reason` (deny reason: flat-miss, require-any, require-all,
  empty-active-set). One event type keeps cardinality bounded; the event
  type name never embeds subject or client.
- Counter `sso_authz_checks_total{decision="allow"|"deny"}` registered in
  the metering registry (there is no `sso_authz_*` prefix today; this is the
  first). Labels stay bounded: `decision` only. `client_id`/`subject_id`
  live in the audit meta, not metric labels — a label per client would be a
  cardinality leak.
- Denials additionally get a structured deny-log line (subject, client,
  permission, resource, reason) for troubleshooting, mirroring how
  `handlers.go` logs lookup failures.
- Emission point is `Check` itself in `interfaces/grpcserver/authz.go`, so
  both decision paths (flat and resource-aware) and both outcomes are
  covered by construction. Audit-recorder nil-safety follows the existing
  `recordAdmin` pattern (fire-and-forget, fail-open on sink errors).

**2. `PolicyBundle` v2 (additive, ETag-preserving).**
- `PolicyBundleVersion` bumps 1 → 2. New fields, all additive after the v1
  fields (an old sidecar that ignores unknown JSON fields keeps working):
  `resources` (sorted `ResourceBundle{ID, Type, Name, RequiresAuth,
  RequireMode, RequiredPermissions, Attributes}` — tenant-bucket included),
  `conflict_sets` (`{ssod: [][]string, dsod: [][]string}` per client).
- `BuildPolicyBundle` type-asserts the provider for `ResourceProvider` and
  `SoDProvider`; backends without the extensions emit empty sections (v2
  shape is stable regardless of backend capability — the sidecar branches on
  `version`, never on section presence).
- `CanonicalBytes` v2 appends the new sections in sorted order (resources by
  tenant, type, name; permissions and attribute keys sorted; conflict sets
  and their codes sorted) and keeps `GeneratedAt` excluded — identical data
  still yields an identical ETag. The `version` field in the canonical bytes
  makes v1 and v2 bytes distinct, so a bundle whose content is unchanged but
  whose schema moved to v2 gets a new ETag exactly once.
- Cache/invalidation plumbing already exists: the bundle endpoint and ETag
  handling are in `server_discovery.go`; `invalidateAuthzPolicy` is wired to
  `InvalidateAuthzPolicyBundleCache` (local + `KindAuthzPolicyChange` bus).
  The new admin mutations (register/delete resource, set conflict sets) call
  the same callback — that is the data-closure the spec's evidence found.

**3. OPA reference policy + drift conformance.**
- `docs/examples/opa-authz-policy.rego` gains: (a) resource-gated decision —
  resolve `input.resource` against `data.bundle.resources` (method/path
  match with `:param` wildcards, mirroring `MatchResource`), apply
  `require_mode`/`requires_auth`; (b) SoD-aware decision — when
  `input.session_roles` is present, `granted` is computed from those instead
  of the token's full roles (mirroring the `Check` matrix); fall back to
  token roles otherwise. The policy branches on `data.bundle.version >= 2`.
- Drift detection: a conformance test runs a shared fixture set (granted
  roles × resource lookups × wanted permissions, including wildcards,
  require-all, empty-active-set, and no-match fallback) through both the
  server `Check` and the OPA policy and asserts identical decisions. OPA is
  NOT in `go.mod` today; the decision is a test-only Go dependency
  (`github.com/open-policy-agent/opa/rego`) so CI is hermetic — it never
  ships in the binary and the "root go.mod unchanged" rule applies only to
  `cli.py configure` module builds. Fallback if the dependency weight is
  rejected in review: exec the `opa` CLI with skip-if-absent (non-hermetic,
  documented as weaker).
- `MatchResource` and the rego matcher share the fixture set, so the drift
  test is what prevents the two from diverging later.

### Storage model

None new. The bundle is rendered from the tables of decisions 1-2; the only
state is the existing per-replica render cache keyed by
`(clientID, baseURL)` with `DefaultAuthzPolicyBundleCacheTTL` and
ETag/`Cache-Control` handling. Audit events go through the existing sink
plumbing; counters through the metering registry.

### Failure modes

- **Audit sink down**: event emission fails open (existing recorder
  contract), counters still update — the metering path is independent.
- **Bundle render error** (provider down): existing endpoint behavior
  (error response) unchanged; the cache means a briefly-down provider still
  serves the last good render until TTL.
- **Sidecar on v1 while server ships v2**: additive fields mean v1 decoders
  read roles correctly and simply ignore resources/conflict-sets — they
  degrade to v1 enforcement, which is exactly the pre-change behavior.
  Drift is visible only when the server's data includes resources/conflicts,
  and the OPA reference policy's version branch documents that.
- **ETag churn**: unsorted or timestamped bundle content would defeat the
  cache. The canonical encoder's sorting rules are the contract; the
  existing `policy_bundle_extra_test.go` style stability tests extend to v2.
- **Metering registry absent in a build**: counter registration must be
  nil-safe like the audit recorder (unwired build = no counters, no panic).

### What could break the design

- **The auditreport drift test** will fail CI the moment the new event
  constant lands unclassified — this is intended (it forces the
  classification update in the same change), but the change must include it
  or `make ci` breaks.
- **Cardinality creep** in `EventPermissionCheck` meta: `reason` must be a
  small enum (flat-miss, require-any, require-all, empty-active), not a free
  string — a free string makes the audit store unbounded.
- **OPA dependency weight** is the main review risk; the CLI-exec fallback
  is the escape hatch, with the documented downside that CI without `opa`
  installed silently skips drift detection.
- **Bundle/`Check` semantic agreement**: the drift test covers decisions
  but not the `RequiresAuth` gate (the gate is HTTP-level and the sidecar
  enforces it from bundle data). The fixture set must include
  `requires_auth` resources so the sidecar's gate logic is pinned too, or
  the server and sidecar can disagree about anonymous callers.
- **Docs contracts**: `docs/config-reference.md`/`docs/feature-matrix.md`
  entries for the resource catalog and `docs/error-codes.md` rows for
  `ErrResourceNotFound`/`ErrResourceExists`/`ErrInvalidResource` must land
  in the same change (AGENTS.md §5).

## Decision: sequencing, gate compliance, and what could break the design overall

### Sequencing

1. Shared `MatchResource` + `ResourceConformanceSuite` + sqlite resources
   table (the foundation; everything else reads the catalog).
2. Resource admin services (gRPC+REST) + resource-aware `Check` + RAR
   validation + bundle v2 resources section (one change: every enforcement
   point ships its audit event and bundle data together, per the spec's
   priority note).
3. SoD tables + admin services + `Check` session matrix + bundle conflict
   sets + logout hook.
4. `EventPermissionCheck`/counters/deny-log + OPA policy + drift test
   (support plane; can land merged into 2/3 incrementally).

Each step is independently releasable; steps 2-4 each end with the full
gates (`go build ./... && go vet ./...`,
`TestMaintainability_|TestArchitecture_`, `make ci`).

### Budget compliance summary (checked against the tree)

| Constraint | State | Action |
|---|---|---|
| `grpcadmin/` non-test files | 10/10 (ceiling) | new services in `interfaces/grpcserver/` (6→8/10) |
| `domains/permissions/` non-test files | 10/10 (ceiling) | matcher + RAR validator fold into `resources.go` |
| File length | `resources.go` 216 → ~450 max | under 500; do not add a third resource file |
| Directory depth | grpcserver=3, sqlite=3 | no new subdirectories anywhere |
| `interfaces/sso` 60-file ceiling | bundle handler exists | only `BuildPolicyBundle` changes, no new files |
| `authz.proto` / `admin.proto` | ADR-0008 STABLE | additive fields/messages/services only |

### What could break the design (cross-cutting)

- **Gate regressions from placement**: the two hard constraints above
  (grpcadmin fan-out, permissions fan-out) are the most likely way an
  implementation "works" but fails `make ci`. The design bakes the
  relocation in; an implementer that reverts to the spec's literal placement
  breaks the architecture gate and must not do it.
- **Oracle-safety creep**: the new endpoints must not introduce
  distinguishable errors — `ErrRoleConflict` maps to one code for every
  pair; RAR catalog validation returns the generic
  `invalid_authorization_details`; resource-catalog misses are
  `Found=false`, never a leak of what IS registered. Details belong in
  audit meta only.
- **Fail-open/fail-closed discipline**: decisions (Check) fail closed on
  store errors; issuance (RAR validation) fails open with audit; admin
  mutations (assignments, conflict sets) fail closed. Mixing these up —
  e.g. failing open in `Check` when the catalog is down — silently weakens
  the control and must be caught in review and the conformance suite.
- **Behavioral compatibility**: the only user-visible semantic changes are
  (a) RAR-issuance narrowing when a resource resolves (zero registered
  resources ⇒ zero change today) and (b) `Check` with `session_id` on an
  activator backend (new opt-in field ⇒ old callers unchanged). Anything
  beyond that — changing flat `Check`, changing the `Found=false` default,
  changing conflict-set semantics — is out of scope and would break
  existing deployments.
- **Cache-coherence**: every admin mutation that changes bundle content
  must fire `invalidateAuthzPolicy` in the same code path as the write;
  missing one (e.g. `DeleteResource`) recreates the stale-sidecar window the
  invalidation bus exists to close. The acceptance checks pin this per RPC.
- **Docs drift**: error codes, feature matrix, config reference, and the
  OPA example must move in lockstep; the docs gates treat a missing row as
  drift, and the auditreport drift test makes the event classification
  failure loud rather than silent.
