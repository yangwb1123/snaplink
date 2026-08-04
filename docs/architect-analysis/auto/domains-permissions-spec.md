# Requirements Specification: `domains/permissions` improvements

Source baseline: `docs/architect-analysis/auto/domains-permissions-analysis.md` (模块现状 / 上下文基线).
Scope: exactly 3 evidence-backed improvements. Every claim below was verified
against the current tree.

## 1. Wire the resource catalog into an enforcement point (resource-level authorization)

### Problem

`ResourceProvider` (resource catalog) is a complete, densely tested extension
with zero consumers outside its own package: no middleware calls
`ResolveResource`, no admin API manages resources, no durable backend
implements it, and no documentation entry exists. It is a "model without an
enforcement point": the code runs, but the policy never takes effect. The
wire protocol and the RFC 9396 path already anticipate resource-level
authorization, so the gap is wiring, not design.

### Evidence

- `domains/permissions/resources.go`: full `ResourceProvider` contract
  (`RegisterResource`/`GetResource`/`ListResources`/`DeleteResource`/
  `ResolveResource`), 6 `ResourceType`s (`http_api`/`grpc_api`/`graphql_api`/
  `page`/`ui_element`/`js_fn`), `RequireMode` any/all, `Resource.RequiresAuth`,
  `ResourceLookup`, `ResourceDecision` with `Found=false`-is-not-error default
  semantics.
- Zero consumers: `grep -rn "ResourceProvider\|ResolveResource\|RegisterResource"`
  across `*.go` returns nothing outside `domains/permissions/`.
- `domains/permissions/sqlite/sqlite.go:18-21`: package doc explicitly states
  resources are "NOT covered here" — a "separate ... resource store" is deferred
  to operators; redis/postgres backends likewise have no resource tables.
- `interfaces/grpcserver/authz.go` `Check`: only flat
  `permissions.Matches(perms, in.Permission)`; `ListPermissions` maps
  `Permission{Code: p.Code, Resource: p.Resource}` but `memory.go:283`
  (`Permissions()`) only ever produces `Permission{Code: code}` — the
  `resource` field is never populated by any backend.
- `proto/authz/v1/authz.proto` `Permission` message: `string resource = 2;`
  already on the wire — the protocol layer anticipated resource-level checks.
- `protocols/oauth/oauthvalidate/rar.go`: RFC 9396 `authorization_details` is
  only shape-checked (`checkRARShape` + type-allowlist) and passed through
  verbatim into the token; nothing interprets or validates it against the
  catalog.
- `domains/permissions/memory_resources_test.go`,
  `memory_resources_extra_test.go`, `memory_extra_test.go`: invested but idle
  tests; `domains/permissions/permissionstest/` contains only
  `conformance.go` + `sod_conformance.go` — no resource-catalog conformance
  suite, so no backend can be validated against the contract.

### Proposed behavior

- Add a `ResourceConformanceSuite` to `permissionstest` and make sqlite (and
  redis/postgres) implement `ResourceProvider` with durable tables, so the
  catalog is cluster-shared like roles/assignments/menus.
- Add admin management surface: gRPC RPCs in `proto/admin/v1/permissions.proto`
  (register/get/list/delete resource) implemented in
  `interfaces/grpcserver/grpcadmin/admin_permissions.go`, reusing the existing
  `invalidateAuthzPolicy` callback pattern, plus REST admin routes as the
  existing `/me/*` pattern dictates.
- Make `interfaces/grpcserver/authz.go` `Check` resource-aware: accept a
  `ResourceLookup` (method+path / service+method) on the authz proto
  (additive field), resolve via `ResourceProvider.ResolveResource`, and apply
  `RequireMode`/`RequiresAuth` semantics; keep flat `Matches` as the fallback
  when no catalog entry matches (`Found=false`).
- Validate `authorization_details` elements in `oauthvalidate` against the
  catalog (a RAR `type`/fields resolve to a registered resource whose
  `RequiredPermissions` the token must satisfy at exchange), keeping the
  fail-open default when no resource matches.
- Add `docs/config-reference.md` / `docs/feature-matrix.md` entries and
  `docs/error-codes.md` rows for `ErrResourceNotFound`/`ErrResourceExists`/
  `ErrInvalidResource`.

### Acceptance check

- All four backends (memory/sqlite/redis/postgres) pass the new
  `ResourceConformanceSuite`; sqlite resource tables survive restart and
  replicate across instances.
- An admin can register an `http_api` resource (method+path) and a subject
  without the required permission gets `allowed=false` from authz `Check`
  while one with it gets `allowed=true`; `RequireAll` requires every listed
  permission; `RequiresAuth` blocks anonymous callers.
- A token issued after a RAR request whose `authorization_details` names a
  registered resource carries only the permissions that resource requires;
  unregistered types still pass through unchanged (fail-open preserved).
- No pre-existing gate regressions: `go build ./... && go vet ./...`,
  `TestMaintainability_|TestArchitecture_`, `make ci`.

## 2. Make Separation of Duty (SSoD/DSoD) operable end-to-end

### Problem

SoD is a SOC2/audit staple, but today it is a memory-only demonstration:
not configurable (no admin API to declare conflict sets), not durable (only
`MemoryProvider` implements it), and not enforced (no decision point
consumes the ACTIVE role set). The model, error types, and tests exist, but
no real deployment can use it — and a compliance control that exists but
cannot be configured or enforced is worse than none.

### Evidence

- `domains/permissions/sod.go`: complete contracts — `SoDProvider`
  (`SetConflictSets`/`ConflictSets`), `SessionRoleActivator`
  (`ActivateRoles`/`ActiveRoles`/`DeactivateSession`,
  `SetActivationConflictSets`/`ActivationConflictSets`),
  `ErrRoleConflict`/`ConflictError`/`ErrRoleNotAssigned`/
  `ErrInvalidConflictSet`.
- Implementation exists only in `MemoryProvider` (`sod.go` + `memory.go`);
  `domains/permissions/permissionstest/sod_conformance.go` gates every
  subtest on `t.Skip("provider doesn't implement SoDProvider")` /
  `SessionRoleActivator` type-asserts — the conformance suite itself admits
  the backend capability matrix is inconsistent.
- `proto/admin/v1/permissions.proto` `PermissionAdminService`: only
  roles/assignments/menus RPCs (`ListRoles`…`SetMenus`, 8 total); no conflict
  set declaration and no session-activation RPCs.
- Zero execution consumers: `grep -rn "ActiveRoles\|SessionRoleActivator"`
  across `*.go` returns nothing outside `domains/permissions/` —
  `interfaces/grpcserver/authz.go` `Check` reads `Permissions()` (full
  ASSIGNED set), never `ActiveRoles`; even on memory, activation is
  "activated but nobody checks".
- Contract-doc drift (violates AGENTS.md §5): `docs/feature-matrix.md` has no
  SoD row; `docs/error-codes.md` has no `ErrRoleConflict`/`ErrRoleNotAssigned`
  entries.

### Proposed behavior

- Admin surface: add gRPC RPCs to `proto/admin/v1/permissions.proto`
  (set/list SSoD conflict sets, activate/list/deactivate session roles) with
  `grpcadmin` implementations mapping `ErrRoleConflict`/`ErrRoleNotAssigned`/
  `ErrInvalidConflictSet` to status codes; add REST admin routes following the
  `/me/*` handler pattern.
- Durable backends: add SSoD/DSoD tables to the sqlite backend (and redis/
  postgres peers), removing the `t.Skip` branches in
  `sod_conformance.go` for those backends.
- Enforcement: make the authorization decision path consume the ACTIVE set —
  authz `Check` and the HTTP gate accept an optional sessionID; when the
  provider implements `SessionRoleActivator` and a session is active, evaluate
  against `ActiveRoles` (subject's granted permissions projected from active
  roles) instead of the full assigned set. SessionID maps to the OIDC `sid`
  claim so login/session lifecycle can activate and `DeactivateSession` on
  logout.
- Contracts: add `ErrRoleConflict`/`ErrRoleNotAssigned`/`ErrInvalidConflictSet`
  to `docs/error-codes.md` and an SoD row to `docs/feature-matrix.md`.

### Acceptance check

- On sqlite/postgres backends, declaring a conflict set and assigning two
  conflicting roles to one user fails with `ErrRoleConflict` (and the
  equivalent gRPC status via admin RPC) across restarts and replicas; the
  `sod_conformance.go` skip branches for these backends are gone.
- With DSoD configured and a session activated to a non-conflicting subset,
  authz `Check` (with sessionID) denies a permission held only by the
  deactivated role and allows one held by the active subset; the full
  assigned set still applies when no sessionID is supplied (backward
  compatible).
- Activating an unassigned role returns `ErrRoleNotAssigned`; session logout
  clears activation via `DeactivateSession`.
- Error codes and feature matrix updated; full gates pass (`make ci`).

## 3. Make the authorization decision plane observable and the policy export complete

### Problem

The authorization decision surface is a black box, and the exported policy
data is only "half" of the model. (a) `Authorizer.Check` makes every decision
with no audit event, no metric, and no deny log — while the same module's
`/me/*` read queries emit `audit.EventPermissionQuery`; a security-critical
decision is less observable than a permissions list lookup. (b) The
`PolicyBundle` exported to external enforcers contains only role definitions,
not resource-catalog entries, `RequireMode`/`RequiresAuth` semantics, or SoD
conflict sets — so a sidecar (`docs/examples/opa-authz-policy.rego`) can
drift from the server's own decision semantics.

### Evidence

- `interfaces/grpcserver/authz.go` `Check` body: only
  `permissions.Matches(perms, in.Permission)` returning a bool — no audit
  event, no metrics vector; `grep -rn "sso_authz"` across `*.go` returns
  nothing (no decision counters exist).
- Contrast: `domains/permissions/handlers.go:37-136` `RecordQuery` emits
  `audit.EventPermissionQuery` (defined at `platform/audit/aliases_spi.go:162`)
  but only for the `/me/*` REST paths — the read path is audited, the
  decision path is not.
- `domains/permissions/policy_bundle.go`: `PolicyBundle` carries only
  `Version`, `GeneratedAt`, `ClientID`, `Roles` (`RoleBundle`: code+name+
  permissions), `WildcardSemantics` — no resources, no `RequireMode`/
  `RequiresAuth`, no conflict sets.
- `interfaces/sso/server_health.go:40`: the mount comment itself admits the
  bundle is "the role-definition half of the permissions model".
- Existing plumbing ready to reuse: `grpcadmin.NewPermissionAdminService`
  takes an `invalidateAuthzPolicy` callback
  (`interfaces/grpcserver/grpcadmin/admin_permissions.go:18-39`) that already
  invalidates the bundle cache, so the data-closure skeleton exists.

### Proposed behavior

- Emit an audit event (new `audit.EventPermissionCheck`-style type classified
  in `auditreport`, added via `audit.SetMeta` only, preserving bounded
  cardinality) plus decision counters (`sso_authz_checks_total{decision=...}`)
  from `authz.go` `Check`, covering both allow and deny outcomes with subject/
  client/action context, following the existing metering/audit patterns;
  denials also get a deny-log entry for troubleshooting.
- Extend `PolicyBundle` (bump `PolicyBundleVersion` to 2 per the existing
  versioning comment) to include: resource-catalog entries with their
  `RequireMode`/`RequiresAuth`/`RequiredPermissions` and type attributes, and
  SSoD/DSoD conflict sets per client; keep the ETag/`CanonicalBytes` scheme so
  regeneration of identical data stays cache-stable.
- Update `docs/examples/opa-authz-policy.rego` to implement resource-gated
  and SoD-aware decisions from the extended bundle, and add a conformance
  test asserting the exported bundle and the server's `Check` agree on a
  shared decision fixture set (drift detection).

### Acceptance check

- Every `Check` call (allow and deny) produces one audit event and updates
  the `sso_authz_checks_total` counters; a denied request is identifiable in
  the audit trail with subject, client, permission, and outcome.
- `PolicyBundle` v2 contains resources and conflict sets; `ETag` is unchanged
  for identical data and changes when a resource or conflict set changes;
  `invalidateAuthzPolicy` fires on those admin mutations.
- The OPA reference policy and the server `Check` return identical decisions
  on the shared fixture set (no drift); bundle schema-version branches on
  `PolicyBundleVersion`.
- Error/docs updated as applicable; full gates pass (`make ci`).

---

Priority note (from the analysis): direction 1 delivers the largest product
value (converts invested engineering into a sellable fine-grained
authorization capability and pairs with RFC 9396 RAR); direction 2 is the
compliance gap with the clearest missing surface; direction 3 is the support
plane for both and can be merged incrementally — each enforcement point added
in 1/2 should ship its audit event and bundle data in the same change.
