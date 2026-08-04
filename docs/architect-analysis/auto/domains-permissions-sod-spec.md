# Requirements Specification: `domains/permissions` — SoD as an operable compliance control (方向 2)

Source baseline: `docs/architect-analysis/auto/domains-permissions-analysis.md` 方向 2
（把 SoD（SSoD/DSoD）从"内存演示"变成可运营的合规控制）.
Scope: exactly 3 evidence-backed improvements. Every claim below was verified
against the current tree.

## 1. Admin surface: declare conflict sets and manage session activation over gRPC/REST

### Problem

SoD is unconfigurable: no server surface exists to declare SSoD/DSoD conflict
sets or to activate/deactivate session roles. `SoDProvider` and
`SessionRoleActivator` are unreachable from production tooling, so a customer
cannot express the compliance policy at all — the model exists but no API can
drive it.

### Evidence

- `proto/admin/v1/permissions.proto` `PermissionAdminService` (lines 18–55):
  exactly 8 RPCs (`ListRoles`/`AddRole`/`UpdateRole`/`RemoveRole`/
  `ListAssignments`/`AssignRoles`/`UnassignRoles`/`SetMenus`); no
  conflict-set declaration and no session-activation RPC, so
  `sod.go`'s `SetConflictSets`/`SetActivationConflictSets`/`ActivateRoles`
  have no caller outside tests.
- `interfaces/grpcserver/grpcadmin/admin_permissions.go:37` —
  `NewPermissionAdminService(prov, recorder, invalidateAuthzPolicy)` is the
  established pattern: every mutation emits an audit event via
  `recordAdminMeta` (e.g. `audit.EventAdminRoleAssigned` in `AssignRoles`)
  and fires the `invalidateAuthzPolicy` cache-invalidation callback. The new
  RPCs must reuse it.
- Both transports are already wired: gRPC at `cmd/sso-server/main_servers.go:225`
  and grpc-gateway REST at `cmd/sso-server/build_http.go:437`
  (`RegisterPermissionAdminServiceHandlerServer`), so adding
  `google.api.http`-annotated RPCs to the proto yields the REST admin routes
  for free.
- `domains/permissions/sod.go` `ConflictError{ClientID, Set, Roles}` was
  designed precisely so admin UIs and audit trails can explain WHY an
  assignment/activation was rejected — no surface currently returns it.

### Proposed behavior

- Extend `proto/admin/v1/permissions.proto` `PermissionAdminService`
  (additive; the package is STABLE but additions are allowed) with:
  `SetConflictSets`/`ListConflictSets` (SSoD),
  `SetActivationConflictSets`/`ListActivationConflictSets` (DSoD), and
  `ActivateSessionRoles`/`ListActiveRoles`/`DeactivateSessionRoles`
  (DSoD, carrying `session_id`), each with `google.api.http` annotations for
  REST parity. Regenerate `gen/proto/`.
- Implement in `grpcadmin` with the existing pattern: map
  `ErrInvalidConflictSet` → InvalidArgument, `ErrRoleNotAssigned` →
  FailedPrecondition, `ErrRoleConflict` → FailedPrecondition carrying the
  `ConflictError` set/roles in status details; emit new audit events
  (classified in `auditreport`, per AGENTS.md §4) for conflict-set mutations
  and session activation; fire `invalidateAuthzPolicy` on conflict-set
  changes (they alter future assignment/activation outcomes and must bust the
  bundle cache).
- All RPCs scoped by `client_id` exactly like the existing eight.

### Acceptance check

- bufconn test against `grpcadmin`: after `SetConflictSets`, admin
  `AssignRoles` of two conflicting roles returns FailedPrecondition with the
  offending codes; activating an unassigned role returns FailedPrecondition;
  a single-role conflict set returns InvalidArgument with no partial write.
- Audit sink receives the new events; `invalidateAuthzPolicy` fires on
  `SetConflictSets`; REST route test through the grpc-gateway mount.
- Proto regenerated; `go build ./... && go vet ./...` and
  `go test -run 'TestArchitecture_|TestMaintainability_' .` pass.

## 2. Durable backends: SoD tables in sqlite/postgres (redis parity), conformance skips removed

### Problem

SoD is not durable: only `MemoryProvider` implements `SoDProvider` and
`SessionRoleActivator`, so conflict declarations and session activations
vanish on restart and fork per replica. The conformance suite institutionalizes
the gap by type-asserting and skipping — durable backends "pass" the
compliance contract by not running it.

### Evidence

- `domains/permissions/sqlite/sqlite.go:16–22`: package doc lists exactly
  three tables (roles/assignments/menus); no SoD tables, in the same
  "NOT covered here" vein as the resource catalog.
- `domains/permissions/sod.go`: compile-time asserts
  `_ SoDProvider = (*MemoryProvider)(nil)` and
  `_ SessionRoleActivator = (*MemoryProvider)(nil)` only — no sqlite,
  postgres, or redis peer implements either interface.
- `domains/permissions/permissionstest/sod_conformance.go`: all 11 SoD
  subtests begin with `t.Skip("provider doesn't implement ...")` on a
  type-assert; the suite itself documents that "redis/postgres/sqlite peers
  that haven't grown SoD support yet keep passing this suite unmodified".
- The state model is three JSON-able maps (`ssodConflicts`, `dsodConflicts`,
  `activeRoles` keyed `userID\x00clientID\x00sessionID` via `sod.go`
  `sessionKey`) — trivially mappable to tables, and `stripActiveRole`
  already defines the RemoveRole cascade semantics.

### Proposed behavior

- sqlite backend: add `ssod_conflicts(client_id, sets_json)`,
  `dsod_conflicts(client_id, sets_json)`, and
  `active_roles(user_id, client_id, session_id, roles_json)` with atomic
  whole-table replace (SET semantics, matching `SetConflictSets`) and DELETE
  on clear; enforce SSoD inside the same transaction as `AssignRoles` /
  `AddRoleToUser` writes; `RemoveRole` strips the code from every
  `active_roles` row for that client (mirror `stripActiveRole`).
- postgres peer: identical tables plus transactional enforcement; redis peer:
  the same three maps under scoped keys, matching its existing JSON-document
  style.
- `permissionstest/sod_conformance.go`: delete the skip branches — the
  capability matrix becomes complete (interfaces stay optional in code for
  additivity, but every backend in the suite implements them), so all
  `testSoD*` subtests run against every backend.

### Acceptance check

- `permissionstest.ConformanceSuite` SoD subtests execute (no `t.Skip`)
  against sqlite and postgres peers; restart-and-reread test proves conflict
  sets and activations survive; a cross-replica test shows one replica's
  `SetConflictSets` visible on another's next lookup.
- Atomicity: a rejected conflicting `AssignRoles` leaves no partial rows;
  `RemoveRole` removes the code from every `active_roles` row for that client.
- Race runs with `-count=10+`; `make ci` passes.

## 3. Enforcement: the decision path consumes the ACTIVE role set (session-scoped Check) + contract docs

### Problem

SoD is not enforced: even on the memory backend, the ACTIVE set written by
`ActivateRoles` is read by nobody. `authz` `Check` always evaluates the full
ASSIGNED set, so a declared DSoD constraint has zero runtime effect —
"activated but nobody checks". The public contracts are also drifting
(AGENTS.md §5): the error types and the feature are absent from the docs.

### Evidence

- `interfaces/grpcserver/authz.go` `Check`: resolves `perms` via
  `s.provider.Permissions(ctx, in.SubjectId, in.ClientId)` and returns
  `permissions.Matches(perms, in.Permission)` — `Permissions()` (`memory.go:270`)
  projects the full ASSIGNED set; `ActiveRoles`/`SessionRoleActivator` have
  zero references outside `domains/permissions/` (grep across `*.go`).
- `proto/authz/v1/authz.proto:31–35` `CheckRequest`: fields
  `subject_id`/`client_id`/`permission` only — no `session_id` slot, so
  session-scoped evaluation is not even expressible on the wire.
- Session identity already flows through the stack:
  `interfaces/sso/accessors_handlers.go:69` (`SessionID: claims.SID`) and
  `interfaces/sso/mesh_authz.go:226` (`meshCheckSession` reads `claims.SID`)
  — the OIDC `sid` is the natural DSoD `sessionID`, exactly as
  `SessionRoleActivator`'s doc anticipates.
- `docs/error-codes.md` has no `ErrRoleConflict`/`ErrRoleNotAssigned`/
  `ErrInvalidConflictSet` rows (only unrelated `user_conflict` /
  `lifecycle_state_conflict`); `docs/feature-matrix.md` has no SoD row.

### Proposed behavior

- Extend `proto/authz/v1/authz.proto` `CheckRequest` with `session_id`
  (mirrored in the HTTP gate); `Check` becomes session-aware: when the
  provider implements `SessionRoleActivator` and `session_id` is non-empty,
  evaluate against permissions projected from `ActiveRoles` (session
  unknown/expired → deny, fail closed); when `session_id` is empty, fall back
  to the full ASSIGNED set — byte-identical to today's behavior (backward
  compatible).
- Project active permissions through the same `Role.Permissions` resolution
  `Permissions()` uses, so one code path defines both modes.
- Wire lifecycle: activate at login/session start from the OIDC `sid`
  (`accessors_handlers.go` session material), and call `DeactivateSession` on
  logout/session revocation alongside the existing `sid` tracking in
  `interfaces/sso/server_token_clientauth.go:334`.
- Contracts updated in the same change: the three `Err*` rows in
  `docs/error-codes.md`, an SoD row in `docs/feature-matrix.md`, and the
  `CheckRequest.session_id` field in `docs/openapi.yaml`.

### Acceptance check

- Test (unit + authz bufconn): with a DSoD set declared and a session
  activated to a non-conflicting subset, `Check(session_id)` denies a
  permission held only by the deactivated role and allows one held by the
  active subset; `Check` without `session_id` still allows via the full
  assigned set (backward compatible); `Check` with an unknown `session_id`
  denies (fail closed).
- `ActivateRoles` on an unassigned code surfaces `ErrRoleNotAssigned` as its
  mapped status; `DeactivateSession` clears the session, after which
  session-scoped `Check` falls back to the assigned set.
- `docs/error-codes.md`/`docs/feature-matrix.md`/`docs/openapi.yaml` updated;
  mandatory gates pass (`go build ./... && go vet ./...`,
  maintainability/architecture tests, `make ci`).
