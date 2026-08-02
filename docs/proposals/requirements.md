Spec written to `docs/auto/domains-permissions-sod-spec.md`. All evidence was re-verified against the tree (line numbers confirmed via grep/sed):

## Summary of the 3 improvements (方向 2: SoD → operable compliance control)

**## 1. Admin surface: declare conflict sets and manage session activation over gRPC/REST**
- **Problem**: SoD is unconfigurable — no server surface reaches `SetConflictSets`/`ActivateRoles`.
- **Evidence**: `proto/admin/v1/permissions.proto:18-55` (only 8 roles/assignments/menus RPCs); the reusable pattern at `interfaces/grpcserver/grpcadmin/admin_permissions.go:37` (`NewPermissionAdminService(prov, recorder, invalidateAuthzPolicy)`); both transports already mounted (`main_servers.go:225`, `build_http.go:437`); `ConflictError{ClientID, Set, Roles}` in `sod.go` designed for admin explanations but never returned anywhere.
- **Proposed**: additive RPCs (SSoD/DSoD conflict sets + session activation), error mapping (`ErrInvalidConflictSet`→InvalidArgument, `ErrRoleConflict`/`ErrRoleNotAssigned`→FailedPrecondition with details), audit events + `invalidateAuthzPolicy` firing.
- **Acceptance**: bufconn admin test, audit/invalidation assertions, REST gateway route, regenerated proto, gates pass.

**## 2. Durable backends: SoD tables in sqlite/postgres (redis parity), conformance skips removed**
- **Problem**: memory-only — declarations vanish on restart and fork per replica; the suite institutionalizes the gap.
- **Evidence**: `domains/permissions/sqlite/sqlite.go:16-22` (three tables, SoD absent); `sod.go` compile-time asserts only `*MemoryProvider`; `permissionstest/sod_conformance.go` — all 11 subtests `t.Skip` on type-assert; state model is three JSON-able maps (`sessionKey`).
- **Proposed**: 3 tables with atomic SET semantics, transactional SSoD enforcement in `AssignRoles`/`AddRoleToUser`, `RemoveRole` cascade via `stripActiveRole` mirror; delete the skip branches.
- **Acceptance**: suite runs SoD subtests (no skip) on sqlite/postgres, restart + cross-replica persistence, atomicity, `-count=10+`, `make ci`.

**## 3. Enforcement: decision path consumes the ACTIVE set (session-scoped Check) + contract docs**
- **Problem**: even on memory, `ActivateRoles` output is read by nobody; `Check` always uses the ASSIGNED set; docs drift.
- **Evidence**: `interfaces/grpcserver/authz.go` `Check` → `Permissions()` (`memory.go:270`, full assigned set); zero external `ActiveRoles`/`SessionRoleActivator` references; `proto/authz/v1/authz.proto:31-35` `CheckRequest` has no `session_id`; `sid` already flows (`accessors_handlers.go:69`, `mesh_authz.go:226`, `server_token_clientauth.go:334`); `docs/error-codes.md`/`feature-matrix.md` lack SoD entries.
- **Proposed**: add `session_id` to `CheckRequest`; session-aware `Check` (active subset when present, fail closed on unknown session, full assigned set when absent — backward compatible); activate/deactivate wired to OIDC `sid` lifecycle; error-codes/feature-matrix/openapi updated in the same change.
- **Acceptance**: session-scoped allow/deny tests, backward-compat and fail-closed cases, docs updated, `make ci`.

The spec follows the format of the existing `docs/auto/domains-permissions-spec.md` (Problem/Evidence/Proposed behavior/Acceptance check) and stays within the three gaps the analysis named: 不可配置 → 不持久 → 不执行.
