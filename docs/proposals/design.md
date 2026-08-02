Design doc written to `docs/auto/domains-permissions-sod-design.md` (509 lines), as the counterpart to the spec. All evidence re-verified against the tree before writing; two claims were corrected in-flight (the audit-helper location).

## Design decisions

**## Decision: admin surface — `SoDAdminService` in the proto file, implemented in `grpcserver`, not `grpcadmin`**
- The spec's literal placement fails two gates: `grpcadmin/` is at 10/10 non-test files (verified), and adding ~175 lines to `admin_permissions.go` (264 lines today) would crowd the 500-line budget. Mandatory deviation: same proto file/package/REST prefixes, but a **new additive service** (ADR-0008-safe) implemented in `interfaces/grpcserver/sod_admin.go` (6→7/10 files).
- Pinned the wire contract: 7 RPCs, REST paths under `/conflicts` and `/users/{user_id}/sessions/{session_id}/roles`, error mapping table (InvalidArgument/FailedPrecondition → 400 with `invalid_conflict_set`/`role_not_assigned`/`role_conflict`), `ConflictDetails` in status details + audit only (oracle-safe family), 4 new audit events (auditreport-classified), `invalidateAuthzPolicy` on declarations only.

**## Decision: storage model — three tables per durable backend, atomic check-and-write**
- Migration v2 on sqlite (named consistently `permissions_sod_conflicts`/`permissions_activation_conflicts`/`permissions_active_sessions` with a client index for the `RemoveRole` cascade), identical postgres tables, redis JSON docs + TTL.
- Atomicity per backend: sqlite `BEGIN IMMEDIATE` (writer-serialized), postgres `SELECT ... FOR UPDATE`/SERIALIZABLE, redis Lua — closing the "works on memory, breaks on sqlite" race.
- Conformance: spec's "delete skip branches" strengthened to skip→`t.Fatalf` — the type-assert stays as self-documentation, but a backend omitting SoD now *fails* instead of silently passing.

**## Decision: enforcement — session-scoped `Check` over the ACTIVE set**
- `CheckRequest.session_id = 6` (coordinated with the sibling resource design's reserved numbering), full decision matrix — including the row the spec left open (session_id present + provider without activator → documented assigned-set fallback, unreachable from first-party callers since the mesh gate checks the interface first).
- "Activate at login" pinned: best-effort activation of the *full assigned set* (fresh sessions behave exactly like today); `ErrRoleConflict` (legitimately held DSoD-exclusive pair) → audit + empty active set, login never fails, decision point stays fail-closed.
- One shared projection via `UnionPermissions` folded into `matcher.go` (domains/permissions is at 10/10 files); lifecycle hooks fold into `accessors_handlers.go` (interfaces/sso at its 60-file ceiling).

**## Decision: sequencing and cross-cutting risks** — land storage → admin → enforcement (the only caller-visible behavior change), budget table, and the cross-cutting breakage list (field-number collision, non-retroactive `SetConflictSets` semantics, multi-client `sid` scoping, per-login write cost, drift between the two design docs).
