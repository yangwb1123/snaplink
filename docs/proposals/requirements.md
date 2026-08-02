Specification written to `docs/auto/interfaces-snapshot-restore-safety.md`. All evidence claims were verified against the code before writing (restore plan ordering, prune-first semantics, operations-store bookkeeping, `Compensations` slot, retention sweep behavior, redactor override precedence, and the 474-line `restorer.go` budget constraint).

## 3 improvements (direction 1: restore safety — atomicity/rollback + pre-restore safety snapshot)

**## 决策 1 — 恢复前自动安全快照 (Pre-Restore Safety Snapshot)**
- **Problem**: destructive `ModeReplace` restore has zero rollback artifact; `restoreTracked`/`failRestoreOperation` (`interfaces/grpcserver/grpcadmin/admin_snapshots.go`) only do operations bookkeeping — no undo data.
- **Evidence**: `SnapshotAdminService` already holds `pipeline`+`storage`+`snapshotter`+`restorer` but `Restore` never uses `snapshotter`; `PruneOldest` (`retention.go`) would sweep the safety artifact; `effectiveRedactor`/`RedactorFunc` already support an explicit no-redaction override (a redacted snapshot is not restorable).
- **Proposed**: mandatory capture for replace+non-dry-run via existing `Snapshotter.Export`+`Pipeline.Save` (fail-closed `FailedPrecondition` when unwired), `Kind="safety"` marker for recursion guard + retention protection, `safety_snapshot_id` in response/audit metadata.

**## 决策 2 — 破坏性操作延迟提交 (Stage-Then-Prune)**
- **Problem**: `restorePlan` (`restorer.go`) runs each category's `prune*` before inserts; a mid-plan failure (e.g. `restoreAssignments`' `AssignRoles` error) leaves earlier categories already wiped. Deletes are the only irreversible ops; there is no cross-store transaction.
- **Evidence**: `pruneClients`/`pruneUsers`/`pruneTenants`/`pruneConnections`/`prunePairwise`/`pruneAssignments` all delete-first; upsert paths are already idempotent (`Add`+`ErrClientExists`→`Update`, `CreateOrUpdate`), and prunes are keep-set-pure → resumable.
- **Proposed**: two phases — all non-destructive upserts first, all prunes only after full success; capability preflight moves into `prepareRestore` so `ErrUnsupportedRestore` still fails with zero writes; `Report.Committed`.

**## 决策 3 — 失败自动回滚与部分应用状态暴露 (RollbackOnError + Committed/RolledBack)**
- **Problem**: callers cannot distinguish unapplied/partial/applied state; `RestoreInvalidator` fires only on full success, so partial applies change raw stores while caches stay stale; rollback is manual.
- **Evidence**: `Restore` returns partial `Report`+error with no committed flag; error path returns no report at all; `Operation.Compensations []Step` (`platform/lifecycle/operations/operations.go`) exists but is unused.
- **Proposed**: `RollbackOnError` option (validation-guarded to require the safety net), rollback orchestration in `restoreTracked` re-applying the safety snapshot with recursion guards, compensation-step bookkeeping, cache invalidation after rollback, and fail-closed error messaging when rollback itself fails.

Each decision includes a concrete acceptance check (fault-injection Given/When/Then, round-trip equality, zero-write guarantees, backward-compat regression), plus the contract-update checklist (proto additive fields, openapi, error codes, dr-framework runbook) required by AGENTS.md §5.
