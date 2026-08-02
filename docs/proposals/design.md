Design doc written to `docs/auto/interfaces-snapshot-restore-safety-design.md`. All spec evidence claims were re-verified against the code before writing; the doc follows the house format (companion header, fixed constraints, `## Decision N` sections each covering API surface / storage model / failure modes / what could break).

## Verified corrections found while checking the spec's claims

- **`operations.AddCompensation` already exists** (`platform/lifecycle/operations/operations.go`) and `AdminOperation.compensations` is already on the wire (proto field 7, projected by `operationToProto`) — D3 needs no new operations API or proto, only population of the existing slot. The spec's "operations 包需暴露 append 辅助" assumption is outdated.
- **`mapSnapshotError` maps `ErrUnsupportedRestore` → `Internal` today** (default branch) — D2's preflight move must also fix this to `FailedPrecondition`.
- **`PruneOldest` is pipeline-free** and `Kind` lives in the encrypted body — retention can't see it. D1 therefore mirrors `kind` into the `SealedEnvelope` header (additive JSON field) so retention skips victims with a cheap `Get`+`PeekEnvelope` (O(victims), no decryption). This is the storage-model mechanism the spec left open.
- **Menus have no separate prune** (`replaceMenus` wipes via `SetMenus` replace semantics) — they stay in D2's Phase A; the split table must not invent `pruneMenus`.
- **No existing test pins the wipe-first partial-failure shape** — D2's changed failure semantics break no committed test, but the fault-injection tests must land in the same change.
- **Spec checklist gap closed**: the proto checklist omits `rollback_on_error`, but `restoreTracked` must learn rollback intent — the design adds `RestoreSnapshotRequest.rollback_on_error = 8` (BoolValue, additive) and flags it explicitly for the spec amendment.

## Design highlights

- **D1 (safety snapshot)**: capture step between `load_snapshot` and `apply_resources`, explicit no-op `RedactorFunc` override (beats `DefaultExportRedactor` — verified `effectiveRedactor`), kind-based recursion guard, fail-closed `FailedPrecondition` before `operations.Start` when snapshotter is unwired, tri-state `BoolValue` opt-out, dry-run precedence.
- **D2 (stage-then-prune)**: `stagePlan`/`prunePlan` move to new `restorer_stage.go` (restorer.go shrinks from 474 lines), capability preflight limited to the two verified capability-guarded prunes (connections `Lister`, pairwise `Lister`+`Deleter`), Phase B preserves category order (load-bearing for FK-strict backends), `Committed=false` on dry-run.
- **D3 (rollback)**: rollback validation reads the raw `AutoSafetySnapshot` before defaulting (explicit net required), `Exclude` carried into the rollback re-apply for minimality, invalidator fires twice total (inner re-apply success + orchestrator — matching the spec's acceptance), error-with-response semantics and the grpc-gateway body-drop caveat documented, rollback-failure never claims success.

Key risks surfaced: rolling-upgrade retention hazard (old node deletes safety artifacts), capture non-atomicity under concurrent writes, secrets-at-rest on retention-exempt artifacts, storage growth, and the rollback-is-also-not-a-transaction limitation.
