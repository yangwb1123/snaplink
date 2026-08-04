# Design: interfaces/snapshot — Restore safety (atomicity/rollback + pre-restore safety snapshot)

> Companion to `docs/auto/interfaces-snapshot-restore-safety.md`. Design only —
> no code was modified. Every evidence claim was re-verified against the
> executable code at the current commit before writing.
>
> The three decisions form one coherent restore-safety upgrade: a mandatory
> pre-restore safety snapshot (D1), two-phase stage-then-prune atomicity (D2),
> and optional automatic rollback plus committed/rolled-back observability
> (D3). Each `##` decision covers API surface, storage model, failure modes,
> and what could break the design. Contract updates and verification are
> collected at the end.

**Verified corrections to the spec's assumptions (bind every decision):**

- `operations.AddCompensation(ctx, store, operation, name, state, message)`
  **already exists** (`platform/lifecycle/operations/operations.go`), and
  `AdminOperation.compensations` is already on the wire (proto field 7) with
  `operationToProto` projecting it (`interfaces/grpcserver/grpcadmin/admin_paginate.go:289`).
  Decision 3 needs **no new operations API and no operations proto change** —
  only population of the existing slot.
- `mapSnapshotError` (`admin_snapshots.go`) currently maps `ErrUnsupportedRestore`
  to `codes.Internal` (default branch). D2's capability preflight must also fix
  this mapping to `FailedPrecondition` — a capability gap is a caller-side
  precondition, not a server fault.
- `PruneOldest` (`interfaces/snapshot/retention.go`) is **pipeline-free**: it
  only touches `Storage.List/Delete`. The spec's `Kind` lives in the Snapshot
  BODY (encrypted + codec-encoded); retention cannot see it without a full
  `Pipeline.Load`. D1 therefore mirrors `kind` into the `SealedEnvelope` header
  (additive JSON field) so retention skips safety artifacts without decryption.
- Menus have **no separate prune**: `replaceMenus` (`restorer_menus.go`) wipes
  via `SetMenus`'s replace semantics per client-roster entry. Menus stay in
  D2's Phase A — the split table must not invent a `pruneMenus`.
- No existing test pins the current wipe-first *partial-failure* ordering
  (`restore_modes_test.go` only asserts full-success counts and dry-run
  no-mutation), so D2's changed failure shape breaks no committed test — but
  the new fault-injection tests must be added in the same change.
- No server node-identity config exists in `cmd/sso-server` wiring; the safety
  capture's `ExportOptions.SourceNodeID` stays empty (the field is optional).

**Fixed constraints discovered while verifying:**

- `interfaces/snapshot/restorer.go` is exactly 474 lines (500 budget). All new
  restore logic goes to new files `restorer_stage.go` (D2) and `restorer_safety.go`
  (D1/D3 helpers); the two-phase orchestration must *shrink* restorer.go, not
  grow it. Per-category files are far under budget (clients 150, users 116,
  assignments 177, roles 136, menus 119, netpolicy 97) and can absorb the
  `stageX` extraction. `interfaces/sso`'s 60-file ceiling is not involved.
- `SnapshotAdminService` already holds `pipeline + storage + snapshotter +
  restorer + recorder + operations` (`NewSnapshotAdminService`); the `Restore`
  path is the only RPC that never touches `snapshotter`. Capture cost is one
  wired call.
- `Snapshotter.Export` redaction precedence is per-call override first, then
  `DefaultExportRedactor` (`effectiveRedactor`, `snapshotter.go`) — an explicit
  `RedactorFunc(func(*Snapshot){})` guarantees an unredacted, restorable safety
  artifact even when `snapshot.redact_secrets=true` is wired.
- `snap_`-prefix + timestamp-lexicographic ID convention (`newSnapshotID`)
  gives safety snapshots sortable IDs at zero cost; `PruneOldest` already
  filters by that prefix.
- Restore is a raw-store writer with a documented cache limitation
  (`admin_snapshots.go` header comment); `RestoreInvalidator` is wired as the
  `sso.Server` (`build_stores.go buildSnapshotterRestorer`). The design keeps
  invalidation exactly where it is today (success path) plus the rollback path.
- SDK-direct restore callers that get the new `Report` fields without
  orchestration: `platform/bootstrap/builtin.ApplyRestore` (builtin.go:90,
  default mode overwrite) and `serverbuildstore/build_network_snapshot.go:165`
  (ModeOverwrite). Both are non-replace by default and unaffected semantically.

---

## Decision 1 — Pre-restore safety snapshot（恢复前自动安全快照）

**Rule.** Every `ModeReplace` non-dry-run restore through the admin surface
captures the destination node's current state with the existing
`Snapshotter.Export` + `Pipeline.Save` into the same storage, marked
`Kind = "safety"`, before any target-store write. The capture is the undo
artifact for D3's rollback and for manual operator recovery. Capture is
mandatory-by-default, explicitly opt-out-able, fail-closed when the
snapshotter is unwired, and recursion-guarded for safety-kind sources.

### API surface

SDK (`interfaces/snapshot`):

- `Snapshot.Kind string` with `json:"kind,omitempty"`; constant
  `KindSafetySnapshot = "safety"`. Empty kind = ordinary export. `SchemaVersion`
  stays `"2"` — the JSON codec round-trips the struct field wholesale; old
  readers ignore the unknown field, new readers treat missing as normal.
- `RestoreOptions.AutoSafetySnapshot bool`, normalized in `prepareRestore`
  **after** validation: `if !opts.AutoSafetySnapshot { opts.AutoSafetySnapshot =
  opts.Mode == ModeReplace && !opts.DryRun }`. The Restorer itself never
  captures (it has no Pipeline/Storage); the flag is the normalized intent the
  orchestrator consumes and the validation hook D3 couples to. Explicit opt-out
  is not expressible with a plain bool at the SDK layer — it is a
  gRPC/REST tri-state concern (below), matching the spec's split of duties.
- No change to `Snapshotter`/`Pipeline` signatures; capture reuses
  `Export(ctx, ExportOptions{Redactor: RedactorFunc(func(*Snapshot){})})` and
  `Save(ctx, snap, storage, snap.SnapshotID)`.

gRPC/REST (all additive, proto3, no schema bump):

- `RestoreSnapshotRequest.auto_safety_snapshot = 7`
  (`google.protobuf.BoolValue`): `nil` = server default
  (`mode == "replace" && !dry_run && source.Kind != "safety"`), `false` =
  explicit opt-out, `true` = capture regardless of mode.
- `RestoreSnapshotResponse.safety_snapshot_id = 4` (empty when no capture).
- `SnapshotMeta.kind = 10` — List/Get render safety artifacts without
  decryption (header mirror, see storage model).
- `RestoreReport.safety_snapshot_id = 8` (with `committed`/`rolled_back`, D3).

Orchestration in `restoreTracked` (`admin_snapshots.go`):

1. Before `operations.Start` (zero writes, including the operations store):
   resolve tri-state → `captureIntended`; if `captureIntended && s.snapshotter
   == nil` → `FailedPrecondition` (fail-closed; explicit opt-out with a nil
   snapshotter proceeds, operator accepted no net).
2. `load_snapshot` step as today; recursion guard: effective capture =
   `captureIntended && snap.Kind != snapshot.KindSafetySnapshot` — restoring a
   safety snapshot never spawns another one (rollback and manual
   safety-source restores are both covered).
3. New `capture_safety_snapshot` step (only when effective capture): `Export`
   with the explicit no-op redactor (overrides `DefaultExportRedactor`),
   `snap.Kind = KindSafetySnapshot`, `Pipeline.Save` under its own SnapshotID.
4. `apply_resources` as today. Success path: response carries
   `safety_snapshot_id`; `recordAdminMeta(EventSnapshotRestored, ..., meta{
   safety_snapshot_id, auto_safety})` (helper exists, `admin_paginate.go:214`);
   `Operation.ResultJSON` is the full report (which now includes the ID).
5. Explicit opt-out: `recordAdminMeta` carries `auto_safety=false` so the
   decision is auditable.
6. Dry-run never captures, regardless of the flag (`dry_run` wins — dry-run
   stays provably zero-write per D2's invariant); merge/overwrite default to no
   capture; explicit `true` captures (harmless, gives an undo artifact).

### Storage model

- Safety snapshot = a normal `SealedEnvelope` in the same `Storage`, `snap_`
  prefix, same codec/sealer as ordinary exports. Distinguished only by kind.
- `SealedEnvelope` gains an additive header field `kind string
  json:"kind,omitempty"`; `Pipeline.Save` copies `snap.Kind` into it.
  `EnvelopeVersion` stays `"1"` (additive JSON; old readers ignore, new
  readers treat missing as normal). Benefits: (a) `PruneOldest` skips victims
  with `kind == "safety"` using only `Get` + `PeekEnvelope` — O(victims)
  header reads, no decryption, no Pipeline dependency; (b) `List` renders
  `SnapshotMeta.kind` from the header; (c) retention and display never pay
  `Load` cost.
- `PruneOldest` change: for each *victim* name (only the eldest `len-keep`
  entries), `Get` + `PeekEnvelope`; skip victims whose header kind is `"safety"`.
  Undecodable/unknown-kind envelopes remain deletable (backward compatible —
  every pre-change envelope has no kind). `keep <= 0` no longer deletes
  everything when safety snapshots exist; the doc comment and
  `docs/dr-framework.md` runbook state that safety artifacts are removed by
  explicit `Delete` RPC after the rollback window (TTL is a later iteration).
- No schema bump, no new storage backend, no migration: the artifact is a
  regular snapshot with a marker.

### Failure modes

| Point of failure | Behavior |
|---|---|
| `snapshotter == nil` + capture intended + no opt-out | `FailedPrecondition` before `operations.Start` — zero writes anywhere |
| `Export` backend List error | Capture step failed → operation fails at `capture_safety_snapshot`; zero target-store writes (capture precedes apply) |
| `Pipeline.Save` / storage error | Same as above; partial envelope in storage is harmless (opaque bytes, never referenced) |
| Capture ok, apply fails later | Safety artifact persists; operator recovers via the ID in operation `ResultJSON` + audit meta (design: `failRestoreOperation` persists the partial report + `safety_snapshot_id` in `ResultJSON` — see D3) |
| Retention sweep during rollback window | Skipped by kind; artifact survives until explicit `Delete` |

### What could break the design

1. **Rolling-upgrade retention hazard.** An old binary (no header `kind`)
   running `PruneOldest` treats safety artifacts as ordinary and deletes them —
   including mid-rollback-window. Unavoidable for any additive marker; the
   runbook must state that rollback-window operations run on the new version.
   No wire-version guard exists for retention, and adding one is out of scope.
2. **Redaction silently disables restorability.** If capture ever drops the
   explicit no-op redactor override, `DefaultExportRedactor` (wired when
   `snapshot.redact_secrets=true`) produces a safety snapshot that cannot
   restore credentials. There is no detectable in-band marker for redaction.
   Mitigation: unit test pinning that capture passes an explicit no-op
   `Redactor`; D3's rollback additionally fails loudly if the re-applied state
   diverges from the report's expectations (see D3 failure modes).
3. **Secrets at rest.** Safety snapshots carry `User.Attributes` password
   hashes and `Connection.Config` secrets (client `Secret`/
   `RegistrationAccessToken` are `json:"-"` and never serialized — verified in
   `restorer_clients.go`). Same trust domain as ordinary restorable backups,
   but they now *linger* (retention-exempt). Runbook: same storage hygiene as
   backups; never share; delete after the rollback window.
4. **Storage growth.** Every replace restore adds one full snapshot, exempt
   from retention. Frequent restores on a busy node grow storage unboundedly
   until operator deletion. Mitigation: runbook guidance + explicit `Delete`;
   TTL flagged as a follow-up.
5. **Capture is not atomic.** `Export` lists stores sequentially; a concurrent
   write can produce a safety snapshot that never existed (e.g., an assignment
   whose user was added after the user list). Rollback then restores that
   near-state. Restore is documented for maintenance windows; the same caveat
   now applies to the safety net. Document in the runbook; a quiesce/lock is a
   later iteration.
6. **Header/body kind divergence.** Two writers could drift (header says
   safety, body doesn't or vice versa). Invariant: `Pipeline.Save` is the only
   writer and copies from the same struct; enforce with a round-trip test
   asserting `PeekEnvelope(kind) == snap.Kind` after `Save`.

**Acceptance mapping** (spec D1 checks): one new `snap_*` envelope with
category-equal decode; `safety_snapshot_id` echoed in response + audit;
recursion guard (safety-source restore produces no second artifact);
`PruneOldest(keep=0)` skips safety but `Delete` RPC removes it; nil snapshotter
→ `FailedPrecondition` with zero writes; explicit opt-out runs with
`auto_safety=false` audit meta.

---

## Decision 2 — Stage-then-prune atomicity（破坏性操作延迟提交）

**Rule.** `ModeReplace` becomes two phases: Phase A applies every category's
insert/update/upsert in the current dependency order with **all prunes
disabled**; Phase B, only after Phase A fully succeeds, runs every category's
prune in the same order. A mid-plan failure therefore leaves either an
old-state superset (Phase A fail — nothing deleted, retry-safe) or a
target-state superset (Phase B fail — partial deletes, same-snapshot retry
converges). Capability preflight moves into `prepareRestore` so
`ErrUnsupportedRestore` still fails with zero writes.

### API surface

- No new public API. `Report.Committed bool` is added (D3 projects it):
  `true` iff a non-dry-run restore completed all phases without error. Dry-run
  always reports `Committed == false` (predictions, not writes). Bootstrap
  advance failure after a successful Phase B leaves `Committed == true` (data
  is applied; only the tracker didn't advance).
- Internal refactor, new file `interfaces/snapshot/restorer_stage.go`:
  - `restorePlan` is replaced by two builders, `stagePlan(ctx, snap, opts)`
    and `prunePlan(ctx, snap, opts)`, returning `catRunner`s in the current
    category order (tenants → tenant_domains → connections → clients → users →
    pairwise → roles → menus → assignments → netpolicy). `restorer.go`'s
    `Restore` loop delegates to a shared `runPlan` helper; restorer.go shrinks
    (the plan builders move out), keeping it under 500 lines.
  - Each per-category `restoreX` splits into `stageX` (the existing insert
    loop with the `pruneX` call removed) and keeps `pruneX` unchanged. Menus
    are the exception: `replaceMenus` has no separate prune (wipe semantics
    live inside `SetMenus`); it stays in Phase A.
  - `Restore` for `ModeReplace`: Phase A loop (stage runners), then Phase B
    loop (prune runners). Merge/overwrite: single phase (stage only), identical
    to today. Dry-run: both phases run with writes disabled — counts
    (`Inserted/Updated/Deleted/Skipped`) are byte-identical to today's
    success-path numbers.
- Capability preflight in `prepareRestore` (ModeReplace only, per category
  that is `snap.IncludesCategory` and not `opts.Exclude`-d, and whose backend
  is wired): connections require `connections.Lister` (`pruneConnections`);
  pairwise require `PairwiseSubjectLister` + `PairwiseSubjectDeleter`
  (`prunePairwise`). All other prunes call methods on the base interfaces
  (`Clients.List/Delete`, `Users.List/Delete`,
  `Tenants.ListTenants/DeleteTenant/ListDomains/DeleteDomain`,
  `NetPolicy.List/Delete`, `Permissions.ListAllRoles/RemoveRole/
  ListAssignments/UnassignRoles`) — verified, no assertions needed. Failure →
  `ErrUnsupportedRestore` before any write.
- `mapSnapshotError`: map `ErrUnsupportedRestore` → `FailedPrecondition`
  (currently falls into the `Internal` default — a contract fix, see header).

### Storage model

No storage or schema change. Atomicity is operational ordering, not a
distributed transaction (none exists across `ClientStore`/`UserProvider`/
`permissions.Provider`/`tenant.Store`/`connections.Store`/`netpolicy.Store`/
`PairwiseSubjectStore`). The state machine per replace run:

```text
old ──Phase A──▶ old ∪ inserts (retry-safe superset) ──Phase B──▶ target
```

Convergence rests on two verified properties: upserts are replayable
(`Add`+`ErrClientExists`→`Update` with `preserveClientSecrets`, `CreateOrUpdate`,
`AssignRoles`, `PutTenant`/`PutDomain`, `Upsert`, `SetMenus`, `Apply`), and
prunes are keep-set-pure — they read only `List` + snapshot data, never insert
results — so re-running Phase B deletes exactly the remaining orphans.

### Failure modes

| Point of failure | State left | Recovery |
|---|---|---|
| Phase A, category K errors | old ∪ partial inserts; **zero deletions** | Retry same snapshot (idempotent upserts) |
| Phase B, category K errors | target ∪ partial deletions (some orphans) | Retry same snapshot: Phase A replays to no-ops, Phase B finishes the keep-set prune |
| Preflight capability gap | zero writes | Fix backend wiring; `ErrUnsupportedRestore` → `FailedPrecondition` |
| Concurrent admin write between phases | Phase B may prune records created after capture of the keep-set | Inherent to replace; maintenance-window assumption documented |

`Report.Committed == false` on every failure path; per-category `Deleted`
counts are partial on Phase B failure while `Inserted/Updated` are complete —
consumers must key on `Committed`, not counts.

### What could break the design

1. **Deletes now happen after all inserts — same failure profile, different
   window.** No existing test pins the old mid-plan partial shape (verified),
   but the new fault-injection tests (spec D2 checks) must land in the same
   change or the ordering guarantee is unenforced. The success-path count
   regression (`TestRestore_Replace_*`) must pass unchanged.
2. **Phase B ordering is load-bearing.** Category order within Phase B must
   stay identical to today's interleaved order (clients before roles before
   assignments before netpolicy) because a strict backend may reject deleting
   a client whose roles/assignments still exist. Pin the order with a test and
   a comment in `prunePlan`.
3. **Prune purity is an invariant.** A future "prune by comparing inserted
   IDs" optimization would break resumability (Phase B would depend on Phase A
   state). The keep-set computation is already pure; add a test asserting
   prunes derive solely from `List()` + snapshot data.
4. **`upsertClient`'s preserve-secrets read-modify-write is racy** (Get-then-
   Update backfill). Pre-existing, unchanged by the split; a concurrent secret
   rotation between the probe and the update could be lost. Note in the runbook;
   out of scope.
5. **Counts semantics drift on Phase B failure** — `Deleted` partial while
   `Inserted/Updated` complete. The `Committed` flag exists for exactly this;
   document that counts are meaningful only when `Committed` or error-free.
6. **Budget.** restorer.go must shrink (plan builders move out) — the split is
   a strict line subtraction for restorer.go; `restorer_stage.go` (~180 lines)
   and per-category stage extractions stay well under all budgets.

**Acceptance mapping** (spec D2 checks): injected `AssignRoles` failure in
Phase A → error, `Committed == false`, all `Deleted == 0`, stores equal
pre-restore (old superset); injected `ClientStore.Delete` failure in Phase B →
inserts + first delete applied, same-snapshot retry converges to the
once-successful terminal state; missing pairwise deleter → `ErrUnsupportedRestore`
before any write; clean-node replace success → `CategoryCounts` identical to
pre-split behavior.

---

## Decision 3 — RollbackOnError + Committed/RolledBack（失败自动回滚与恢复状态暴露）

**Rule.** When a replace restore fails and the caller explicitly requested
rollback with a safety net in place, `restoreTracked` automatically re-applies
the D1 safety snapshot, records the compensation step, invalidates caches
again, and returns a failing RPC whose message states the rollback. The
`Report`/RPC/operation/audit layers expose committed / rolled-back / partial
state. Rollback requires `AutoSafetySnapshot=true` (explicit); without the net
it is a validation error with zero writes. A failed rollback never claims
success — the error says the target state is unknown.

### API surface

SDK (`interfaces/snapshot`):

- `RestoreOptions.RollbackOnError bool`. Validation in `prepareRestore`,
  **before** the D1 defaulting (so it sees the caller's raw value):
  `RollbackOnError && !AutoSafetySnapshot → ErrRollbackWithoutSafety`
  (new sentinel; zero writes). Consequently rollback requires an *explicit*
  `AutoSafetySnapshot=true` — the spec's "no safety net, no auto-rollback".
- `Report` gains `Committed bool`, `RolledBack bool`, `SafetySnapshotID string`.
  The Restorer sets `Committed` (D2). `RolledBack`/`SafetySnapshotID` are set
  by the orchestrator (the Restorer never captures/orchestrates — SDK-direct
  callers like `builtin.ApplyRestore` only read the fields, per the spec's
  scope boundary).
- New sentinel `ErrRollbackWithoutSafety = errors.New("snapshot: rollback
  requires a safety snapshot")` → `docs/error-codes.md`.

gRPC/REST (all additive):

- `RestoreSnapshotRequest.rollback_on_error = 8` (`google.protobuf.BoolValue`,
  `nil` → `false`). **Design extension beyond the spec's checklist**: the
  checklist omits this field, but `restoreTracked` must learn rollback intent
  from somewhere; the additive `BoolValue` is the same mechanism as
  `auto_safety_snapshot` and the only consistent option. Flagged explicitly.
- `RestoreReport.committed = 6`, `rolled_back = 7`, `safety_snapshot_id = 8`;
  `reportToProto` projects them.
- `SnapshotMeta.kind = 10` (D1) lets operators identify safety artifacts when
  picking a manual rollback source.

Orchestration in `restoreTracked` (error path only; success path unchanged):

1. `restorer.Restore` fails. If rollback not requested → today's behavior
   (`failRestoreOperation`, nil response) plus one design addition: persist the
   partial report in `ResultJSON` (so operators see partial state via
   `GetOperation` without code changes to the RPC surface).
2. If rollback requested:
   - `FinishStep(apply_resources, cause)` → `BeginStep("rollback_safety_snapshot")`.
   - `pipeline.Load(safetyID)` → on failure: compensation step
     `AddCompensation("rollback_safety_snapshot", StepFailed, err)` (helper
     exists — verified), error message explicitly "rollback failed; target
     state unknown" (never claims restored), audit meta
     `{rolled_back: false, rollback_error}`.
   - Re-apply: `restorer.Restore(ctx, safetySnap, RestoreOptions{Mode:
     ModeReplace, Confirm: safetySnap.SnapshotID, AutoSafetySnapshot: false,
     RollbackOnError: false, Exclude: <original request's exclude>})`.
     Recursion guard = D1's kind guard + explicit `AutoSafetySnapshot=false`;
     rollback never rolls back itself. `Exclude` is carried so rollback
     touches exactly the categories the failed restore touched (minimality —
     excluded categories are neither pruned nor re-inserted).
   - On rollback success: `AddCompensation("rollback_safety_snapshot",
     StepSucceeded, "")` → `Invalidator.InvalidateRestoredControlPlane()`
     (total invalidator probe count = 2: once from the rollback re-apply's own
     success path inside `Restorer.Restore`, once here — matching the spec's
     "twice" acceptance) → build the failed report mutated to
     `{RolledBack: true, Committed: false, SafetySnapshotID: safetyID}` →
     `operations.Finish(state=failed, ResultJSON = report JSON)` → return
     `(response-with-report, err)` where the error is the original cause
     wrapped as `restore <id> rolled back to safety snapshot <sid>: <cause>`
     and mapped via `mapSnapshotError` — the RPC still fails (fail-closed:
     the caller must know the restore did not take effect) but the state is
     safe.
3. Validation: `rollback_on_error=true` + effective `auto_safety=false`
   (explicit opt-out or non-replace mode) → `FailedPrecondition` before any
   write (gRPC mirror of `ErrRollbackWithoutSafety`). `rollback_on_error=true`
   + source `Kind == "safety"` → `FailedPrecondition`: a safety snapshot is
   itself the net; there is nothing to roll back *to* (restoring S and failing
   leaves a superset of S — re-applying S is the retry, not a rollback).
4. Audit: `recordAdminMeta(EventSnapshotRestored, ..., {safety_snapshot_id,
   rolled_back, committed, auto_safety})` on both success and rollback paths;
   `rollback_error` on rollback failure. No new event types — `auditreport`
   classification and bounded cardinality untouched.
5. Scope boundary (unchanged paths): `builtin.ApplyRestore` and
   `build_network_snapshot.go` get `Report.Committed/RolledBack` fields only;
   no orchestration, no capture, no rollback.

### Storage model

No new stores. The undo artifact is the D1 safety snapshot in `Storage`. The
operations record is the rollback ledger: `Operation.Compensations` (already
on the wire as `AdminOperation.compensations`, field 7, already projected by
`operationToProto`) gains `rollback_safety_snapshot` steps with
`StepSucceeded`/`StepFailed`. `ResultJSON` carries the final report on success,
the partial report on plain failure, and `{rolled_back, safety_snapshot_id,
committed}` on the rollback path.

### Failure modes

| Point of failure | Behavior |
|---|---|
| Safety snapshot deleted before rollback (`Load` fails) | Compensation `StepFailed`, error states "rollback failed; target state unknown", audit `rolled_back=false` — never claims restored |
| Rollback re-apply fails mid-way (backend still down) | Same as above; state is a superset of the safety state; operator retries the safety snapshot manually (converges) |
| Rollback validation (no net / safety source) | `FailedPrecondition` before `operations.Start` — zero writes |
| Operations-store write fails during compensation bookkeeping | The rollback itself already succeeded; operation record is stale — audit still records; runbook: treat op record as advisory, verify via stores |
| Rollback succeeded, cache invalidation fails | Invalidation is fire-and-forget today (same as success path); documented staleness window unchanged |

### What could break the design

1. **Rollback is not a transaction either.** It is a second two-phase replace.
   Its failure leaves a partial-rollback state; the only guarantee is honest
   error messaging + convergence by retry. Any future claim of stronger
   atomicity would be false — the design must keep the "state unknown" wording
   on rollback failure.
2. **Rollback reverts concurrent writes too.** The safety snapshot is captured
   before apply; writes between capture and rollback are reverted by the
   rollback re-apply (e.g., a login that changed a user hash between capture
   and failure gets the pre-restore hash back). Rollback semantics =
   "return to captured state", not "undo exactly the restore". Restore is
   maintenance-mode; document.
3. **Error-with-response through grpc-gateway.** Returning a non-nil response
   alongside the error works on gRPC, but the REST gateway drops the message
   body on error — REST clients must read the outcome from
   `GetOperation(operation_id)` (compensations + ResultJSON). Document in the
   runbook and openapi notes.
4. **Rollback churn under retry automation.** A script that retries restore on
   error now triggers rollback-then-retry, doubling writes and producing a new
   safety snapshot per attempt (D1 storage growth). Runbook: cap retries;
   delete stale safety artifacts.
5. **Double-finish hazard.** `failRestoreOperation` already calls
   `FinishStep` + `Finish`; the rollback path must not call it after its own
   bookkeeping. Refactor: `failRestoreOperation` gains an optional
   `(result []byte, rolledBack bool)` variant; a single code path owns
   operation termination.
6. **`Confirm` coupling in the rollback re-apply.** `Confirm =
   safetySnap.SnapshotID` must match the loaded snapshot's ID (it does by
   construction). A corrupt/tampered `Load` fails validation
   (`ErrConfirmationMismatch`) → rollback-failed path. Fail-closed, correct —
   but the error message must attribute it to rollback, not operator error.
7. **Secret preservation interplay.** Client secrets are never in snapshots
   (`json:"-"`); rollback's `upsertClient` backfills from the live store, so
   the *current* live secret survives — the safe direction. User `password_hash`
   IS in the snapshot, so rollback restores pre-restore hashes; a login between
   capture and rollback breaks. Acceptable and documented; a test should pin
   that rollback preserves live client secrets.
8. **Spec discrepancy handled.** The spec's "operations 包需暴露 append 辅助"
   is obsolete — `AddCompensation` exists; no new API. And the spec's checklist
   gap (`rollback_on_error`) is closed here with an additive field; note it in
   the PR description so the spec can be amended.

**Acceptance mapping** (spec D3 checks): injected `restoreAssignments` failure
+ rollback → non-nil error containing `rolled back to safety snapshot`, stores
equal pre-restore, `Compensations[0].state == succeeded`, `RolledBack == true`,
`Committed == false`, audit `rolled_back=true`, invalidator probe count == 2;
`RollbackOnError=true, AutoSafetySnapshot=false` → validation error, zero
writes; safety snapshot deleted before rollback → `StepFailed` + "rollback
failed" message, no success claim; `RollbackOnError=false` → today's partial-
apply + error + `Committed == false`.

---

## Cross-cutting contract updates (one change, per AGENTS.md §5)

- `proto/admin/v1/snapshots.proto` (all additive, no schema bump; needs
  `import "google/protobuf/wrappers.proto"`): `RestoreSnapshotRequest`
  `auto_safety_snapshot = 7` (BoolValue), `rollback_on_error = 8` (BoolValue);
  `RestoreSnapshotResponse.safety_snapshot_id = 4`;
  `RestoreReport.committed = 6`, `rolled_back = 7`, `safety_snapshot_id = 8`;
  `SnapshotMeta.kind = 10`. Regenerate via the repo's proto pipeline; no
  operations proto change (`compensations` already exists).
- `docs/openapi.yaml`: Restore request/response fields, `RestoreReport`
  fields, `SnapshotMeta.kind`.
- `docs/error-codes.md`: `ErrRollbackWithoutSafety` (validation,
  `FailedPrecondition`), `ErrUnsupportedRestore` now surfaced as
  `FailedPrecondition` on the Restore endpoint (was `Internal`), rollback
  status descriptions.
- `docs/dr-framework.md` §4/§6 runbook: pre-restore safety snapshot behavior,
  rollback behavior, retention exemption, rollback-window hygiene (delete via
  explicit `Delete`; TTL later), maintenance-window/quiesce caveats (D1/D3
  consistency), retry-churn warning (D3).
- Audit: no new event types; `EventSnapshotRestored` metadata via
  `recordAdminMeta` (`safety_snapshot_id`, `rolled_back`, `committed`,
  `auto_safety`, `rollback_error`); `auditreport` untouched.
- Budgets: restorer.go shrinks; new files `restorer_stage.go`,
  `restorer_safety.go`; per-category files grow by the stage extraction only.

## Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/snapshot/... ./interfaces/grpcserver/grpcadmin/... -race
go test ./test/ -run TestE2E -v
make ci
```

Targeted tests (beside the code, fault-injection style):

- D1: capture round-trip equality (order-insensitive per category); header/body
  kind consistency; retention skip (`keep=0` keeps safety, `Delete` RPC
  removes); recursion guard; nil-snapshotter `FailedPrecondition` zero-write;
  opt-out audit meta; no-op-redactor-override pin (capture is restorable even
  with `DefaultExportRedactor` wired).
- D2: Phase A mid-failure (zero `Deleted`, old superset); Phase B mid-failure
  (convergence on same-snapshot retry, byte-equal terminal state); capability
  preflight zero-write; dry-run and success-path count regression
  (existing `TestRestore_Replace_*`).
- D3: rollback success (store equality, compensation step, invalidator count
  == 2, error text, `RolledBack/Committed` projection); rollback validation;
  rollback-failure messaging; `RollbackOnError=false` backward-compat;
  rollback preserves live client secrets.
