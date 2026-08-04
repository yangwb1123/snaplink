# QA Lead Review — Snapshot Restore Safety Design (D1/D2/D3)

**Revision reviewed:** `docs/auto/interfaces-snapshot-restore-safety-design.md`
at HEAD `3be9b3d6` (design staged; no code modified by this review). Companion
spec: `docs/auto/interfaces-snapshot-restore-safety.md`.

**Role basis:** risk-based test review per `ai-dev/prompts/README.md` +
`qa_lead.md`. Every claim below is labeled **Verified** (read at the cited
symbol/path in this revision), **Partial**, **Missing**, or **Proposed**.
Coverage numbers come from commands actually run for this revision (§1), never
from prior reports. The review is advisory: it modifies no code.

**Scope of the change under review:** D1 mandatory pre-restore safety snapshot,
D2 stage-then-prune two-phase replace, D3 rollback-on-error with
committed/rolled-back observability. The design correctly identifies the
restored surface: `interfaces/snapshot` (SDK), `interfaces/grpcserver/grpcadmin`
(orchestration), `platform/lifecycle/operations` (ledger), `cmd/sso-server`
(wiring), `proto/admin/v1/snapshots.proto` (wire), `docs/*` (contracts).

**Every design evidence claim was re-verified against code at this revision;
all 20 spot-checked claims hold (verified list in §1.2).** This review's job is
the testability gap between the design's acceptance mapping and what the
current suite can actually assert.

---

## 1. Test inventory and commands actually run for this revision

### 1.1 Command results

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | Full module compiles at this revision |
| `go test -run 'TestMaintainability_\|TestArchitecture_' .` | ok (0.132s) | Gate baseline green |
| `go test ./interfaces/snapshot/... ./interfaces/grpcserver/grpcadmin/... -race -count=1` | ok (8 packages) | SDK + admin service green under race |
| `go test ./interfaces/snapshot -cover -count=1` | **80.8%** statements | Function-level table below |
| `go test ./interfaces/grpcserver/grpcadmin -cover -count=1` | **75.2%** statements | Function-level table below |
| `go test ./test/ -count=1` | ok (20.3s) | Full integration package green |
| `go test ./test/ -run TestAdminGRPC_SnapshotExport -v` | PASS | The only snapshot E2E; Export+List only |
| `go test ./test/dr/ -v -count=1` | 4/4 PASS | DR drills; all use `ModeMerge` into empty targets |
| `go test ./platform/lifecycle/operations/ -count=1` | ok | `AddCompensation` already unit-tested |
| `make ci` | **FAILED at `fmt` gate** | 14 pre-existing unformatted files, none in snapshot/grpcadmin/operations — pre-existing drift, reported separately (§5.1). Not caused by this docs-only revision |

**Function-level coverage (measured this revision, `go tool cover -func=`):**

Snapshot package, restore-relevant functions:

| Function | Coverage | Comment |
|---|---|---|
| `restorer.go Restore` / `prepareRestore` / `restorePlan` / `advanceBootstrap` | 100% | |
| `restorePairwise` / `prunePairwise` | 71.4% / 83.3% | Merge paths covered; replace-prune partial |
| `restoreTenants` / `pruneTenants` | 66.7% / **0.0%** | Replace-prune never exercised |
| `restoreTenantDomains` / `pruneTenantDomains` | 66.7% / **0.0%** | Replace-prune never exercised |
| `restoreConnections` / `pruneConnections` | 66.7% / **0.0%** | Replace-prune never exercised; capability guard untested |
| `restoreClients` / `pruneClients` / `upsertClient` / `preserveClientSecrets` | 76.9% / 85.7% / 83.3% / 69.2% | |
| `restorer_assignments.go` (all) | 80–100% | |
| `restorer_menus.go` (all) | 83–100% | |
| `retention.go PruneOldest` | see §2 | Envelope-agnostic today; all fixtures use dummy blobs |
| `snapshotter.go Export` / `effectiveRedactor` / `Validate` / `newSnapshotID` | 70% / 100% / 100% / 80% | |
| `pipeline.go Save` / `Load` / `PeekEnvelope` | 83.3% / 92.3% / 100% | |

grpcadmin package:

| Function | Coverage | Comment |
|---|---|---|
| `restoreTracked` | 73.1% | Success + load-failure + confirm-failure paths; no mid-apply fault |
| `failRestoreOperation` | 100% | |
| `mapSnapshotError` | 60% | **`ErrUnsupportedRestore` branch never triggered** — falls to default `Internal` today; D2's fix is untestable until a capability-gap test exists |
| `reportToProto` | 83.3% | New D2/D3 fields untested |
| `recordAdminMeta` | 85.7% | New meta keys untested |
| `operationToProto` | 83.3% | `compensations` field 7 already projected (Verified, `admin_paginate.go:289`) |

### 1.2 Design evidence claims re-verified (all Verified at this revision)

1. `operations.AddCompensation(ctx, store, op, name, state, msg)` exists (`platform/lifecycle/operations/operations.go:153`); `AdminOperation.compensations = 7` (`proto/admin/v1/operations.proto:33`); projected by `operationToProto` (`admin_paginate.go:289`). D3 needs no operations API/proto change.
2. `mapSnapshotError` maps `ErrUnsupportedRestore` to `codes.Internal` via the default branch (`admin_snapshots.go:319-331`).
3. `PruneOldest` is pipeline-free: only `Storage.List` + `Storage.Delete` (`retention.go`). `Kind` lives in the encrypted body; header mirror is required for O(victims) skip.
4. `replaceMenus` wipes via `SetMenus` replace semantics; no `pruneMenus` exists (`restorer_menus.go`).
5. No committed test pins the wipe-first partial-failure shape: all replace tests assert full-success counts or dry-run no-mutation (`restore_modes_test.go`, `snapshot_test.go:252/275`). D2's changed failure shape breaks nothing today.
6. No node-identity config in `cmd/sso-server`; `ExportOptions.SourceNodeID` comes only from the gRPC request (`admin_snapshots.go:60`).
7. `restorer.go` = 474 lines; `SnapshotAdminService` holds pipeline+storage+snapshotter+restorer+recorder+operations (`admin_snapshots.go:16-56`); `Restore` is the only RPC that never touches `snapshotter`.
8. `effectiveRedactor(perCall, def)` — per-call override wins (`snapshotter.go:372-374`, 100% covered). Explicit no-op `RedactorFunc` beats `DefaultExportRedactor`; `cmd` wires `SnapshotRedactSecrets()` only when `snapshot.redact_secrets` (`build_stores.go:150`).
9. `newSnapshotID` emits `snap_<RFC3339-dashes>_<rand>` (lexicographically sortable); `PruneOldest` already filters `snap_` prefix.
10. `RestoreInvalidator` wired as the `sso.Server` (`build_stores.go:150` `Invalidator: srv`); invalidation fires once per successful non-dry-run `Restorer.Restore` (`restorer.go:126-128`) — D3's "probe count == 2" mechanism (inner re-apply success + orchestrator) is structurally correct.
11. `builtin.ApplyRestore` defaults `ModeOverwrite` (`platform/bootstrap/builtin/builtin.go:90`); `build_network_snapshot.go:165` uses `ModeOverwrite`. Both are non-replace, unaffected by D1 default.
12. Proto numbering: `RestoreSnapshotRequest` 1–6, `RestoreSnapshotResponse` 1–3, `RestoreReport` 1–5, `SnapshotMeta` 1–9 — fields 7/8, 4, 6–8, 10 are all free; additive plan is wire-compatible. `wrappers.proto` import is not yet present (needed for `BoolValue`).
13. Client `Secret`/`RegistrationAccessToken` are `json:"-"` (`restorer_clients.go:105` comment); user `password_hash` IS serialized (`snapshotter.go:407`). D1/D3 secret-at-rest and rollback-preserve claims consistent.
14. `Snapshot.Validate()` checks schema version + non-empty namespace only (`snapshotter.go:463`); a safety snapshot round-trips and satisfies `Confirm` handshake.
15. `SealedEnvelope` version guard rejects unknown `EnvelopeVersion` (`pipeline.go:139`) — additive `kind` header with `omitempty` is safe; old readers ignore it.
16. `recordAdminMeta` helper exists (`admin_paginate.go:214`); audit events `EventSnapshotRestored` etc. already wired.
17. `pruneConnections` asserts `connections.Lister` (`restorer.go:403`); `prunePairwise` asserts `PairwiseSubjectLister` + `PairwiseSubjectDeleter` (`restorer.go:228`). All other prunes use base-interface methods — D2's preflight scope (two capability-guarded prunes) is accurate.
18. `failRestoreOperation` already calls `FinishStep` + `Finish` (`admin_snapshots.go:243-254`) — D3's double-finish hazard is real and the refactor requirement is justified.
19. `Restore` returns first-error abort with partial counts (`restorer.go:111-124`); `Report` has no `Committed` today — D2's flag is a new semantic, and existing consumers (`builtin.ApplyRestore`, DR drills) only read counts, so adding fields is non-breaking.
20. Fixture reality: `newFixture`/`newBlank` (`snapshot_test.go:21`, `restore_modes_test.go:14`) and grpcadmin `newSnapshotFixture` wire **clients/users/permissions/netpolicy only** — no tenants, connections, or pairwise stores anywhere in the suite. This explains the 0.0% prune numbers and is the root of Finding 1.

---

## 2. Requirement-to-test matrix

Status key: **Covered** (assertion exists and passes at this revision) ·
**Partial** (mechanism covered, acceptance-specific assertion missing) ·
**Missing** (no test exists) · **N/A** (no test possible in-tree).

### D1 — pre-restore safety snapshot

| # | Spec/design check | Status | Evidence / required test |
|---|---|---|---|
| 1a | Capture round-trip equality (category-equal decode) | Missing | New test: `Export`(no-op redactor) → `Save` → `Load` → category counts + field equality vs live stores (order-insensitive compare per category) |
| 1b | Header/body kind consistency (`PeekEnvelope(kind) == snap.Kind`) | Missing | Round-trip test through `Pipeline.Save`; also guards the "two writers drift" risk (design §D1 what-could-break #6) |
| 1c | `PruneOldest(keep=0)` skips safety; `Delete` RPC removes it | Partial | `TestPruneOldest_KeepZeroDeletesEverything` covers keep=0 on dummy blobs only; safety-skip needs real envelopes (Finding 6). `Delete` RPC mechanics covered by `TestSnapshotAdminService_FullCycle` |
| 1d | Recursion guard (safety-source restore produces no second artifact) | Missing | Restore a kind=safety snapshot with replace+default capture → assert storage has exactly 1 envelope after |
| 1e | Nil snapshotter + capture intended → `FailedPrecondition`, zero writes | Partial | `TestSnapshotAdminService_OptionalDepsUnimplemented` covers nil *restorer* only; nil *snapshotter* + replace restore is a new path. Assert `operations.List` is empty (zero writes incl. ledger) |
| 1f | Explicit opt-out runs with `auto_safety=false` audit meta | Missing | Audit-sink query test asserting the meta key on `EventSnapshotRestored` |
| 1g | No-op-redactor override pin (restorable even with `DefaultExportRedactor` wired) | Partial | `effectiveRedactor` precedence is covered (100%); the *capture path passes the override explicitly* is a new assertion (design D1 what-could-break #2) |
| 1h | Dry-run never captures (zero-write invariant) | Missing | Replace + dry-run + default capture → storage count unchanged |
| 1i | Capture failure (backend List error) → operation fails, zero target writes | Missing | Error-fake store (house pattern: `errStorage`, `error_paths_test.go`) wired into a Snapshotter backend |

### D2 — stage-then-prune

| # | Spec/design check | Status | Evidence / required test |
|---|---|---|---|
| 2a | Phase A mid-failure: error, `Committed==false`, all `Deleted==0`, stores equal pre-restore | Missing | Fault-injected `AssignRoles` (per design acceptance). Needs a failing wrapper around `permissions.Provider` (Finding 2) |
| 2b | Phase B mid-failure: inserts + first delete applied; same-snapshot retry converges byte-equal | Missing | Fault-injected `ClientStore.Delete`; retry then assert terminal-state equality with a once-successful control run |
| 2c | Capability preflight zero-write (`ErrUnsupportedRestore` before any write) | Missing | Wrapper connection store without `Lister`; wrapper pairwise store without `Deleter` (both memory impls expose the capabilities, so thin wrappers needed) |
| 2d | `mapSnapshotError`: `ErrUnsupportedRestore` → `FailedPrecondition` | Missing | gRPC-level trigger of 2c; assert `codes.FailedPrecondition` + failed operation record (today `mapSnapshotError` 60%, branch untriggerable) |
| 2e | Success-path count regression (`TestRestore_Replace_*` unchanged) | Covered | 8 replace tests pass today; must pass unchanged after the split (design §D2 what-could-break #1) |
| 2f | Phase B category order pinned (load-bearing for FK-strict backends) | Missing | Recording wrapper logging call order: clients → … → netpolicy within Phase B |
| 2g | Prune purity (keep-set derived only from `List()` + snapshot data) | Missing | Assert prune wrappers receive no insert results — call-order/arg recording test |
| 2h | Dry-run replace counts byte-identical to today | Covered | `TestRestore_Replace_DryRun_NoMutation` (counts + no mutation); rerun after split |
| 2i | `Committed==false` on every failure path; counts meaningful only when committed | Missing | Assert `Committed` on 2a/2b failure reports and on dry-run (`false` by design) |
| 2j | Bootstrap-advance failure after successful Phase B leaves `Committed==true` | Missing | `errTracker`-style MarkApplied fault (pattern exists, `error_paths_test.go`) |

### D3 — rollback

| # | Spec/design check | Status | Evidence / required test |
|---|---|---|---|
| 3a | Rollback success: stores equal pre-restore; `Compensations[0].state==succeeded`; `RolledBack==true`; `Committed==false`; error text contains "rolled back to safety snapshot" | Missing | Full orchestration test at grpcadmin level with fault-injected restore + wired capture |
| 3b | Invalidator probe count == 2 (inner re-apply success + orchestrator) | Missing | Counting `RestoreInvalidator` wrapper (house pattern: `errTracker`); assert exactly 2 calls on rollback, 1 on plain success |
| 3c | `RollbackOnError=true, AutoSafetySnapshot=false` → validation error, zero writes | Missing | SDK-level `ErrRollbackWithoutSafety` + gRPC-level `FailedPrecondition`; assert no operation created |
| 3d | Safety snapshot deleted before rollback → `StepFailed` + "rollback failed; target state unknown", no success claim | Missing | Delete the safety envelope between capture and apply-failure (two RPCs or injected storage) |
| 3e | `RollbackOnError=false` → today's partial-apply + error + `Committed==false` | Missing | Regression shape test; also asserts partial report in `ResultJSON` (design addition) |
| 3f | Rollback preserves live client secrets | Partial | `TestRestore_Overwrite_PreservesLiveClientSecret` proves the mechanism for overwrite; the rollback-specific re-apply path (replace + preserve backfill) needs its own pin |
| 3g | `Exclude` carried into rollback re-apply (minimality) | Missing | Excluded categories untouched by rollback (neither pruned nor re-inserted) |
| 3h | Safety-source + `rollback_on_error` → `FailedPrecondition` | Missing | Validation test |
| 3i | Operation terminated exactly once (double-finish refactor) | Missing | Assert operation record: state `failed`, single `finish`, `rollback_safety_snapshot` compensation step present |
| 3j | REST gateway body-drop caveat documented + verified | Partial | No REST snapshot test exists at all; gateway error-path behavior for error-with-response is untested (see Finding 3) |

### Cross-cutting

| # | Check | Status | Evidence |
|---|---|---|---|
| 4a | Proto additive fields (7/8/4/6-8/10) regenerate cleanly; `proto-lint` | Covered/Partial | `make ci` includes `proto-lint` (not reached at this revision — fmt gate fails first, §5.1) |
| 4b | OpenAPI + error-codes + dr-framework updates land in same change | Missing | AGENTS.md §5.6 contract rule; no test, but doc diff must be in the PR |
| 4c | E2E restore coverage (bufconn, full wiring) | Partial | Only `TestAdminGRPC_SnapshotExport` (Export+List). **No restore E2E exists anywhere** (Finding 3) |
| 4d | Retention loop wiring E2E (`RunSnapshotRetention` + `pruneSnapshotSafe`) | Missing | cmd wiring untested; D1 changes `PruneOldest` semantics under a running loop |
| 4e | Race: concurrent restore vs retention / concurrent admin writes | Missing | No concurrent restore test exists; D2's Phase-B-window race is documented, not tested (accepted scope, §4) |

---

## 3. Findings (severity-sorted)

### F1 — High: D2 restructures functions with zero test coverage, including the capability guards it adds

**Evidence (measured):** `pruneTenants` 0.0%, `pruneTenantDomains` 0.0%,
`pruneConnections` 0.0% (`go tool cover`, §1.1). No test wires
`tenant.Store`/`connections.Store`/`PairwiseSubjectStore` into any restorer
fixture (`snapshot_test.go:21`, `restore_modes_test.go:14`,
`admin_snapshots_test.go:62`). D2 moves exactly these functions into Phase B
and adds a preflight assertion on `connections.Lister` (`restorer.go:403`).

**Regression risk:** the split is a pure refactor of these prunes, but the
"Phase B ordering is load-bearing" invariant and the new preflight are
unenforceable without coverage. A wrong capability assertion silently turns
replace restores of connections/pairwise into `FailedPrecondition` for every
production backend that lacks `Lister` — and today's suite cannot detect it.

**Test to add (with the change, per design §D2 what-could-break #1):**
`interfaces/snapshot/restorer_stage_test.go`:

```go
// 1. Replace-prune correctness for tenants/tenant_domains/connections/pairwise.
//    Fixture: tenant/memory.New(), connections/memory.NewMemoryStore(),
//    security.NewMemoryPairwiseSubjectStore() + existing blank fixture.
//    Seed orphans, run ModeReplace, assert Deleted counts and orphan absence.
// 2. Preflight: connections store WITHOUT Lister (thin wrapper embedding
//    *connections.memory.MemoryStore but not exposing List), pairwise store
//    without Deleter -> Restore returns ErrUnsupportedRestore before any write;
//    assert destination stores byte-identical to pre-restore.
// 3. gRPC: same capability gap through Restore RPC -> codes.FailedPrecondition
//    (pins the mapSnapshotError fix, F4), operation record state=failed.
```

**Acceptance assertion:** replace restore with orphan tenants/domains/
connections/pairwise reports `Deleted==N` and orphans are gone; a
`Lister`-less connections backend returns `errors.Is(err,
snapshot.ErrUnsupportedRestore)` with zero store mutations.

### F2 — High: no fault-injection seam exists for the Restorer; D2/D3 acceptance tests are unbuildable without new fixtures

**Evidence (Verified):** the only boundary fakes are `errStorage` and
`errTracker` (`error_paths_test.go`). `Restorer` consumes concrete interfaces
(`sso.ClientStore`, `permissions.Provider`, `tenant.Store`, `connections.Store`,
`netpolicy.Store`, `security.PairwiseSubjectStore`) and every memory
implementation never errors. The design's acceptance tests require injecting
`AssignRoles` failure (Phase A) and `ClientStore.Delete` failure (Phase B) —
**no such capability exists in the tree today, and the design does not
specify the wrappers.**

**Impact:** the two most important new assertions in the whole design — the
Phase A "zero deletions" guarantee and Phase B "retry converges" guarantee —
depend on fixtures the design leaves implicit. Without them, D2's failure-mode
table is untestable prose.

**Test to add (fixture, with the change):** `interfaces/snapshot/failing_stores_test.go`
following the `errStorage` house pattern:

```go
// failClients wraps defaultimpl.MemoryClientStore; Delete fails after the
// first N successful calls (failAfter). Same shape for failPerms (AssignRoles)
// and failNetPolicy. Each records the ordered call sequence for the
// Phase-B-order pin (F1 test 2g).
type failClients struct {
    *defaultimpl.MemoryClientStore
    failDeleteAfter int
    deleteCalls     int
}
```

**Acceptance assertion:** `TestRestore_Replace_PhaseAFailure`: injected
`AssignRoles` error → `err != nil`, `rep.Committed == false`, every
`Items[cat].Deleted == 0`, and all stores deep-equal their pre-restore state.
`TestRestore_Replace_PhaseBConverges`: injected `ClientStore.Delete` failure
after 1 delete → first restore fails with partial deletes; same-snapshot retry
(with no fault) yields a terminal state byte-equal to a control run that never
failed.

### F3 — High: zero restore coverage at the E2E layer; D1/D3 change the RPC surface and error-with-response semantics there

**Evidence (Verified):** `test/admin_grpc_snapshots_test.go` contains exactly
one test, `TestAdminGRPC_SnapshotExport` (Export+List). The DR drills
(`test/dr/`) call `Restorer.Restore` with `ModeMerge` into empty targets —
they never touch `restoreTracked`, operation steps, or the wire report. There
is no REST-gateway test for snapshots at all (the D3 "gateway drops the body
on error" caveat is therefore untested), and no test asserts the
`snapshot.retention.enabled` loop wiring that D1 changes semantics under.

**Regression risk:** D1 inserts a new step between `load_snapshot` and
`apply_resources` and D3 changes the error path to return an error *with* a
response — the two most failure-prone orchestration changes land where the
suite has the least observation.

**Test to add (with the change):** extend `test/admin_grpc_snapshots_test.go`:

```go
// TestAdminGRPC_RestoreReplaceWithSafetySnapshot: Export from a seeded
// source -> Restore(replace, confirm) -> assert response safety_snapshot_id
// non-empty, operation succeeded with 3 steps (load/capture/apply), List
// shows 2 envelopes (source + safety), audit event meta carries
// safety_snapshot_id + auto_safety. Then Restore(replace, confirm) of a
// rollback request path via the same client.
// TestAdminGRPC_RestoreGatewayBodyDrop: drive the REST gateway handler
// (RegisterSnapshotAdminServiceHandlerServer, build_http.go:463) with a
// failing restore; assert the HTTP error carries no body while
// GetOperation(operation_id) exposes compensations + ResultJSON.
```

**Acceptance assertion:** replace restore through the real service returns the
safety ID and leaves exactly 2 envelopes; a rollback-triggered failure returns
a non-OK gRPC status while `GetOperation` shows `rolled_back=true`
compensation and the REST mirror drops the body but the operation ledger
carries the outcome.

### F4 — Medium: `mapSnapshotError`'s `ErrUnsupportedRestore → Internal` mapping is untested; D2's fix needs a triggering test

**Evidence (measured):** `mapSnapshotError` 60%; no test can reach the
`ErrUnsupportedRestore` case today because no fixture produces it (F1).
The design fixes the mapping to `FailedPrecondition` — without a trigger test
the fix ships unverified and the old `Internal` behavior can silently return.

**Test to add:** see F1 test 3 (gRPC capability-gap restore). Acceptance:
`status.Code(err) == codes.FailedPrecondition` and the message contains the
failed-category prefix, not "Internal".

### F5 — Medium: D1's fail-closed check runs before the recursion guard is resolvable — safety-source restores on snapshotter-less nodes spuriously fail

**Evidence (Verified, design §D1 steps 1–2):** step 1 resolves
`captureIntended` and fails closed when `snapshotter == nil`; step 2 (after
`load_snapshot`) applies the recursion guard `snap.Kind != "safety"`. A node
with pipeline+storage+restorer but no snapshotter (e.g., a DR receiver) that
restores a safety snapshot — where capture would be a no-op by the recursion
guard — is rejected with `FailedPrecondition` even though no capture was ever
needed. The same pre-load kind resolution is needed for D3's
`safety-source + rollback_on_error` validation.

**Recommendation (Proposed):** resolve `source.Kind` before `operations.Start`
via `PeekEnvelope` (the D1 header mirror makes this zero-decryption and
zero-write), then run the nil-snapshotter fail-closed check on *effective*
capture intent. This also keeps "validation before `operations.Start` — zero
writes" for both D1 and D3 validations.

**Test to add:** restore a safety-kind snapshot on a service with nil
snapshotter → succeeds, no capture, storage unchanged (vs. the design-as-
written which fails). If the design team prefers the stricter reading
(capture intended = replace+non-dry-run, guard or no guard), the doc must
state it and the test pins the chosen semantics.

### F6 — Medium: D1's `PruneOldest` Get+PeekEnvelope step has undefined Get-error semantics; existing tests pin behavior that may flip

**Evidence (Verified):** `TestPruneOldest_DeleteErrorContinues` uses
`countingDeleteStorage` whose `Get` returns `ErrSnapshotNotFound`
(`error_paths_test.go:103-106`). With D1's per-victim `Get`+`PeekEnvelope`,
this storage's victims are undecodable — the design says "Undecodable/
unknown-kind envelopes remain deletable", but a **Get I/O error** is neither
an undecodable envelope nor a kind decision. If Get-error → skip (treat as
safety-unknown), the existing test flips to `deleted == 0` and breaks the
partial-success contract; if Get-error → delete-through, retention stays
fail-open on I/O faults, matching today.

**Recommendation (Proposed):** delete-through on Get/peek errors (retention is
a fail-open cleanup path; skipping on I/O fault turns a transient error into
permanent retention of the newest-keep victim and masks progress — see F7).
Pin with: `TestPruneOldest_GetErrorStillDeletes` (Get fails for victim → still
deleted, error NOT reported) and keep `TestPruneOldest_DeleteErrorContinues`
semantics (Delete error → partial list + first error).

### F7 — Medium: safety artifacts can mask ordinary retention progress

**Evidence (Proposed, by construction):** with `keep=1` and one safety + one
ordinary snapshot, the victim set is `[oldest]`; if the oldest is the safety
artifact it is skipped forever and the ordinary snapshot (inside the keep
window) is never pruned. Retention makes no progress until the safety
artifact is explicitly deleted. The design's "delete after rollback window"
runbook mitigates but does not prevent silent drift on busy nodes.

**Test to add:** `TestPruneOldest_SafetyArtifactDoesNotMaskProgress` — with
mixed kinds, assert the ordinary victim IS deleted while the safety artifact
survives (e.g., keep=1, [safety(old), ordinary(new)] → ordinary survives
because it is in the keep window — this case is inherent; the test should pin
the documented behavior and the doc comment must state the masking caveat).
Runbook language belongs in `docs/dr-framework.md` §4.

### F8 — Medium: rollback re-apply is always `ModeReplace`, even when the failed restore was merge/overwrite

**Evidence (Verified, design §D3 step 2):** `rollback_on_error=true` is valid
with any mode iff `auto_safety_snapshot=true` explicitly (merge/overwrite
default to no capture). The rollback re-apply is hardcoded `ModeReplace` +
`Confirm=safetySnap.SnapshotID`. So a failed *merge* restore is undone by a
full *replace* of the node state — safe in a maintenance window but a
semantic leap the design does not call out, and it interacts with concurrent
writes (design D3 what-could-break #2) more aggressively than a merge failure
warrants.

**Recommendation (Proposed):** pin the chosen semantics with a test —
`TestRestore_MergeFailureRollbackConvergesToCapturedState` (merge restore with
fault → rollback → stores deep-equal captured state) — and add one runbook
sentence: rollback always re-applies the captured state as a replace, i.e.
"return to captured state", regardless of the original mode.

### F9 — Low: `Committed==true` after bootstrap-advance failure is a subtle semantic that needs a pin

**Evidence (Verified, design §D2):** data is applied; only the tracker failed.
Consumers keying on `Committed` would treat the restore as fully successful.
The design states it; no test asserts it. **Test to add:** `errTracker`
`MarkApplied` fault + replace success → `rep.Committed == true`,
`rep.Bootstrap.Reason` set, error returned.

### F10 — Low: pre-existing `make ci` failure at the fmt gate (not caused by this revision)

**Evidence (measured):** `make ci` fails at `fmt` on 14 files — federation,
adapters, branding, auditspi, rebac, caep, middleware, region tests — none in
`interfaces/snapshot`, `interfaces/grpcserver/grpcadmin`, or
`platform/lifecycle/operations`. Reported per AGENTS.md §5.7 as pre-existing;
the D1/D2/D3 change must land with its own files formatted so this gate is
not widened.

### F11 — Info: rolling-upgrade retention hazard is operationally untestable in-tree

The old-binary-deletes-safety-artifacts risk (design D1 what-could-break #1)
cannot be covered by a unit test. The only guard is the runbook statement;
make it an explicit PR checklist item ("runbook updated: rollback-window
operations run on the new version") and note it in the release notes, since
retention runs on a timer and will fire in mixed-version fleets.

### F12 — Info: D3's error-with-response is a gRPC protocol oddity worth a contract test

Returning a non-nil response with a non-OK status is legal in gRPC but
surprising; the design already documents the gateway body-drop. Add a
bufconn-level assertion (F3) that the rollback-failure response still carries
the report on the gRPC path — this pins the fail-closed "RPC still fails"
requirement (design D3 step 2) against a future refactor that might return
`(nil, err)` and lose `RolledBack`.

---

## 4. Prioritized scenario list

Priority P0 = must land in the change (design acceptance), P1 = same change or
immediately after, P2 = follow-up.

| Pri | Path | Scenario | Key assertion |
|---|---|---|---|
| P0 | Happy | Replace restore captures safety snapshot; response echoes `safety_snapshot_id`; audit meta `{safety_snapshot_id, auto_safety}` | 1 envelope added, operation steps = load/capture/apply |
| P0 | Happy | Dry-run replace with default capture | zero writes, storage unchanged, `Committed==false` |
| P0 | Error | Phase A fault (AssignRoles) | `Committed==false`, all `Deleted==0`, stores == pre-restore |
| P0 | Error | Phase B fault (ClientStore.Delete) + retry | converges byte-equal to control terminal state |
| P0 | Error | Capability gap (no connections `Lister`, no pairwise `Deleter`) | `ErrUnsupportedRestore`, `FailedPrecondition` on gRPC, zero writes |
| P0 | Recovery | Rollback success | stores == captured state, compensation `succeeded`, invalidator count 2, `RolledBack==true`, error text "rolled back to safety snapshot" |
| P0 | Error | Rollback validation (no net / safety source) | `FailedPrecondition`/`ErrRollbackWithoutSafety`, zero writes incl. ledger |
| P0 | Recovery | Rollback load failure (safety deleted) | compensation `StepFailed`, "target state unknown", no success claim |
| P1 | Boundary | `PruneOldest(keep=0)` with safety artifact | safety survives, ordinary deleted |
| P1 | Boundary | `PruneOldest(keep=1)` mixed kinds | masking behavior pinned + doc comment |
| P1 | Boundary | Opt-out tri-state `auto_safety_snapshot=false` | no capture, audit `auto_safety=false` |
| P1 | Boundary | Safety-source restore (recursion guard) | no second artifact, succeeds on snapshotter-less node (see F5) |
| P1 | Boundary | `Exclude` carried into rollback | excluded categories untouched |
| P1 | Error | Capture failure (backend List error) | operation fails at capture step, zero target writes |
| P1 | Error | Bootstrap-advance failure post-Phase-B | `Committed==true`, error returned |
| P1 | Regression | Merge/overwrite + SDK-direct callers (`builtin.ApplyRestore`, network snapshot) | byte-identical behavior; new report fields default correctly |
| P1 | Regression | Existing `TestRestore_Replace_*` counts | unchanged after split |
| P1 | Race | Invalidator firing: success=1, rollback=2 | counting wrapper |
| P2 | Race | Concurrent admin write between phases (documented window) | no assertion; runbook note only |
| P2 | Race | Restore vs retention sweep concurrently | both complete without partial envelope corruption (envelope is opaque to retention) |
| P2 | Recovery | Manual operator recovery from safety snapshot | replace restore of safety artifact converges (covered by recursion-guard test) |
| P2 | Boundary | Merge/overwrite failure + explicit auto-safety + rollback | rollback converges to captured state (F8 semantics pin) |

---

## 5. CI gaps, flake risks, fixtures needed, exit criteria

### 5.1 CI / manual-suite gaps

1. **`make ci` is red at the fmt gate at this revision** (14 pre-existing
   unformatted files, §1.1). Pre-existing, unrelated to this design; must be
   fixed or quarantined before any implementation PR can pass `make ci`.
2. **No restore E2E** (F3): `test/` covers Export+List only. The design's
   handoff gate `go test ./test/ -run TestE2E -v` exercises no restore path.
3. **No REST-gateway snapshot test**: the D3 body-drop caveat and the
   `auto_safety_snapshot`/`rollback_on_error` BoolValue JSON encoding are
   untested on the HTTP surface (`build_http.go:463` handler).
4. **Retention loop wiring untested**: `RunSnapshotRetention`/
   `pruneSnapshotSafe` (`build_background.go:177-199`) has no test; D1 changes
   the semantics the loop relies on.
5. **No concurrency test for restore**; D2's Phase-B window and D1's
   non-atomic capture are documented caveats. Given the maintenance-window
   contract, P2 priority is appropriate — but at least one
   restore-vs-retention race run (`-race -count=10`) should exist if restore
   and retention can share a node (they do: `RunSnapshotRetention` runs in
   the same binary as the admin service).

### 5.2 Flake risks

- **Time-dependent IDs**: safety snapshots use `newSnapshotID`
  (`snap_<timestamp>`). Tests comparing storage listings must use
  prefix/set assertions, not ordering (the existing lexical test
  `TestPruneOldest_LexicalOrderingPreservesChronology` shows the pattern for
  fixed names; capture tests must not assume ordering between source and
  safety snapshots taken milliseconds apart — same-second IDs collide
  lexically with the random suffix, which is fine for set-compare).
- **Parallel tests sharing stores**: grpcadmin fixtures are per-test
  (Verified, `newSnapshotFixture`); keep the new fault-injection wrappers
  per-test too — a shared `failAfter` counter across `t.Parallel()` tests
  would be a flake source.
- **Invalidator counting**: the counter wrapper must be per-test; D3 asserts
  exactly 2 — a shared `sso.Server` invalidator in unit tests would overcount
  across parallel tests.
- **Audit sink capacity**: `audit.NewMemorySink(50)` in existing tests; the
  new rollback paths add no events (design: no new event types) but do add
  meta keys — assert meta by key lookup, not by sink ordering.

### 5.3 Fixtures needed (all follow existing house patterns)

1. Tenants/connections/pairwise-wired restorer fixture — `tenant/memory.New()`
   (Verified exists), `connections/memory.NewMemoryStore()` (Verified,
   implements `Lister`), `security.NewMemoryPairwiseSubjectStore()` (Verified,
   implements both capability interfaces).
2. Failing wrappers: `failClients` (Delete), `failPerms` (AssignRoles),
   `failNetPolicy` (Apply/Delete) — pattern: `errStorage`/`errTracker`
   (`error_paths_test.go`), delegating to the memory impl with a
   `failAfterN` counter + ordered call log (the call log doubles as the
   Phase-B-order and prune-purity assertion vehicle).
3. Capability-hiding wrappers: connections store embedding the memory store
   without `List`; pairwise store without `DeletePairwiseSubject` — Go
   interface narrowing by composition (no mocking framework, per house style).
4. Counting `RestoreInvalidator` (D3 probe-count == 2).
5. Envelope-aware retention storage: `inline.Storage` seeded via
   `Pipeline.Save` with real envelopes (kind set/absent), replacing the
   dummy-blob seeding in `retention_test.go` for the new tests only.

### 5.4 Exit criteria for the implementation

1. All P0 scenarios in §4 have passing tests **in the same change** (design
   §D2 what-could-break #1 and the design's own verification plan require it).
2. Existing `TestRestore_Replace_*` count assertions pass unchanged (2e).
3. `go test ./interfaces/snapshot/... ./interfaces/grpcserver/grpcadmin/... -race`
   green; `-count=10` on the new rollback tests (race-sensitive paths).
4. `go test ./test/` green with the new restore E2E; `make ci` green on a
   clean base (pre-existing fmt drift fixed separately).
5. Contract docs updated in the same PR: `docs/openapi.yaml`,
   `docs/error-codes.md` (`ErrRollbackWithoutSafety`, `ErrUnsupportedRestore`
   reclassification), `docs/dr-framework.md` §4/§6 (rollback window, retention
   exemption, masking caveat, quiesce note, retry-churn warning), proto
   regeneration with `wrappers.proto` import.
6. The two design open items this review surfaced are resolved in the doc or
   code: F5 (pre-load kind resolution vs. fail-closed ordering) and F6
   (PruneOldest Get-error semantics).
