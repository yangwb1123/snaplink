# Distributed-Systems Engineering Review: `interfaces/snapshot` restore safety

Independent review counterpart to
[`interfaces-snapshot-restore-safety-design.md`](interfaces-snapshot-restore-safety-design.md).
Scope: the consistency, ordering, atomicity, idempotency, ownership,
conflict-resolution, and recovery guarantees of the three decisions — D1
(pre-restore safety snapshot), D2 (stage-then-prune atomicity), D3 (rollback
+ committed/rolled-back observability) — traced through the restore
orchestration, the operations ledger, retention, the invalidation bus, and
the underlying stores as they exist in code today. Assumes replicas,
retries, partial failure, partitions, failover, and clock anomalies.

## 0. Method and verification

Checks that actually ran for this review revision:

- Full reads: `interfaces/snapshot/restorer.go` (474 lines),
  `admin_snapshots.go`, `retention.go`, `snapshotter.go`, `pipeline.go`,
  `snapshot.go`, `restorer_{clients,users,roles,assignments,menus,netpolicy,
  pairwise(restorer.go)}.go`, `platform/lifecycle/operations/{operations,
  file_store}.go`, `interfaces/grpcserver/grpcadmin/admin_paginate.go`,
  `cmd/sso-server/build_stores.go`, `build_app_cluster.go`,
  `serverbuildplatform/build_releases.go`, `serverbuildstore/build_network_
  snapshot.go`, `build_background.go`, `platform/lifecycle/dr/replicator.go`,
  `interfaces/sso/server_invalidation.go`, `server_discovery_cache.go`,
  `proto/admin/v1/{snapshots,operations}.proto`, `docs/dr-framework.md`.
- `wc -l`: `restorer.go` = 474 (matches the design's budget claim).
- Test inventory: `restore_modes_test.go` (success-path counts + dry-run
  no-mutation only — no partial-failure ordering pinned, matching the
  design's claim), `error_paths_test.go`, `retention_test.go`,
  `test/admin_grpc_snapshots_test.go` (Export only; no gRPC-level Restore
  test), `test/dr/dr_integrity_test.go` (restore + signing keys / audit
  chain), `test/dr/harness_test.go` (ModeMerge restore).
- `grep` scans: no boot-time reconciliation of `StateRunning` operations;
  `AddCompensation` exists; `recordAdminMeta` at `admin_paginate.go:214`;
  `operationFailureError` at `admin_paginate.go:318`.

No `go build`/`go test`/`make ci` ran for this review (the design is not
implemented). All behavior labels below are **Verified** (exists in code
today), **Proposed** (design contract, not yet code), **Partial**
(verified in one place, extrapolated elsewhere), or **Missing**.

Design claims re-verified against source before inclusion (all hold):
`operations.AddCompensation(ctx, store, op, name, state, msg)` exists
(`operations.go:151`); `AdminOperation.compensations` is proto field 7 and
projected by `operationToProto` (`admin_paginate.go:289`);
`mapSnapshotError` routes `ErrUnsupportedRestore` to the `Internal` default
(`admin_snapshots.go:318`); `PruneOldest` is pipeline-free
(`retention.go:29-70`); `replaceMenus` has no separate prune
(`restorer_menus.go:41-58`); `effectiveRedactor` per-call override wins
(`snapshotter.go:334`); `newSnapshotID` uses the `snap_` + wall-clock
timestamp prefix (`snapshotter.go:461`); `InvalidateRestoredControlPlane`
is the `sso.Server` and is fail-open on publish
(`build_stores.go:137-149`, `server_invalidation.go:47-59`); the admin
Restorer wires **no Tracker** (`build_stores.go` — `advance_bootstrap` is
therefore a no-op on the admin surface); `builtin.ApplyRestore` defaults to
ModeOverwrite (`builtin.go:88-96`); `SnapshotRestorerAdapter.RestoreByID`
uses ModeOverwrite with an explicit no-bootstrap-advance comment
(`build_network_snapshot.go:160-175`).

## 1. State map

| State | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Control-plane resources (clients, users, roles, assignments, menus, tenants, domains, connections, pairwise, netpolicy) | Domain packages via `Snapshotter`/`Restorer` | Backend-selected per config: memory / SQLite / Postgres / Redis (`docs/dr-framework.md` §3); restores write these **raw**, bypassing admin-RPC invalidate+publish | Backend-native (SQLite WAL, Postgres WAL, Redis RDB/AOF) | Per-backend; **no cross-store transaction exists** for a restore (Verified: `restorer.go` runs per-category closures sequentially; D2 is operational ordering, not a distributed txn — Proposed) | Backend-native (Postgres streaming, Redis replica, etcd Raft); snapshots replicate only the enumerated subset, off-node via `dr.SnapshotReplicator` | Backend-native; restore has no quorum/fencing — last writer wins per category (Verified: no lock anywhere in `SnapshotAdminService`) |
| Snapshot storage (`SealedEnvelope` blobs) | `snapshot.Storage` (file default, `./snapshots`) | `storagefile` (temp+rename+fsync, 0600, sanitized names; no directory fsync after rename — Verified `storagefile/file.go`) | Atomic per-envelope writes; crash leaves either absent or complete file (Verified) | Single-writer assumption; `Storage.List` order is arbitrary; concurrent writers race only via rename (atomic, no torn reads) | **None** — node-local; DR loop copies *fresh exports* to `dr.target_dir`, never the storage contents (Verified `buildDRExportFunc` `build_app.go:476-490`) | None (replica crash may lose un-replicated envelopes); off-node copy only via `dr.interval` cadence |
| Safety snapshot (D1, Proposed) | Orchestrator (`restoreTracked`) | Same `Storage`; `snap_` prefix; header `kind` mirror (Proposed) | Same as snapshot storage | Captured state is a **near-state**: sequential per-category `List`s, not a point-in-time snapshot (Verified export order `snapshotter.go:88-118`; caveat acknowledged in design) | Not DR-replicated (DR exports fresh; safety artifact stays node-local — the undo net dies with the node) | None; manual `Delete` after rollback window |
| Operations ledger (`op_*` records, steps, compensations, ResultJSON) | `operations.Store` | `operations.FileStore` under `<snapshot dir>/.operations` or `./operations` (`build_releases.go:30-55`) | temp+rename+fsync per update; **no dir fsync** (Verified `file_store.go`); ledger is crash-consistent per write | Read-modify-write whole-file updates; process-local mutex only — two processes sharing the dir race (unsupported) | **None** — per-node journal | **No recovery sequencing**: `StateRunning` records are never reconciled at boot (Verified: no sweep exists); D3 keeps this gap |
| Per-replica caches (client store, authz bundle, discovery snapshot/doc, JWKS body, tenant suspension/residency) | `sso.Server` | In-memory TTL caches | Ephemeral | Eventual; restored via flush + TTL | Cross-replica invalidation via bus (`KindControlPlaneRestore`, best-effort publish — Verified `server_invalidation.go:47-59`) | Bus recovery: resubscribe backoff → full cache flush + revocation deny-set re-seed → clear degraded (Verified `server_invalidation.go:144-224`); missed restore events are covered by the full flush on recovery |
| Invalidation bus / readiness | `platform/cluster` | etcd-backed (per dr-framework §3) | etcd Raft | Best-effort publish, no delivery/ordering guarantees (Verified `server_invalidation.go` package comments) | etcd in-region HA | Orchestrator reschedule; degraded readiness until reseed succeeds |

## 2. Findings

### F1 — High — Rolling-upgrade retention hazard is acknowledged but its mitigation is a process promise, and a second prune loop is unaccounted for

- **Evidence (Verified):** `PruneOldest` is version-agnostic and kind-blind
  (`retention.go:29-70`); the kind marker exists only in new binaries' header
  writes. The retention loop runs per node on its own interval
  (`startSnapshotRetention`, `build_app_cluster.go:433-466`). The DR
  replicator runs a **second** independent prune, `pruneReplicas(dir, keep)`,
  that also matches the `snap_` prefix with no kind awareness
  (`platform/lifecycle/dr/replicator.go:211-250`), pruning whatever is in
  `dr.target_dir`.
- **Triggering failure:** rolling deploy of old+new nodes where the snapshot
  storage dir is a shared/backed-up mount (or `dr.target_dir` is pointed at
  the same directory as `snapshot.storage.file.dir`), with retention enabled,
  during a restore's rollback window. An old node's `PruneOldest` — or the
  DR loop on any version — deletes safety artifacts.
- **User impact:** the undo net (D1/D3) silently disappears exactly when it
  exists to be used; D3 then degrades to the honest "rollback failed; target
  state unknown" path (design's own failure table) and manual recovery needs
  an external backup. Also: safety artifacts are **never** copied to the DR
  mount (the DR loop exports fresh), so replica loss destroys the net with
  no off-node copy.
- **Recovery:** external backup; re-run the restore (D2 superset convergence).
- **Corrective pattern:** (a) centralize kind-aware retention in one helper
  used by both `PruneOldest` and `pruneReplicas`; (b) boot-time or config
  validation that `dr.target_dir` is not the snapshot storage dir; (c) a
  version-skew test (old `PruneOldest` against a kind-marked envelope)
  asserting the runbook warning is at least testable; (d) runbook statement
  (design has it) plus a documented TTL follow-up.

### F2 — Medium — No invalidation on any failure path; D2's Phase-B-failure state is exactly the state stale caches misrepresent

- **Evidence (Verified):** `Restore` calls `Invalidator` only on the success
  path (`restorer.go:110-113`); every error path returns before it
  (`restorer.go:115-122` → `failRestoreOperation`, `admin_snapshots.go:247-257`,
  which never invalidates). The cache limitation is documented for
  the success path only (`admin_snapshots.go` header comment). D3 adds
  invalidation on rollback success (design) but the plain-failure and
  rollback-failure paths stay un-invalidated. Under D2, a Phase-B failure
  leaves stores at target ∪ partial-deletes while local caches serve
  pre-restore grants for TTL.
- **Triggering failure:** any non-dry-run replace restore that fails without
  rollback on a live node (or a rollback that itself fails).
- **User impact:** authorization decisions, discovery documents, and client
  metadata are served from stale caches against partially-restored stores —
  both directions (grants that were revoked by the prune still authorize;
  new grants are invisible).
- **Recovery:** TTL expiry; manual cache flush.
- **Corrective pattern:** fire `InvalidateRestoredControlPlane()` on **every**
  non-dry-run terminal state (success, rollback, plain failure, rollback
  failure). It is already fail-open with audit logging
  (`server_invalidation.go:47-59`) — consistent with the documented
  fail-open boundary; one extra bus publish per failed restore.

### F3 — Medium — Crash mid-restore leaves a permanently `running` operation with no recovery sequencing, and D3's rollback is in-process only

- **Evidence (Verified):** `operations.Start` writes `StateRunning`
  (`operations.go:109`); only in-process error paths reach `Finish`
  (`admin_snapshots.go:247-257`); no boot-time sweep of orphaned `running`
  records exists anywhere in `platform/lifecycle/operations` or `cmd` wiring.
  `BeginStep("apply_resources")` is written once **before** the whole phase
  (`admin_snapshots.go:225`) — step granularity does not record per-category
  progress.
- **Triggering failure:** pod eviction / `kill -9` / power loss between store
  writes. The ledger then permanently shows `running`; the client saw an
  error (or nothing) and does not know how far the restore got.
- **User impact:** operator cannot distinguish "Phase A done" from "Phase B
  pending" from the ledger; the op list accumulates zombie records. The
  actual data state is always a D2 superset, so retry **converges** regardless
  of crash point (Proposed but sound: upserts replayable, prunes keep-set
  pure) — but nothing in the design or runbook says so. D3's rollback cannot
  run after a crash (it lives in the same request); the safety snapshot
  remains as a manual undo artifact — if the node died, so did the artifact
  (F1).
- **Recovery:** operator retries the same snapshot (converges); verify via
  `GetOperation` once a reconciliation pass exists.
- **Corrective pattern:** startup reconciliation marking orphaned `running`
  operations `failed` with reason `interrupted` (matches the "recovery
  sequencing" focus), plus a runbook row stating crash-point retry safety.
  Optional: per-category step progress in the ledger.

### F4 — Medium — D1/D3 "zero writes before validation" cannot be met as written: the recursion guard and the safety-source check need the snapshot's kind before `operations.Start`

- **Evidence (Verified):** `restoreTracked` starts the operation and writes
  the ledger **before** loading the snapshot (`admin_snapshots.go:199-209`).
  D1's guard `effective capture = captureIntended && snap.Kind != safety`
  runs post-load; the pre-`Start` nil-snapshotter check (Proposed) therefore
  uses the **unguarded** `captureIntended`. D3's "source `Kind == "safety"`
  → `FailedPrecondition` before any write" (Proposed) requires the kind
  before any write — impossible without a pre-load read.
- **Triggering failure:** restoring a safety snapshot with default
  `auto_safety` (nil tri-state) on a node whose snapshotter is unwired →
  spurious `FailedPrecondition` even though the recursion guard would have
  made effective capture false. Production wiring builds snapshotter +
  restorer together (`build_stores.go:137-149`), so this is defensive-only
  in the stock binary — Low practical impact, but the design's zero-write
  claim is otherwise unenforceable.
- **User impact:** a safety-source restore (the D3 manual-recovery path)
  can be blocked by an unrelated misconfiguration; the ledger gains a
  spurious failed record.
- **Corrective pattern:** resolve the source kind via `storage.Get` +
  `PeekEnvelope` (the D1 header mechanism — O(1), no decryption) before
  `operations.Start`, and run **all** validation (nil snapshotter, safety
  source, rollback-without-safety, tri-state resolution) against it.
  This makes the "zero writes" claim literal.

### F5 — Medium — Concurrent restores are unserialized; the D2 convergence proof covers one run or same-snapshot retries, not overlapping runs of different snapshots

- **Evidence (Verified):** no mutex or lock exists in `SnapshotAdminService`
  (`admin_snapshots.go` struct); operation IDs are random with no
  target-keyed exclusion (`operations.go:171-175`); `upsertClient`'s
  preserve-secrets path is a Get-then-Update without CAS
  (`restorer_clients.go:121-150`, racy under concurrency — design
  acknowledges). Two runs with **different** keep-sets interleave Phase A/B:
  run #2's Phase B prune can delete run #1's just-inserted records and vice
  versa.
- **Triggering failure:** operator retry overlapping an in-flight restore,
  or two operators restoring different snapshots concurrently (shared
  Postgres backend, two nodes).
- **User impact:** convergent retry is no longer guaranteed; last-writer-wins
  per category; a "success" report may describe a state another run already
  partially reverted.
- **Recovery:** re-run after the other completes (converges); audit + op
  ledger forensics.
- **Corrective pattern:** per-node mutex around `restoreTracked` (cheap,
  single-process), a documented cross-node exclusion for shared-backend
  deployments (maintenance window), and a concurrent-restore test with
  injected interleaving.

### F6 — Medium — The rollback acceptance "stores equal pre-restore" only holds on a quiesced node; concurrent-write reversion is the semantics, and it should be pinned by a test, not just documented

- **Evidence (Verified):** `Export` lists stores sequentially
  (`snapshotter.go:88-118`), so the safety snapshot is a near-state; D3's
  rollback re-apply is a full second `ModeReplace`
  (design §D3) that reverts **any** write between capture and rollback —
  e.g., a login that changed `password_hash` between capture and failure is
  rewound (users carry `password_hash` in snapshots — Verified
  `snapshot.go` Resources; client secrets are `json:"-"` and survive via
  backfill — Verified `restorer_clients.go`, the safe direction).
- **Triggering failure:** any live traffic during the restore window.
- **User impact:** the design documents "return to captured state, not undo
  exactly the restore" — correct, but the acceptance test as written would
  pass only in a quiesced harness and could mask the live-node behavior.
- **Corrective pattern:** an explicit test pinning that a concurrent write
  between capture and rollback **is** reverted (making the semantics
  intentional), plus the runbook maintenance-window note (design has it).

### F7 — Low — The rollback error path should reuse `operationFailureError` so REST clients can reach the operation record

- **Evidence (Verified):** `operationFailureError` attaches
  `errdetails.ErrorInfo{operation_id, operation_url}` to the status
  (`admin_paginate.go:318-329`) and is used by `failRestoreOperation` today.
  The design's D3 caveat ("REST gateway drops the message body on error")
  is correct for the response body, but the default grpc-gateway error
  handler renders `google.rpc.Status` details — so routing the rollback
  error through `operationFailureError` (instead of a bare
  `mapSnapshotError`) gives REST clients the `operation_url` to
  `GetOperation`, where compensations + ResultJSON live. The design does not
  specify this.
- **Corrective pattern:** rollback error path: `operationFailureError(op,
  mapSnapshotError(wrapped, prefix))`; document in the runbook.

### F8 — Low — The safety-capture content vs. the rollback `Exclude` coverage must be pinned as a pair

- **Evidence (Proposed):** the design pins the rollback re-apply's `Exclude`
  (carried from the original request) but is silent on whether the D1
  capture honors `Exclude`. If a future implementer makes the capture honor
  `Exclude` and a later change drops the rollback's carry-over, the rollback
  re-apply would prune categories the failed restore never touched.
- **Corrective pattern:** state explicitly "capture is full (ignores
  `Exclude`); rollback re-applies with the original `Exclude`" and add a
  test asserting excluded categories are untouched after rollback.

### F9 — Low — Clock rollback reorders retention; D1's kind-skip incidentally protects safety artifacts, ordinary snapshots and DR replicas remain exposed

- **Evidence (Verified):** `newSnapshotID` sorts by wall-clock timestamp
  (`snapshotter.go:461-467`); `PruneOldest` and `pruneReplicas` both order
  lexicographically by name (`retention.go:39-49`, `replicator.go:250`). A
  stepped-back clock makes new snapshots sort oldest → they become victims.
  D1's kind-skip (Proposed) protects safety artifacts even then; ordinary
  snapshots and DR replicas (no kind marker) do not benefit.
- **User impact:** new snapshots pruned immediately after a clock step-back;
  retention silently keeps stale ones (storage growth) — pre-existing.
- **Corrective pattern:** runbook note ("do not step node clocks backward on
  nodes with retention/DR enabled"); a monotonic suffix would not fix the
  leading sort key — a timestamp-source change is out of scope.

### F10 — Info — Failed restores emit no audit event today; the rollback path's `EventSnapshotRestored` with hardcoded `OutcomeSuccess` describing a failed+rolled-back restore is semantically odd

- **Evidence (Verified):** `recordAdminMeta` hardcodes
  `audit.OutcomeSuccess` (`admin_paginate.go:220`); `failRestoreOperation`
  records no audit event (`admin_snapshots.go:262-269`). The design keeps
  `EventSnapshotRestored` for the rollback path with `rolled_back=true`
  meta — useful, but the outcome field will read success. The op ledger is
  the failure record. Design's "no new event types" constraint is
  reasonable; flagging for the auditreport classification follow-up.

### F11 — Info — No directory fsync after rename in either `operations.FileStore` or `storagefile`

- **Evidence (Verified):** both writers fsync the temp file then `rename`
  without a directory fsync (`file_store.go:76-91`, `storagefile/file.go`).
  A power loss immediately after `Finish`/`Put` can lose the rename. Standard
  tradeoff; worth a comment in the durability column of the runbook.

## 3. Scenario table

| Scenario | Current behavior (Verified) | Proposed behavior (D1–D3) | Expected outcome | Notes |
|---|---|---|---|---|
| **Partition: admin client ↔ node** mid-restore | Client ctx cancels; file/memory stores ignore ctx, so the restore **continues to completion**; Postgres-backed stores honor ctx and may abort mid-phase | Same; D2 superset invariants hold either way | Retry of same snapshot converges; op ledger records the terminal state when the node-side path completes | `FileStore`/`MemoryStore` ignore ctx (Verified `file_store.go` signatures); treat "client timeout ≠ abort" as a feature for convergence |
| **Partition: node ↔ invalidation bus** at restore time | Local flush runs; bus publish fails open (logged); peers serve stale until TTL (`server_invalidation.go:47-59`) | Same; D3 adds a second publish on rollback | TTL-bounded staleness; no false success | On bus recovery, the full flush covers the missed restore event (`server_invalidation.go:144-224`) |
| **Replica crash mid-restore** | Stores at a D2 superset (today: wipe-first partial); ledger stuck `running`; no reconciliation | D2 supersets are retry-convergent; D3 rollback cannot run (in-process); safety artifact survives only if storage dir survived (F1/F3) | Operator retries same snapshot → converges; zombie op record needs a manual note until F3's reconciliation lands | No fencing/quorum needed — single-node restore; cross-node concurrency is F5 |
| **Replica crash mid-rollback** | n/a | Stores at a partial-rollback state (superset of safety state); ledger: `apply_resources` failed, no compensation step | Re-run the safety snapshot manually (converges); never claim restored | Design's "state unknown" wording is the correct guarantee |
| **Retry (duplicate delivery)** after timeout | Second `Restore` starts a fresh op (no dedup by target); today's wipe-first ordering makes the retry a fresh destructive run | Same-snapshot retry: Phase A replays to no-ops, Phase B finishes the keep-set prune (convergence, Proposed) | Terminal state byte-equal to a once-successful run (Proposed acceptance) | Different-snapshot overlap is F5 |
| **Clock rollback** on the node | New `snap_` IDs sort old → become retention victims; DR prune unaffected by kind | D1 kind-skip protects safety artifacts; ordinary snapshots and DR replicas still exposed (F9) | Safety net survives; runbook: don't step clocks back | No monotonic clock source; `TakenAtUnix`/operation timestamps are display-only; `Confirm` is string equality — clock-independent |
| **Stale cache after restore** | Success path invalidates local + bus; failure path never invalidates (F2); documented TTL staleness for success only | D2/D3 success paths unchanged; failure paths still un-invalidated unless F2 is adopted | Authorization/discovery served stale against partial state for TTL | Full flush on bus recovery covers missed events; peers converge |
| **Dependency outage: store backend down** mid-Phase A | Category error → abort with partial old-superset (today: partial wipe) | Abort at Phase A → zero deletions, old superset; retry-safe (Proposed) | `Committed=false`; counts partial; consumer keys on `Committed` | Preflight (capability) fails before any write with `FailedPrecondition` once `mapSnapshotError` is fixed (Verified: today `Internal`) |
| **Dependency outage: backend down at rollback** | n/a | Rollback re-apply fails → `StepFailed` compensation, "rollback failed; target state unknown", audit `rolled_back=false` (Proposed) | Honest failure; state is a superset of safety state; manual re-apply converges | Never claims success (design's hard rule — correct) |
| **Recovery sequencing (boot)** | No reconciliation of `running` operations (F3) | Unchanged unless F3 lands | Ledger can lie until then | DR readiness and `/readyz` do not consult the op ledger |

## 4. Stated guarantees, unsupported topologies, validation tests, residual risks

### Guarantees that hold (Verified or sound-by-construction)

- **Per-envelope atomicity:** storage `Put` is temp+rename+fsync; a failed
  `Save` never leaves a torn envelope; `Delete` is idempotent
  (`pipeline.go:28-42`, `storagefile`).
- **Integrity:** every `Load` verifies envelope version, codec, algorithm,
  and SHA-256 (`pipeline.go:113-158`); `ErrChecksumMismatch` →
  `codes.DataLoss` (`admin_snapshots.go:312-315`).
- **All-or-nothing capture:** `Snapshotter.Export` fails the capture step if
  any wired backend `List` fails — no partial safety artifact is ever
  persisted or referenced (`snapshotter.go:55-66`).
- **D2 convergence (Proposed):** upserts are replayable (`Add`→
  `ErrClientExists`→`Update`+`preserveClientSecrets`, `CreateOrUpdate`,
  `PutTenant`/`PutDomain`, `Upsert`, `AssignRoles`, `SetMenus`, `Apply` —
  Verified across `restorer_*.go`); prunes are keep-set-pure (read only
  `List` + snapshot data — Verified); therefore same-snapshot retry
  converges from both Phase A and Phase B failure states.
- **Fail-closed:** capture with an unwired snapshotter → `FailedPrecondition`
  before `operations.Start` (Proposed); capability preflight →
  `FailedPrecondition` before any write (Proposed, requires the
  `mapSnapshotError` fix — Verified today it is `Internal`); rollback
  without a safety net is a validation error with zero writes (Proposed);
  rollback failure never claims success (Proposed).
- **Fail-open (preserved):** invalidation publish, retention-loop errors,
  DR-loop errors, audit recording — all best-effort with logging (Verified).
- **Ledger integrity:** the operations record is crash-consistent per write
  (temp+rename+fsync); compensations and ResultJSON are already on the wire
  (Verified proto field 7, `operationToProto`).

### Unsupported topologies (must stay documented)

1. **Multi-node concurrent restores into shared backends** (shared Postgres):
   no fencing, no target-keyed exclusion — last writer wins per category (F5).
2. **Shared snapshot storage dir across replicas with per-node retention
   loops** (NFS-backed `snapshot.storage.file.dir`): racing `List`/`Delete`,
   and old-binary prunes delete safety artifacts (F1).
3. **`dr.target_dir` pointed at the snapshot storage dir**: the DR prune
   (`pruneReplicas`) deletes safety artifacts (F1).
4. **Restore into a live fleet relying on cache convergence**: TTL-bounded
   staleness is documented for the success path; failure paths are worse
   (F2).
5. **Rollback as a transaction**: it is a second two-phase replace; a crash
   mid-rollback leaves a partial-rollback state; only honest messaging +
   retry convergence are guaranteed (design's own limitation, correct).
6. **Rolling upgrade with retention enabled during a rollback window**: old
   binaries prune kind-marked artifacts (F1).

### Validation tests (existing vs. needed)

Existing (Verified): `restore_modes_test.go` success-path counts + dry-run
no-mutation; `error_paths_test.go` (PruneOldest list/delete errors,
pipeline errors, bootstrap errors); `retention_test.go`; DR integrity tests
(restore keeps signing keys, audit chain continuous — `test/dr/`).

Needed (Proposed by the design, all fault-injection style):

- D1: capture round-trip equality; header/body kind consistency; retention
  skip; recursion guard; nil-snapshotter zero-write; opt-out audit meta;
  no-op-redactor pin.
- D2: Phase A mid-failure (zero `Deleted`, old superset); Phase B mid-failure
  (convergence); capability preflight zero-write; dry-run/success count
  regression.
- D3: rollback success (store equality on a **quiesced** harness —
  see F6; compensation step; invalidator count == 2; error text); rollback
  validation; rollback-failure messaging; `RollbackOnError=false`
  backward-compat; rollback preserves live client secrets.
- Gap tests this review recommends (not in the design): version-skew
  retention (old `PruneOldest` vs. kind-marked envelope); concurrent
  same-node restores of different snapshots; concurrent-write-between-
  capture-and-rollback (pinning reversion semantics, F6); clock-step-back
  retention ordering; zombie-operation reconciliation once F3 lands.

### Residual risks (accepted by the design)

- **Capture non-atomicity** and **rollback-reverts-concurrent-writes**:
  restore and rollback are maintenance-window operations; the runbook
  carries the quiesce caveat. The acceptance test must not mask this (F6).
- **Secrets at rest on retention-exempt artifacts**: safety snapshots carry
  `password_hash` and connection `Config` secrets; storage hygiene is
  operator-owned (design's runbook updates).
- **Storage growth**: every replace restore adds one full exempt snapshot;
  no TTL — explicit `Delete` only (design flags TTL as follow-up).
- **Rollback churn under retry automation**: each retry doubles writes and
  adds a safety snapshot (design flags; runbook caps retries).
- **Client-secret preservation**: `json:"-"` fields never serialize; the
  Get-then-Update backfill is racy (pre-existing, unchanged; safe direction
  for rollback — Verified).
- **No cross-store transaction**: D2's ordering gives convergence, not
  atomicity; the design's wording ("not a transaction") is the correct
  guarantee and must never be upgraded silently.

---

*Advisory review only. No code was modified. All **Proposed** labels refer to
the design's contracts, not shipped behavior; the design's own verified
corrections to the spec (existing `AddCompensation`, proto field 7,
`mapSnapshotError` mapping, pipeline-free retention, no `pruneMenus`,
missing `rollback_on_error` in the checklist) were re-confirmed against
source during this review.*
