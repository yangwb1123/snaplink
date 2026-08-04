# Design: interfaces/snapshot — 快照差异与漂移检测（条目级 diff 引擎 / Compare RPC / 恢复预览门）

> Companion to `docs/auto/interfaces-snapshot-diff-spec.md`（方向 3）。Design only —
> no code was modified. Every evidence claim was re-verified against the
> executable code at the current commit before writing.
>
> The three decisions form one coherent observability upgrade: a pure
> entry-level diff engine (D1) that upgrades dry-run from counts to
> item-level snapshot-vs-live preview; a Compare RPC (D2) that exposes
> snapshot-vs-snapshot and cross-node drift over the same engine; and a
> restore preview gate (D3) that records entry-level evidence into the
> operation ledger and audit meta before any write. Each `##` decision
> covers API surface, storage model, failure modes, and what could break
> the design. Contract updates, verification, and the pre-existing gate
> failures are collected at the end.

**Verified corrections to the spec's assumptions (bind every decision):**

- The spec's claim "`snapshot/` 在 `engineering.yaml:43` 的 `ignore_pattern` 中，新增
  `diff.go`/`diff_test.go` 不触发文件数门" cites the WRONG gate. `engineering.yaml:43`
  is the **complexity** ignore pattern, which does contain `snapshot/` — so new
  files there do not trip cyclomatic complexity. The committed **directory
  fan-out** gate (`directory_fanout_test.go`, `maxGoFilesPerDir = 10`) is a
  separate Go gate with a frozen ceiling for `interfaces/snapshot` of **14**
  non-test files — and the directory currently holds **16** (`codec.go,
  codec_json.go, pipeline.go, redactor.go, restorer*.go ×9, retention.go,
  snapshot.go, snapshotter.go`). `TestArchitecture_DirectoryFileFanout` is
  **already red on the current commit** (`go-file count 16 > frozen ceiling 14`).
  D1's `diff.go` therefore cannot land without a consolidation pass that brings
  the directory to ≤ 14 files first. The frozen-ceiling ratchet forbids
  re-seeding the exemption upward.
- `interfaces/grpcserver/grpcadmin` sits **exactly at** the 10 non-test-file cap
  (10 files, no exemption). D2's handler cannot go into a new file without a
  one-file consolidation elsewhere in that directory.
- The snapshot/restore area carries four **pre-existing** red gates on the
  current commit (verified, reported separately at the end): directory
  fan-out (snapshot 16 > 14); file size (`admin_snapshots.go` 581 > 500);
  function length (`restoreTracked` 81 > 50, `PruneOldest` 53 > 50);
  cyclomatic complexity (`resolveRestoreSafety` 18, `restoreTracked` 16).
  D3's preview step lands inside `restoreTracked`, so the implementation
  MUST refactor that function (extract the preview step + helpers), which
  also serves the pre-existing length/cyclo breaches.
- The spec's dry-run semantic fix ("内容相同计 `Unchanged` 而非 `Updated`") is
  not currently implemented anywhere: `upsertClient`/`upsertUser`/
  `upsertMenus` dry-run branches classify by **existence** only; `upsertRole`
  and `mergeRole` dry-run are **optimistic** (`c.Inserted++` with no probe —
  `restorer_roles.go`, comment "Dry-run cannot introspect existence without
  a Get"); menus without a `permissions.MenuLister` always count `Inserted`.
  The projection design below (D1) makes the diff engine the single source
  of truth for dry-run counts of **covered** categories and keeps today's
  probe/optimistic counting only for categories the engine cannot enumerate.
- `exportRoles`/`exportAssignments`/`exportMenus` (`snapshotter.go`) skip
  clients with zero entries (`len(...) == 0 { continue }`), while the
  restorer's replace prunes key off the client ROSTER. A pure slice-union
  diff is still correct for the wipe-to-zero semantics: a snapshot-side
  client with zero roles is simply absent from the category slice, so its
  live roles surface as `deleted` (they will be wiped); live-side zero roles
  surface as `inserted` (they will be seeded). No roster expansion needed.
- All five existing dry-run tests (`TestRestore_Overwrite_DryRun`,
  `TestRestore_Replace_DryRun_NoMutation`, `snapshot_test.go:319`,
  `restore_safety_test.go:365`, `bootstrap_advance_test.go:143`) assert only
  `Inserted`/`Deleted`/`Committed`/`Bootstrap` — never `Updated`/`Skipped`
  on content-identical targets. The D1 projection keeps every one of them
  green (verified fixture-by-fixture, see D1 "What could break").
- `SnapshotDigest` cannot digest the whole `Snapshot` struct: `SnapshotID`,
  `TakenAtUnix`, `SourceNodeID`, `SourceNamespace`, and `Kind` differ across
  nodes/exports of identical state, which would make the cross-node drift
  use case (D2) impossible. The digest must cover only **canonicalized
  redacted `Resources`** (entries sorted by identity key; List order is
  unspecified per the store interfaces).
- ADR-0008 confirmed: adding a field to a stable `v1` package is always
  allowed; a new RPC + new messages are additive. `interfaces/snapshot →
  platform/configaudit` is a downward import (rank 5 → 1) — legal, precedent
  `interfaces/sso/server_backup.go:64-65`. `SourceNodeID`/`SourceNamespace`
  have no consumer anywhere in the tree (only Export-write at
  `admin_snapshots.go:63` and meta projection at `admin_snapshots.go:523`) —
  the spec's evidence holds.

---

## Decision 1 — 条目级差异引擎：dry-run 从计数升级为条目级 snapshot-vs-live 预览

**Rule.** A new pure-function diff engine in the `snapshot` package computes
entry-level `inserted/updated/unchanged/deleted` classifications with the
restorer's identity keys. Dry-run counts become a mode-aware projection of
the diff for every category the engine can enumerate; `CategoryCounts`
gains `Unchanged`. Diff inputs always pass through `SnapshotRedactSecrets`
first. The engine never touches a backend, never mutates its inputs, and is
byte-deterministic for the same pair of inputs.

### API surface (SDK, all in `interfaces/snapshot/diff.go`, one new file)

```go
// DiffStatus classifies one entry. "unchanged" entries are never listed —
// they exist only as counts (identical snapshots → zero entries).
type DiffStatus string // "inserted" | "updated" | "deleted"

type DiffOptions struct { Exclude []ResourceCategory }

// DiffEntry is one changed item. Changes carries the RFC 6902 patch for
// "updated" entries (from platform/configaudit.Diff), paths like
// "/clients/{id}/redirect_uris".
type DiffEntry struct {
    ID      string
    Status  DiffStatus
    Changes []configaudit.Op
}

// CategoryDiff is one category's outcome: counts + the changed entries.
type CategoryDiff struct {
    Category ResourceCategory
    Inserted, Updated, Deleted, Unchanged int
    Entries []DiffEntry // sorted by ID; unchanged omitted
}

type DiffResult struct { Categories []CategoryDiff } // AllCategories() order

func Diff(before, after *Snapshot, opts DiffOptions) (*DiffResult, error)
func SnapshotDigest(s *Snapshot) (string, error) // canonical redacted Resources sha256
```

- **Identity keys** (exactly the restorer's, verified file-by-file):
  tenants → `Tenant.ID`; tenant_domains → `Domain.Hostname`; connections →
  `Connection.ID`; clients → `Client.ID`; users → `User.ID`; pairwise →
  `PairwiseSub`; roles → `(ClientID, Role.Code)`; assignments →
  `(ClientID, UserID)`; menus → `ClientID`; netpolicy → `Policy.Name`.
- **Comparison**: each matched pair is marshaled to `map[string]any`
  (`json.Marshal` → `json.Unmarshal`) and compared via
  `configaudit.Diff`; `updated` iff the op list is non-empty. Marshal is
  the normalization: `json:"-"` fields (client secrets) are invisible,
  map keys sort, and both sides run through the identical pipeline.
  `configaudit.Diff` sorts ops by path — deterministic output.
- **Redaction**: `Diff` copies each client/user entry (struct copy; users
  get a fresh `Attributes` map) and applies `SnapshotRedactSecrets` to the
  copies — the inputs are never mutated, and `Secret`/
  `RegistrationAccessToken`/credential `User.Attributes` keys never reach
  the output. Redaction makes the classification match restore reality for
  clients (the restorer backfills live secrets via `preserveClientSecrets`,
  so a secret-only difference is genuinely a no-op).
- **Determinism**: entries sorted by identity key, categories in
  `AllCategories()` order, ops sorted by path. The same pair of inputs
  yields byte-identical `json.Marshal(DiffResult)` — the property D3's
  `diff_digest` and D2's replayability depend on.
- **Category universe**: a category is diffed iff `before.IncludesCategory`
  AND `after.IncludesCategory` (v1 snapshots therefore diff only their
  legacy categories) and not in `opts.Exclude`. Nil backends on either side
  mean "nothing of this kind" (empty side), matching restore semantics.
- **`SnapshotDigest`**: canonical form = `Resources` with every category
  slice sorted by identity key, clients/users redacted, envelope metadata
  (`SnapshotID`/`TakenAtUnix`/`SourceNodeID`/`SourceNamespace`/`Kind`/
  `BootstrapState`/`Categories`) excluded, then `configaudit.Digest`
  (sha256 of `json.Marshal`). Cross-node equality holds iff the two nodes
  hold identical redacted state with identical category coverage.

### Restorer integration (dry-run projection)

- `restorer.go`: `CategoryCounts` gains `Unchanged int`; `RestoreOptions`
  gains `Preview bool`; `Report` gains `Diff *DiffResult json:"preview,omitempty"`.
- New internal helper (same `diff.go`): `(*Restorer).previewDiff(ctx, snap,
  opts)` enumerates the live side from the restorer's OWN backends using
  the exact reads the restorer already uses — per-item Get for
  clients/users/tenants/domains/connections/pairwise/netpolicy; `List` for
  the delete-detection side (replace mode only, where the prunes already
  require Listers and `preflightReplace` guarantees them); `ListAllRoles` /
  `ListAssignments` per live roster client for roles/assignments;
  `MenuLister.GetMenus` when the provider implements it. Categories whose
  capability is absent (e.g. no `MenuLister`; non-Lister connections/
  pairwise backend in merge/overwrite) are **omitted from the diff** and
  keep today's probe/optimistic counting — a documented coverage limit, not
  a fabrication: the engine never reports "inserted" for something it could
  not enumerate.
- `Restore()`: when `DryRun || Preview`, compute the preview BEFORE Phase A
  (after `prepareRestore`). A preview error aborts the restore with zero
  writes (fail-closed — the preview is a gate, see D3). On dry-run, after
  the existing plan runs (probes still detect backend errors and count
  uncovered categories), overlay `rep.Items[cat] = projectCounts(mode,
  catDiff)` for every diff-covered category and attach `rep.Diff`. The
  projection is the single source of truth for covered categories:
  - merge: absent → `Inserted`; present → `Skipped` (existing merge
    semantics preserved — merge never updates, so identical content is
    `Skipped`, not `Unchanged`);
  - overwrite: absent → `Inserted`; present + differs → `Updated`; present +
    same → `Unchanged`;
  - replace: as overwrite, plus live-only → `Deleted`.
- `RestoreOptions.Preview` defaults false → `Report.Diff` nil →
  `json:"preview,omitempty"` keeps every existing `ResultJSON` byte
  identical; SDK-direct callers (`builtin.ApplyRestore`,
  `build_network_snapshot.go`) are untouched.

### Storage model

None. The engine is pure in-memory; the live side is assembled per call
from the restorer's stores; nothing new is persisted by D1 itself. The
preview's persistence lives in D3 (operation `ResultJSON`).

### Failure modes

- Preview enumeration error (transient backend failure during a live Get/
  List) → `Restore` returns the error before any write; the operation
  ledger records the failure (D3). This is stricter than today's dry-run
  (which tolerates probe errors per category and returns partial counts) —
  deliberate: the preview is the deliverable, and a preview that cannot
  enumerate must not be silently replaced by optimistic counts.
- Diff on a v1-schema snapshot → restricted to legacy categories; no error.
- Redaction's known denylist gap (a custom backend storing a secret under
  an unlisted `User.Attributes` key) → that value is invisible to the
  comparison and can leak into `Changes.Value` of an `updated` entry. Same
  documented limitation as the redactor itself; diff is an inspection
  surface, never a credential channel.

### What could break the design

- **The fan-out gate (binding)**: `interfaces/snapshot` is at 16 files vs a
  frozen ceiling of 14 — already red. `diff.go` makes 17. The same change
  MUST consolidate to ≤ 14 net. Concrete plan: (a) merge `codec.go` (27) +
  `codec_json.go` (60); (b) merge `restorer_safety.go` (71) into
  `restorer_stage.go` (374) → 445; (c) merge `restorer_roles.go` (131) +
  `restorer_assignments.go` (172) → 303 (or `restorer_menus.go` +
  `restorer_netpolicy.go` → 215). 16 − 3 + 1 = 14, at the ceiling; each
  merged file stays < 500 lines. Exact pairing is the implementer's choice,
  but the count arithmetic is not.
- **`diff.go` must stay ≤ 500 lines** (filesize gate; `snapshot/` is NOT in
  the filesize ignore list). Budget: types ~70, `Diff` + classify ~120,
  `SnapshotDigest` + canonicalization ~50, live enumeration ~130,
  projection ~40 — ≈ 410–450 lines. If it exceeds, split the live
  enumeration into a merged/absorbed file rather than adding a new one.
- **Dry-run count changes are visible semantics**: `TestRestore_Overwrite_DryRun`
  (target `alpha` Name="Stale" vs snapshot) still yields `Updated=1`
  (content differs); `TestRestore_Replace_DryRun_NoMutation` still yields
  `Deleted=1`/`Inserted=2` (orphan-only destination); the merge dry-run
  tests still yield `Inserted=2`. All verified against fixtures. The ONLY
  observable changes are: identical-content targets now count `Unchanged`
  instead of `Updated` (overwrite/replace), and role/assignment/menu
  dry-run counts become content-accurate instead of optimistic — both are
  the point of the feature.
- **Menus presence-detection mismatch (documented)**: the restorer's
  `upsertMenus` treats an empty live tree as "absent" (`len(existing) > 0`),
  while the diff compares content. An empty-vs-empty pair is `Unchanged` in
  the preview but the apply path would still `SetMenus` (a write) and count
  `Inserted`. The preview is the review surface; apply counts describe
  writes. Never reconciled — noted so nobody "fixes" one side.
- **json-shape comparison subtleties**: `omitempty`-tagged fields that are
  nil-vs-empty marshal identically and are therefore `unchanged`; a field
  changing JSON type is `replace`. Both are stable properties of the
  comparison pipeline, not bugs; tests must pin them explicitly so future
  tag edits don't silently change classifications.

---

## Decision 2 — Compare RPC：snapshot-vs-snapshot 与跨节点漂移比对

**Rule.** A new additive `Compare` RPC on `SnapshotAdminService` computes the
D1 diff between two stored snapshots, or between a stored snapshot and the
current node's live state, and returns the entry-level diff plus both
`SnapshotMeta` projections and both canonical digests. The peer's state is
always supplied by the caller (stored snapshot IDs, or `live=true` against
this node) — zero new outbound capability, mirroring
`configaudit.HandleClusterDiff`.

### API surface (wire, `proto/admin/v1/snapshots.proto`, additive per ADR-0008)

```proto
rpc Compare(CompareSnapshotsRequest) returns (CompareSnapshotsResponse) {
  option (google.api.http) = {
    post: "/api/v1/admin/snapshots:compare"   // collection-level custom verb
    body: "*"
  };
}

message CompareSnapshotsRequest {
  string before_id = 1;   // branch (a): two stored snapshots
  string after_id  = 2;
  string id        = 3;   // branch (b): stored snapshot vs live export
  bool   live      = 4;   // requires id; ignored otherwise
  repeated string exclude = 5; // category filter on the diff output
}

message CompareSnapshotsResponse {
  DiffResult diff = 1;        // entry-level; unchanged omitted; redacted
  SnapshotMeta before = 2;    // meta pair — source_node_id mismatch is the
  SnapshotMeta after  = 3;    // machine-readable drift evidence
  string before_digest = 4;   // SnapshotDigest, exclude-independent
  string after_digest  = 5;
}

// DiffResult / CategoryDiff / DiffEntry / FieldChange — the D1 SDK types
// projected to proto. DiffEntry.changes carries RFC 6902 ops with
// value_json (raw JSON string) for add/replace.
```

Also additive: `CategoryCounts.unchanged = 5`; `RestoreReport.preview = 9`
(D3). `ResourceCategory` stays a string — no schema bump.

Handler (new file `interfaces/grpcserver/grpcadmin/admin_snapshots_diff.go`
— requires the grpcadmin consolidation below):

- Validation matrix: exactly one of `(before_id && after_id)` or
  `(id && live)`; anything else → `InvalidArgument`. Branch (a) requires
  `ready()` (pipeline+storage); branch (b) requires a non-nil `snapshotter`
  (else `FailedPrecondition`, same as Export) and does NOT require storage.
- Branch (a): `Pipeline.Load` both; unknown id → `mapSnapshotError` →
  `NotFound`; checksum failure → `DataLoss`. Branch (b): `Load` the stored
  side, `Snapshotter.Export(ExportOptions{})` the live side (the export's
  `DefaultExportRedactor`, if wired, is idempotent with the redaction
  below).
- Both sides through `SnapshotRedactSecrets` (same unconditional redaction
  as `Get`) BEFORE `Diff` and `SnapshotDigest` — the response is an
  inspection surface, never a credential channel.
- `Compare(A, A)` short-circuits (single load, empty diff — the acceptance
  case).
- Read-only: requires `admin:read`; writes no audit event (mirrors `Get`).
  No cluster-bus broadcast — `configaudit.DriftDetector`'s territory stays
  untouched (spec non-goal).

### Storage model

Reads existing snapshot storage via `Pipeline.Load` (envelope fetch,
checksum verify, decrypt, decode). No new persistence: digests are derived
per call; the caller's automation stores them (or compares them in flight).
Safety-kind snapshots are first-class inputs — comparing the D1 net against
a post-restore export is the natural drift check after a rollback window.

### Failure modes

- Unknown/removed `before_id`/`after_id` between `Get` and `Load` →
  `NotFound` via the shared mapper (atomic enough for a maintenance-window
  read; no new consistency machinery).
- Backend failure inside the live export (branch b) → `Internal` (export is
  all-or-nothing by design; partial snapshots are never returned).
- TOCTOU: the live export is non-atomic (documented `CaptureSafetySnapshot`
  caveat applies), so a `live=true` diff against concurrent writes reflects
  a state that may never have existed. Restore/Compare are maintenance-
  window operations; documented, not solved.
- Cross-node digest inequality caused by differing category coverage (one
  node wired fewer backends) is a TRUE positive of the signal but may be
  operator-intended — `exclude` filters the diff, never the digests, so
  automation can distinguish "same coverage, drifted" (digest mismatch,
  diff non-empty) from intentional divergence (operator uses exclude and
  ignores digest).

### What could break the design

- **grpcadmin is at the 10-file cap** — `admin_snapshots_diff.go` (+1)
  requires a one-file consolidation in the same change. Candidate:
  merge `admin_keys.go` (156) + `admin_tokens.go` (192) → 348 lines.
  Alternative: fold the handler into `admin_snapshots.go` — rejected:
  that file is already 581 lines and red on the filesize gate; the diff
  handler would grow it further.
- **Gateway routing**: the collection-level custom verb
  `POST /api/v1/admin/snapshots:compare` must be regenerated
  (`buf generate`) and mirrored in `docs/openapi.yaml` (AGENTS.md §5.6);
  `make ci` validates proto generation. The pattern matches the existing
  instance-level `{id}:restore` annotation.
- **`SnapshotDigest` correctness is load-bearing**: if canonicalization
  misses a slice order or leaks envelope metadata, two identical nodes
  report drift — a false alarm that destroys operator trust in the whole
  surface. The digest must sort every category by identity key, redact
  clients/users, and exclude all envelope fields; pinned by a
  cross-construction test (same state, different List order → equal
  digest).
- **Old-client compatibility**: an old binary calling `Compare` gets
  `Unimplemented` (expected for a new RPC); new binaries against old
  servers simply lack the method. `CategoryCounts.unchanged`/
  `RestoreReport.preview` are unknown-field-ignored by old readers. No
  deprecation window needed (ADR-0008 additive rules).
- **Response size**: a full entry-level diff of two large states is the
  same order as `Get`'s `resources_json` — acceptable under the
  control-plane "small and low-frequency" doctrine (dr-framework), and the
  `exclude` filter is the operator's escape hatch.

---

## Decision 3 — 恢复预览门：replace 恢复前必算 preview，ResultJSON + audit meta 落条目级证据

**Rule.** `restoreTracked` computes the D1 preview after `ValidateRestore`
and BEFORE the D1 safety capture; the preview rides the operation
`ResultJSON` on success AND failure paths, and two fixed bounded audit
meta keys (`diff_digest`, `diff_summary`) ride `EventSnapshotRestored`.
Preview computation is fail-closed: any error aborts the restore before a
single write (including the capture). Default behavior (`Preview=false`,
non-dry-run) is byte-identical to today.

### API surface

- SDK: `RestoreOptions.Preview bool` (default false); `Report.Diff
  *DiffResult json:"preview,omitempty"` — dry-run always computes it
  (`needPreview := opts.DryRun || opts.Preview`).
- `restoreTracked` step order becomes: `load_snapshot →
  [compute_preview] → [capture_safety_snapshot] → apply_resources →
  [rollback_safety_snapshot]`. The `compute_preview` step runs only when
  `needPreview`; its failure terminates the operation with zero writes and
  the step name in the ledger (precise failure attribution, house style).
- Wire (additive): `RestoreReport.preview = 9` (the proto `DiffResult`
  projection). Populated on dry-run responses (the dry-run deliverable —
  an operator must not need a second `GetOperation` round-trip to see what
  a dry-run found) and on failure status details (`withReportDetail`, the
  only body a failing RPC delivers). Suppressed on non-dry-run success
  responses per the spec's light-response intent — the preview is then
  read via `GetOperation` (`ResultJSON`).
- `restoreAuditMeta` gains exactly two fixed keys: `diff_digest` (sha256 of
  the canonical preview `DiffResult` JSON via `configaudit.Digest` — the
  "规范化 JSON" the spec requires; reuses the same digest primitive as
  `SnapshotDigest`, interpreted as "复用" of the primitive, since digesting
  the preview itself fingerprints the exact evidence bytes) and
  `diff_summary` (`{"inserted":N,"updated":N,"deleted":N,"unchanged":N}`
  totals across categories). Keys appear on the success and rollback audit
  events (the only paths that already emit `EventSnapshotRestored`); they
  are absent when no preview ran (load/validate failures — nothing was
  computed). Bounded cardinality preserved; no new event type
  (`auditreport/drift_test.go:46` already classifies
  `EventSnapshotRestored`).

### Storage model

- The preview persists inside the existing **operation ledger**
  (`operations.Store` `ResultJSON`): `json.Marshal(rep)` embeds the preview
  via `Report.Diff`'s `preview` key; the capture-failure path (no `Report`
  exists yet) passes `json.Marshal(map[string]any{"preview": diff})`
  instead of today's `nil` — both shapes expose the same `preview` segment
  to `GetOperation` consumers. Restart-persistent by the ledger's existing
  guarantees; zero new storage.
- The safety snapshot (D1 net) is untouched: still kind="safety",
  retention-exempt, delete-explicit. The preview never writes to snapshot
  storage.
- Size: the entry-level preview is bounded by control-plane state size; the
  ledger stores byte blobs without a cap. Under the documented
  "small and low-frequency" doctrine this is acceptable; flagged as the one
  growth axis (see below).

### Failure modes

- Preview error (backend read failure) → operation FAILED at
  `compute_preview`, zero writes, no capture, no apply; audit meta without
  diff keys (no preview); `ResultJSON` absent (nothing to retain). This is
  the gate's fail-closed contract: a restore that cannot produce its
  evidence does not proceed — the same discipline as "an invalid request
  must not write — not even the undo artifact".
- Apply failure after a successful preview → partial `Report` (now
  including `preview`) lands in `ResultJSON` via the existing
  `failRestoreOperation` path — an auditor can reconstruct exactly what
  was intended vs what applied.
- Rollback path: `terminateRollback`'s `finalRep` marshal includes the
  preview; the rollback audit event carries `diff_digest`/`diff_summary`.
- **Preview/dry-run consistency**: the operation's preview and an
  independent dry-run of the same state are byte-identical — same engine,
  same redaction, same sorting, same live enumeration. The D3 acceptance
  ("失败恢复的 ResultJSON 含 preview 且与独立 dry-run 一致") holds by
  construction, not by coincidence. (The failure-path `items` counts are
  partial and differ from the dry-run's projected counts — the acceptance
  scopes itself to the `preview` segment, which is what the design pins.)

### What could break the design

- **`restoreTracked` is already over budget (81 lines, cyclo 16)**. The
  preview step must be an extraction, not an insertion: a
  `computeRestorePreview(ctx, operation, snap, opts) (*previewEvidence, error)`
  helper (in `admin_snapshots_diff.go`) holding step bookkeeping, diff
  computation, and meta construction. The refactor must ALSO bring
  `restoreTracked` under 50 lines / cyclo 15 where possible; the remaining
  pre-existing breaches (`resolveRestoreSafety` cyclo 18,
  `admin_snapshots.go` 581 lines, `PruneOldest` 53 lines) are reported
  separately and are not silently absorbed by this change.
- **Existing dry-run behavior must not shift for `Preview=false`**: the
  plan still runs on dry-run (probes keep detecting backend errors, and
  uncovered categories keep today's counts); the projection overlays only
  covered categories. Skipping the plan entirely would change error
  propagation and was rejected.
- **`json:"preview,omitempty"` on `Report.Diff`** is what keeps every
  existing `ResultJSON` byte identical — a plain `json:"preview"` would
  emit `"preview":null` into every legacy operation record and break the
  "存量零变化" requirement. Pinned by a regression assertion.
- **Audit meta must stay bounded**: entries never enter meta; only the two
  fixed keys do. A future operator asking for "the diff in the audit
  event" must be redirected to `ResultJSON` — the bounded-cardinality
  contract (AGENTS.md §4) is a regression boundary, not a suggestion.
- **ResultJSON growth on large states**: a 10k-client snapshot produces a
  multi-MB preview in the ledger. Acceptable today; if it ever bites, the
  fix is a preview-size cap with a truncated-digest fallback — NOT
  dropping the digest (the evidence fingerprint must survive).
- **`diff_digest` replayability**: "同一状态两次 preview 的 digest 字节相同"
  holds only if the preview JSON is deterministic — which D1's sorting
  guarantees. A future change that adds an unsorted field to `DiffResult`
  silently breaks replayability; the determinism property needs its own
  pinned test (two runs, byte-equal digest).

---

## Contract updates (same change, per AGENTS.md §5.6)

- `proto/admin/v1/snapshots.proto`: `rpc Compare` + `CompareSnapshotsRequest/
  Response`, `DiffResult/CategoryDiff/DiffEntry/FieldChange`,
  `CategoryCounts.unchanged = 5`, `RestoreReport.preview = 9`; regenerate
  `gen/proto` (buf). All additive (ADR-0008).
- `docs/openapi.yaml`: `POST /api/v1/admin/snapshots:compare` endpoint +
  new schemas; `RestoreSnapshotRequest.preview` and
  `RestoreReport.preview` field docs.
- No new `Err*` sentinels → `docs/error-codes.md` unchanged; no config
  knob → `docs/config-reference.md` unchanged.

## Verification plan

- `interfaces/snapshot/diff_test.go` (new): identical snapshots → zero
  entries, unchanged counts; add/update/delete per category; identity-key
  alignment per category (roles by `(ClientID, Code)`, domains by
  Hostname, netpolicy by Name, pairwise by PairwiseSub); redaction
  (secret-bearing client never leaks into entries/changes); determinism
  (two runs, byte-equal); `SnapshotDigest` cross-construction equality
  (reordered List → same digest; metadata difference → same digest).
- Restorer: `TestRestore_Overwrite_DryRun` /
  `TestRestore_Replace_DryRun_NoMutation` unchanged and green; new
  assertions for identical-content `Unchanged` and for `Preview=true`
  `Report.Diff` on the success path.
- grpcadmin bufconn (reuse `startSnapshotGRPC` harness): export A → mutate
  store → export B → `Compare(A,B)` shows the inserted/updated/deleted
  entries and both `source_node_id`s; `Compare(A,A)` empty; `live=true`
  reflects the current store; unknown id → `NotFound`; invalid combos →
  `InvalidArgument`; secret values absent from the response.
- Restore preview: failed replace restore → `GetOperation` `ResultJSON`
  contains `preview` identical to an independent dry-run's diff;
  `EventSnapshotRestored` meta contains `diff_digest` + `diff_summary`;
  replay stability (same state twice → equal digest).
- Gates: `go build ./... && go vet ./...` and `go test -run
  'TestMaintainability_|TestArchitecture_' .` after every `.go` edit;
  `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`.

## Pre-existing gate failures (reported separately, NOT introduced by this design)

Verified at the current commit; all in the snapshot/restore area and all
red before any doc-only work:

1. `TestArchitecture_DirectoryFileFanout` — `interfaces/snapshot` 16
   non-test files > frozen ceiling 14.
2. `TestMaintainability_FileSizeBudget` — `admin_snapshots.go` 581 lines >
   500.
3. `TestMaintainability_FunctionLength` — `restoreTracked` 81 lines > 50;
   `retention.go:PruneOldest` 53 lines > 50.
4. `TestMaintainability_CyclomaticComplexity` — `resolveRestoreSafety`
   cyclo 18 > 15; `restoreTracked` cyclo 16 > 15.

This design's implementation plan absorbs #1 (consolidation), and the
`restoreTracked` extraction serves #3/#4 for that function. #2 and
`PruneOldest` are independent of the feature and should be tracked
separately so `make ci` can return to green.
