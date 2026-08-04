# Principal Review — Restore Safety Design (D1/D2/D3)

Companion: `docs/auto/interfaces-snapshot-restore-safety-design.md`
Inputs synthesized: protocol review, database-architect review, distributed-engineer
review, security review, QA review (all in `docs/auto/`), plus spot re-verification
of the load-bearing code facts at revision `3be9b3d6`.

Status: **advisory**. This document does not approve the release, bind maintainers,
or override accountable owners. No code was modified during this review.

---

## 1. Advisory recommendation

**Conditionally ready** — proceed to implementation only with the amendment set in
§4 landed in the same change, and the P0 test suite in the same change.

Evidence confidence: **High for the verified code facts** (the five supplied
reviews independently re-verified the same evidence — `AddCompensation` +
proto field 7, `mapSnapshotError` → `Internal` default, pipeline-free
`PruneOldest`, 474-line restorer, free proto slots, `effectiveRedactor` override —
and my spot checks of `codec_json.go:49`, `admin_paginate.go:318`,
`operations.go:153`, `pipeline.go:174` agree). **Medium for the design's
operational claims** (rolling-upgrade behavior, storage growth, quiesce
assumptions) — several are corrected below, and volume/performance evidence is
entirely absent (§6).

Why not "ready": the design's central wire-compat premise is false (F-1), its
rollback-minimality claim is false (F-2), and its error-transport claim is false
(F-3). Each has a mechanical fix, so the approach survives; but the doc as
written would mislead implementers and the acceptance tests would not be
implementable as specified. Why not "not ready": no reviewer found a defect in
the core mechanism (additive envelope header, existing compensation slot, staged
prune, fail-closed preflight) that requires a different architecture, and all
findings have concrete remediations with test specifications.

## 2. Consolidated findings

Severity reflects the *design document's* state, not shipped code (nothing was
implemented). Source tags: [P]=protocol, [D]=database, [DS]=distributed,
[S]=security, [Q]=qa. "— verified" marks facts I re-checked or that multiple
reviews independently verified.

### Critical

None. All Highs are design-contract defects with identified mechanical fixes;
none is a verified exploit or data-loss path in current code (no code changed).

### High

**F-1 — Body-level `kind` field breaks the "additive, old readers ignore"
premise.** [S-F1, D-H1 — dedup of two independent findings, identical evidence]
`JSONCodec.Unmarshal` uses `dec.DisallowUnknownFields()` (`interfaces/snapshot/
codec_json.go:49`, pinned by `codec_edges_test.go:80`) — verified. A safety
artifact whose *body* carries `"kind"` cannot be decoded by a pre-change binary:
`Pipeline.Load` fails, surfaced as a confusing `Internal` codec error, and a D3
rollback on an old node cannot run. Fail-closed direction (no silent misread),
but it violates the AGENTS.md §1 wire-compatibility regression boundary, and the
design's D1 risk table covers only the deletion direction of the old-binary
hazard. The envelope *header* path is genuinely additive (plain `json.Unmarshal`
in `Load`/`PeekEnvelope`). **Fix (both reviewers agree): header-only `kind`** —
`Snapshot.Kind` tagged `json:"-"`, `Pipeline.Save` copies it into
`SealedEnvelope.Kind`; retention/List/orchestrator read it via `PeekEnvelope`.
Bodies stay byte-identical across versions; ordinary exports are unchanged
(`omitempty`). Golden-marshal + strict-decoder round-trip tests required.

**F-2 — Rollback scope ≠ failed-restore scope; rollback can rewrite categories
the restore never touched.** [S-F2; DS-F8 is the test-side pair] The restore loop
skips categories via `IncludesCategory` + `Exclude` (`restorer.go:118-121` —
verified by security review); D3's rollback re-apply passes only the original
request's `Exclude` over a safety capture that covers *every* wired category.
Excluding `netpolicy` is a documented pattern. A rollback can then silently
revert a security-relevant netpolicy change made in the rollback window — the
data-plane firewall rewound without the operator asking. **Fix: rollback exclude
= original `Exclude` ∪ (AllCategories ∖ source snapshot's categories).**
Regression test: snapshot excluding netpolicy; change netpolicy mid-window;
assert rollback leaves it byte-equal.

**F-3 — "Error-with-response works on gRPC" is false; rollback reports and
`operation_id` never reach any client.** [P-F1, S-F3 — dedup; DS-F7 partially
overlaps] Per the gRPC spec, a non-OK status discards the response message on
both transports. The house pattern already exists: `operationFailureError`
(`admin_paginate.go:318`, used at `admin_snapshots.go:253` — verified). **Fix:
carry the rollback report as `status.WithDetails` detail** (grpc-gateway renders
details into REST error bodies) **and keep `operationFailureError` wrapping on
both failure paths**; embed `operation_id` in the status message text as the
fallback for REST clients. The design's runbook instruction "read the outcome
from `GetOperation(operation_id)`" is unsatisfiable until this is fixed.

**F-4 — The P0 acceptance tests are unbuildable against current test
infrastructure.** [Q-F2 — no dedup; this is a delivery gate, not a design defect]
Only `errStorage`/`errTracker` fault seams exist; D2/D3's fault-injection
acceptance (Phase-A zero-delete, Phase-B convergence, rollback paths) requires
`failAfterN` wrapper fixtures that do not exist and must be specified in the
design. Related, [Q-F1]: the restructured functions (`pruneTenants`,
`pruneTenantDomains`, `pruneConnections`) sit at 0.0% coverage and no fixture
wires tenants/connections/pairwise anywhere (all memory implementations verified
to exist). Both must land with the change or the design's acceptance criteria
cannot be demonstrated.

**F-5 — Zero restore coverage at the E2E/REST layer.** [Q-F3; DS notes the same
for gRPC: `test/admin_grpc_snapshots_test.go` covers Export only] D3's error
transport (F-3) and the grpc-gateway body-drop behavior are untestable until a
REST gateway restore test exists. Mandatory once F-3's fix lands.

### Medium

**F-6 — Rolling-upgrade retention hazard.** [Design-flagged; P-F3, DS-F1, S-F9 —
dedup with conflict resolution, see §3] Old binaries delete safety artifacts
(kind-unaware `PruneOldest`) and cannot load them (F-1). Two scope corrections
from the reviews: (a) S-F9 — the deletion hazard materializes only in
shared-storage topologies (per-node file storage means node N's old binary never
sees node N+1's envelopes); the more likely mixed-version *read* failure is F-1,
which fails closed. (b) DS-F1's "second prune loop" (`dr.pruneReplicas`) is
refuted by D-M3's verified evidence: `buildDRExportFunc` (`cmd/sso-server/
build_app.go:482`) creates its own exports with no read path into the admin
Storage, so safety artifacts never reach the DR mount and the replicator prune
never sees them today — latent only, and the header-kind field is exactly what a
future replicator-side filter would need. Net: **runbook gate** — upgrade all
nodes first, disable `snapshot.retention.enabled` during a mixed fleet, no
replace restores in a mixed fleet. Ownership: release/devops authority, not a
code change beyond F-1.

**F-7 — Single-node safety net: DR never replicates safety artifacts.**
[D-M3; DS-F1 second half] A safety snapshot lives only in the primary node's
`./snapshots` dir; disk loss inside the rollback window loses the net. Runbook
note now (the M-3/D-M3 evidence is verified); a later iteration can replicate
safety-kind envelopes explicitly. Related: the safety artifact is a *new* copy
the DR loop will not re-create — unlike ordinary exports which the replicator
re-generates every 15 min.

**F-8 — Concurrent restores unserialized; one restore's rollback reverts
another's committed state.** [S-F4, DS-F5, D-I8 — dedup] No locking in
`restoreTracked`/`Restorer.Restore`; `operations.Start` only creates a record.
D2's convergence proof covers same-snapshot retries, not overlapping runs of
different snapshots. **Fix: single-flight gate** — reject `Restore`
(`FailedPrecondition`, zero writes) while a `snapshot_restore` operation is
`running` (the operations store can serve as the lock), or explicitly serialize;
runbook note. Regression test: concurrent A (injected failure + rollback) and B;
assert B is rejected up front or B's terminal state survives A's rollback.

**F-9 — D1 "zero writes before validation" is unimplementable as written.**
[DS-F4, Q-F5 — dedup, identical fix] The recursion guard and safety-source check
need the snapshot's kind *before* `operations.Start`, but the nil-snapshotter
check fires first and a safety-source restore on a snapshotter-less node
spuriously fails. **Fix: resolve kind via `Get` + `PeekEnvelope` pre-Start** —
which is exactly what F-1's header-only design enables (the orchestrator already
holds the raw bytes). F-1 and F-9 are mutually reinforcing; implement together.

**F-10 — Automatic unredacted full-state captures at rest: plaintext default +
retention-exempt + no TTL.** [S-F5, D-M5, P-F8 — dedup; conflict resolved in §3]
Default sealer `none` (plaintext JSON), capture is automatic on every replace
restore with a no-op redactor override (verified correct), retention-exempt with
no TTL, grows per retry. Contents include `password_hash`, `Connection.Config`
secrets, pairwise mappings, and `Client.Attributes["caep_receiver_auth"]` — the
last is a live SET-push bearer the redactor does *not* scrub even in the redacted
path (`redactClientSecrets` zeroes only `Secret`/`RAT` — verified). API surface
is clean (`Get` redacts, `List` headers only); disk and backup-pipeline surfaces
are the exposure. **Fix package: (a) safety TTL is a first-class D1 requirement
(auto-`Delete` after N days), not "later iteration"; (b) emit a prominent
audit/log line when capturing with `Algorithm == none`; (c) extend the redactor
scrub (or explicitly document as known-unsafe) to `caep_receiver_auth`; (d)
runbook: snapshot-dir permissions.** Decision needed on refusal-vs-warn (§3).

**F-11 — D2 "Phase A failure → zero deletions / stores equal pre-restore" is
unsatisfiable for menus.** [D-H2 — unique, verified] `replaceMenus` →
`SetMenus` replace semantics wipe the destination tree in Phase A (category 8 of
10); an injected `AssignRoles` failure occurs after menus are already wiped. The
count assertion passes (wipe counts as `Updated`, not `Deleted`) while the
store-equality assertion fails — a test would catch the contradiction. **Fix:
rewrite the Phase-A failure row as "old ∪ inserts, minus any menus already
replaced; zero *prune* deletions; retry-safe because all writes are replayable
upserts"** — and keep menus in Phase A (the design correctly refuses to invent
`pruneMenus`). DS-F6 is the sibling constraint: "stores equal pre-restore" also
requires a quiesced node; concurrent-write reversion must be pinned by a test,
not just documented.

**F-12 — Rollback re-apply is always `ModeReplace`, even for failed
merge/overwrite restores.** [Q-F8 — unique] A failed merge restore rolled back
via replace is more destructive than the failed operation itself. Needs a
semantics pin (validation or explicit ModeReplace-with-confirm on the rollback
path) plus a runbook sentence.

**F-13 — Stale caches on failure paths.** [DS-F2 — unique] D2's Phase-B-failure
state (target ∪ partial deletes) is exactly what TTL caches misrepresent; no
invalidation fires on failure. **Fix: fire `InvalidateRestoredControlPlane()` on
every non-dry-run terminal state** (already fail-open; verified flush covers
tenant suspension/residency caches).

**F-14 — Crash mid-restore leaves a permanently `running` operation.** [DS-F3 —
unique] Operations FileStore has no boot reconciliation of `running` records;
D3's rollback is in-process only. Retry convergence (D2 supersets) still holds —
the design should say so. Recovery sequencing for zombie operations belongs in
the design or runbook.

**F-15 — Restore is a credential-rewriting, governance-bypassing primitive.**
[S-F6 — unique] Verified: tenant `Status`/residency are in the snapshot body and
rewritten; the invalidator flushes suspension caches, so restoring an old
snapshot **immediately re-activates a suspended tenant** and rewinds residency.
`upsertUser` rewrites `password_hash` wholesale — a restore of a snapshot older
than a rotation **re-enables a rotated-away credential**; D3's rollback does the
same with capture-time hashes. MFA/WebAuthn bindings and signing keys are not in
snapshots (the only limiting factor). **Fix package: (a) design must state these
properties explicitly (governance state is part of the backup); (b) runbook +
audit: mandate rotation after restoring snapshots older than the
known-compromise horizon; (c) explicitly consider rollback preserving live
`password_hash` when it changed after capture (mirror `preserveClientSecrets` —
pattern and test precedent exist).** (c) is a security/product decision (§3).

**F-16 — `PruneOldest` Get-error semantics undefined; two reviews conflict.**
[S-F8(2), Q-F6 — conflict resolved in §3] See ledger.

### Low

**F-17 — Silent client-side downgrade: `rollback_on_error`/`auto_safety_snapshot`
dropped by old servers with no signal.** [P-F2 — unique] Client believes rollback
is armed; gets a plain replace restore. Shares the F-6 upgrade window; document
in the runbook and openapi notes.

**F-18 — Tri-state asymmetry and error message self-explanation.** [P-F4 —
unique] `nil auto_safety` = server default vs `nil rollback` = false;
`rollback=true` + omitted auto-safety fails validation. Document; make the error
message self-explanatory.

**F-19 — SDK-direct callers: both-flags-true silently no-ops on a bare
`Restorer`.** [S-F7, P-F5 — dedup] `builtin.ApplyRestore` and
`SnapshotRestorerAdapter.RestoreByID` call `Restorer.Restore` directly; validation
passes, neither capture nor rollback occurs. **Fix: normalize
`AutoSafetySnapshot` in the orchestrator, not in `Restorer`** (P-F5's fix);
document both flags as orchestrator-only intents. Test: `prepareRestore` on a
bare `Restorer`.

**F-20 — `Committed` semantics contradiction on bootstrap-advance failure.**
[S-F8(1), Q-F9 — dedup] API section says `Committed == true`; failure table says
`false` on every failure path. Fix table wording to "`Committed == true` *with
error*" (data applied, tracker not advanced) and pin with a test.

**F-21 — `PruneOldest(keep<=0)` change is unreachable in stock wiring.**
[D-L6, P-F7 — dedup] Boot rejects `keep <= 0` (`build_app_cluster.go:440`,
verified); the D1 "keep=0 no longer deletes everything" behavior only affects
SDK-direct callers. Doc comment and acceptance test must say so (the D1
acceptance pinning `keep=0` skip runs SDK-direct).

**F-22 — `advance_bootstrap` is a silent no-op on the admin RPC in stock
wiring.** [D-M4 — unique] `buildSnapshotterRestorer` never sets `Restorer.Tracker`
(verified); flag yields observable `BootstrapAdvance{NoOp:true}` but only after
the fact. Document in openapi/runbook; optionally surface the reason in the REST
response.

**F-23 — Clock rollback reorders retention.** [DS-F9 — unique] Kind-skip
incidentally protects safety artifacts; note in runbook, no code change.

### Info

- **Pre-existing orphan leak**: `pruneRoles`/`pruneAssignments` iterate the
  snapshot's roster; a destination client deleted by `pruneClients` orphans its
  role/assignment rows (no FK cleanup). Unchanged by D2; the design's
  data-ownership story should mention it. [D]
- **Failed restores emit no audit event; the rollback
  `EventSnapshotRestored` hardcodes `OutcomeSuccess`.** [DS-F10]
- **No directory fsync after rename in either file store.** [DS-F11]
- **Retention skip reads full envelopes per victim** (`Storage.Get` is
  whole-file); "O(victims), no decryption" is CPU-accurate, each read is a full
  envelope. Fine at 6h cadence; a header-only `Peek`-style storage method is the
  later optimization. [D-L7]
- **`dr.pruneReplicas` kind-unawareness is latent only** — safety artifacts
  never reach the DR mount (see F-6 conflict resolution). [D-M3 vs DS-F1]
- **Restore RPCs are not serialized** (F-8) and retention can delete an
  envelope a concurrent restore is `Load`-ing (restore fails cleanly, operation
  marked failed) — pre-existing, documented. [D-I8]

## 3. Trade-off ledger

| # | Conflict | Options | Recommendation | Consequence | Decision owner |
|---|---|---|---|---|---|
| T1 | F-1: bump `SchemaVersion` to "3" vs header-only `kind` | (a) schema bump: explicit fail-closed rejection, but old nodes cannot restore *any* new export; (b) header-only `kind`: bodies byte-identical, additive claim becomes true | **(b)** — both security and database reviews independently converge; enables F-9's fix | Old binaries still cannot roll back safety artifacts (deletion hazard only, F-6); no codec break | Maintainers (wire-compat regression boundary, AGENTS.md §1) |
| T2 | F-2: rollback minimality vs completeness | (a) rollback touches only failed-restore scope (exclude ∪ source-category complement); (b) rollback always replaces everything captured | **(a)** — matches design intent, closes the netpolicy rewind | Rollback may not revert concurrent writes in excluded categories; that is the documented non-transaction limitation | Maintainers + security authority (netpolicy rewind is a data-plane safety issue) |
| T3 | F-3: error transport | (a) error-with-response (design; impossible per gRPC spec); (b) `status.WithDetails` report + `operationFailureError` + operation_id in message text (house pattern) | **(b)** | REST clients get operation_id via message/details; grpc-gateway renders details into REST bodies | Maintainers (contract amendment to the design, C6/C7 per protocol review) |
| T4 | F-10: capture under `encryption: none` | (a) refuse capture unless explicitly opted out (fail-closed); (b) prominent audit/log warning only (fail-open, matches AGENTS.md fail-open-for-audit pattern) | **(b) warn + audit meta now, with safety TTL as a first-class requirement; revisit (a) if telemetry shows silent plaintext capture** | Plaintext credential dumps remain possible on operator-chosen defaults; bounded by TTL and runbook | Security authority + CTO (TTL duration is a product/risk decision) |
| T5 | F-16: `PruneOldest` Get-error semantics | (a) skip (keep) victim on any Get error — protects the safety net (S); (b) delete-through — matches existing `TestPruneOldest_DeleteErrorContinues` (Q) | **(a) for transient errors; preserve delete-through only for `ErrSnapshotNotFound`** (concurrent-delete race). Split the rule explicitly; extend the existing test rather than flip it | Half-written/corrupt envelopes: still deletable by name per design (temp+rename means readers never see partial files); undecodable-but-present envelopes are skipped with a log | Maintainers |
| T6 | F-15: rollback and `password_hash` | (a) rotation runbook only; (b) rollback preserves live `password_hash` when changed after capture (mirror `preserveClientSecrets`) | **(b) at least for rollback; runbook for plain restore of old snapshots** | Live credentials survive rollback (fixes login-break and compromised-credential revival); restore-of-old-snapshot hazard remains documented, not code-fixed | Security authority + product (behavioral change to rollback semantics) |
| T7 | F-8: concurrent restores | (a) single-flight reject while a restore op is `running`; (b) document maintenance-window assumption only | **(a)** — cheap, closes the rollback-reverts-committed-restore hole | Serialized restores; retry scripts get `FailedPrecondition` instead of interleaving | Maintainers (architect) |
| T8 | F-12: rollback mode for failed merge/overwrite | (a) rollback always `ModeReplace` (design); (b) pin ModeReplace + require the same `Confirm` on the rollback path | **(b) pin semantics + runbook sentence**; (a) is acceptable only with explicit documentation | Merge-restore rollback is more destructive than the failed op; operators must know before arming | Maintainers |
| T9 | F-6: rolling upgrade | (a) rely on runbook; (b) code gate (refuse replace restore when fleet version unknown) | **(a)** — no fleet-version signal exists in the codebase; a code gate is speculative | Mixed-fleet window is a release-discipline requirement: upgrade all nodes first, disable retention until uniform, no replace restores in the window | Release/devops authority (runbook gate; not citable as a code control) |
| T10 | F-11: Phase-A acceptance | (a) scope equality assertion to non-menu categories; (b) move menus to Phase B with invented `pruneMenus` | **(a)** — (b) violates "never invent `pruneMenus`" | Acceptance test becomes implementable; menus remain replace-semantics (documented) | Maintainers |

## 4. Preconditions (amendment set — must land in the same change)

Design amendments (contract-level):
1. **F-1**: `kind` header-only; `Snapshot.Kind` `json:"-"`; bodies byte-identical; document that safety artifacts are new-binary-only in both retention and load.
2. **F-2**: rollback exclude = original `Exclude` ∪ (source snapshot's category complement).
3. **F-3**: rollback report via `status.WithDetails` + `operationFailureError` on both failure paths; `operation_id` in status message text; openapi notes updated (protocol C6/C7 deviations amended in the same change).
4. **F-9**: kind resolution via `Get`+`PeekEnvelope` before `operations.Start`; nil-snapshotter check ordered after kind resolution.
5. **F-11**: Phase-A failure row and acceptance rewritten (old ∪ inserts, minus replaced menus; zero prune deletions).
6. **F-20**: `Committed` wording fixed; **F-16**: skip-on-transient-Get-error rule specified; **F-21**: `keep<=0` documented SDK-direct-only; **F-18**: tri-state asymmetry documented; **F-19**: orchestrator-only normalization; **F-12**: rollback-mode pin.

Contract docs in the same change (AGENTS.md §5): `docs/error-codes.md` (new `Err*`), `docs/openapi.yaml` (fields 7/8, error notes), `docs/dr-framework.md` (safety artifacts, TTL, single-node net). Proto: `RestoreSnapshotRequest.rollback_on_error = 8` + `auto_safety_snapshot = 7` (all field numbers verified free; no `reserved` ranges).

Executable acceptance checks (P0, same change — from the design's suite plus review-gap tests):
- Golden-marshal test: no `kind` key in the body after `Save`; `PeekEnvelope` returns it; strict-decoder round-trip (old-reader simulation) succeeds [F-1].
- Rollback-scope test: netpolicy excluded from source, changed mid-window, survives rollback [F-2].
- Gateway + gRPC tests: REST error body for a rolled-back restore contains `operation_id`; errdetails carry it [F-3].
- Single-flight test: concurrent A/B — B rejected or B's state survives A's rollback [F-7/F-8].
- Fault-injection suite (requires the new `failAfterN` seam [F-4]): Phase-A zero-delete (amended for menus [F-11]), Phase-B convergence, retention skip, recursion guard, nil-snapshotter zero-write, invalidator count == 2, rollback-failure wording, live-secret preservation on rollback.
- Existing counts unchanged: `TestRestore_Replace_*`; `TestPruneOldest_DeleteErrorContinues` extended, not flipped [T5].
- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./interfaces/snapshot/... ./interfaces/grpcserver/grpcadmin/... -race`; rollback tests with `-count=10`; `go test ./test/ -run TestE2E -v`; `make ci` green on the change's base (the current 14-file fmt drift is pre-existing — QA verified none are in snapshot/grpcadmin/operations — and must not be attributed to this change).

## 5. Rollback triggers, monitoring, exclusions, residual risks

Rollback triggers (feature, per database review §4.4): before downgrading, delete all safety-kind artifacts with the new binary's `Delete` RPC (old binaries cannot delete-by-kind; retention-based deletion may also eat ordinary snapshots — do not rely on it). Fleet-upgrade ordering is the hard operational gate: upgrade all nodes first; no replace restores during a mixed-version fleet; `snapshot.retention.enabled` disabled until uniform.

Monitoring (to add in the same change or runbook): audit meta on safety capture incl. sealer algorithm (F-10/T4); per-node safety-artifact count and age (TTL follow-up); operation `running`-record age (zombie detection, F-14); per-replace storage growth (D1 adds one full snapshot per replace — currently unmeasured, §6).

Explicit exclusions (not in scope, stated to prevent scope creep): no schema/envelope-version bump (T1); no `pruneMenus` (F-11); no shared-storage backend work; no replicator changes for safety artifacts (F-7 is runbook now); no fleet-version code gate (T9); no transactions in the restore path (D2 remains an operational ordering guarantee, correctly not-a-distributed-transaction — verified: `interfaces/snapshot` contains zero transaction use); SDK-direct restore paths (`builtin.ApplyRestore`, `RestoreByID`) get documentation only (F-19).

Residual risks (accepted, with owners): capture non-atomicity under concurrent writes (quiesce requirement; design claims match code — verified) — operator discipline; rollback-is-also-not-a-transaction (partial rollback possible; honest messaging only) — documented; secrets-at-rest on retention-exempt artifacts bounded only by TTL once adopted (T4) — security authority; single-node safety net (F-7) — devops runbook; retention-versus-concurrent-load deletion (pre-existing) — accepted; `upsertClient` preserve-secrets read-modify-write race (pre-existing, unchanged by D2) — accepted.

## 6. Missing reviews and evidence

Supplied: protocol, database architect, distributed engineer, security, QA. **Not supplied** (do not assume they ran): performance, SRE/devops, compliance, product/PM, CTO, tech-lead/staff, business-analyst, UX. No supplementary report is release proof.

Evidence gaps that block a "ready" verdict on operational claims (all **Unknown**, from the database review's §5 — nothing in the repo measures them):
- Envelope size distribution by category mix; per-replace storage growth; `List` RPC p95 at N≥1000 envelopes; retention-tick duration at victim counts.
- Expected rollback-window duration (the TTL follow-up needs a number).
- Restore RTO/RPO and drill cadence: `docs/dr-framework.md` targets are proposals, not measurements; no evidence of rollback-path recovery testing — the fault-injection suite will be the first coverage.
- No gRPC-level Restore test exists today (verified); the P0 suite is therefore net-new test surface, not regression coverage.

Narrow next actions to decide:
1. Maintainers: approve the amendment set (§4) and the T1/T2/T3/T5/T7/T8/T10 resolutions; these are design-contract decisions, not owner-delegable.
2. Security authority + CTO: T4 (TTL duration, refusal-vs-warn) and T6 (live-hash preservation on rollback); also confirm the F-15 runbook/audit language.
3. Release/devops authority: T9 fleet-upgrade ordering and F-6/F-7 runbook gates (these are process requirements; the codebase has no fleet-version signal).
4. Implementation: land the amendment set + P0 suite in one change, then re-run the QA gate set (build/vet/maintainability/architecture/race/E2E/`make ci` on the change's base).
5. Re-review after implementation: the P0/P1 test results, especially F-1 golden-marshal, F-2 rollback-scope, F-3 gateway error transport, F-8 single-flight — these are the acceptance evidence for the amended claims.

No sign-offs, deadlines, or approval status are fabricated here; none exist in-tree for this design.
