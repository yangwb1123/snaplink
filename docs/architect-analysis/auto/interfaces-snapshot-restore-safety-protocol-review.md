# Protocol Review: interfaces/snapshot — Restore safety design (wire-contract and identity-data invariants)

> Advisory review of `docs/auto/interfaces-snapshot-restore-safety-design.md` at
> commit `3be9b3d6` (design staged; no code modified by this review). All
> evidence labels follow the house standard: **Verified** (read at the cited
> symbol/path in this revision), **Partial**, **Missing**, **Proposed**.
> Static evidence only — no `go build`/`go test`/`make ci` were executed
> because this review changes no code; the design's own verification plan is
> reproduced in §4. The design's own evidence claims were re-checked against
> the same revision; every claim this review relies on is cited below.

## 1. Protocol/profile scope and authoritative references

The design is **not** an OAuth 2.0 / OIDC / CAEP-SSF / SAML / SCIM / WebAuthn
protocol change. Snapshot/restore is an operator-facing disaster-recovery
surface; the standards and contracts actually in scope are:

| # | Contract | Authoritative reference |
|---|---|---|
| S1 | Admin gRPC/REST wire contract, STABLE package | `proto/admin/v1/snapshots.proto` (header: breaking changes need 6-month deprecation), `docs/adr/ADR-0008-proto-versioning.md` rule 1, `docs/openapi.yaml` `/api/v1/admin/snapshots/{id}:restore` |
| S2 | gRPC status semantics (message/error mutual exclusion) | gRPC core spec: a unary RPC returns either a response message with OK status or a non-OK status; on non-OK the response message is not delivered to the client |
| S3 | OAuth 2.0 client authentication credentials | RFC 6749 §2.3.1 (`client_secret`), RFC 7592 §2.2 (registration access token) |
| S4 | House security invariants | `AGENTS.md` §3 (oracle-safe responses, fail-closed/fail-open classification), §4 (audit metadata, operations ledger) |
| S5 | DR operational contract | `docs/dr-framework.md` §4/§6 (snapshot scope: "Signing keys, sessions, and tokens are NOT part of" snapshots) |

Scope statement: the design touches no request binding, redirect, token,
claims, replay, or discovery surface of the OAuth/OIDC runtime. Discovery
metadata (`interfaces/sso/server_discovery.go`) does not advertise admin
snapshot endpoints and does not change. The protocol-relevant surface is the
admin RPC contract (S1/S2) plus the identity-data invariants restore can
violate (S3/S4/S5).

## 2. Compliance matrix

| # | Section / requirement | Level | Implementation evidence (this revision) | Status | Deviation | Test |
|---|---|---|---|---|---|---|
| C1 | ADR-0008 rule 1: additive v1 proto fields, numbers outside `reserved` | must | **Verified**: `RestoreSnapshotRequest` uses 1–6 (7/8 free), `RestoreSnapshotResponse` 1–3 (4 free), `RestoreReport` 1–5 (6/7/8 free), `SnapshotMeta` 1–9 (10 free); no `reserved` ranges in `snapshots.proto`/`operations.proto` | Complies | None | proto compile + regenerate; old-shape request (fields absent) accepted by new server |
| C2 | proto3 unknown-field tolerance (old client ↔ new server) | must | **Verified**: new fields are `google.protobuf.BoolValue`/scalar; absent = nil = default; grpc-go discards unknown fields | Complies | None (see F2 for the reverse direction) | tri-state gRPC test: nil/`false`/`true` |
| C3 | Envelope additive JSON field (`kind`), `EnvelopeVersion` stays `"1"` | must | **Verified**: `SealedEnvelope` (`interfaces/snapshot/pipeline.go`) has no `kind` today; `Load`/`PeekEnvelope` use plain `json.Unmarshal` → unknown fields ignored; missing kind = normal | Complies | Semantic downgrade: old binaries cannot see `kind` (F3) | round-trip `PeekEnvelope(kind) == snap.Kind` after `Save`; old envelope (no kind) still deletable |
| C4 | `Snapshot.SchemaVersion` stays `"2"` with additive `Kind` field | must | **Verified**: `Snapshot` (`interfaces/snapshot/snapshot.go`) has no `Kind` today; JSON codec round-trips struct fields wholesale | Complies | None | capture round-trip category-equality test |
| C5 | Restore must not wipe or transport live client credentials (RFC 6749 §2.3.1, RFC 7592) | must | **Verified**: `Client.Secret`/`RegistrationAccessToken` are `json:"-"` (`restorer_clients.go`); `upsertClient` → `preserveClientSecrets` backfills from the live store; design extends the same guarantee to the rollback re-apply | Satisfied | None; design correctly pins it with a rollback-preserves-live-secrets test | existing `restore_preserve_secret_test.go`; add rollback variant |
| C6 | Oracle-safe error surface | must (house) | **Verified**: Restore requires `admin:write` (openapi `bearerAuth`); `mapSnapshotError` distinguishes NotFound/FailedPrecondition/DataLoss/Internal; not an unauthenticated oracle | Complies | `ErrUnsupportedRestore` currently lands in the `Internal` default branch (`admin_snapshots.go` `mapSnapshotError`) — design fixes to `FailedPrecondition`; `docs/error-codes.md` has **no** snapshot codes today (Verified via grep) — both belong in the same change | capability-preflight zero-write test; gRPC code assertions |
| C7 | Failure-context transport on the error path | must (house pattern) | **Verified**: `operationFailureError` (`admin_paginate.go:318`) attaches `errdetails.ErrorInfo{operation_id, operation_url}` via `status.WithDetails` — the established way to carry failure context | Deviation in design (F1): "error-with-response" contradicts gRPC semantics; use status details instead | Design must be amended | status-details test asserting the rollback report rides the error |
| C8 | Fail-closed classification | must (house) | **Verified**: design D1 fails closed (`FailedPrecondition` before `operations.Start`, zero writes) when snapshotter unwired; D3 validation reads the raw `AutoSafetySnapshot` **before** D1 defaulting; rollback failure never claims success | Complies | None | nil-snapshotter zero-write test; validation-ordering test |
| C9 | Operations ledger: compensations already on the wire | must (house) | **Verified**: `operations.AddCompensation` (`platform/lifecycle/operations/operations.go:153`); `Operation.Compensations` JSON; proto `AdminOperation.compensations = 7` (`proto/admin/v1/operations.proto`); projected by `operationToProto` (`admin_paginate.go:296–302`) | Complies; design's "no new operations API" claim is correct | None | compensation-step assertion in rollback test |
| C10 | Audit: metadata via `audit.SetMeta` path, no new event types | must (house) | **Verified**: `recordAdminMeta` exists (`admin_paginate.go:209`); `EventSnapshotRestored` used by `restoreTracked`; design extends meta keys only | Complies | None | audit-meta assertions in D1/D3 tests |
| C11 | Snapshot scope excludes sessions/tokens (S5) | must (house) | **Verified**: `Restorer` fields cover only stores + `Invalidator` + `Tracker` (`restorer.go`); DR doc states sessions/tokens excluded | Complies | Restore orphans live refresh/authorization state after client deletion — fail-closed at token time (unknown client → `invalid_grant`), documented DR caveat | E2E regression only |
| C12 | Retention semantics | must (house) | **Verified**: `PruneOldest` (`interfaces/snapshot/retention.go`) is pipeline-free, `snap_`-prefix filtered, `keep <= 0` deletes everything; wired on a background loop (`cmd/sso-server/serverbuildstore/build_background.go:189`) | Complies with design | `keep <= 0` no longer flushes when safety artifacts exist — doc comment + runbook must say the flush path is the `Delete` RPC (F7) | keep=0 keeps safety; Delete removes |

## 3. Findings

### F1 — Medium (design correctness; S2) — "Error-with-response" is not a gRPC-legal delivery mechanism

**Location**: design D3, "What could break the design" item 3 and the
orchestration step 2; `restoreTracked` rollback path.

**Claim checked**: "Returning a non-nil response alongside the error works on
gRPC, but the REST gateway drops the message body on error."

**Finding**: per the gRPC core spec, a unary RPC delivers either a response
message with OK status or a non-OK status; on non-OK the response message is
not delivered to the client. grpc-go enforces this: when a handler returns
`(reply, err)` with `err != nil`, the reply is discarded and only the status
error is sent. The rollback report is therefore lost on **both** transports,
not just REST. The design's own mitigation ("REST clients must read the
outcome from `GetOperation(operation_id)`") is in fact the only channel for
gRPC clients too.

**Impact**: operators and automation cannot rely on the failing RPC's payload;
the design's API-surface description would mislead the implementer into
building a delivery path that never reaches a client.

**Corrective behavior**: use the house pattern from `operationFailureError`
(`admin_paginate.go:318`): attach the rollback outcome (`RestoreReport` or a
small `RollbackState{rolled_back, safety_snapshot_id, committed}` message) as a
`status.WithDetails` detail on the failing status. grpc-gateway renders error
details into REST error bodies, so both transports carry it; `GetOperation`
remains the durable source of truth via `ResultJSON`. Amend D3 wording
accordingly ("neither gRPC nor REST delivers the report on the error path").

### F2 — Medium (interoperability/downgrade; S1) — Silent client-side downgrade for the new request fields

**Location**: design D1/D3 API surface (`auto_safety_snapshot = 7`,
`rollback_on_error = 8`); `proto/admin/v1/snapshots.proto`.

**Finding**: new-client → old-server requests drop the unknown fields
silently (proto3 semantics). A client that sends `rollback_on_error: true`
against a node still running the old binary gets a plain replace restore —
no safety capture, no rollback, and no signal in the response or error. The
design flags the *retention-side* downgrade hazard (F3) but not this
client-side silent downgrade, which is the same mixed-version window.

**Impact**: automation believing rollback is armed can leave a half-applied
replace restore without the undo artifact it expects.

**Corrective behavior**: state in `docs/openapi.yaml` and the DR runbook that
capture/rollback guarantees require the fleet on the new version; for
automation, recommend a capability probe (server version or a
`kind`-aware `Get` response) before arming `rollback_on_error`.

### F3 — Medium (availability/DR; C3) — Rolling-upgrade retention hazard (design-flagged, endorsed)

**Location**: design D1 "What could break the design" item 1; `PruneOldest`
wiring at `build_background.go:189`.

**Finding**: an old binary running the retention loop treats safety envelopes
as ordinary (`kind` is invisible to it) and deletes them mid-rollback-window.
**Verified**: `PruneOldest` is pipeline-free and deletes by name only
(`retention.go`), and the background loop runs continuously. No wire-version
guard exists for retention, and the design correctly declares one out of
scope.

**Impact**: the undo artifact can vanish during the exact window it exists
for, on mixed-version fleets.

**Corrective behavior**: the design's runbook mitigation ("rollback-window
operations run on the new version") is the right bound; tie it to F2 so both
downgrade hazards share one documented upgrade window.

### F4 — Low (usability; C2) — Tri-state asymmetry between the two BoolValue fields

**Location**: design D1/D3 gRPC surface; `restoreTracked` validation.

**Finding**: `auto_safety_snapshot` `nil` = server default (capture on
replace), but `rollback_on_error` `nil` = `false`; and `rollback_on_error:
true` with `auto_safety_snapshot` *omitted* is a `FailedPrecondition` even
though the server default would capture. The fail-closed posture (rollback
requires an *explicit* `true`) is defensible and consistent with AGENTS.md,
but the asymmetry is a real operator trap: "I asked for rollback, why did it
fail?" with a message that must explain itself.

**Impact**: operator confusion and failed automation on a deliberately strict
validation path.

**Corrective behavior**: document both nil semantics explicitly in
`docs/openapi.yaml` and make the `FailedPrecondition` message name the
requirement (`rollback_on_error requires auto_safety_snapshot=true`), not just
the sentinel.

### F5 — Low (SDK semantics; C1/C4) — Restorer-level normalization lies to SDK-direct callers

**Location**: design D1 "API surface" (normalization in `prepareRestore`);
`platform/bootstrap/builtin/builtin.go` `ApplyRestore` (line 71) and
`cmd/sso-server/serverbuildstore/build_network_snapshot.go`.

**Finding**: normalizing `AutoSafetySnapshot = mode==replace && !dryRun`
inside the Restorer mutates `opts` for SDK-direct callers that never capture
(the Restorer has no Pipeline/Storage). `ApplyRestore` would see
`AutoSafetySnapshot == true` with no capture performed — the flag reads as a
promise the SDK path does not keep.

**Impact**: a future SDK consumer keying on the normalized flag assumes an
undo artifact exists. Bounded today (the field is new), but the seed of a
false invariant.

**Corrective behavior**: perform the defaulting in the orchestrator
(`restoreTracked`) instead, or document the field as orchestrator-consumed
intent only; keep the D3 validation-before-defaulting ordering either way.

### F6 — Info (concurrency) — Concurrent restore RPCs are not serialized; D2's convergence assumes a single writer

**Location**: design D2 "Failure modes" (concurrent admin write row).

**Finding**: two concurrent replace restores interleave both phases; the
Phase B keep-set of run 1 can prune records staged by run 2. This hazard is
unchanged from today, and the design's maintenance-window assumption covers
admin writes, but the convergence proof in D2 ("same-snapshot retry
converges") silently assumes exclusivity.

**Corrective behavior**: one sentence in the runbook (concurrent restore RPCs
are not serialized; run one restore at a time), or gate on an already-running
`snapshot_restore` operation in the operations store — a cheap single-flight
that needs no new API.

### F7 — Info (contract change) — `PruneOldest` `keep <= 0` semantics change

**Location**: design D1 storage model; `retention.go`.

**Finding**: today `keep <= 0` deletes everything; with the design it leaves
safety artifacts behind. The doc-comment update is planned, but the callers
(`build_background.go` keep validation) should be re-read in the same change,
and the runbook must name the `Delete` RPC as the flush path for safety
artifacts.

### F8 — Info (secrets at rest) — Retention-exempt artifacts carry identity secrets

**Location**: design D1 "What could break" item 3.

**Finding**: **Verified** — `Connection.Config` (map, no JSON tags;
`domains/connections/connections.go:32`) carries upstream IdP secrets
(OIDC client secrets, SAML private keys under the heuristic key set in
`redactor.go:153`), and `User.Attributes` carries `password_hash`. The
explicit no-op redactor override is correct (`effectiveRedactor` per-call
override wins, `snapshotter.go:374`), so the safety artifact is restorable —
and necessarily secret-bearing. Same trust domain as ordinary backups, but
now exempt from retention.

**Corrective behavior**: the design's runbook hygiene (explicit `Delete`
after the rollback window; TTL as follow-up) is adequate; keep it.

## 4. Priority conformance tests, declared unsupported features, certification evidence

### Priority conformance tests (land in the same change, fault-injection style)

1. **D2 Phase A mid-failure**: injected category failure → error,
   `Committed == false`, all `Deleted == 0`, stores equal pre-restore (old
   superset). This is the test the design correctly notes no committed test
   pins today (**Verified**: `restore_modes_test.go` covers full-success
   counts and dry-run no-mutation only).
2. **D2 Phase B mid-failure**: injected `ClientStore.Delete` failure → inserts
   + partial deletes; same-snapshot retry converges to the once-successful
   terminal state (byte-equal).
3. **D2 capability preflight**: missing pairwise `Lister`/`Deleter` →
   `ErrUnsupportedRestore` → `FailedPrecondition` (gRPC), zero writes.
4. **D1 kind integrity**: `PeekEnvelope(kind) == snap.Kind` after `Save`;
   old envelope without `kind` remains deletable; `keep=0` keeps safety,
   `Delete` RPC removes; nil-snapshotter `FailedPrecondition` zero-write;
   no-op-redactor-override pin (capture restorable even with
   `DefaultExportRedactor` wired); recursion guard (safety-source restore
   produces no second artifact).
5. **D3 rollback**: store equality, `Compensations[0].state == succeeded`,
   invalidator probe count == 2, error text contains "rolled back to safety
   snapshot", `RolledBack == true` / `Committed == false`, audit
   `rolled_back=true`, rollback preserves live client secrets; rollback
   validation (no net / safety source) zero-write; rollback-failure "state
   unknown" messaging; `RollbackOnError=false` backward compatibility.
6. **Wire (new, per F1/F2)**: rollback report rides the error via status
   details (not as a discarded reply); old-shape request (fields absent) →
   server defaults; explicit `false` vs nil tri-state over gRPC and REST.
7. **Regression**: existing `TestRestore_Replace_*` count-identical success
   paths; dry-run reports `Committed == false` with `DryRun == true`.

### Declared unsupported features

- TTL / auto-expiry of safety artifacts (explicit `Delete` is the flush path;
  follow-up iteration).
- Quiesce/lock for capture atomicity (capture is not a transaction; rollback
  is not a transaction either — a second two-phase replace with honest "state
  unknown" messaging on failure).
- Wire-version guard for retention (mixed-version window handled by runbook,
  F2/F3).
- Orchestration for SDK-direct callers (`builtin.ApplyRestore`,
  `build_network_snapshot.go`): `Report.Committed/RolledBack/SafetySnapshotID`
  fields only; no capture, no rollback.
- Serialization of concurrent restore RPCs (F6).

### Certification evidence

No OIDF or other certification is claimed for this surface, and none exists
in-tree to cite. The snapshot admin API is an operator surface, not an
OIDF-certifiable protocol surface; the design introduces no new OAuth/OIDC
wire behavior, so no certification delta exists. Any future certification
claim must cite a published current result.

### Remaining evidence gaps

- No executable run of the design's verification plan in this review (no code
  changed; gates apply to `.go` edits).
- `grpc-go`'s reply-discard-on-error behavior (F1) is asserted from the gRPC
  spec and the repo's own `operationFailureError` pattern; a status-details
  test (item 6) converts it into executable evidence.
- The design's claim that no server node-identity config exists in
  `cmd/sso-server` wiring (empty `SourceNodeID`) was spot-checked, not
  exhaustively verified; harmless either way (the field is optional).
