# Design: audit-verify real-relay trust-path test (--anchor-hash against real governance-relay batches)

- Requirements spec: `docs/architect-analysis/cmd-sso-ctl-auditverify-relay-trust-path-requirements.md` (R1–R3, AC-1..AC-5)
- Module: `cmd/sso-ctl/auditverify` — **test-only change** (`relay_trust_test.go`); zero production edits
- Status: design (every claim in the requirements evidence re-verified against HEAD; verdicts in §0)

## 0. Evidence verification — every untrusted claim re-checked

| Evidence claim | Verified reality (file:line) | Verdict |
|---|---|---|
| `main.go` `--anchor-hash` docstring names "a relayed batch's first event" | `cmd/sso-ctl/auditverify/main.go` docstring: "…or a relayed batch's first event — NOT a checkpoint file"; `Run` dispatches to `verifyAnchoredSegment` when `anchorHashSet`; exit contract 0/1/2; empty value and `--checkpoint` coexistence are misuse (exit 2, `checkMisuse`) | Confirmed |
| `segment.go` `verifyAnchoredSegment`/`normalizeSegmentOrder`: empty→1, single `VerifyChainSegment` call, `segment verified:`/`chain BROKEN:` output | `segment.go` — empty segment → exit 1 ("cannot verify an empty segment"); `normalizeSegmentOrder` (cases a/b/c) then exactly one `audit.VerifyChainSegment(events, anchor)`; success `segment verified: %d event(s), anchored=%s, head=%s`; failure `chain BROKEN: %v` exit 1; truncated → `prefix verified` exit 1 | Confirmed |
| `segment_test.go:132` `TestRun_Anchor_RelayShapedBatch` — synthetic window, pins without-anchor `chain break at index 0` | Function is exactly at line 132; uses `midChainWindow(t, 6, 2, 5)` (synthetic in-memory chain); with anchor → 0, without → 1 with `chain break at index 0` | Confirmed — synthetic, not relay output (the gap this design closes) |
| `managed_relay.go` `ManagedRelayFactory`/`runOnce` → `Relay.RunOnce` | `infrastructure/auditgovernance/managed_relay.go:45` (`ManagedRelayFactory`), `:189` (`runOnce`), `:200` (`runner.Relay.RunOnce(ctx)`); `relay.go:137` `RunOnce` = `ClaimOutbox` → `deliver` → `CompleteOutbox` | Confirmed |
| `event_types.go:15` `EventTokenIssued = "token_issued"` | `platform/audit/auditspi/event_types.go:15` — exact line | Confirmed |
| L1 aggregation absent; only OpenFGA-style `aggregate_type/id/version` in `http_client.go:194-196` | `infrastructure/auditgovernance/http_client.go:194-196` — `governanceEvent.AggregateType/AggregateID/AggregateVersion`; no L1 aggregation anywhere in `auditgovernance/` or `platform/audit/` | Confirmed — L1 is proposed, not implemented |
| `fact.go` gates the in-tx connector fail-closed to `login_failure` only | `infrastructure/auditoutbox/fact.go` `FactFromAudit`: non-`login_failure`/nil → `ErrClassNotPermitted`; tenant-less → `ErrFactNotTenantScoped`; `MemorySink.Record` (sink.go:39) records first then best-effort enqueues | Confirmed — a real relay batch cannot contain `token_issued` |
| `commerce.OutboxEvent` (store.go:74) carries no `PrevHash`/`Hash`; linkage is the fact's `audit_hash` | `domains/tenant/commerce/store.go:74` — `OutboxEvent` fields end at `CreatedAt`; no chain fields; `fact.go` `PayloadKeyAuditHash` = "links the fact to its single chain event" | Confirmed — the CLI-verifiable "relayed batch" is the chain segment reconstructed via `audit_hash` |
| `test/auditoutbox_governance_test.go` drives real managed relay batches but never the CLI; `test/` cannot import `cmd/` | `test/auditoutbox_governance_test.go` — real server + sqlite `WithTxAppender` + `ManagedRelayFactory` via `modules` manager + capture client; verifies via `auditexport.BuildExportBundle`/`VerifyExportBundle` + notary; header: "CLI-side evidence … lives in cmd/sso-ctl/auditexport/main_test.go (test/ cannot import cmd/)" | Confirmed — relay→CLI leg is the unclosed gap |
| Test helpers exist: `runVerify`, `writeEventsFile`, `chainedEvents`, `captureStdout/Stderr` | `checkpoint_test.go:133` (`runVerify`), `:60` (`writeEventsFile`), `main_test.go:174` (`chainedEvents`), `coverage_test.go:156/197` | Confirmed |
| Layer gate skips `_test.go`; downward imports precedented | `architecture_layer_test.go:147` — `strings.HasSuffix(path, "_test.go")` skips; `cmd/sso-ctl/{importcmd,hashcmd,snapshotcmd,generate}` already import `infrastructure/`/`domains/` | Confirmed |
| Chainer messages `chain break at index %d` / `hash mismatch at index %d` | `platform/audit/chainer.go` `verifyChainFrom` — both messages; `GenesisHash = ""` (line 141); `VerifyChainSegment` (line 172) seeds `prev` with the anchor | Confirmed |

**New findings beyond the evidence (shape the design):**

1. **`infrastructure/auditoutbox/fact_test.go:25` `TestFactFromAudit_RejectsNonLoginFailure` already pins `token_issued` → `ErrClassNotPermitted`** (table case `{"token_issued", …}`). AC-4's blocker pin therefore already exists upstream; the design keeps a one-call locality copy in `relay_trust_test.go` so the trust-path file is self-documenting and fails in place if the gate ever widens (both tests must fail together).
2. **`audit.NewMemorySink(0)` is safe**: `platform/audit/memory_sink.go:25` — `capacity <= 0` → `DefaultMemoryCapacity` (10,000), no eviction for a 6-event chain.
3. **`MemoryOutboxStore.ClaimOutbox` ordering is `CreatedAt`, then `ID`** (`memory.go` `eligibleLocked`) — `FactFromAudit` sets `CreatedAt = e.Timestamp`, so a sequential 6-event record yields deterministic batch splits evt-0..2 / evt-3..5. The recorder stamps `Timestamp = r.now()` per call, so timestamps strictly increase in practice; even a collision falls back to `ID` ordering.
4. **Recorder mutates the caller's `*audit.Event` in place** (`recorder.go` `Record`: Timestamp, then PrevHash/Hash stamped before the sink). The design still reads the chain back from the sink (`base.Query` + reverse, exactly `chainedEvents`) so the segment/anchors come from the authoritative stored form, not caller-side pointers.
5. **`captureStdout`/`captureStderr` cannot survive `os.Exit`** — `errorf`/`usageErr` exit the process directly. All three CLI legs must stay on the return-code paths (valid files, non-empty anchor, no `--from-url`, no truncation) — already true of every existing anchored test.

## 1. Goal and design overview

Close the G1 trust-path loop to the extent this tree can prove it: verify a **real relay-produced batch** through the existing `sso-ctl audit-verify --anchor-hash` CLI path, in-process, deterministically. Today the CLI's relay-shaped coverage is a synthetic slice (`segment_test.go:132`), and the real relay E2E never reaches the CLI (`test/` cannot import `cmd/`).

Data flow (no mocks; real Memory* implementations per AGENTS.md):

```text
audit.NewMemorySink(0)  ─┐
auditoutbox.NewMemoryOutboxStore() ─┤
auditoutbox.NewMemorySink(base, store, nil) ─┐   (record-first, fail-open enqueue)
audit.New(wired, audit.WithHashChain())      ─┘
        │ rec.Record ×6 (login_failure, tenant-scoped, IDs evt-0..evt-5)
        ▼
base sink: 6-event hash chain (evt-0.PrevHash="", evt-i.PrevHash=evt-(i-1).Hash)
store:     6 pending facts, Payload[audit_hash] = chain Hash (documented linkage)
        │ auditgovernance.NewRelay(store, capture, {Owner, BatchSize:3})
        │ RunOnce ×2 (the exact call managed_relay.go runOnce makes)
        ▼
batch1 = facts evt-0..evt-2  batch2 = facts evt-3..evt-5   (AC-5)
        │ reconstruct via audit_hash linkage
        ▼
segment = chain events evt-3..evt-5 (chain order), anchor = evt-2.Hash (= segment[0].PrevHash)
        │ writeEventsFile + runVerify
        ▼
AC-1: --anchor-hash → 0 "segment verified: 3 event(s), anchored=…, head=…"
AC-2: tampered file  → 1 "chain BROKEN: … hash mismatch at index 1"
AC-3: no anchor      → 1 "chain BROKEN: … chain break at index 0"
```

Why batch 2: it is a **mid-chain** window — `evt-3.PrevHash = evt-2.Hash ≠ ""` — which is exactly the boundary-anchored shape the `--anchor-hash` contract exists for (a relayed batch's first event carries a non-genesis `PrevHash`). Batch 1 is genesis-adjacent (`evt-0.PrevHash = ""`) and would pass the unanchored walk, defeating AC-3.

## 2. Concrete design

### 2.1 Files

```text
Create:
  cmd/sso-ctl/auditverify/relay_trust_test.go   (new; package auditverify)
  docs/architect-analysis/cmd-sso-ctl-auditverify-relay-trust-path-design.md  (this document)
Modify: none.  Delete: none.
```

### 2.2 Imports (all downward; `_test.go` is layer-gate-exempt at architecture_layer_test.go:147)

```go
import (
    "context"
    "errors"
    "fmt"
    "strings"
    "sync"
    "testing"

    "github.com/yangwb1123/snaplink/domains/tenant/commerce"
    "github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
    "github.com/yangwb1123/snaplink/infrastructure/auditoutbox"
    "github.com/yangwb1123/snaplink/platform/audit"
)
```

`auditoutbox` → `commerce` + `audit`; `auditgovernance` → `commerce`; no cycle; no package imports `cmd/`.

### 2.3 Test-local capture client (pattern: `test/auditoutbox_governance_test.go` `captureClient`)

```go
type relayCapture struct {
    mu  sync.Mutex
    got []*commerce.OutboxEvent
}
func (c *relayCapture) Publish(_ context.Context, e *commerce.OutboxEvent) (auditgovernance.Receipt, error) {
    c.mu.Lock(); defer c.mu.Unlock()
    c.got = append(c.got, e)
    return auditgovernance.Receipt{EventID: e.ID, TenantID: e.TenantID, Status: "accepted", AcceptedAt: e.OccurredAt}, nil
}
func (c *relayCapture) snapshot() []*commerce.OutboxEvent { /* locked copy */ }
```

The capture client plays the remote governance boundary (same role as the E2E's), so the relay takes its real production path: `ClaimOutbox` → `deliver` → `Publish` → `CompleteOutbox`. No httptest server is needed — `auditgovernance.Client` is the seam the shipped E2E uses; a `captureClient` is not a mock of Snaplink internals (AGENTS.md: prefer real implementations over mocks; the client is an external boundary).

### 2.4 Test 1 — `TestRun_Anchor_RealRelayBatch` (AC-1/AC-2/AC-3/AC-5)

```go
func TestRun_Anchor_RealRelayBatch(t *testing.T) {
    ctx := context.Background()

    // R1.1 real chain + in-tx connector (identical record path to chainedEvents)
    base := audit.NewMemorySink(0)
    store := auditoutbox.NewMemoryOutboxStore()
    wired := auditoutbox.NewMemorySink(base, store, nil) // record-first, fail-open enqueue
    rec := audit.New(wired, audit.WithHashChain())
    reasons := []string{"bad_password", "unknown_user", "account_locked",
        "password_expired", "rate_limited", "mfa_required"} // bounded closed vocabulary
    for i := range 6 {
        rec.Record(ctx, &audit.Event{
            ID: fmt.Sprintf("evt-%d", i), Type: audit.EventLoginFailure,
            TenantID: "tenant-acme", Reason: reasons[i],
        })
    }
    // read back the authoritative stored chain (newest-first → reverse), like chainedEvents
    stored, err := base.Query(ctx, audit.Query{Limit: 6})
    // ... reverse; assert len==6 and IDs == evt-5..evt-0; assert evt-0.PrevHash == "" and
    //     evt-i.PrevHash == evt-(i-1).Hash for i in 1..5 (chain actually chained)

    // R1.2 real relay, two deterministic batches
    capture := &relayCapture{}
    relay, err := auditgovernance.NewRelay(store, capture, auditgovernance.RelayConfig{
        Owner: "auditverify-trust", BatchSize: 3,
    })
    res1, err := relay.RunOnce(ctx) // claims evt-0..evt-2
    res2, err := relay.RunOnce(ctx) // claims evt-3..evt-5

    // AC-5 realism guard
    //   res1.Delivered == 3 && res2.Delivered == 3 && res1.Claimed == 3 && res2.Claimed == 3
    //   capture count == 6, no duplicates; each delivered fact f has
    //     f.Payload[auditoutbox.PayloadKeyAuditHash] == storedHashOf(f.ID)  (linkage contract)
    //   batch-2 facts are exactly evt-3..evt-5 (contiguous in chain order)

    // R1.3 reconstruct the relayed segment via the linkage
    batch := stored[3:6]        // evt-3..evt-5 in chain order
    anchor := stored[2].Hash    // evt-2.Hash
    if batch[0].PrevHash != anchor { t.Fatalf(...) } // docstring: "a relayed batch's first event"

    // AC-1 anchored → 0
    code, out, errOut := runVerify(t, "--from-file", writeEventsFile(t, batch), "--anchor-hash", anchor)
    // code == 0
    // out == fmt.Sprintf("segment verified: 3 event(s), anchored=%s, head=%s", anchor, batch[2].Hash)
    // errOut == ""

    // AC-2 tamper → 1 (JSON-level tamper after relay, same pattern as
    // TestRun_Checkpoint_TamperedEvent: mutate a copy, then writeEventsFile)
    tampered := append([]*audit.Event(nil), batch...)
    copyEv := *tampered[1]; copyEv.Reason = "tampered-after-relay"; tampered[1] = &copyEv
    code, out, errOut = runVerify(t, "--from-file", writeEventsFile(t, tampered), "--anchor-hash", anchor)
    // code == 1; strings.HasPrefix(errOut, "chain BROKEN: ");
    // strings.Contains(errOut, "hash mismatch at index 1"); !strings.Contains(out, "segment verified")

    // AC-3 no anchor → 1, index-0 fail-closed
    code, out, errOut = runVerify(t, "--from-file", writeEventsFile(t, batch))
    // code == 1; strings.Contains(errOut, "chain break at index 0"); !strings.Contains(out, "segment verified")
}
```

Determinism: no polling, no sleeps, no wall-clock comparisons. Both `RunOnce` calls complete synchronously; `MemoryOutboxStore` claims in `CreatedAt` then `ID` order (verified §0 finding 3); expected stdout is built from runtime hash values (hash byte-instability convention from `segment_test.go`).

### 2.5 Test 2 — `TestFactFromAudit_TokenIssuedBlocked` (AC-4)

```go
func TestFactFromAudit_TokenIssuedBlocked(t *testing.T) {
    // Locality pin: upstream coverage is fact_test.go
    // TestFactFromAudit_RejectsNonLoginFailure ("token_issued" case).
    ev := &audit.Event{ID: "evt-token", Type: audit.EventTokenIssued, TenantID: "tenant-acme"}
    fact, err := auditoutbox.FactFromAudit(ev)
    // errors.Is(err, auditoutbox.ErrClassNotPermitted); fact == nil
}
```

Comment in the test file records: `auth.token.issue` L1 aggregation is proposed (`docs/campaigns/implementation-gate.md:15`); this test is class-parameterized on the relayable class so the token-issue variant becomes a one-line change (swap the recorded `Type`) once L1 lands — and this pin is the tripwire that fails first.

## 3. API changes

**None.** This is the load-bearing compatibility statement:

| Surface | Status |
|---|---|
| `sso-ctl audit-verify` flags (`--from-file`, `--from-url`, `--bearer`, `--limit`, `--page-size`, `--timeout-sec`, `--checkpoint`, `--notary-key`, `--anchor-hash`) | unchanged |
| Exit-code contract 0/1/2 and stdout/stderr lines (`segment verified:`, `chain BROKEN:`, `prefix verified:`) | unchanged, exercised not extended |
| `platform/audit` chainer/recorder/notary API | untouched |
| `infrastructure/auditoutbox` `FactFromAudit` fail-closed gate | untouched (AGENTS.md invariant) |
| `infrastructure/auditgovernance` relay/client | untouched |
| HTTP/proto/OpenAPI/config/`Err*` | no changes; no new routes, keys, or error codes |
| Existing tests (`segment_test.go` AC-1..AC-10, `checkpoint_test.go`, `main_test.go`) | byte-identical behavior; the new file only adds coverage |

The API the design *consumes* (documented contract to pin): `audit.VerifyChainSegment`'s fail-closed messages — `chain break at index %d` when `PrevHash != expected`, `hash mismatch at index %d` when `Hash != eventHash` (`platform/audit/chainer.go` `verifyChainFrom`).

## 4. Compatibility constraints

1. **Zero production edits.** `main.go`, `segment.go`, and every non-test file in the module stay byte-identical. No "while here" cleanup.
2. **Layer discipline.** New imports are downward (`cmd/` composition → `infrastructure/` → `domains/` → `platform/`); `_test.go` is layer-gate-exempt; no package imports `cmd/` (hence the test cannot live in `test/` — it lives in the module it verifies, mirroring `auditexport`'s CLI-side evidence split).
3. **Budgets.** `cmd/sso-ctl/auditverify` has 2 non-test files of the 10-file cap; `_test.go` files do not count toward file/fan-out budgets. No production function is added or touched. The new file stays under the 500-line file budget (~220 lines estimated).
4. **Oracle-safe / wire contracts.** No `AGENTS.md` §3 row touched; no bearer challenges, no-store headers, no discovery/issuer behavior.
5. **Module rules.** No manifest, no cold/hot module change, no `go.mod` change, no new dependency (all four imported packages are already in the root module).
6. **Determinism contract.** No sleeps/polling (flake resistance); expected strings built from runtime values only; explicit IDs pin ordering; mutex on the capture client for `-race`.
7. **Test-only helper reuse.** Only existing helpers (`runVerify`, `writeEventsFile`, capture wrappers) plus the test-local capture client; no changes to shared fixtures.

## 5. Failure modes and mitigations

| # | Failure mode | Consequence if ignored | Mitigation in design |
|---|---|---|---|
| F1 | `os.Exit` paths inside `Run` (`errorf`, `usageErr`) would kill the test binary | test suite aborts | All legs use valid files, non-empty anchors, file source only, no truncation — every path returns a code (the exact discipline of existing anchored tests). No `--from-url`, so `--bearer` misuse cannot trigger. |
| F2 | Hash byte-instability (wall-clock `Timestamp` in `eventHash`) | literal-hash assertions flake | Expected strings built from runtime `stored` values (`fmt.Sprintf` with `anchor`/`head`), per the established `segment_test.go` convention. |
| F3 | Batch split drift (ordering change in `MemoryOutboxStore.ClaimOutbox`) | AC-5 fails, test mislabels batches | Design pins ordering at the source: `FactFromAudit` sets `CreatedAt = e.Timestamp`; recorder stamps strictly increasing timestamps; `ID` tiebreak is explicit (`evt-0..5`). AC-5 asserts claimed/delivered counts and exact fact IDs, so drift fails loudly as a product regression, not a flake. |
| F4 | Caller-side event pointers diverge from stored form (recorder redaction/stamping order) | wrong anchor/hashes | Segment and anchor read back from `base.Query` (authoritative sink state), never from the pre-record pointers. |
| F5 | Tamper leg verifies the wrong index | AC-2 silently passes | Assert `hash mismatch at index 1` naming the tampered position, plus absence of `segment verified` in stdout (mirrors `TestRun_Checkpoint_TamperedEvent`'s prefix lock). |
| F6 | Without-anchor leg accidentally passes (batch genesis-adjacent) | AC-3 false green | Batch 2 is mid-chain by construction (`evt-3.PrevHash = evt-2.Hash ≠ ""`); the test asserts the anchor/predecessor equality before running the CLI legs. |
| F7 | Future L1 widening of `FactFromAudit` silently invalidates the scope claim | spec's token-issue hedge rots | AC-4 blocker pin (in this file and upstream `fact_test.go`) fails first; the file comment records the parameterization path. |
| F8 | `-race` data race on the capture client | CI failure | Mutex-protected `relayCapture` (same pattern as the shipped E2E `captureClient`). |
| F9 | MemorySink eviction (capacity) | lost events → wrong chain | `NewMemorySink(0)` → `DefaultMemoryCapacity` 10,000; 6 events. Also asserted by the read-back length check. |
| F10 | Relay retry/lease timing nondeterminism | flake | `RunOnce` is called directly (the exact call `managedRelayInstance.runOnce` makes), never via the background manager; successful `Publish` completes each fact synchronously, so no leases/backoff/jitter are in play. |

## 6. Migration steps

1. **Production migration: none.** No artifacts, configs, stores, or wire formats change; rollout/rollback is n/a (test-only).
2. **Acceptance migration (the one real migration in this direction):** the direction's literal `token_issued` batch content is migrated to the only class the verified production gate permits — `login_failure` — with the token-issue variant preserved verbatim as AC-4's blocker pin (regression-locked, not silently faked). Rationale is evidence-backed: `FactFromAudit` rejects `token_issued` (`ErrClassNotPermitted`), `auth.token.issue` L1 aggregation is absent (`implementation-gate.md:15` lists it as proposed connector work), and the in-tree token-issue **chain** leg is already proven by the E2E's A4 test via export-bundle verification.
3. **Future L1 landing path (documented, not implemented):** when an `auth.token.issue` L1 aggregation lands, (a) AC-4 flips from blocker to enabler — the pin fails and the class parameterization becomes `token_issued`; (b) the relay reconstruction logic in this file is class-agnostic (linkage via `audit_hash`) and needs no structural change; (c) the new direction must widen `FactFromAudit`'s gate deliberately and re-run this file plus `fact_test.go` as the tripwires.
4. **Handoff sequence:** `go build ./... && go vet ./...` → `go test -run 'TestMaintainability_|TestArchitecture_' .` → `go test ./cmd/sso-ctl/auditverify/ -race` → `go test ./test/ -run TestE2E -v` (the E2E this test complements, unchanged) → `make ci`.

## 7. Testable acceptance mapping

| Acceptance | Given | When | Then (assertions) | Pinned additionally by |
|---|---|---|---|---|
| AC-1 — real relay batch, anchored → 0 | R1 chain (6 real `login_failure` events), two real `RunOnce` batches, batch 2 = `evt-3..evt-5`, anchor = `evt-2.Hash` = batch[0].PrevHash; delivered-fact `audit_hash` linkage asserted (proves relay output, not fixture) | `runVerify(t, "--from-file", file, "--anchor-hash", anchor)` | exit 0; stdout exactly `segment verified: 3 event(s), anchored=<anchor>, head=<evt-5.Hash>` (runtime-built); stderr empty | `segment_test.go` AC-1 (synthetic twin) |
| AC-2 — tamper → 1 | same clean file with exactly one event's `Reason` mutated (JSON-level, post-relay) | `runVerify(t, "--from-file", tamperedFile, "--anchor-hash", anchor)` | exit 1; stderr `chain BROKEN: ` prefix + `hash mismatch at index 1`; stdout lacks `segment verified` | `checkpoint_test.go` `TestRun_Checkpoint_TamperedEvent` (pattern), E2E A2 tamper leg (bundle-level) |
| AC-3 — no anchor → 1, index-0 fail-closed | same clean mid-chain file | `runVerify(t, "--from-file", file)` | exit 1; stderr contains `chain break at index 0`; stdout lacks `segment verified` | `segment_test.go:132` (synthetic twin) |
| AC-4 — blocker pin | `token_issued` event (tenant-scoped) | `FactFromAudit(ev)` | `errors.Is(err, ErrClassNotPermitted)`; fact nil | `fact_test.go` `TestFactFromAudit_RejectsNonLoginFailure` ("token_issued" case) |
| AC-5 — single-batch realism guard | two `RunOnce` runs | inspect results + capture | each run: Claimed 3 / Delivered 3; 6 total, no duplicates; every fact's `audit_hash` == its chain event's `Hash`; batch-2 facts contiguous `evt-3..evt-5` in chain order | `test/auditoutbox_governance_test.go` A1 (linkage, one fact), `infrastructure/auditoutbox/memory_test.go`, `infrastructure/auditgovernance/relay_test.go` |

R1 is satisfied by the AC-1/AC-2/AC-3/AC-5 test; R2 by AC-4; R3 by §3/§4 (zero production edits, existing tests byte-identical, mandatory gates).

## 8. Engineering-gate verification checklist

```text
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/auditverify/ -race -count=1
go test ./test/ -run TestE2E -v            # existing E2E untouched, must stay green
make ci                                    # full handoff gate
```

Report any pre-existing failure separately, per AGENTS.md §5.
