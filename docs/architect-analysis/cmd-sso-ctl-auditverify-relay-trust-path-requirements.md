# Requirements Spec: audit-verify end-to-end trust-path test (real governance-relay batch via --anchor-hash)

- Direction: "End-to-end trust-path test: real governance-relay auth.token.issue batch verified via `--anchor-hash`" (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-auditverify-e0e1fbf0.json`, entry 2)
- Module: `cmd/sso-ctl/auditverify` (test-only change; no production code)
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository, plus the
files the direction's own hedge implies. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/auditverify/main.go` — `--anchor-hash` docstring names "a relayed batch's first event" as anchor source | Docstring: "`--anchor-hash` anchors verification to the segment START: the boundary PrevHash the oldest exported event carried at export time (an auditexport bundle's `boundary_prev_hash`, the event before the window in a full export, or a relayed batch's first event — NOT a checkpoint file)". `verifyAnchoredSegment` branch in `Run`; exit contract 0/1/2; `--anchor-hash` + `--checkpoint` mutually exclusive (R5), empty value is misuse | Confirmed |
| `cmd/sso-ctl/auditverify/segment.go` — `verifyAnchoredSegment`/`normalizeSegmentOrder` | Both present. `verifyAnchoredSegment`: empty segment → exit 1; `normalizeSegmentOrder` then exactly one `audit.VerifyChainSegment` call; success prints `segment verified: %d event(s), anchored=%s, head=%s`; failure prints `chain BROKEN: %v` (exit 1); truncated → honest `prefix verified` (exit 1). `normalizeSegmentOrder`: case (a) anchor at [0] keeps order, (b) anchor at [len-1] reverses, (c) untouched → fail-closed at index 0 | Confirmed |
| `cmd/sso-ctl/auditverify/segment_test.go:132` — `TestRun_Anchor_RelayShapedBatch` | Function is exactly at line 132. It verifies a **synthetic** in-memory `midChainWindow(t, 6, 2, 5)` slice ("the shape a durable-outbox relay delivers"), pins with-anchor → 0 and without-anchor → 1 with `chain break at index 0` | Confirmed (synthetic, not relay output — the gap) |
| `infrastructure/auditgovernance/managed_relay.go` — `ManagedRelayFactory`/`runOnce` | Both present. `ManagedRelayFactory.Prepare` builds `ManagedRelay` runners; `managedRelayInstance.runOnce` claims a background lease then calls `runner.Relay.RunOnce(ctx)` — the relay delivery path is `Relay.RunOnce` (relay.go: `ClaimOutbox` → `deliver` → `CompleteOutbox`) | Confirmed |
| `platform/audit/auditspi/event_types.go:15` — `EventTokenIssued` `'token_issued'` | `EventTokenIssued EventType = "token_issued"` is exactly at line 15 | Confirmed |
| "L1 aggregation: grep for L1/aggregate found only http_client.go aggregate_type fields" | `rg -i 'L1|aggregate' infrastructure/auditgovernance/` (non-test) hits only `http_client.go:194-196` — `AggregateType`/`AggregateID`/`AggregateVersion`, the OpenFGA-governance aggregate fields on the outbox event, **not** an audit `auth.token.issue` L1 aggregation. No L1 aggregation or chained-batch production exists anywhere in `infrastructure/auditgovernance/` or `platform/audit/` | Confirmed — L1 aggregation is proposed, not implemented |
| `infrastructure/auditoutbox/fact.go` — the in-tx connector gate (not cited by the direction; decisive for its acceptance) | `FactFromAudit` is **fail-closed to `login_failure` only**: `ErrClassNotPermitted` rejects every other class ("login_failure is the only governance fact class"), `ErrFactNotTenantScoped` rejects tenant-less events. `MemorySink.Record` records first (authoritative) then best-effort enqueues; the sqlite path appends the fact in the audit row's own transaction (`WithTxAppender`). A real relay batch in this tree **cannot contain `token_issued`** — it can only contain `login_failure` facts | Confirmed — the direction's "batch containing token_issued events" is blocked by the verified production gate; consistent with the direction's own "proposed, not verified" hedge |
| `domains/tenant/commerce/store.go:74` — `OutboxEvent` shape | `OutboxEvent` (store.go:74) carries **no `PrevHash`/`Hash`**: `Payload map[string]string` + `PayloadDigest`. The batch's chain linkage is the fact payload key `audit_hash` (`infrastructure/auditoutbox/fact.go` `PayloadKeyAuditHash`), documented as "links the fact to its single chain event" | Confirmed — the CLI-verifiable "relayed batch" is the chain segment whose events the relay delivered, linked via `audit_hash` |
| `test/auditoutbox_governance_test.go` — existing B4-5/G5 E2E | Already drives **real** managed relay batches: real server + sqlite audit sink + `WithTxAppender` + `ManagedRelayFactory` through `modules` manager + capture client. A1 asserts fact `audit_hash == chain event Hash` for one delivered `login_failure` fact; A4 proves the real `token_issued` chain leg (refresh grant) and verifies it via `auditexport.VerifyExportBundle` + notary — **never through the audit-verify CLI**. File header states the split: "the CLI-side evidence (--dsn/--verify/--anchor exit codes) lives in cmd/sso-ctl/auditexport/main_test.go (test/ cannot import cmd/)" | Confirmed — the relay→CLI leg is exactly the unclosed gap; `test/` cannot close it (no package may import `cmd/`) |
| `platform/audit/chainer.go` — `VerifyChainSegment` | `VerifyChainSegment(events, expectedPrevHash)` (line 172) = `verifyChainFrom(events, prev)`; fail-closed: `chain break at index %d ... expected %q` and `hash mismatch at index %d`; `GenesisHash = ""`; `eventHash` covers `PrevHash`, so the anchor is cryptographically bound | Confirmed |
| `cmd/sso-ctl/auditverify` test helpers | `chainedEvents` (main_test.go:174) already builds real chains via the real record path (`audit.NewMemorySink(0)` + `audit.New(sink, audit.WithHashChain())` + `rec.Record`); `runVerify` (checkpoint_test.go:133), `writeEventsFile` (checkpoint_test.go:60), `captureStdout/captureStderr` exist for in-process exit-code/stream assertions | Confirmed |
| T-8(a) / B4-5 / G1 mapping | `docs/campaigns/implementation-gate.md` line 11: T-8(a) = `POST /token` → 200 + kid + claims `{iss/aud/scope/client_id/tenant_id/roles}` — a deploy-repo acceptance (G1 gate, line 73); line 15 (B4-5 row): connector acceptance "重启 L0 不丢（10 logins → 10 行）；P2 parity；L1 摘要生效" with "auth.token.issue L1 聚合" listed as connector work; line 77 (G5): "B4-2..5 → T-2、T-8(b–e)、T-9、L0 持久化、P2 parity" | Confirmed — token-issue content maps to the deploy repo / proposed L1 work; the in-tree verifiable leg is the P2-parity connector path |

Net verification result: the direction's factual core is confirmed and its hedge is
necessary. The `--anchor-hash` contract names a relayed batch's first event, the
existing CLI test uses a synthetic window, and the real relay machinery exists —
but the only class that can flow through the real in-tx connector is
`login_failure`, and the `auth.token.issue` L1 aggregation is absent. The
acceptance below therefore preserves the supplied checks verbatim in structure
(real relay batch → anchor → 0; tamper → 1; no anchor → 1 with the index-0 break)
and re-anchors the batch content to what the verified relay can actually emit,
with the token-issue variant pinned as a blocker instead of silently faked.

## 2. Goal and user outcome

Close the G1 trust-path loop (`token-issue → in-tx audit → relay → verify` per
the direction) to the extent this tree can prove it: today, `--anchor-hash`
verification of a **real** relay-produced batch is exercised nowhere — the CLI
tests feed a synthetic in-memory window (segment_test.go:132), and the real
managed-relay E2E (`test/auditoutbox_governance_test.go`) verifies via export
bundle + notary, never through the CLI (`test/` cannot import `cmd/`).

Completion marker: a new in-process test in `cmd/sso-ctl/auditverify` records a
real hash-chained batch through the real recorder and the real in-tx connector
(`infrastructure/auditoutbox`), drains it with the real relay machinery
(`infrastructure/auditgovernance.Relay.RunOnce` — the exact call
`managed_relay.go`'s `runOnce` makes), reconstructs the delivered chain segment
via the connector's documented `audit_hash` linkage, and proves the three
`--anchor-hash` exit-code contracts against that real output (0 with anchor,
1 on tamper, 1 with `chain break at index 0` without anchor). It additionally
pins the verified blocker that keeps the direction's literal `token_issued`
content out of scope: the production connector gate rejects it.

Maps to: G1 P0 trust path (`implementation-gate.md:73`), T-8(a) token-issue path
(`implementation-gate.md:11`) and the B4-5 P2-parity acceptance
(`implementation-gate.md:15`, G5 `:77`) — with the verified caveat that the
token-issue **relay** content (L1 aggregation) is proposed, and the in-tree
token-issue **chain** leg is already proven by the A4 test via export-bundle
verification; this spec adds the CLI `--anchor-hash` leg for the real relay batch.

## 3. Product boundary

- Surface: operator tool `sso-ctl audit-verify` (`cmd/sso-ctl/auditverify`), test-only.
- Default: no production behavior change; new tests only. The existing
  `--anchor-hash` implementation (segment.go) is complete and stays untouched.
- Explicit non-goals (do not implement — scope is exactly the direction's test):
  - No L1 aggregation, no `auth.token.issue` relay production code anywhere
    (proposed per the direction's own evidence; a future L1 change is a separate
    direction that may then parameterize the class of this test).
  - No widening of `FactFromAudit`'s fail-closed class gate (AGENTS.md §3/§4
    invariant; would change production behavior).
  - No `--dsn` sqlite store-verification mode (separate direction, entry 1 of
    the source analysis) and no endpoint-posture sweep (entry 3).
  - No changes to `test/auditoutbox_governance_test.go`, `infrastructure/auditgovernance/`,
    `infrastructure/auditoutbox/`, `platform/audit/`, or any production file.
  - No new packages, no new CLI flags, no new routes/Err*/config keys/OpenAPI surface.

## 4. Module classification

- [x] Audit/observability (trust-path evidence test)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Authorization · [ ] Infrastructure/config · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/auditverify` (composition layer). The new
test file imports `infrastructure/auditgovernance`, `infrastructure/auditoutbox`,
and `domains/tenant/commerce` — all downward (composition → infrastructure →
domains → platform → shared), no upward import, no package imports `cmd/`.
Precedent: `cmd/sso-ctl/generate` already imports `infrastructure/` in production
code, and the layer gate skips `_test.go` files (architecture_layer_test.go:147).

## 5. Requirements

### R1 — Real-relay trust-path test (`cmd/sso-ctl/auditverify/relay_trust_test.go`)

Build a real batch with the real components (no mocks; Memory* implementations
per AGENTS.md) and drive it through the existing `--anchor-hash` CLI path
in-process via the existing `runVerify` helper:

1. **Real chain + in-tx connector**: `base := audit.NewMemorySink(0)`;
   `store := auditoutbox.NewMemoryOutboxStore()`;
   `wired := auditoutbox.NewMemorySink(base, store, nil)` (record-first,
   fail-open enqueue wrapper — the in-process governance path);
   `rec := audit.New(wired, audit.WithHashChain())` (the real record path,
   identical to `chainedEvents`). Record **6** tenant-scoped `login_failure`
   events (`Type: audit.EventLoginFailure`, `TenantID: "tenant-acme"`, explicit
   IDs `evt-0..evt-5`, distinct bounded `Reason` values) — the only class the
   real gate permits, and the class the real server emits per
   `test/auditoutbox_governance_test.go` A1.
2. **Real relay batch**: `auditgovernance.NewRelay(store, capture, RelayConfig{Owner: "auditverify-trust", BatchSize: 3})`
   where `capture` implements `auditgovernance.Client` (records delivered
   `*commerce.OutboxEvent`s; same pattern as the shipped E2E's `captureClient`).
   Call `RunOnce(ctx)` twice — the exact call `managedRelayInstance.runOnce`
   makes (managed_relay.go). Batch 1 delivers `evt-0..evt-2`, batch 2 delivers
   `evt-3..evt-5` (deterministic: `MemoryOutboxStore.ClaimOutbox` orders by
   `CreatedAt`, then `ID`). No polling, no sleeps.
3. **Batch reconstruction via the documented linkage**: assert every delivered
   fact's `Payload[auditoutbox.PayloadKeyAuditHash]` equals the corresponding
   chain event's `Hash` (the connector's linkage contract, A1-asserted in the
   E2E). The verified segment = the batch-2 events in chain order; the anchor =
   `segment[0].PrevHash` (= `Hash` of the last batch-1 event = the batch's
   first-event PrevHash, exactly the main.go docstring's "a relayed batch's
   first event"). This reconstruction is the only coherent meaning of "verify a
   relayed batch": outbox facts carry no `PrevHash`/`Hash`
   (commerce/store.go:74), the CLI consumes chain `audit.Event`s, and
   `audit_hash` is the connector's stated link between the two.
4. **CLI leg**: write the segment with the existing `writeEventsFile` helper and
   run `runVerify(t, "--from-file", file, "--anchor-hash", anchor)` plus the
   tamper and no-anchor variants (testable acceptance below). Hashes are
   runtime-derived (recorder wall-clock timestamps), so expected strings are
   built from the runtime events, per the existing convention
   (segment_test.go `TestRun_Anchor_MidChainWindow`).

### R2 — Blocker pin for the token-issue variant

The direction's literal batch content (`token_issued`) cannot flow through the
real relay: `FactFromAudit` rejects it (`ErrClassNotPermitted`). Pin this so the
scope claim is regression-locked — if a future L1 aggregation widens the gate,
this pin fails and the spec must be revisited:

- `FactFromAudit(tokenIssuedEvent)` returns `ErrClassNotPermitted` (direct unit
  assertion, mirroring `infrastructure/auditoutbox/fact_test.go`'s style);
- a comment in the test file records that the `auth.token.issue` L1 aggregation
  is proposed (`implementation-gate.md:15`) and that this test is class-
  parameterized (recording the events via the relayable class) so the token-issue
  variant becomes a one-line change once L1 lands.

### R3 — Regression invariance

- No production file changes: `main.go`, `segment.go`, and all existing tests
  (segment_test.go AC-1..AC-10, checkpoint_test.go, main_test.go) pass
  byte-identical output and exit codes.
- The new test uses only existing helpers (`runVerify`, `writeEventsFile`,
  `captureStdout`/`captureStderr`) plus a test-local capture client — no changes
  to shared test fixtures.
- Mandatory gates: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` after the edit;
  `go test ./cmd/sso-ctl/... -race` and `make ci` before handoff.

## 6. Testable acceptance (Given/When/Then)

Preserved from the direction's acceptance, made deterministic and pinned to the
verified relay class:

1. **AC-1 (real relay batch, anchored → 0).** Given a real relay batch produced
   by R1 steps 1–3 (two real `RunOnce` batches, batch 2 = `evt-3..evt-5`, anchor
   = `evt-2.Hash` = the batch's first-event `PrevHash`), when
   `runVerify(t, "--from-file", segmentFile, "--anchor-hash", anchor)` runs,
   then exit code is 0, stdout is exactly
   `segment verified: 3 event(s), anchored=<anchor>, head=<evt-5.Hash>`
   (built from runtime values), and stderr is empty. The test additionally
   asserts the delivered-fact `audit_hash` linkage so the file is proven to be
   relay output, not a fixture.
2. **AC-2 (tamper → 1).** Given the same clean segment file with exactly one
   event's `reason` mutated in the JSON (per-event tamper, the
   `auditexport.VerifyExportBundle`-style mutation used by the E2E A2 leg), when
   `runVerify(t, "--from-file", tamperedFile, "--anchor-hash", anchor)` runs,
   then exit code is 1 and stderr starts with `chain BROKEN: ` and contains
   `hash mismatch at index <i>` naming the tampered index (the chainer's honest
   per-event report; pattern pinned in main_test.go). stdout must not contain
   `segment verified`.
3. **AC-3 (clean relay batch, no anchor → 1, index-0 fail-closed).** Given the
   same clean segment file, when `runVerify(t, "--from-file", segmentFile)` runs
   (no `--anchor-hash`), then exit code is 1 and stderr contains
   `chain break at index 0` — the mid-chain window's first event carries a
   non-genesis `PrevHash`, so the unanchored walk fails closed at index 0. This
   is the without-anchor break already pinned at segment_test.go:132; the new
   test re-pins it against real relay output.
4. **AC-4 (blocker pin).** Given a `token_issued` event (real `audit.Event` with
   `Type: audit.EventTokenIssued`, tenant-scoped), when `FactFromAudit` is
   called, then it returns `ErrClassNotPermitted` — proving the direction's
   literal token-issue relay content is proposed, not implementable through the
   verified gate (R2).
5. **AC-5 (single-batch realism guard).** Given the two `RunOnce` runs, when the
   delivered counts are inspected, then batch 1 and batch 2 each delivered
   exactly 3 facts, each fact's `audit_hash` equals its chain event's `Hash`,
   and the batch-2 segment events are contiguous (`evt-3..evt-5`) in chain
   order — the "real managed relay batch" precondition of AC-1.

Mapping: AC-1/AC-2/AC-3 preserve the direction's three checks; AC-4/AC-5 are the
testable form of the direction's own "L1 aggregation … must be treated as
proposed, not verified" hedge and of the "real batch" precondition.

## 7. Engineering-gate constraints (verified)

- **Budgets**: `cmd/sso-ctl/auditverify` holds 2 non-test Go files (main.go,
  segment.go) of the 10-file cap; the change adds one `_test.go` file (test
  files do not count toward file/fan-out budgets). No new functions in
  production code; no function/file budget touched.
- **Architecture**: test-only imports of `infrastructure/auditgovernance`,
  `infrastructure/auditoutbox`, `domains/tenant/commerce` from `cmd/` are
  downward (composition → infrastructure → domains); the layer gate skips
  `_test.go` (architecture_layer_test.go:147); precedent `cmd/sso-ctl/generate`.
  No package imports `cmd/` anywhere (so the test cannot live in `test/`; it
  lives in the module it verifies).
- **Security/wire invariants untouched**: no routes, no `Err*`, no config keys,
  no OpenAPI, no `AGENTS.md` §3 oracle table row, no store changes. The relay
  path exercised is the existing production machinery; the capture client is the
  remote governance boundary (same role as the E2E's `captureClient`), and the
  outbox/relay behavior asserted (claim order, linkage, idempotent completion)
  is already pinned by `infrastructure/auditoutbox/*_test.go` and
  `infrastructure/auditgovernance/relay_test.go`.
- **Flake resistance**: no sleeps, no polling, no wall-clock comparisons — both
  `RunOnce` calls are deterministic; ordering is pinned by explicit IDs;
  expected stdout strings are built from runtime hash values (hash
  byte-instability convention already established in segment_test.go).

## 8. Files

### Create

```text
cmd/sso-ctl/auditverify/relay_trust_test.go — R1 test: real recorder + real
    auditoutbox MemorySink/MemoryOutboxStore + real auditgovernance.Relay
    (two deterministic RunOnce batches) -> reconstruct delivered chain segment
    via PayloadKeyAuditHash linkage -> runVerify AC-1/AC-2/AC-3 + AC-4 blocker
    pin + AC-5 realism guard. Test-local captureClient implementing
    auditgovernance.Client (pattern: test/auditoutbox_governance_test.go).
docs/architect-analysis/cmd-sso-ctl-auditverify-relay-trust-path-requirements.md — this spec
```

### Modify

```text
(none — the --anchor-hash implementation and all existing tests stay untouched)
```

### Do not modify

```text
cmd/sso-ctl/auditverify/main.go — --anchor-hash contract, exit codes, docstring
cmd/sso-ctl/auditverify/segment.go — verifyAnchoredSegment/normalizeSegmentOrder
infrastructure/auditgovernance/ — relay machinery (incl. managed_relay.go)
infrastructure/auditoutbox/ — fail-closed FactFromAudit gate (invariant)
test/auditoutbox_governance_test.go — server-side E2E (A1–A5 legs)
platform/audit/chainer.go — VerifyChainSegment fail-closed semantics
```

## 9. Dependencies and compatibility

- New/changed SPI: none.
- New option/store wiring: none (existing `--from-file` + `--anchor-hash` flags).
- New YAML/env keys: none.
- Storage migration: none.
- HTTP/proto compatibility: none (no server surface touched; the relay client
  boundary is the same interface the shipped E2E uses).
- Rollout/rollback: n/a — tests only; no production artifact changes.
- Handoff gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./cmd/sso-ctl/auditverify/ -race`, then `make ci`.
