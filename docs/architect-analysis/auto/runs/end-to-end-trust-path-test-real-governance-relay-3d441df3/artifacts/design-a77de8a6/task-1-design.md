Design produced and verified. Summary:

## Evidence verification — all claims confirmed, plus refinements

Every citation in the evidence was re-checked against HEAD:

| Claim | Verdict |
|---|---|
| `main.go` `--anchor-hash` docstring names "a relayed batch's first event" | ✓ exact wording found; `Run` → `verifyAnchoredSegment` branch |
| `segment.go` `verifyAnchoredSegment`/`normalizeSegmentOrder` (empty→1, single `VerifyChainSegment`, `segment verified:`/`chain BROKEN:`) | ✓ exact behavior, exit 0/1/2 contract |
| `segment_test.go:132` `TestRun_Anchor_RelayShapedBatch` | ✓ at exactly line 132, synthetic `midChainWindow(t, 6, 2, 5)`, pins `chain break at index 0` |
| `managed_relay.go` `ManagedRelayFactory`/`runOnce` → `Relay.RunOnce` | ✓ (`managed_relay.go:200` = `runner.Relay.RunOnce(ctx)`) |
| `event_types.go:15` `EventTokenIssued = "token_issued"` | ✓ exact line |
| L1 aggregation absent (only `aggregate_type/id/version` at `http_client.go:194-196`) | ✓ |
| `fact.go` fail-closed to `login_failure` only | ✓ `ErrClassNotPermitted` gate; real relay batches cannot carry `token_issued` |
| `commerce.OutboxEvent` (store.go:74) has no `PrevHash`/`Hash`; linkage = fact's `audit_hash` | ✓ |
| `test/auditoutbox_governance_test.go` uses real managed relays but never the CLI; `test/` cannot import `cmd/` | ✓ header states the split explicitly |
| Helpers (`runVerify` :133, `writeEventsFile` :60, `chainedEvents` :174, captures), layer gate skips `_test.go` (:147), downward-import precedent | ✓ all confirmed |

**New findings that refine the design:** `fact_test.go` already pins `token_issued` → `ErrClassNotPermitted` (AC-4 stays as a locality pin, both must fail together); `NewMemorySink(0)` → 10,000-capacity default (safe); `ClaimOutbox` orders by `CreatedAt` then `ID` (deterministic evt-0..2 / evt-3..5 batch splits); recorder stamps the caller's event in place, so the test reads the chain back from the sink (`base.Query`) for authoritative hashes.

## Design delivered

**`docs/architect-analysis/cmd-sso-ctl-auditverify-relay-trust-path-design.md`** (+ run artifact at `docs/architect-analysis/auto/runs/end-to-end-trust-path-test-real-governance-relay-3d441df3/artifacts/design-f70f610c/design.md`), covering:

- **Concrete design** — one new test-only file `cmd/sso-ctl/auditverify/relay_trust_test.go` (~220 lines): real `MemorySink` + `auditoutbox.MemorySink`/`MemoryOutboxStore` + `audit.New(..., WithHashChain())` recording 6 tenant-scoped `login_failure` events; real `auditgovernance.Relay.RunOnce` twice (BatchSize 3 — the exact call `managedRelayInstance.runOnce` makes, no sleeps/polling); segment reconstructed via the documented `audit_hash` linkage; batch 2 (`evt-3..evt-5`, mid-chain, anchor = `evt-2.Hash`) driven through `runVerify`.
- **API changes: none** — zero production edits; the CLI surface (flags, exit codes, stdout/stderr lines) is exercised, not extended; the consumed contract pinned is `VerifyChainSegment`'s `chain break at index %d` / `hash mismatch at index %d`.
- **Compatibility** — layer-discipline (downward imports, `_test.go` exempt, `test/` cannot host it), budget-safe (2/10 non-test files, tests uncounted), no oracle/wire/module surface touched.
- **Failure modes F1–F10** — `os.Exit` paths killing the test binary, hash byte-instability, batch-split drift, pointer-vs-stored divergence, wrong tamper index, genesis-adjacent false green, future L1 gate widening, `-race`, ring eviction, relay lease timing — each with a concrete mitigation.
- **Migration** — none for production; the acceptance re-anchor `token_issued` → `login_failure` (blocker-pinned, not silently faked) and the documented future-L1 parameterization path.
- **Acceptance mapping** — AC-1..AC-5 → Given/When/Then assertions, each cross-pinned to existing coverage (synthetic twin, tamper pattern, E2E A1/A2 linkage, `fact_test.go`).
- **Gates** — `go build ./... && go vet ./...`, maintainability/architecture tests, `-race`, E2E, `make ci`.
