Spec written. Summary of the evidence-backed result:

**Spec:** `docs/architect-analysis/cmd-sso-ctl-auditverify-relay-trust-path-requirements.md`

**Evidence verification — every citation checked:**
- `main.go` `--anchor-hash` docstring naming "a relayed batch's first event" ✓
- `segment.go` `verifyAnchoredSegment`/`normalizeSegmentOrder` (empty→1, single `VerifyChainSegment` call, `segment verified:`/`chain BROKEN:` output) ✓
- `segment_test.go:132` `TestRun_Anchor_RelayShapedBatch` — confirmed synthetic `midChainWindow` window, pins the without-anchor `chain break at index 0` ✓
- `managed_relay.go` `ManagedRelayFactory`/`runOnce` (→ `Relay.RunOnce`) ✓
- `event_types.go:15` `EventTokenIssued = "token_issued"` — exact line ✓
- L1 aggregation — confirmed absent (only OpenFGA-style `aggregate_type/id/version` in `http_client.go:194-196`) ✓

**New decisive findings that shape the spec:**
- `infrastructure/auditoutbox/fact.go` gates the in-tx connector **fail-closed to `login_failure` only** — a real relay batch cannot contain `token_issued`, so the direction's literal batch content is blocked by production code (its own hedge made this necessary).
- `commerce.OutboxEvent` (store.go:74) carries no `PrevHash`/`Hash`; the connector's documented linkage is the fact's `audit_hash` → the CLI-verifiable "relayed batch" is the chain segment whose events the relay delivered, reconstructed via that linkage.
- `test/auditoutbox_governance_test.go` already drives real managed relay batches but verifies via export bundle, never the CLI (`test/ cannot import cmd/`) — the exact gap.

**Acceptance preserved and made testable** (R1/R2, AC-1..AC-5): real recorder + real `auditoutbox` Memory* + real `Relay.RunOnce` (two deterministic batches, no sleeps) → `--anchor-hash` → exit 0 `segment verified:`; tamper one event → exit 1 `chain BROKEN:` + `hash mismatch at index <i>`; clean batch without anchor → exit 1 `chain break at index 0`; plus a blocker pin asserting `FactFromAudit(token_issued)` → `ErrClassNotPermitted` so the scope claim is regression-locked.

**Scope discipline:** test-only change in `cmd/sso-ctl/auditverify/relay_trust_test.go`; zero production edits; no L1 aggregation, no gate widening, no `--dsn` mode (entry 1) or endpoint sweep (entry 3); imports are downward (`cmd/`→`infrastructure/`→`domains/`→`platform/`), precedented by `cmd/sso-ctl/generate`.
