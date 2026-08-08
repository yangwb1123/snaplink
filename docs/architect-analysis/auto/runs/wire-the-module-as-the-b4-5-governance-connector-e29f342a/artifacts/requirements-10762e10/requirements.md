Spec written. Summary of what was produced and verified:

**Deliverable**: `docs/architect-analysis/auto/runs/wire-the-module-as-the-b4-5-governance-connector-e29f342a/artifacts/requirements-10762e10/requirements.md`

**Citation verification (10/10 checked against HEAD, 2 corrections, both strengthening the direction):**

| Claim | Verdict |
|---|---|
| `relay.go:35-60` Relay drains `commerce.OutboxStore` | ✅ exact |
| `managed_relay.go:17-32` ManagedRelay/Builder | ✅ exact |
| `snaplink-billing/relay.go:41-74` sole relay wiring | ✅ with nuance — `cmd/snaplink-audit-provisioner` also imports `auditgovernance` but only the receiving side; billing is the sole outbox-draining consumer |
| zero `auditgovernance` refs in `cmd/sso-server` | ✅ grep-verified; **correction**: `build_governance.go` doesn't exist — it's `governance_wiring_test.go` |
| `main_test.go:45-1150` fixture-only | ✅ 27 tests, all `seedStore` synthetic; no server/outbox/relay |
| `auditexport.go:99-112` contiguity/anchor fields | ✅ exact |
| `event_types.go:9-16` `EventLoginFailure` | ✅ exact (:14) |
| "main.go:622-1070" anchor tests | **correction**: tests are `main_test.go:573-1110`; implementation is `main.go:194-358` (`loadCheckpoint`/`enforceAnchorHead`) |
| `chainer.go SignedCheckpoint` + Notary | ✅; new finding: Notary is unwired in the server — e2e composes it in-harness (sqlite `LastHash` is the ChainTip) |
| G5 P2-parity leg at `implementation-gate.md:77` + contract B4-5 (`audit-contract-batch-snaplink.md:16`) | ✅ exact |

**New verified constraints baked into the spec**: single `recordLoginFailure` funnel (server_helpers.go:279-293) is the post-decision commit point; no outbox exists in `platform/audit`/`interfaces/sso`; `token_issued` carries `TenantID` but **no roles today** (REQ-5 pins the projection); `auditgovernance` is at its 10-file fan-out ceiling (new connector lives in a new `infrastructure/auditoutbox` package); `interfaces/sso` at its 60-file ceiling (option extends an existing file); `test/` cannot import `cmd/` (AGENTS.md), so the acceptance split is e2e-in-`test/` (server/relay/chain) + governed-store CLI tests in the module.

**Acceptance preserved 1:1 as A1–A5**, each with given/when/then: A1 post-commit outbox durability before relay + single linked chain event after; A2 `contiguous=true` + boundary/head vs store `LastHash` + tamper→1; A3 fresh/stale/forged `--anchor` enforcement; A4 `tenant_id`/`roles` in the exported `token_issued`; A5 G5 P2-parity leg green with evidence pointer. Scope is bounded: postgres/`--from-url`, L1 aggregation, external HTTP delivery, and the L0 drill are explicitly out.
