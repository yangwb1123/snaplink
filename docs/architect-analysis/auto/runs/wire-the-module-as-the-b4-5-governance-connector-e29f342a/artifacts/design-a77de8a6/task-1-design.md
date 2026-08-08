The design artifact is complete. Here's the summary of what was verified and decided:

## Verification results (10/10 claims checked, 3 corrections)

All citations in the evidence hold in substance against HEAD. Corrections:

1. **Anchor implementation location** — the evidence's own correction is still ambiguous: `loadCheckpoint`/`enforceAnchorHead` live at `cmd/sso-ctl/auditexport/main.go:270/290` (and tests at `main_test.go:573-1110`) — **not** `cmd/sso-server` (which has no `main_test.go`; its `main.go:194-358` is server struct fields).
2. **Test count drift** — 32 `^func Test` in the module, not 27 (immaterial).
3. **Path precision** — the `recordLoginFailure` funnel is `interfaces/sso/server_helpers.go:279-293`, not `cmd/sso-server/server_helpers.go`.

Everything else verified exact: relay drains `commerce.OutboxStore`; billing is the sole relay consumer (memory-only outboxes, no durable outbox exists anywhere); zero `auditgovernance` refs in `cmd/sso-server`; `auditexport.go:99-112` contiguity/anchor fields; `EventLoginFailure` at `event_types.go:14`; Notary unwired (sqlite `LastHash` is the ChainTip); G5 P2-parity leg at `implementation-gate.md:77` and B4-5 at `audit-contract-batch-snaplink.md:16`.

## Design decisions (deliverable: `artifacts/design-a77de8a6/task-1-design.md`)

- **New `infrastructure/auditoutbox` package** (auditgovernance is at its 10-file ceiling): `FactFromAudit` (single permitted-class gate: login-failure, tenant-scoped, redacted payload carrying `audit_hash` for chain linkage), `MemoryOutboxStore` + `SQLiteOutboxStore` (self-owned `audit_outbox` DDL), and a fail-open `Sink` wrapper for the memory path.
- **`platform/audit/sqlite` `TxAppender` seam** — the contract-faithful "同事务写入": audit row + outbox row commit atomically, with **fail-open degradation** (append error → rollback → audit row re-inserted alone, error surfaced) so governance can never lose an audit record.
- **A4 roles projection** without touching the `audit.Event` hash-chain wire contract: roles travel as `Metadata` via a variadic `RecordTokenIssued(…, meta …)` + a fail-open `tokenIssuedRolesMeta` helper in `accessors_handlers.go` (one-line change in the 498-line funnel file, both stay ≤500).
- **Acceptance split**: e2e in `test/` (server + managed relay via `ManagedRelayFactory`/`modules.Activate` + in-harness Notary + export checks) and governed-store CLI tests in the module (real connector → `Run --dsn/--verify/--anchor`), since `test/` can't import `cmd/`.
- **Constraints honored**: no new `interfaces/sso` files (60-ceiling), no auditgovernance changes, no CLI/bundle/config/HTTP-error changes, byte-identical defaults, failure modes F1–F11, phased migration (seams → projection → evidence), and A1–A5 mapped to concrete test cases. Server cmd wiring is explicitly a follow-up (external HTTP delivery and the L0 drill stay out of scope).
