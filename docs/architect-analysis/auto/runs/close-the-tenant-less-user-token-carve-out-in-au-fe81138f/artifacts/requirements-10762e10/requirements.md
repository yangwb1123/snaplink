The requirements specification is complete and written to `docs/architect-analysis/cmd-snaplink-stripe-adapter-b4-1-tenantless-carveout-requirements.md`.

## Evidence verification results

Every citation was checked against the repository; all confirmed with minor line drift:

| Citation | Measured reality |
|---|---|
| `http.go:236-246` | `authorizeUserCheckout` spans 233-252; guard at 241; D1 carve-out comment at 243-248 (confirmed, drift) |
| `http_test.go:452-462` | Helper comment "tenant-less console / pre-B4-1 fleet shape" at 453-455; func at 456-464; the A15 pin itself at 322-348 (confirmed, drift) |
| `http_test.go:281-296` | A8 baseline-comparison block in `TestCheckoutMachineRejectsClaimMismatch` (265-296); byte-equality compare at 291-296 (confirmed) |
| `issue_payload.go:57-63` | `TenantID: subject.TenantID` at line 46, unconditional with `omitempty` (confirmed, drift to 43-46) |
| `claims.go:83-88` | `HasTenantID` at 87-89 (confirmed) |
| `test/stripe_adapter_tenant_claim_test.go` | Exists; T-9 e2e harness with A11-A13 pins (confirmed) |

**Key verification findings folded into the spec:**
- **B4-1 nuance**: the mint guarantee stamps `tenant_id` for every *bound* client; an *unbound* client still mints claim-less by design (entitiescmd B4-1 contract case 5, `omitempty`). So "claim-less = drift" is a deployment-model statement, not a wire-level one — recorded as decision D6 with the A18 e2e pinning the unbound mint shape.
- **Legacy-test precedent confirmed**: `docs/campaigns/implementation-gate.md` row 3 orders `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` deleted as transitional defect locks — the exact category the direction assigns to the A15 pin.
- **E2E boundary honored**: `test/` (package `ssotest`) cannot import `cmd/` (package main), so T-9's "passes the gate / fails closed" is split — mint shape + rs projection in `test/` (A17/A18), gate decision at unit level (A16).
- **Acceptance preserved**: T-8(c) → A16 (byte-identical to the claim-mismatch baseline via the A8 comparison shape, exact challenge equality, A15 + D1 comment deleted); T-9 → A17/A18; wire contracts (openapi.yaml, error-codes.md) updated in the same change per AGENTS.md §5.6.

No scope expansion: mint-side, rs, machine-flow, and config are explicitly non-goals; the change is one guard-condition removal, two test edits, one new unit test, one e2e extension, and two doc wordings.
