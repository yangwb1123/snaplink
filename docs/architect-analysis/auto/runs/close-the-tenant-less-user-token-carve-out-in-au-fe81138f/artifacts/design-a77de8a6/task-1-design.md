Design delivered. Summary:

## Evidence verification verdict

All 7 primary citations **verified against HEAD** — the requirements spec is accurate. Confirmed with measured line positions: guard at `http.go:241` with carve-out comment 243-248; A15 pin at `http_test.go:322-348`; A8 byte-equality comparison at 291-296; unconditional mint stamp at `issue_payload.go:46` (`omitempty`); `HasTenantID` at `claims.go:87-89`; e2e harness exists (200 lines, A11-A13). Load-bearing supporting facts also checked: machine flow already fails closed (A9), entitiescmd B4-1 case 5 (unbound client mints 200 with no `tenant_id`) and case 7, the legacy-discovery deletion precedent in `implementation-gate.md` row 3, the `test/`-cannot-import-`cmd/` boundary, and the 10-file fan-out ceiling.

**Two drifts found, one new:**
1. `token_client_credentials.go:52` lives at `internal/handler/tokengrant/` — the spec omitted the path (non-goal citation only; substance confirmed).
2. Corrected two of my own line citations during drafting: the nil-claims guard is at `http.go:201-204`, and A6 spans 158-171.

## Design (written to `docs/architect-analysis/cmd-snaplink-stripe-adapter-b4-1-tenantless-carveout-design.md`)

- **Core change**: one guard-condition prefix removal at `http.go:241` — `claims.HasTenantID() &&` dropped, making a claim-less user token (`"" != input.TenantID`) fail closed. Four causes, one `writeCheckoutChallenge(…, ErrTenantMismatch, "")` writer call, byte-identical wire response.
- **API changes**: none at the wire level — no endpoint/schema/error-code/config/metric changes. A documented behavioral contract change: the `tenant_mismatch` cause set grows 3→4 and claim-less user tokens stop passing. Docs-only wording updates in `openapi.yaml` and `error-codes.md`.
- **Compatibility constraints**: no opt-out (deliberate); deployment-model compatibility is the hard constraint — every console client must be tenant-bound at the IdP before rollout; `binding == nil` short-circuit order preserved; `HasTenantID` stays live in `rs`; nil-safety of the field access relies on the `authorizeCheckout` guard at 201-204 (recorded in the comment).
- **Failure modes**: all dependency-chain failures (pre-B4-1 issuer, unbound client, partial rollout, mint regression) degrade to the constant 403 — never to a possibly-wrong-tenant 201; rollback is a one-line revert that restores A15 with the guard.
- **Migration**: 7 ordered steps from mint-guarantee confirmation through client inventory/binding, pre-flight mint proof, ship, observe, rollback.
- **Acceptance mapping**: T-8(c) → A16 (claim-less vs claim-mismatch baseline, byte-equal via the A8 comparison shape); T-9 → A17/A18 (console-e2e mints `tenant_id == "tenant-e2e"` + rs projection; console-legacy mints claim-less); contracts → A19, with Given/When/Then form and the exact assertion list per pin.
