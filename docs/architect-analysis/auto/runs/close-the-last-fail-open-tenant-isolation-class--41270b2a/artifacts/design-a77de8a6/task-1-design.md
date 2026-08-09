Design complete. Summary of the verification and the deliverable:

## Evidence verification — all claims confirmed

Every citation in the supplied evidence was re-measured against the working tree (which holds this direction's partial landing as uncommitted edits):

| Claim | Verdict |
|---|---|
| `http.go:233-252` carve-out at :241, D1 comment :243-248, single writer :250-251 | ✅ Confirmed |
| `http_test.go:322-348` A15 pin, :456-464 claim-less helper | ✅ Confirmed |
| `issue_payload.go` B4-1 mint — `TenantID` unconditional at :46, Roles guard+copy :86-88 | ✅ Confirmed (minor drift) |
| Machine flow fails closed (`claims.TenantID != binding.TenantID` at :226) | ✅ Confirmed — landed |
| `ErrTenantMismatch` at model.go:55 | ✅ Confirmed |
| A8 byte-identity shape :273-295, openapi.yaml 20-29/175/215-221, error-codes.md 1043-1062 | ✅ Confirmed |
| Baseline green | ✅ Re-ran: `go build ./... && go vet` + `TestCheckout|TestStripe` → `ok 0.014s` |

No claim was contradicted. The gap is real: a claim-less user token still passes any bound input tenant (the `HasTenantID() &&` prefix at http.go:241), while the machine path rejects the identical shape.

## Design delivered

Written to the pipeline's design-stage path: `docs/architect-analysis/auto/runs/close-the-last-fail-open-tenant-isolation-class--41270b2a/artifacts/design-a77de8a6/task-1-design.md`

- **API change**: single production edit — http.go:241 becomes `binding == nil || claims.TenantID != input.TenantID` (short-circuit-safe; the `"" != "tenant-one"` case is the only new 403). No new code/header/param/knob; the one wire delta is a previously-201 class now returning the existing constant `403 tenant_mismatch`.
- **Compatibility**: four-cause byte-identity (missing/unbound/mismatch/claim-less) via one writer call, pinned by A4/A5 + new A16; machine flow, mint, `rs`, and all A8/A9 pins frozen; `cmd/snaplink-stripe-adapter` at its 10-file fan-out ceiling → edits only.
- **Failure modes**: unbound console client still in fleet → intended 403 (detect via `checkout_created` drop; bind at IdP, don't roll back); stale pre-B4-1 IdP → same fail-closed 403; rolling deploy is safe (authz precedes any store write); no oracle-leak risk (A5/A16 byte pins).
- **Migration**: M0 precondition already true (mint live at `issue_payload.go:46`) → M1 bind console clients at IdP → M2 code change → M3 gates (`TestCheckout`, `TestStripeAdapterTenantClaim`, `-race`, `make ci`) → M4 rolling deploy → M5 one-line rollback.
- **Acceptance mapping**: T-8(c) → A16 unit pin with exact body/challenge/byte-equality assertions + A15 deletion; T-9 → A17 (console-e2e mints `tenant_id` + `HasTenantID()==true` through production rs middleware) / A18 (`console-legacy` mints the 200 claim-less shape the gate rejects), honoring the `test/`-cannot-import-`package main` boundary; A19 via `make ci`.
