Requirements spec complete. Written to the pipeline's requirements artifact path:

**`docs/architect-analysis/auto/runs/close-the-last-fail-open-tenant-isolation-class--41270b2a/artifacts/requirements-10762e10/requirements.md`** (122 lines)

## Evidence verification — every direction citation re-checked against the working tree

| Citation | Verdict | Measured reality |
|---|---|---|
| `http.go:233-252` carve-out at :241, D1 comment :243-248 | Confirmed | Guard `binding == nil \|\| (claims.HasTenantID() && ...)` at 241; carve-out sentence at 246-249; single `ErrTenantMismatch` writer at 250-251 |
| `http_test.go:322-348` A15 pin, :456-464 helper | Confirmed | `TestCheckoutUserAcceptsTenantlessConsoleToken` func 322-348 (201 + binding-selected assertion); `testAdapterHandlerSubjectWithoutTenantClaim` 456-464 |
| `issue_payload.go:26-48,83-87` B4-1 mint | Confirmed (minor drift) | `TenantID: subject.TenantID` unconditional at 46; Roles guard+copy at 86-88 |
| `http.go:212-231` machine fails closed | Confirmed | `claims.TenantID != binding.TenantID` at 226 — already **landed** in the working tree |
| Approved spec R1.1/R2.1/R3 | Confirmed | `ErrTenantMismatch` const landed (model.go:55); user-gate flip, A15 pin, D1 comment still present — partial-landing state matches the direction exactly |

Baseline verified green: `go build ./... && go vet ./cmd/snaplink-stripe-adapter/... && go test ./cmd/snaplink-stripe-adapter/ -run 'TestCheckout|TestStripe'` (0.018s).

## Spec structure

- **R1** — guard flip at http.go:241 to `binding == nil || claims.TenantID != input.TenantID` (short-circuit-safe), comment rewrite, no other production change
- **R2** — delete A15 pin (315-348) and D1 references; helper comment drop
- **R3** — T-8(c) pin `TestCheckoutUserRejectsClaimlessToken`: claim-less user token on bound `tenant-one` → 403, exact body `{"error":"tenant_mismatch"}`+"\n", exact `tenantMismatchChallenge` equality, full response byte-equal to the recorded claim-mismatch baseline via the A8 comparison shape (273-295), transitivity with A5
- **R4** — T-9 e2e: `console-e2e` (seeded `TenantID: "tenant-e2e"`) mints wire `tenant_id` + projects `HasTenantID()==true` through production rs middleware (A17); `console-legacy` (`TenantID: ""`) mints a 200 claim-less token, the exact shape the unit gate rejects (A18)
- **R5** — preserved wire-contract wordings (openapi.yaml 20-29/175/215-221, error-codes.md 1043-1062), A19 via `make ci`

Both acceptance checks (T-8(c), T-9) are preserved verbatim and made testable with exact byte/header assertions; the e2e boundary (`test/` cannot import `package main`) is honored by splitting mint+projection (test/) from gate decision (unit). Scope is bounded to the direction: no mint-side, `rs`, machine-flow, or config changes.
