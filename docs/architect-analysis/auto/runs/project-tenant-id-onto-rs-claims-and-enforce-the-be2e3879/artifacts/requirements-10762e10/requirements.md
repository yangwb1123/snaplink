The spec is complete and internally consistent. Final deliverable summary:

## Deliverable

**`docs/architect-analysis/cmd-snaplink-stripe-adapter-tenant-claim-requirements.md`** — an evidence-backed requirements specification for the direction "Project tenant_id onto rs.Claims and enforce the token's tenant binding in the adapter's checkout authorization", following the sibling `cmd-snaplink-billing-tenant-claim-requirements.md` (same campaign, same B4-1 claim) as the house template.

## Evidence verification (all 5 citations confirmed)

| Citation | Verdict |
|---|---|
| `infrastructure/defaultimpl/issue_payload.go:46` — `TenantID: subject.TenantID` | ✅ line-exact; unconditional stamp, `omitempty` omission, `ext` duplicate stripped |
| `shared/core/consts_wire.go:169` — `KeyTenantID = "tenant_id"` | ✅ line-exact |
| `interfaces/ssoclient/rs/claims.go:13-38` — no TenantID field | ✅ struct 13-46, `Raw` only; `wireClaims` (93-109) / `parseClaims` (113-141) project nothing |
| `cmd/snaplink-stripe-adapter/http.go:200-235` — trio never reads tenant_id | ✅ trio spans 198-236; user flow binds from `input.TenantID`→`TenantBindings`, machine from `CheckoutBindings[clientID]` |
| `interfaces/ssoclient/rs/authz.go:23` — `CheckScope` | ✅ line-exact |

Key supporting verification that shaped the spec: the mint chain is fully live (`internal/handler/tokengrant/token_client_credentials.go:52` stamps `TenantID: client.TenantID` → claim emitted), the adapter runs JWT-mode `rs.HTTPMiddleware` (no introspection), and the server-side introspection body doesn't echo `tenant_id` (declared non-goal).

## Spec decisions (all within the direction's boundary)

- **R1**: `Claims.TenantID` + wire tag + both decode paths + `HasTenantID()` — T-8(a) parse tests (new rs test file; existing rs tests untouched).
- **R2 (user flow)**: claim ≠ input tenant → single constant `403 tenant_mismatch` (existing documented code), with unbound/missing-input-tenant causes **collapsed into the same byte-identical response** — the oracle-collapse the "without leaking tenant existence" clause requires. Missing-claim passes (shared-console deployment preserved; decision D1).
- **R3 (machine flow)**: claim inconsistent with clientID binding — including **absent** (fail-closed, decision D2) — folds into the existing byte-identical `403 insufficient_scope` (decision D4, matching the billing sibling's no-new-oracle precedent; no test-pin churn for the input-mismatch case).
- **R5**: cross-server e2e (package `ssotest`, real `POST /token` mint → production `rs` middleware → `ClaimsFromContext`), mirroring the campaign's established `srCC` seam; self-contained (registry unwired, no dependency on the sibling scope-matrix direction).
- **R6**: openapi.yaml + `docs/error-codes.md` in the same change; A14 pins `make ci`.
- Enumerated the exact existing-test assertion changes (R4) — only the two user-flow unbound/missing cases change shape; all other pins hold.
- Rollout sequencing (G1 → G5) and budget checks (both gate functions stay ≤50 lines, `claims.go`/`http.go` comfortably inside 500) documented.
