# Requirements Spec: close the tenant-less user-token carve-out in authorizeUserCheckout under the B4-1 mint guarantee

- Direction: "Close the tenant-less user-token carve-out in authorizeUserCheckout once the B4-1 mint guarantee lands" (source: `docs/architect-analysis/auto/analyses/cmd-snaplink-stripe-adapter-f67dafca.json`, entry 1)
- Analysis module: `cmd/snaplink-stripe-adapter`; change surface: `cmd/snaplink-stripe-adapter/http.go` (gate condition + comment), `cmd/snaplink-stripe-adapter/http_test.go` (delete the A15 pin, add the T-8(c) pin, helper comment), `test/stripe_adapter_tenant_claim_test.go` (e2e extension), `cmd/snaplink-stripe-adapter/openapi.yaml` and `docs/error-codes.md` (wire-contract wording). No mint-side, rs, config, or machine-flow changes.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/snaplink-stripe-adapter/http.go:236-246` — authorizeUserCheckout HasTenantID carve-out | `authorizeUserCheckout` spans 233-252. The guard `binding == nil \|\| (claims.HasTenantID() && claims.TenantID != input.TenantID)` is at line 241; the comment at 243-248 states "A claim-less token (tenant-less console client — no mint-time binding) passes when the input tenant is bound; the HasTenantID guard is the policy carve-out that keeps shared-console deployments working" | Confirmed (line drift: guard 241, carve-out comment 243-248) |
| `cmd/snaplink-stripe-adapter/http_test.go:452-462` — testAdapterHandlerSubjectWithoutTenantClaim "pre-B4-1 fleet shape", A15/D1 pin | Helper comment at 453-455 ("mints a claim-less token (the tenant-less console / pre-B4-1 fleet shape) for the absent-claim negatives (A9) and the D1 pin (A15)"), func at 456-464. The A15 pin itself is `TestCheckoutUserAcceptsTenantlessConsoleToken` (comment 315-321, func 322-348): claim-less user token on bound input tenant → 201 + binding-selected assertion; companion unbound input → exact `tenantMismatchChallenge` | Confirmed (line drift; pin func at 322, helper at 456) |
| `cmd/snaplink-stripe-adapter/http_test.go:281-296` — byte-identical rejection baseline pattern | The recorded-baseline + byte-equality shape lives in `TestCheckoutMachineRejectsClaimMismatch` (A8, 265-296): an input-mismatch rejection is recorded as the baseline (273-279), the claim-mismatch response is asserted equal on Code, body bytes, and full `http.Header` map via `reflect.DeepEqual` (291-296). The cited range covers the claim-mismatch construction and comparison | Confirmed (comparison block 291-296) |
| `infrastructure/defaultimpl/issue_payload.go:57-63` — TenantID stamped unconditionally at mint | `TenantID: subject.TenantID` is at line 46 inside `buildAccessPayload` (26-48), assigned unconditionally next to `ServingRegion` (42) with the comment at 43-46: "the client's mint-time tenant binding is stamped unconditionally and omitempty omits it when empty (single-tenant stays byte-identical)". `claimsWithoutEmittedKeys` (115-135) strips a same-named attribute-bag copy so the mint-time literal wins | Confirmed (line drift: 43-46) |
| `interfaces/ssoclient/rs/claims.go:83-88` — HasTenantID | Comment 83-86, `func (c *Claims) HasTenantID() bool` at 87-89, `return c != nil && c.TenantID != ""` — presence == non-empty | Confirmed (line drift: 83-89) |
| `test/stripe_adapter_tenant_claim_test.go` — T-9 e2e, A11-A13 | File exists (200 lines): `newStripeAdapterHarness` seeds two tenant-bound machine clients (`checkout-e2e`/`tenant-e2e`, `checkout-other`/`tenant-other`); `scCC` mints client_credentials with RFC 8707 `resource`; `TestStripeAdapterTenantClaim_MintAndProjection` asserts the wire claim (A11) and the production rs middleware projection (A12/A13); `TestStripeAdapterTenantClaim_ResourceRequired` pins the aud precondition. No console/unbound client today | Confirmed (file exists; extension seam as cited) |

Supporting facts (not cited by the direction but load-bearing for the requirements):

| Fact | Measured reality |
|---|---|
| Machine flow already fails closed (the contrast class) | `authorizeMachineCheckout` (http.go:212-231) rejects when `claims.TenantID != binding.TenantID`, including the absent claim (`""`); pinned by `TestCheckoutMachineRejectsMissingTenantClaim` (A9, http_test.go:296-315), whose comment names the "pre-B4-1 fleet" drift class. The user flow is the only remaining fail-open class — the direction's problem statement is exact |
| B4-1 mint contract (what "every mint" means) | `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-1-tenant-claims-requirements.md` case 7: every grant path (authcode/cc/refresh/device/CIBA/jwt-bearer/token-exchange) mints `tenant_id == client.TenantID`; case 5: an UNBOUND client (`TenantID: ""`) still mints a 200 token with NO `tenant_id` key (single-tenant byte-compat via `omitempty`). So "claim-less = provable mint-time drift" is a deployment-model statement — true for every client the adapter config binds, not a wire-level statement about all possible mints. The fail-closed gate is the enforcement point; see decision D6 |
| The A4/A5 user-flow pins this change must not disturb | `TestCheckoutUserRejectsTenantClaimMismatch` (A4, 211-230) and `TestCheckoutUserTenantMismatchIsByteIdentical` (A5, 232-262) pin the three-cause constant collapse: bound-other mismatch, unbound input, missing input → 403, body exactly `{"error":"tenant_mismatch"}`+"\n", challenge exactly `Bearer realm="stripe-adapter", error="tenant_mismatch"` (no scope attribute), byte-equal across causes (`tenantMismatchChallenge` const at 204). The T-8(c) pin joins this collapse as a fourth cause; A5's own map needs no edit |
| The legacy-discovery-test precedent the direction analogizes to | `docs/campaigns/implementation-gate.md` row 3 (F-3 discovery truthiness): the contract orders `TestOIDCDiscovery` (legacy `routes_test.go:41`, asserting `/authenticate`, `/login`) and `TestOIDCDiscoveryEndpoint` (legacy `routes_test.go:497`, asserting the 8080:0 port bug) deleted and not carried into the deploy repo — transitional defect regression locks removed once the corrected behavior is pinned. `TestCheckoutUserAcceptsTenantlessConsoleToken` is the same category: it locks in a transitional carve-out whose precondition (claim-less mint) is drift under B4-1 |
| Wire contracts that must track the flip | `cmd/snaplink-stripe-adapter/openapi.yaml:24-29` (authorization description), `:175` (`CheckoutRequest.tenant_id` description), `:218-221` (Forbidden response) and `docs/error-codes.md:1044-1051` (Stripe adapter section + `tenant_mismatch` row at 1051) all describe the rejection causes; the claim-less cause must join them or the docs assert the pre-change behavior |
| Helper reuse after the A15 deletion | `testAdapterHandlerSubjectWithoutTenantClaim` (http_test.go:456-464) stays in use: `TestCheckoutMachineRejectsMissingTenantClaim` (A9) needs the claim-less shape. Only its comment (453-455) must drop the "(A15)" reference |
| E2E boundary | `test/` is package `ssotest`; the adapter is `package main` and cannot be imported (AGENTS.md; established in the prior spec). The e2e proves the mint-side shape and the production rs projection; the gate decision stays pinned at unit level. The T-9 "passes the tenant gate / fails closed" clauses are therefore split: mint+projection in `test/`, gate decision in `cmd/snaplink-stripe-adapter/http_test.go` |

**Gap confirmation (the direction's problem is real).** B4-1's mint stamps `tenant_id` from the client binding at `issue_payload.go:46`, and the machine flow already fails closed on a missing claim (http.go:225-226, A9). The user flow alone still accepts a claim-less token against any bound input tenant (http.go:241, `claims.HasTenantID() &&`), documented at 243-248 as the D1 policy carve-out and pinned by the A15 test (http_test.go:322-348). Under the B4-1 deployment model — the adapter's `TenantBindings`/`CheckoutBindings` correspond to IdP client bindings — a claim-less user token is provable mint-time drift, and this is the last fail-open tenant-isolation class in the adapter.

## 2. Goal and user outcome

The checkout route's tenant isolation becomes uniformly fail-closed:

- A user token without a `tenant_id` claim is rejected against any bound input tenant with the existing constant `403 tenant_mismatch` response, byte-identical to the claim-mismatch, unbound, and missing-input causes (four causes, one writer call, no new observable class).
- The D1 carve-out comment and its A15 defect-test pin are deleted; the carve-out's transitional precondition (a tenant-less console client minting claim-less tokens) no longer exists in a B4-1 fleet.
- The e2e proves the mint-side half of the new contract: a console client seeded with a tenant binding mints a binding-stamped `tenant_id` (the token shape that passes the gate), and the only remaining claim-less mint source — an unbound client — produces exactly the token shape the unit-pinned gate rejects.

Completion marker: the direction's acceptance — T-8(c) unit pin (claim-less user token on a bound input tenant → 403 `tenant_mismatch` byte-identical to the claim-mismatch row, WWW-Authenticate without scope attribute; delete `TestCheckoutUserAcceptsTenantlessConsoleToken` and the D1 carve-out comment) and T-9 e2e extension (console client mints a binding-stamped `tenant_id` and passes the tenant gate; a claim-less token minted by the pre-change issuer fails closed) — plus the campaign's single-trust-path intent: the adapter's user path now consumes the B4-1 mint-time claim exactly as the machine path already does.

## 3. Product boundary

- Surface: `cmd/snaplink-stripe-adapter/http.go` (one guard condition at 241 + comment rewrite at 243-248), `cmd/snaplink-stripe-adapter/http_test.go` (delete A15 pin 315-348; add the T-8(c) pin; update helper comment 453-455), `test/stripe_adapter_tenant_claim_test.go` (two new harness clients + assertions), `cmd/snaplink-stripe-adapter/openapi.yaml` and `docs/error-codes.md` (claim-less cause in the rejection wording).
- Defaults: always-on, no new config knob — the gate condition is a pure removal of the `HasTenantID() &&` prefix.
- Explicit non-goals (do not implement):
  - No mint-side change: `issue_payload.go:46`, `token_client_credentials.go:52`, and the other seven grant-path stamps are correct as shipped (B4-1). The `omitempty` single-tenant behavior stays (decision D6).
  - No `rs` change: `Claims.TenantID`/`HasTenantID` (claims.go:87-89) are already landed from the prior direction.
  - No machine-flow change: `authorizeMachineCheckout` (http.go:212-231) and its A8/A9 pins stay byte-for-byte.
  - No new error code, endpoint, config key, audit event, or metric. `tenant_mismatch` (model.go:55) is already emitted by this adapter.
  - No change to the webhook/worker/relay surface, billing gateway call, or the A4/A5/A6/A7 user-flow pins.
  - The other two analysis rows (scope-matrix aliasing B4-2, governance connector B4-5) are explicitly excluded.

## 4. Module classification

- [x] Authorization / resource-server gate (user-flow tenant gate closes the last fail-open class)
- [x] Testing (T-8(c) unit pin, T-9 e2e extension, A15 deletion)
- [x] Documentation (openapi.yaml, error-codes.md wording)
- [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Cold module · [ ] Refactoring only

## 5. Requirements

### R1 — user-flow gate flips to fail-closed on a claim-less token (http.go:241)

R1.1 The guard becomes `binding == nil || claims.TenantID != input.TenantID`: drop the `claims.HasTenantID() &&` prefix so the absent claim (`""`) mismatches any non-empty bound input tenant. Behavior for the three existing causes is unchanged (`binding == nil` still fires first, short-circuit-safe; `input.TenantID == ""` still resolves `binding == nil`). The claim-mismatch, unbound, missing-input, and claim-less causes share the same single `writeCheckoutChallenge(writer, http.StatusForbidden, ErrTenantMismatch, "")` call (http.go:249-251).
R1.2 Rewrite the comment at 243-248: the carve-out sentence ("A claim-less token (tenant-less console client — no mint-time binding) passes when the input tenant is bound; the HasTenantID guard is the policy carve-out...") is deleted; the surviving comment names all four causes and states that the mint-time binding is stamped unconditionally under B4-1 (`issue_payload.go:46`), so a claim-less user token is provable mint-time drift and fails closed with the same constant response.
R1.3 No other production-code change in `cmd/snaplink-stripe-adapter`: scope-failure path (http.go:234-237), machine gate, challenge writer, and headers stay untouched.

### R2 — delete the A15 pin and the D1 references

R2.1 Delete `TestCheckoutUserAcceptsTenantlessConsoleToken` (http_test.go:315-348) — the transitional defect-test pin of the D1 carve-out, same category as the two legacy discovery tests the contract orders deleted (`TestOIDCDiscovery`, `TestOIDCDiscoveryEndpoint`, `docs/campaigns/implementation-gate.md` row 3).
R2.2 Update the helper comment at http_test.go:453-455: `testAdapterHandlerSubjectWithoutTenantClaim` stays (the A9 machine pin at 296-315 uses it), but the comment drops the "(A9) and the D1 pin (A15)" framing; it now mints the claim-less drift shape only.
R2.3 The `tenantMismatchChallenge` const (http_test.go:204), the A4/A5/A6/A7 pins, and the machine A8/A9/A10 pins remain unchanged and green.

### R3 — T-8(c) unit pin (new test in http_test.go)

R3.1 New test `TestCheckoutUserRejectsClaimlessToken` (the A-series continues at A16), reusing the A8 baseline-comparison shape (http_test.go:273-296): first record the claim-mismatch row as the baseline — user token minted with claim `tenant_id: "tenant-one"` (`testAdapterHandlerSubjectTenant`, scope `admin:write`) posting `{"tenant_id":"tenant-other",...}` → 403, body exactly `{"error":"tenant_mismatch"}`+"\n", challenge exactly `tenantMismatchChallenge`.
R3.2 Then mint a claim-less user token (`testAdapterHandlerSubjectWithoutTenantClaim`, `"user-one"`/`"console-client"`/`scopeAdminWrite` — the fixture's `TenantBindings` already binds `tenant-one`) and post the bound input tenant `{"tenant_id":"tenant-one",...}`. Assert: status 403; body exactly `{"error":"tenant_mismatch"}`+"\n"; `WWW-Authenticate` exactly `tenantMismatchChallenge` (no `scope=` attribute); and the full recorded response — Code, body bytes, and the complete header map via `reflect.DeepEqual` — byte-equal to the R3.1 baseline. Transitivity with A5 (bound-other == unbound == missing are already byte-equal) makes the claim-less cause byte-identical to all four causes without touching A5's map.
R3.3 The test's comment states the pin's meaning: post-B4-1 a claim-less user token is mint-time drift (the mint stamps the client binding unconditionally, `issue_payload.go:43-46`), and the rejection is indistinguishable from every other tenant-class cause (no tenant/claim/binding disclosure).

### R4 — T-9 e2e extension (test/stripe_adapter_tenant_claim_test.go, package ssotest)

R4.1 Harness (`newStripeAdapterHarness`) gains two clients alongside `checkout-e2e`/`checkout-other`:
- `saConsoleClient = "console-e2e"` — the console-shaped client under the B4-1 model, seeded with `TenantID: "tenant-e2e"`, `AllowedScopes` including `saScope` and `"admin:write"` (user tokens carry `admin:write`; the mint path is grant-agnostic — `buildAccessPayload` stamps the client binding identically, so the client_credentials mint proves the console mint shape).
- `saLegacyClient = "console-legacy"` — the pre-B4-1/unbound shape, seeded with `TenantID: ""` (entitiescmd B4-1 contract case 5: an unbound client still mints 200 with no claim).
R4.2 A17 (console mint passes the gate's precondition): `scCC(t, srv, saConsoleClient, saAudience)` → 200; the wire payload (base64url-decode of the middle segment) carries `tenant_id == "tenant-e2e"`; the production rs middleware with the adapter's exact config shape (`Issuer` + `JWKSCache` + `ExpectedAud: saAudience`, no IntrospectURL) yields `ClaimsFromContext().TenantID == "tenant-e2e"` and `HasTenantID() == true`. This is the mint-side half of "a console client mints a binding-stamped tenant_id and passes the tenant gate": the gate's pass for a stamped user token is pinned at unit level by the existing A6 pin, and the gate's consumption of this exact projection is pinned by A12/A13's existing assertions.
R4.3 A18 (pre-change issuer shape fails closed): `scCC(t, srv, saLegacyClient, saAudience)` → 200; the wire payload carries NO `tenant_id` key (the claim-less token the pre-B4-1 fleet / unbound client produces). The fail-closed rejection of exactly this shape is the unit-level T-8(c) pin (R3); together, a claim-less token minted by the pre-change issuer fails closed end to end. The e2e cannot exercise the adapter's handler itself (package main, not importable from `test/` — AGENTS.md), so the e2e asserts the mint-side shape and the unit pin asserts the gate decision.
R4.4 The existing `TestStripeAdapterTenantClaim_MintAndProjection` and `TestStripeAdapterTenantClaim_ResourceRequired` stay unchanged and green.

### R5 — wire contracts (same change)

R5.1 `docs/error-codes.md` Stripe adapter section (1044-1051): the user-flow sentence and the `tenant_mismatch` row (1051) gain the claim-less cause — e.g. the emitted-when cell becomes "...contradicts the request `tenant_id`, the request `tenant_id` is missing or names an unbound tenant, or the token carries no `tenant_id` claim". No new row; no change to any other code's wording.
R5.2 `cmd/snaplink-stripe-adapter/openapi.yaml`: the Forbidden description (218-221) and the authorization description (24-29) gain the claim-less cause ("a user-shaped token without a `tenant_id` claim is rejected identically"); the `CheckoutRequest.tenant_id` description (175) keeps its "required for user-shaped tokens" statement consistent with the flip. No schema change.

Acceptance:
- A19: `make ci` (OpenAPI validation) passes with the updated yaml; `docs/error-codes.md` describes the claim-less cause for `tenant_mismatch`.

## 6. Engineering gates and verification

- Budgets: `http.go` (423 lines) loses a condition prefix — `authorizeUserCheckout` (233-252) stays at 20 lines, complexity and `if`-nesting unchanged. `http_test.go` (556 lines) deletes 34 lines and adds ~35. `test/stripe_adapter_tenant_claim_test.go` (200 lines) gains two constants and one test (~45 lines). No new packages, no new non-test files in `cmd/snaplink-stripe-adapter` (already at its 10-file fan-out ceiling — edits only); `interfaces/sso` (60-file ceiling) and `interfaces/ssoclient/rs` untouched.
- After every `.go` edit: `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .`.
- Targeted: `go test ./cmd/snaplink-stripe-adapter/...`, then `go test ./test/ -run 'TestStripeAdapterTenantClaim' -v`.
- Handoff: `go test ./... -race` and `make ci` (nested modules, config, module validation unaffected — no manifest/profile change).
- Oracle-safety review (AGENTS.md §3): the user-flow tenant rejection remains a single constant response across all four causes; A5 plus the new T-8(c) pin pin byte-equality; no tenant value, claim value, or binding indicator crosses any wire; no audit path exists on this surface (metrics only).
- Rollout sequencing: this lands after the B4-1 mint guarantee, which is already live in-tree (`issue_payload.go:46` stamps the binding unconditionally; the prior direction's gates already landed). Deployment note: a fleet that still runs a genuinely tenant-less console client (unbound at the IdP) must bind that client to its tenant before rollout — the A17 mint assertion doubles as the deployment-time proof that `/token` stamps the claim for the console client, and A18 proves the unbound shape is exactly what the gate now rejects. This mirrors the prior spec's G1 → G5 sequencing applied to the carve-out removal.

## 7. Acceptance summary (direction contract, preserved)

| Direction acceptance | Testable form (this spec) |
|---|---|
| T-8(c): unit pin that a claim-less user token on a bound input tenant returns 403 `tenant_mismatch` byte-identical to the claim-mismatch row (reuse the baseline-comparison shape at http_test.go:281-296, WWW-Authenticate without scope attribute); delete `TestCheckoutUserAcceptsTenantlessConsoleToken` and the D1 carve-out comment | R1 + R2 + R3 → A16 (new `TestCheckoutUserRejectsClaimlessToken`: claim-less user token on bound `tenant-one` → 403, exact body, exact challenge equality, full response byte-equal to the A4 claim-mismatch baseline via the A8 comparison shape); A15 test and the http.go:243-248 carve-out sentence deleted; A4/A5/A6/A7/A9 pins unchanged and green |
| T-9: extend `test/stripe_adapter_tenant_claim_test.go` so a console client mints a binding-stamped `tenant_id` and passes the tenant gate; a claim-less token minted by the pre-change issuer fails closed | R4 → A17 (console-shaped client `console-e2e` seeded with `TenantID: "tenant-e2e"` mints a wire `tenant_id == "tenant-e2e"` and projects through the production rs middleware with `HasTenantID() == true` — the mint-side guarantee the gate's pass requires; gate pass pinned by A6) and A18 (unbound client `console-legacy` mints a 200 token with no `tenant_id` key — the pre-change issuer shape — which the unit-pinned gate rejects fail-closed) |
| Contracts updated in the same change | R5 → A19 (error-codes.md row gains the claim-less cause; openapi.yaml Forbidden/authorization wording; `make ci` green) |

## 8. Decisions (resolved, with rationale)

- D1 (prior spec) is hereby revoked: the user-flow absent-claim carve-out is closed. Rationale: the B4-1 mint guarantee (`issue_payload.go:43-46`) stamps `tenant_id` from the client binding unconditionally, so under the adapter's deployment model (every client the adapter config binds is tenant-bound at the IdP) a claim-less user token is provable mint-time drift — the same reasoning D2 already applied to the machine flow. The carve-out's protected deployment (tenant-less shared console) becomes a migration, not a supported fleet shape: the console client is bound to a tenant at the IdP, and the T-9 console mint (A17) proves the resulting token passes the gate.
- D2 (machine flow, absent claim → fail closed) stays unchanged.
- D3 (user-flow rejection collapse) is extended from three to four causes: the claim-less token joins missing-input, unbound-input, and claim-mismatch under the one constant `tenant_mismatch` writer call — any distinguishable variant would let a token holder probe whether the IdP binds the minting client.
- D6 (new — "claim-less = drift" is a deployment-model statement, not a wire-level one): B4-1 deliberately keeps the unbound-client mint claim-less (`omitempty`, entitiescmd contract case 5, single-tenant byte-compat). The adapter cannot distinguish "unbound IdP client" from "pre-B4-1 issuer" on the wire, and does not need to: both are drift relative to the adapter's bindings, both get the same constant rejection, and the e2e's A18 pins the mint-side shape while A16 pins the gate decision.
- D7 (new — e2e boundary): `test/` is package `ssotest` and cannot import `cmd/` (package main; AGENTS.md), so "passes the tenant gate / fails closed" in the T-9 acceptance is split: mint shape + production rs projection in `test/` (A17/A18), gate decision in the adapter's unit tests (A6/A16). The direction's acceptance is preserved in full; no cross-package import is introduced.
