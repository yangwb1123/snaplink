# Requirements Spec: project tenant_id onto rs.Claims and enforce the token's tenant binding in the stripe adapter's checkout authorization

- Direction: "Project tenant_id onto rs.Claims and enforce the token's tenant binding in the adapter's checkout authorization" (source: `docs/architect-analysis/auto/analyses/cmd-snaplink-stripe-adapter-f67dafca.json`, entry 2)
- Analysis module: `cmd/snaplink-stripe-adapter`; change surface: `interfaces/ssoclient/rs` (claim projection only), `cmd/snaplink-stripe-adapter` (checkout authorization gates + tests), `test/` (cross-server e2e), `cmd/snaplink-stripe-adapter/openapi.yaml` and `docs/error-codes.md` (wire contract). No mint-side changes — B4-1 already stamps the claim.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `infrastructure/defaultimpl/issue_payload.go:46` — `TenantID: subject.TenantID` | Line 46 in `buildAccessPayload`, assigned unconditionally next to `ServingRegion` (line 42) with the comment "the client's mint-time tenant binding is stamped unconditionally and omitempty omits it when empty (single-tenant stays byte-identical)". `claimsWithoutEmittedKeys` (115-135) strips a same-named `ext` attribute copy so the mint-time literal wins | Confirmed (line exact) |
| `shared/core/consts_wire.go:169` — `KeyTenantID` | `KeyTenantID = "tenant_id"` at line 169, the wire claim name | Confirmed (line exact) |
| `interfaces/ssoclient/rs/claims.go:13-38` — Claims has no TenantID field | `type Claims struct` at line 13; fields are Issuer/Subject/Audience/ClientID/Scope/JTI/ExpiresAt/NotBefore/IssuedAt/ServingRegion (line 28)/RenewAfter/CnfJKT plus `Raw map[string]any` (line 45) — no TenantID anywhere. `wireClaims` (93-109) carries only `serving_region` among the extension claims; `parseClaims` (113-141) projects only the typed fields. The claim is reachable only untyped via `Raw` | Confirmed (struct spans 13-46; no TenantID field) |
| `cmd/snaplink-stripe-adapter/http.go:200-235` — authorizeCheckout trio never validates tenant_id | `authorizeCheckout` (198-210) dispatches on `claims.ClientID != "" && claims.Subject == claims.ClientID`; `authorizeMachineCheckout` (212-223) binds from `config.CheckoutBindings[claims.ClientID]` and compares only `input.TenantID` against the binding; `authorizeUserCheckout` (224-236) binds from `config.TenantBindings[input.TenantID]` with no claim comparison. Neither flow reads the token's tenant binding | Confirmed (cited range 200-235 covers the trio; the trio actually spans 198-236) |
| `interfaces/ssoclient/rs/authz.go:23` — CheckScope | `func CheckScope(c *Claims, required ...string) error` at line 23; the enforcement seam the machine flow already uses | Confirmed (line exact) |

Supporting facts (not cited by the direction but load-bearing for the requirements):

| Fact | Measured reality |
|---|---|
| Mint chain for machine tokens (the e2e seam) | `internal/handler/tokengrant/token_client_credentials.go:52` stamps `TenantID: client.TenantID` on the `core.Subject` for client_credentials; `buildAccessPayload` then emits the wire claim. `/token` mint → tenant_id is end-to-end reachable in a cross-server test |
| rs validation modes | `validateByMode` (validate.go:104-112) routes to introspection ONLY when `Config.IntrospectURL` is set; the adapter mounts JWT mode — `newAdapterHandler` (http.go:93-98) builds `rs.Config{Issuer, JWKSCache, ExpectedAud, TrustedProxies}` with no IntrospectURL. The adapter therefore consumes claims from `parseClaims` only; the introspection path matters for projection completeness, not for the adapter |
| Introspection projection seam | `wireIntrospection` (introspect.go:71-78) embeds `wireClaims`, so one wire-struct change covers both decode paths; the `Claims` constructor in `ValidateTokenWithIntrospect` (introspect.go:78-93) must copy the new field |
| serving_region precedent | `Claims.ServingRegion` + `HasServingRegion()` (claims.go:71-73) is the exact extension-claim precedent to mirror: field, wire tag, decode projection, presence helper |
| Adapter test seam | `cmd/snaplink-stripe-adapter/http_test.go` `testAdapterHandlerSubject` (307-339) mints tokens via `rstest.NewIssuer().MintAccessToken(map[string]any{...})` — arbitrary claims, so tests can stamp/omit `tenant_id` exactly as the acceptance requires |
| Existing response pins that constrain the gate shapes | `TestCheckoutUserRequiresAdminScopeAndExplicitBoundTenant` (http_test.go:120-137) pins the user flow's unbound/missing-input-tenant rejections to 403 + `WWW-Authenticate` containing `scope="admin:write"`; `TestCheckoutMachineRejectsCrossTenantRequest` (139-146) pins the machine flow's input-tenant mismatch to 403 + `scope="billing:checkout:create"`. These pins define which rejection classes may change shape |
| Adapter error-code contract | `docs/error-codes.md` Stripe section (1034-1062) documents `insufficient_scope` as the only authorization-failure code; `docs/error-codes.md:87` already documents `tenant_mismatch` (403) as the governance code for client/tenant binding mismatches |
| openapi contract | `cmd/snaplink-stripe-adapter/openapi.yaml` `CheckoutRequest.tenant_id` description ("Required for user-shaped tokens; omitted or equal to the bound tenant for machine tokens") and the `Forbidden` response (example challenge `error="insufficient_scope", scope="admin:write"`) must be updated in the same change |
| Cross-server e2e precedent in test/ | `test/scope_registry_test.go` (`newScopeRegistryHarness`, `srCC` at 104-131) is the campaign's established seam: in-process `sso.NewServer` + httptest, real `POST /token` client_credentials mint. `test/` is package `ssotest` and cannot import `cmd/` (AGENTS.md), so the adapter's decision logic stays pinned by the adapter's own unit tests while the e2e proves the mint → validation → projection chain through production components |
| Sibling-module precedent | `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-requirements.md` (same campaign, same B4-1 claim) already specified the rs projection (field + wire tag + both decode paths + `HasTenantID`) and chose to fold drift denials into the existing `insufficient_scope` response ("MUST NOT create an observation distinguishable from a scope denial"). This spec follows that shape where the direction's acceptance does not demand otherwise |

**Gap confirmation (the direction's problem is real).** B4-1's `buildAccessPayload` stamps `tenant_id` from the mint-time client binding, but the claim dies at the RS boundary: `rs.Claims` does not project it, and the adapter's checkout authorization binds the tenant from request input (`input.TenantID` vs `config.TenantBindings`) or from the clientID map (`config.CheckoutBindings`) — never from the token. A token minted for tenant A passes `authorizeUserCheckout` for a request naming any bound tenant B (the claim is simply never read), and a machine token whose claim contradicts the adapter's clientID binding passes whenever the request-level checks do. The B4-1 tenant claim is emitted but unenforced by its first-party RS.

## 2. Goal and user outcome

The G1 trust path's tenant binding becomes enforceable at the adapter, the first-party RS of the checkout route:

- `rs.Claims` projects `TenantID` (both validation modes), so the adapter observes the mint-time binding the way it already observes `serving_region`.
- The user checkout flow rejects any request whose named tenant contradicts the token's `tenant_id` claim, with a single constant `403 tenant_mismatch` response that does not reveal which tenants exist.
- The machine checkout flow rejects any token whose `tenant_id` claim is inconsistent with (or absent from) the adapter's clientID → tenant binding, folded into the existing byte-identical `403 insufficient_scope` rejection so no new observable class appears.
- A cross-server e2e proves the `/token`-minted claim survives mint → signature validation → claims projection, i.e. the enforcement input is trustworthy end to end.

Completion marker: the direction's acceptance (T-8(a) parse projection, T-8(b) user-flow mismatch rejection, T-9 machine-flow consistency + cross-server e2e) plus the campaign's single-trust-path intent hold: the adapter consumes the mint-time claim, and the IdP-side mint pin (campaign row 1: `POST /token` → claims {iss/aud/scope/client_id/tenant_id/roles}) has an adapter-side consumption counterpart.

## 3. Product boundary

- Surface: `interfaces/ssoclient/rs/claims.go` (projection only — additive, no config), `interfaces/ssoclient/rs/introspect.go` (one constructor copy), `cmd/snaplink-stripe-adapter/http.go` (two authorization gates), `cmd/snaplink-stripe-adapter/http_test.go` (fixture updates + new tests), a new rs test file, a new e2e file in `test/`, `cmd/snaplink-stripe-adapter/openapi.yaml`, `docs/error-codes.md`.
- Defaults: both adapter gates are always-on, derived from the existing `CheckoutBindings`/`TenantBindings` config — no new config knob. The single-tenant/shared-console carve-out is preserved for the user flow: a token WITHOUT a `tenant_id` claim still passes the user-flow tenant gate (see decision D1); the machine flow fails closed on absence because the adapter's binding expectation is derived from the token's own client (decision D2).
- Explicit non-goals (do not implement):
  - No mint-side change: `issue_payload.go` and `token_client_credentials.go:52` are correct as shipped (B4-1). No change to `shared/core/consts_wire.go`, `Subject`, or any issuer.
  - No change to the server-side introspection body: `populateAccessIntrospectionBody` (protocols/oauth/introspect_body.go:65-108) does not echo `tenant_id` today. The adapter is JWT-mode and never introspects; the AS echo is a separate server-side direction.
  - No `rs.Config` gate (no `AllowedServingRegions`-style static tenant allowlist): the tenant expectation is per-binding and lives in adapter config, so the gate belongs to the adapter, not the shared RS. rs changes are projection-only.
  - No new endpoints, audit event types, metrics, or config keys. `tenant_mismatch` is an existing documented code (docs/error-codes.md:87) newly emitted by this adapter; no new `Err*` constant is required beyond the wire-code string for the adapter's response.
  - No change to the webhook/worker/relay surface; no change to the billing gateway call.
  - The other two analysis rows (scope-matrix registration, relay convergence) are explicitly excluded.

## 4. Module classification

- [x] Authorization / resource-server gate (user-flow tenant gate, machine-flow binding consistency)
- [x] OAuth/OIDC client (rs claims projection)
- [x] Testing (T-8(a) parse test, T-8(b) adapter gate tests, T-9 e2e)
- [x] Documentation (openapi.yaml, error-codes.md)
- [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Cold module · [ ] Refactoring only

## 5. Requirements

### R1 — rs claims projection (interfaces/ssoclient/rs)

R1.1 `Claims` (claims.go:13) gains `TenantID string`; `wireClaims` (claims.go:93-109) gains `TenantID string \`json:"tenant_id"\``; `parseClaims` (claims.go:113-141) projects `TenantID: w.TenantID`. The introspection path gets the same projection: `wireIntrospection` (introspect.go:71-78) embeds `wireClaims`, so decoding is automatic, and the `Claims` constructor in `ValidateTokenWithIntrospect` (introspect.go:78-93) copies `TenantID: w.TenantID`.
R1.2 An absent `tenant_id` claim decodes to the zero value (`""`) — no `omitempty` needed on decode, no reordering, `Raw` unchanged. Existing rs test files stay untouched and green (this is the direction's stated carve-out).
R1.3 `Claims` gains `HasTenantID() bool` mirroring `HasServingRegion()` (claims.go:71-73): true iff `TenantID != ""`. Tenant IDs are non-empty by construction, so presence == non-empty — same discipline as the serving-region precedent.

Acceptance:
- A1 (new file `interfaces/ssoclient/rs/tenant_claim_test.go`, package `rs`): a JWT payload containing `tenant_id: "tenant-one"` passes `ValidateToken` and yields `Claims.TenantID == "tenant-one"` and `HasTenantID() == true`; the same token without the claim yields `TenantID == ""` and `HasTenantID() == false`; the `Raw` map still contains the claim in both cases.
- A2: one introspection-path case in the same new file (reusing the in-package `introspectServer` seam, introspect_test.go:17): an active introspection response carrying `tenant_id` yields `Claims.TenantID`; a response without it yields `""`.
- A3: `go test ./interfaces/ssoclient/rs/...` with zero modifications to existing rs test files — all green.

### R2 — adapter user-flow tenant gate (authorizeUserCheckout, http.go:224-236)

R2.1 After the existing scope/identity pass, the user flow rejects the checkout when either cause holds, with `binding := a.config.TenantBindings[input.TenantID]`:
- `binding == nil` (input tenant missing or not configured), or
- `claims.TenantID != "" && claims.TenantID != input.TenantID` (the token's mint-time binding contradicts the request).
Decision D1 (absent claim): a token WITHOUT a `tenant_id` claim passes this gate when `binding != nil`. The user flow's binding expectation is on the REQUEST's tenant, not on the token's client; the console client may legitimately be tenant-less (shared console), in which case the IdP stamps no claim and every user token would fail a fail-closed gate. Enforcement is live exactly when the IdP binds the client (the B4-1 model), and the acceptance's mismatch case is what this direction demands.

R2.2 Rejection shape: one byte-identical response for ALL three causes (missing input tenant, unbound input tenant, claim mismatch): status 403, body exactly `{"error":"tenant_mismatch"}`, `WWW-Authenticate: Bearer realm="stripe-adapter", error="tenant_mismatch"` (no `scope` attribute), `Cache-Control: no-store`/`Pragma: no-cache` (already set by `handleCheckout` and `writeCheckoutChallenge`). No tenant value, claim value, or binding indicator may appear in the body, headers, or challenge — an attacker holding a valid token for tenant A must not be able to distinguish "input tenant B is unbound" from "input tenant B is bound to someone else" (both are the same rejection).

R2.3 Scope failures stay exactly as today: missing `admin:write` → 403 `insufficient_scope` with `scope="admin:write"` (http.go:229), pinned by the existing "wrong scope" case. The `tenant_mismatch` rejection must not carry a scope attribute, so the two classes remain distinguishable only by their constant codes.

Acceptance (in `cmd/snaplink-stripe-adapter/http_test.go`; fixture update first — see R4):
- A4 (the hole, closed): fixture gains a second binding `tenant-other` in `TenantBindings` (so "bound tenant B" exists); a user token minted with claim `tenant_id: "tenant-one"` (scope `admin:write`) posting `{"tenant_id":"tenant-other", ...}` → 403, body exactly `{"error":"tenant_mismatch"}`, challenge contains `error="tenant_mismatch"` and no `scope=` attribute. Today this request returns 201 (the direction's problem statement).
- A5 (no tenant-existence leak): the full recorded response (status + headers + body) for the A4 request is byte-equal to the response for `{"tenant_id":"tenant-nowhere", ...}` (unbound tenant) and for a request with no `tenant_id` at all, using the same token. All three are 403 `tenant_mismatch` with identical bytes.
- A6 (matching claim passes): user token with claim `tenant_id: "tenant-one"`, input `tenant_id: "tenant-one"` → 201 as today (the existing `TestCheckoutAuthorizesAdminUserForExplicitBoundTenant` with the fixture's claim added covers this).
- A7 (wrong scope unchanged): user token with `admin:write` missing → 403 `insufficient_scope` with `scope="admin:write"` — the existing "wrong scope" case keeps its assertion byte-for-byte.

### R3 — adapter machine-flow tenant gate (authorizeMachineCheckout, http.go:212-223)

R3.1 Extend the existing rejection condition with the claim-consistency check. With `binding := a.config.CheckoutBindings[claims.ClientID]`, reject when: scope check fails, or `binding == nil`, or (`input.TenantID != "" && input.TenantID != binding.TenantID`), or `claims.TenantID != binding.TenantID` (short-circuit-safe: `binding == nil` is first). Decision D2 (absent claim): `claims.TenantID != binding.TenantID` treats the absent claim (`""`) as a mismatch — fail-closed. The machine binding is derived from the TOKEN's own client, and the AS stamps the claim from the same client (`token_client_credentials.go:52`), so an absent claim means the IdP client is unbound while the adapter config binds it: pure drift, with no legitimate deployment. The e2e (R5) proves healthy deployments always carry the claim.

R3.2 Rejection shape: the claim-consistency rejection MUST go through the same `writeCheckoutChallenge(writer, http.StatusForbidden, "insufficient_scope", scopeCheckoutCreate)` (http.go:218) with the same arguments as the existing input-mismatch rejection — status 403, body `{"error":"insufficient_scope"}`, challenge `... error="insufficient_scope", scope="billing:checkout:create"` — byte-identical to today's cross-tenant rejection. No new code, no new observable class: a valid machine token holder probing other tenants already receives this exact response today, and the claim check must not make bound-client vs unbound-client probes distinguishable (both stay `insufficient_scope`). This mirrors the sibling billing direction's decision to fold drift denials into the existing `insufficient_scope` surface.

Acceptance:
- A8 (claim mismatch): machine token (client `checkout-client`, binding tenant-one) minted with claim `tenant_id: "tenant-other"`, input without `tenant_id` → 403 `insufficient_scope` with `scope="billing:checkout:create"`; the recorded response is byte-equal to the existing input-mismatch rejection recorded in `TestCheckoutMachineRejectsCrossTenantRequest`.
- A9 (absent claim fails closed): machine token minted WITHOUT `tenant_id` (helper variant mints the raw claims map) → 403 `insufficient_scope`, same byte shape.
- A10 (matching claim passes): machine token with claim `tenant_id: "tenant-one"` → 201 — the existing happy-path tests (`TestCheckoutUsesBoundTenantAndBillingAmount`, `TestCheckoutReplaysCompletedReservationWithoutStripeCall`, `TestCheckoutSafelyReplacesExpiredSession`, the return-origin case of `TestCheckoutEnforcesClientBindingScopeAndReturnOrigin`) with the fixture claim added; `TestCheckoutMachineRejectsCrossTenantRequest` keeps its pin unchanged (input mismatch still `insufficient_scope` + scope attribute).

### R4 — adapter test fixture updates (same change, enumerated)

R4.1 `testAdapterHandlerSubject` (http_test.go:307-339) mints the claims map with `"tenant_id": "tenant-one"` added for machine-happy fixtures; a helper variant (or parameter) mints without it for the absent-claim negatives; `TestCheckoutAuthorizesAdminUserForExplicitBoundTenant`'s token gains the claim too (input tenant-one == claim tenant-one, still 201).
R4.2 Existing assertions that must change — and ONLY these:
- `TestCheckoutUserRequiresAdminScopeAndExplicitBoundTenant` "missing tenant" and "unbound tenant" cases: expected challenge changes from `scope="admin:write"` to the constant `tenant_mismatch` shape (R2.2). The "wrong scope" case keeps `scope="admin:write"`.
- All other existing assertions stay byte-identical.
R4.3 No other `cmd/snaplink-stripe-adapter` production file changes beyond `http.go`'s two gate conditions (plus the `tenant_mismatch` wire-code string next to the other wire codes in `model.go`).

### R5 — cross-server e2e (test/, package ssotest)

R5.1 New file `test/stripe_adapter_tenant_claim_test.go` builds the campaign's in-process harness (mirroring `newScopeRegistryHarness`, test/scope_registry_test.go:70-101, registry unwired so no scope-registry dependency on the sibling T-8(d) direction): memory stores, Ed25519 issuer, two machine clients seeded with `TenantID: "tenant-e2e"` / `TenantID: "tenant-other"` and `AllowedScopes` including `billing:checkout:create` (and `admin:write`).
R5.2 Mint: `POST /token` (client_credentials, `scope=billing:checkout:create`, RFC 8707 `resource` naming the adapter audience) → 200. Assert the returned JWT's payload (base64url-decode of the middle segment) carries `tenant_id == "tenant-e2e"` for the first client and `tenant_id == "tenant-other"` for the second — the wire claim tracks the client binding, never the request.
R5.3 Validation boundary: validate the same tokens through the production RS components the adapter mounts — `rs.NewJWKSCache(server JWKS)` + `rs.HTTPMiddleware(rs.Config{Issuer, JWKSCache, ExpectedAud: <resource>}, stubHandler)` — and assert the downstream handler's `rs.ClaimsFromContext` yields `TenantID == "tenant-e2e"` / `"tenant-other"` respectively. This is the adapter's exact request path minus the adapter's own handler code, which R2/R3 pin at unit level; together the mint → signature validation → projection → gate chain is covered by production code end to end.

Acceptance:
- A11: both mints return 200 with the claimed `tenant_id` values on the wire (payload decode).
- A12: through the middleware, `ClaimsFromContext().TenantID` equals the seeded client binding for both clients, and `HasTenantID()` is true.
- A13: the middleware path with the adapter's config shape (ExpectedAud matching the minted resource) validates successfully — proving a `/token`-minted token is accepted at the adapter's boundary exactly as production configures it.

### R6 — wire contracts (same change)

R6.1 `cmd/snaplink-stripe-adapter/openapi.yaml`: the `CheckoutRequest.tenant_id` description is updated to state the token's `tenant_id` claim must equal the request tenant for user-shaped tokens and the client's bound tenant for machine tokens; the `Forbidden` response description gains the `tenant_mismatch` case (constant body, no scope attribute) alongside `insufficient_scope`.
R6.2 `docs/error-codes.md` Stripe adapter section (1034-1062): add the `tenant_mismatch` row — 403, emitted when the validated token's `tenant_id` claim contradicts the requested/bound tenant, "response does not disclose the token's or request's tenant; retry with the correct tenant context" — and adjust the `insufficient_scope` wording only where it must now also cover the machine claim-consistency denial (binding causes intentionally hidden, per the existing style at line 1014).

Acceptance:
- A14: the contract gate (`make ci`, OpenAPI validation) passes with the updated yaml; `docs/error-codes.md` documents every wire code the adapter emits, including `tenant_mismatch`.

## 6. Engineering gates and verification

- Budgets: `claims.go` is 191 lines — the field/tag/constructor/helper additions keep it well inside 500. `http.go` is 402 lines; `authorizeUserCheckout` (224-236, 13 lines) and `authorizeMachineCheckout` (212-223, 12 lines) gain one boolean condition each — both stay far under the 50-line function budget, complexity 15, `if`-nesting 3. `model.go` gains one wire-code constant. No new packages; `rs` remains in `interfaces` (import direction intact); `test/` gains one file (package `ssotest` — no `cmd/` import, per AGENTS.md).
- No change to `interfaces/sso` (the 60-file ceiling package); `interfaces/ssoclient/rs` gains one test file only.
- After every `.go` edit: `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .`.
- Targeted: `go test ./interfaces/ssoclient/rs/... ./cmd/snaplink-stripe-adapter/...`, then `go test ./test/ -run 'TestStripeAdapterTenantClaim|TestE2E' -v`.
- Handoff: `go test ./... -race` and `make ci` (nested modules, config, module validation unaffected — no manifest/profile change).
- Oracle-safety review (AGENTS.md §3): the user-flow tenant rejection is a single constant response across all causes (A5 pins byte-equality); the machine-flow claim rejection is byte-identical to the existing cross-tenant `insufficient_scope` (A8 pins byte-equality); no tenant value crosses any wire; no audit path exists on this surface (metrics only), so no audit oracle is introduced.
- Rollout sequencing: the adapter gates must land only after B4-1 mint is live (campaign G1 → G5 ordering): before the IdP stamps `tenant_id` for bound clients, the machine-flow fail-closed gate (R3.1) would deny every bound-client machine checkout on the absent claim. The G5 gate row (T-2, T-8(b–e), T-9 in `docs/campaigns/implementation-gate.md`) is the landing slot; the e2e's mint assertions (A11) double as the deployment-time proof that `/token` stamps the claim.

## 7. Acceptance summary (direction contract, preserved)

| Direction acceptance | Testable form (this spec) |
|---|---|
| T-8(a): unit test parses a token containing `tenant_id` and populates `Claims.TenantID` (proposed field) | R1 → A1 (JWT parse: present → populated, absent → zero), A2 (introspection path), A3 (existing rs tests untouched and green) |
| T-8(b): adapter checkout with claims `tenant_id != input.TenantID` returns 403 `tenant_mismatch`-style error without leaking tenant existence | R2 → A4 (mismatch → 403 `tenant_mismatch`, bound-tenant case that today returns 201), A5 (byte-equal response across unbound/missing/mismatch causes — the no-leak pin), A6 (matching claim still 201), A7 (scope failure unchanged) |
| T-9: machine checkout with `tenant_id` inconsistent with the clientID binding is rejected | R3 → A8 (claim mismatch → 403, byte-equal to the existing cross-tenant rejection), A9 (absent claim fails closed), A10 (matching claim still 201; existing input-mismatch pin unchanged) |
| T-9: cross-server e2e in `test/` shows the `/token`-minted `tenant_id` claim is validated end-to-end | R5 → A11 (wire claim at mint, per client binding), A12 (production rs middleware projects it into `ClaimsFromContext`), A13 (adapter-shaped config accepts the minted token) |
| Contracts updated in the same change | R6 → A14 (openapi.yaml + docs/error-codes.md, `make ci` green) |

## 8. Decisions (resolved, with rationale)

- D1 (user flow, absent claim → pass): the user flow's binding expectation is request-derived; a tenant-less console client is a legitimate deployment and the IdP then stamps no claim. Fail-closed-on-absence would hard-break that deployment. Enforcement fires exactly when the IdP binds the client (the B4-1 model), which is the case the direction's acceptance tests. Rejected alternative: literal `claims.TenantID == input.TenantID` equality — deployment-breaking, beyond the direction's acceptance.
- D2 (machine flow, absent claim → fail closed): the machine binding is token-derived (`clientID → binding`), and `token_client_credentials.go:52` proves `/token` stamps the claim from the same client — absence is provable config drift. Mirrors the sibling billing spec's R2.1 fail-closed rule.
- D3 (user-flow rejection collapse): all three tenant-class causes share one constant `tenant_mismatch` response because any distinguishable variant would let a valid token holder probe which tenants are configured (the "leaking tenant existence" the acceptance forbids).
- D4 (machine-flow rejection shape): claim inconsistency folds into the existing `insufficient_scope` rejection because (a) the direction's acceptance demands only "rejected", (b) any new code would create a distinguishable bound-vs-unbound-client observation where today none exists, and (c) the sibling billing direction set the same precedent (drift denials reuse `insufficient_scope`, no oracle).
- D5 (introspection): `rs` projects the field on the introspection path for completeness (one constructor line, wire struct shared), but the AS-side introspection echo of `tenant_id` is out of scope — the adapter is JWT-mode and never introspects.
