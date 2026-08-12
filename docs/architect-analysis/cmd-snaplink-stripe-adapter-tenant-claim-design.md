# Design: project tenant_id onto rs.Claims and enforce the token's tenant binding in the stripe adapter's checkout authorization

- Source direction (entry 2): "Project tenant_id onto rs.Claims and enforce the token's tenant binding in the adapter's checkout authorization" (`docs/architect-analysis/auto/analyses/cmd-snaplink-stripe-adapter-f67dafca.json`)
- Requirements: `docs/architect-analysis/cmd-snaplink-stripe-adapter-tenant-claim-requirements.md` (R1–R6)
- Status: design (every evidence citation re-verified against HEAD)

## 1. Evidence verification verdict

Every symbol cited in the requirements spec was re-checked against the repository. All are **confirmed**; three nuances the spec glosses over are recorded in §1.1 and the design resolves them explicitly.

| Claim | Verified reality | Verdict |
|---|---|---|
| `infrastructure/defaultimpl/issue_payload.go:46` — `TenantID: subject.TenantID` | Confirmed at line 46 in `buildAccessPayload`: unconditional literal assignment beside `ServingRegion` (line 42), `omitempty` on the wire tag (`ed25519_types.go:50`) performs omission for single-tenant; `claimsWithoutEmittedKeys` (116-138) strips a same-named `ext` copy so the mint-time literal wins | Confirmed (line exact) |
| `shared/core/consts_wire.go:169` — `KeyTenantID = "tenant_id"` | Confirmed, line exact | Confirmed |
| `interfaces/ssoclient/rs/claims.go:13-38` — `Claims` has no TenantID field | Confirmed: struct spans 13-46 (Issuer…ServingRegion/RenewAfter/CnfJKT + `Raw`); `wireClaims` (93-108) carries only `serving_region` among extensions; `parseClaims` (113-136) projects only the typed fields. `grep -i tenant interfaces/ssoclient/rs/*.go` → zero fields | Confirmed |
| `cmd/snaplink-stripe-adapter/http.go:198-233` — trio never validates tenant_id | Confirmed: `authorizeCheckout` (198-210) dispatches on `claims.ClientID != "" && claims.Subject == claims.ClientID`; `authorizeMachineCheckout` (212-222) binds from `CheckoutBindings[claims.ClientID]`, compares only `input.TenantID`; `authorizeUserCheckout` (224-233) binds from `TenantBindings[input.TenantID]`, no claim read. The trio actually spans 198-233 | Confirmed (range covers the trio) |
| `interfaces/ssoclient/rs/authz.go:23` — `CheckScope` | Confirmed at line 23; the enforcement seam the machine flow already uses | Confirmed (line exact) |
| Mint chain: `token_client_credentials.go:52` stamps `TenantID: client.TenantID` | Confirmed: `HandleClientCredentialsGrant` builds `&core.Subject{ID, Resources, ClientID, TenantID: client.TenantID, TTL, …}`; `resources []string` is bound from the request (RFC 8707) and flows into the `aud` claim | Confirmed (line exact) |
| Adapter runs JWT mode (no introspection) | Confirmed: `newAdapterHandler` (http.go:39-65) builds `rs.Config{Issuer, JWKSCache, ExpectedAud, TrustedProxies}` at http.go:59-62 — no `IntrospectURL`; `validateByMode` (interfaces/ssoclient/rs/validate.go:105-110) routes to introspection only when set | Confirmed |
| Introspection seam: `wireIntrospection` embeds `wireClaims` | Confirmed (introspect.go:71-76); the `Claims` constructor literal in `ValidateTokenWithIntrospect` (introspect.go:33-66, literal at 47-61) copies fields explicitly, so the new field needs one constructor line there | Confirmed |
| `serving_region` precedent | Confirmed: `Claims.ServingRegion` (claims.go:24-28), `HasServingRegion()` (71-73), `wireClaims` tag, both decode paths | Confirmed |
| Adapter test seam | Confirmed: `testAdapterHandlerSubject` (http_test.go:286-339) mints via `rstest.NewIssuer().MintAccessToken(map[string]any{...})` — arbitrary claims, stamp/omit `tenant_id` at will; shared by every checkout test through `testAdapterHandler` (279-284) | Confirmed |
| Existing pins constraining the gate shapes | Confirmed: `TestCheckoutUserRequiresAdminScopeAndExplicitBoundTenant` (172-189) asserts 403 + challenge contains `scope="admin:write"` for the "missing tenant" and "unbound tenant" cases; `TestCheckoutMachineRejectsCrossTenantRequest` (191-199) asserts 403 + `scope="billing:checkout:create"` | Confirmed (exactly the churn R4.2 enumerates) |
| Adapter error-code contract | Confirmed: `docs/error-codes.md` Stripe section (1034-1065): the authorization-failure code lives in the section PROSE (1039-1047) — no `insufficient_scope` table row exists — and the working tree ALREADY carries the R6 prose rewrite (user-flow split + machine claim-consistency class, 1039-1047) and the `tenant_mismatch` row (1051); `:87` already documents `tenant_mismatch` (403); `model.go`'s exported wire-code block (44-55) has no `tenant_mismatch` const yet | Confirmed |
| openapi contract | Confirmed: `cmd/snaplink-stripe-adapter/openapi.yaml` — checkout description (20-25) still says "`tenant_id`, when present, must match" (the R6 replacement of that text is PENDING); `CheckoutRequest.tenant_id` (166-170); `Forbidden` (210-227): the working-tree description ALREADY gains the `tenant_mismatch` case and the machine claim-consistency class (213-218), example stays the `insufficient_scope` shape (225) | Confirmed |
| Cross-server e2e precedent | Confirmed: `test/scope_registry_test.go` `newScopeRegistryHarness(t, registryOn)` (70-101) — in-process `sso.NewServer` + memory stores + Ed25519 issuer; `srCC` (104-131) does real `POST /token` client_credentials; package `ssotest` cannot import `cmd/` (AGENTS.md) | Confirmed |
| Campaign gate slot | Confirmed: `docs/campaigns/implementation-gate.md` G5 row (line 77) = T-2, T-8(b–e), T-9; B4-1 mint row (line 11) = T-8(a) `{iss/aud/scope/client_id/tenant_id/roles}` | Confirmed |
| Budgets | Confirmed: `http.go` 402 lines, `claims.go` 191, `model.go` 208; `authorizeUserCheckout` 13 lines, `authorizeMachineCheckout` 12 — both far under 50 | Confirmed |
| Binding identity validation | Confirmed: `validIdentity` (config.go:362-372) rejects `""` and whitespace/control chars; config.go:252/263 gate `TenantID`/`CheckoutClientIDs` at load — `TenantBindings` can never contain a `""` key, so `input.TenantID == ""` always takes the `binding == nil` branch | Confirmed |
| `sso.Client` carries `TenantID` | Confirmed: `sso.Client = core.Client` (interfaces/sso/aliases.go:106); `core.Client.TenantID` drives the mint stamp | Confirmed |

### 1.1 Nuances the requirements spec glosses over (design decisions in §3)

1. **User-flow tokens carry the CONSOLE CLIENT's binding, not the user's.** The authorization-code grant (`internal/handler/tokengrant/token_authcode.go:136`) and the refresh grant (`token_refresh.go:292`) stamp the same `TenantID: client.TenantID` the client_credentials grant does. R2's `claims.TenantID` is therefore the console client's mint-time binding: a tenant-bound console mints user tokens that claim that single tenant (checkouts for any other input tenant → `tenant_mismatch`); a tenant-less console mints no claim (decision D1 passes). This also makes the rollout asymmetry precise: the **user gate is inert before B4-1** (absent claim → D1 pass), while the **machine gate is breaking before B4-1** (absent claim → fail-closed denial of every bound-client machine checkout). The sequencing constraint binds only the machine gate (and the claim-mismatch branch of the user gate, which cannot fire before mint exists). One mid-rollout fleet state is therefore SIMULTANEOUSLY availability-breaking (machine flow: every bound-client checkout denied) and isolation-gaping (user flow: cross-tenant checkouts allowed) — F1 and F6 are two faces of one window, not two scenarios (security review residual). And post-mint, a console client newly bound after its tokens were issued keeps minting claim-less tokens for up to the access-token TTL (1h default); the user gate is inert for those — same shape as F6, covered by the same TTL bound.
2. **`authorizeUserCheckout` needs two rejection branches, not one OR.** Today the function folds subject/scope/binding failures into a single 403 `insufficient_scope` writer call. Under R2, scope failure must keep `insufficient_scope` + `scope="admin:write"` (pinned byte-for-byte by the "wrong scope" case), while binding/claim failures become `tenant_mismatch` with no scope attribute. The split is mandatory for the two classes to stay distinguishable only by their constant codes (R2.3).
3. **An unconditional fixture claim addition is safe for every existing adapter test.** Adding `"tenant_id": "tenant-one"` to the claims map inside `testAdapterHandlerSubject` cannot flip any existing assertion: the machine "unbound client" case and the user "wrong scope" case short-circuit before any tenant check; the user "missing tenant"/"unbound tenant" cases hit `binding == nil` (today) or the claim-mismatch branch (after A4's second fixture binding) — both emit the identical `tenant_mismatch` bytes, so the R4.2 pin change is cause-independent. The byte-equality pin (A5) makes this invariant explicit rather than accidental.

## 2. Design overview

One additive projection + two adapter gates + tests + docs, all internal to the Go tree:

```text
B4-1 mint (unchanged)                    stripe-adapter consumption (this change)
┌────────────────────────┐      ┌──────────────────────────────────────────────┐
│ buildAccessPayload     │      │ rs.Claims.TenantID + HasTenantID             │  R1 (projection,
│  tenant_id = client.   │─────▶│   (JWT + introspection; serving_region       │      JWT + introspect)
│  TenantID (cc, authcode,│      │    precedent; additive, no config)          │
│  refresh — client's    │      ├──────────────────────────────────────────────┤
│  binding, not user's)  │      │ user flow    (authorizeUserCheckout)   R2    │
└────────────────────────┘      │   scope-fail  → 403 insufficient_scope (unch)│
                                │   tenant causes → 403 tenant_mismatch (const) │
                                ├──────────────────────────────────────────────┤
                                │ machine flow (authorizeMachineCheckout) R3    │
                                │   claim != binding (incl. absent) → 403       │
                                │   insufficient_scope (byte-identical, D4)     │
                                └──────────────────────────────────────────────┘
```

- **Enforcement model**: the mint-time claim is the IdP-side client binding; the adapter's bindings file is the server-side expectation. The user flow compares the claim against the REQUEST tenant (the console's binding must match the tenant the user names); the machine flow compares the claim against the binding selected by the TOKEN's own clientID. The two flows differ because the user flow's binding lookup is request-derived (`TenantBindings[input.TenantID]`) and the machine flow's is token-derived (`CheckoutBindings[claims.ClientID]`).
- **No-oracle**: user-flow tenant causes collapse into one constant `403 tenant_mismatch` (missing input tenant, unbound input tenant, claim mismatch are byte-identical — A5); machine-flow claim denials fold into the existing `403 insufficient_scope` bytes (A8 byte-equality). No tenant value crosses any wire; denials increment no metric and no audit path exists on this surface. The no-leak guarantee is claim-bearing-token-scoped: a claim-less user token holder still sees the pre-existing bound→201/unbound→403 enumeration signal (the binding check predates this change; D1's pass-on-absence implies it — A5).
- **Zero new surface**: no config keys, no endpoints, no audit event types, no metrics, no mint-side change, no `rs.Config` gate, no introspection echo. `tenant_mismatch` is an existing documented code newly emitted by this adapter; the docs rows and the exported constant land in the same change. The only non-code addition is the `checks/adapters_check.py` extension (R6/A14) that turns the exported-constant/docs-row pairing into a machine-enforced gate instead of a review-only pairing.

## 3. Concrete changes

### 3.1 R1 — rs claims projection (`interfaces/ssoclient/rs/claims.go` + `introspect.go`)

- `Claims` gains `TenantID string`, placed after `ServingRegion`, before `RenewAfter`, with a comment stating it is the mint-time client-binding tenant claim (SnapLink extension, echoed by introspection, empty when the AS didn't bind the client).
- `wireClaims` gains `TenantID string \`json:"tenant_id"\`` after the `ServingRegion` tag. No `omitempty` — decode treats absence as the zero value (R1.2).
- `parseClaims` projects `TenantID: w.TenantID` into the returned `Claims`.
- `wireIntrospection` embeds `wireClaims`, so the introspection decode is automatic; `ValidateTokenWithIntrospect`'s `Claims` constructor literal (introspect.go:33-66, literal at 47-61) gains the one line `TenantID: w.TenantID` after `ServingRegion` (it builds the struct manually and would otherwise silently drop the claim).
- `Claims` gains the presence helper, mirroring `HasServingRegion()`:

```go
// HasTenantID reports whether the token carries a non-empty tenant_id
// claim. Tenant IDs are non-empty by construction (binding identity
// validation), so presence == non-empty — same discipline as the
// serving-region precedent.
func (c *Claims) HasTenantID() bool { return c != nil && c.TenantID != "" }
```

- `validateClaims`/`validateIntrospectedClaims` are untouched — no `rs.Config` gate (the tenant expectation is per-binding adapter config, not a shared RS static set).
- File impact: `claims.go` 191 → ~205 lines; all 8 existing rs test files untouched and green (A3).

### 3.2 R2 — user-flow tenant gate (`cmd/snaplink-stripe-adapter/http.go`, `authorizeUserCheckout` 224-233)

The single OR becomes two rejection branches (nuance 2, §1.1):

```go
func (a *adapterHTTP) authorizeUserCheckout(
	writer http.ResponseWriter, claims *rs.Claims, input checkoutRequest,
) (*tenantBinding, bool) {
	if claims.Subject == "" || rs.CheckScope(claims, scopeAdminWrite) != nil {
		writeCheckoutChallenge(writer, http.StatusForbidden, "insufficient_scope", scopeAdminWrite)
		return nil, false
	}
	binding := a.config.TenantBindings[input.TenantID]
	if binding == nil || (claims.HasTenantID() && claims.TenantID != input.TenantID) {
		// Single constant response for all three causes (missing input
		// tenant, unbound input tenant, claim mismatch): any distinguishable
		// variant would let a valid token holder probe which tenants are
		// configured. No scope attribute — the code alone separates this
		// class from a scope denial.
		writeCheckoutChallenge(writer, http.StatusForbidden, ErrTenantMismatch, "")
		return nil, false
	}
	return binding, true
}
```

- `claims.Subject == ""` stays in the scope branch (defense in depth; dispatch already 401s subject-less claims — bytes unchanged).
- `binding == nil` fires for `input.TenantID == ""` because `validIdentity` guarantees no `""` key exists in `TenantBindings` (§1.1 verified fact) — the "missing tenant" case is a `binding == nil` cause, byte-identical to the others.
- D1 (absent claim passes): `claims.HasTenantID()` guards the mismatch comparison, so a tenant-less console (no claim minted, per token_authcode.go:136 `client.TenantID == ""`) passes when the input tenant is bound. Enforcement is live exactly when the IdP binds the console client. D1 is a POLICY CARVE-OUT for the legitimate tenant-less/shared-console configuration — not an AGENTS.md outage fail-open: the fail-open-with-audit list (geo/risk scoring, audit-sink errors, tenant-suspension-lookup outage) covers helper/outage failures, whereas D1 is a static, always-on policy choice for a documented configuration; the absence of an audit path on this surface (§2) is the property of a policy decision, not a forgiven outage.
- `writeCheckoutChallenge` already appends `scope=` only when non-empty (http.go:380-389), so the `tenant_mismatch` challenge is `Bearer realm="stripe-adapter", error="tenant_mismatch"` — no scope attribute, by construction.

### 3.3 R3 — machine-flow tenant gate (`authorizeMachineCheckout` 212-222)

One added condition in the existing rejection OR, in short-circuit order:

```go
func (a *adapterHTTP) authorizeMachineCheckout(
	writer http.ResponseWriter, claims *rs.Claims, input checkoutRequest,
) (*tenantBinding, bool) {
	binding := a.config.CheckoutBindings[claims.ClientID]
	if rs.CheckScope(claims, scopeCheckoutCreate) != nil || binding == nil ||
		(input.TenantID != "" && input.TenantID != binding.TenantID) ||
		claims.TenantID != binding.TenantID {
		writeCheckoutChallenge(writer, http.StatusForbidden, "insufficient_scope", scopeCheckoutCreate)
		return nil, false
	}
	return binding, true
}
```

- Ordering is load-bearing: `binding == nil` precedes the claim comparison, so an unbound machine client with ANY claim state keeps the existing 403 `insufficient_scope` (its pin in `TestCheckoutEnforcesClientBindingScopeAndReturnOrigin` is untouched).
- `claims.TenantID != binding.TenantID` treats the absent claim (`""`) as a mismatch — fail-closed (decision D2). The machine binding is derived from the token's own client, and the mint stamps the claim from the same client (`token_client_credentials.go:52`), so absence is provable config drift (adapter binds a client the IdP never bound).
- All four causes share one writer call with the exact arguments of today's cross-tenant rejection — byte-identical by construction (A8), no new observable class.

### 3.4 R4 — adapter fixtures and test pins (`cmd/snaplink-stripe-adapter/http_test.go`, `model.go`)

- `model.go`: the exported wire-code block (44-55) gains `ErrTenantMismatch = "tenant_mismatch"`. The block's export comment (model.go:44) claims a "repository contract gate" proves every documented adapter response is backed by executable code — that gate does not exist today (see §8); R6 realizes it by extending `checks/adapters_check.py` (A14), so the pairing is machine-enforced rather than review-only.
- `testAdapterHandlerSubject` (286-339): the minted claims map gains `"tenant_id": "tenant-one"` unconditionally (safe for every existing test — nuance 3, §1.1). A new variant helper `testAdapterHandlerSubjectWithoutTenantClaim` (or a boolean parameter on a shared inner helper) mints the same map minus `tenant_id` for the absent-claim negatives (A9) and the D1 pin (A15).
- Fixture `runtimeConfig`: `TenantBindings` gains a second binding `"tenant-other": {TenantID: "tenant-other", BillingClientID: "billing-client"}` so the A4 hole-closing case has a real bound-other target. `CheckoutBindings` stays `{"checkout-client": tenant-one}`.
- Existing assertion changes — ONLY these two (R4.2):
  - `TestCheckoutUserRequiresAdminScopeAndExplicitBoundTenant`, "missing tenant" case: expected challenge changes from `scope="admin:write"` to `error="tenant_mismatch"` with no scope attribute.
  - Same test, "unbound tenant" case: same change (after the fixture gains `tenant-other`, this case fires the claim-mismatch branch instead of `binding == nil`, but the response is byte-identical — cause-independent pin, per A5).
  - The "wrong scope" case keeps its `scope="admin:write"` assertion byte-for-byte.
- New test `TestCheckoutUserAcceptsTenantlessConsoleToken` (D1 pin, T-8(b) family, unit level — the e2e cannot mint user-shaped tokens without the authcode dance, a non-goal):
  1. Mint a claim-less user token via `testAdapterHandlerSubjectWithoutTenantClaim(t, store, billing, stripe, "user-one", "console-client", scopeAdminWrite)`.
  2. Input `{"tenant_id":"tenant-one","order_id":"order-one","success_url":"https://console.example.test/s","cancel_url":"https://console.example.test/c"}` → **201**, and assert `billing.lastBinding.TenantID == "tenant-one"` (same assertion shape as `TestCheckoutUsesBoundTenantAndBillingAmount`, http_test.go:116-117) — proving the gate actually selected the bound binding rather than short-circuiting.
  3. Companion, same token: input `tenant-nowhere` → 403 with the challenge **equal to** (not Contains) `Bearer realm="stripe-adapter", error="tenant_mismatch"` — construction is deterministic (http.go:380-389), so exact equality pins that absence waives only the claim comparison, never the `binding == nil` check; without it, a regression deleting `binding == nil` would let tenant-less consoles check out to unbound tenants — the existence leak D3 forbids.
  4. Optional: byte-compare the 201 response with A6's claiming-token pass — absence is unobservable in the pass path.
- Every other existing assertion stays byte-identical: machine happy paths (with the fixture claim), `TestCheckoutMachineRejectsCrossTenantRequest` (input mismatch still `insufficient_scope` + scope attr), `TestCheckoutRejectsUserIdentityUsingBoundClient` (http_test.go:147-155; asserts 403 only and STAYS `insufficient_scope` — `sub=user-one` ≠ `client_id=checkout-client` routes the user flow, and `billing:checkout:create` lacks `admin:write`, so the scope branch fires first and the response never becomes `tenant_mismatch`; no assertion change), webhook/metrics tests (untouched).

### 3.5 R5 — cross-server e2e (`test/stripe_adapter_tenant_claim_test.go`, package `ssotest`)

- `newStripeAdapterHarness(t)` mirrors `newScopeRegistryHarness` (test/scope_registry_test.go:70-101) with the scope registry UNWIRED (no dependency on the sibling scope-matrix direction): memory stores, Ed25519 issuer (`WithEd25519TokenTTL`), two machine clients seeded with `TenantID: "tenant-e2e"` / `"tenant-other"`, `Secret`, `Active: true`, `TokenStrategy: "jwt"`, `AllowedScopes: []string{"billing:checkout:create"}` (allowlist-conformant), in-process `sso.NewServer` + `httptest`.
- `scCC(t, srv, clientID, resource)` extends the `srCC` shape (104-131) with the RFC 8707 form field `resource=<adapter audience>` — required so the minted token carries `aud`, which the adapter's `rs.Config.ExpectedAud` demands. `HandleClientCredentialsGrant` binds `resources` from the request and stamps them into `Subject.Resources` → the `aud` claim (verified §1).
- Flow per client: `POST /token` (client_credentials, `scope=billing:checkout:create`, `resource=stripe-adapter`) → 200; base64url-decode the JWT's middle segment and assert `got, ok := payload["tenant_id"].(string); ok && got == <seeded TenantID>` (A11 — the ok-guard makes a missing claim fail with a clear `"" != ...`-style message instead of a silent skip) and `aud == "stripe-adapter"` as a COMPACT STRING, not an array: `audClaim.MarshalJSON` (ed25519_types.go:141-148) emits a single audience as a scalar per OIDC convention — the array shape would false-fail on a correct mint. `audienceValues` (claims.go) accepts both string and array forms, so A12/A13 are unaffected.
- Validation boundary: validate the same tokens through the production components the adapter mounts — `rs.NewJWKSCache(server JWKS)` + `rs.HTTPMiddleware(rs.Config{Issuer: <server issuer>, JWKSCache: cache, ExpectedAud: "stripe-adapter"}, stubHandler)` — assert the stub's `rs.ClaimsFromContext` yields `TenantID == <seeded TenantID>` and `HasTenantID() == true` for both clients (A12/A13). This is the adapter's exact request path minus the adapter's own handler code; the gates themselves are pinned at unit level (R2/R3) because `test/` cannot import `cmd/`.
- The e2e exercises the machine path only; the user flow's claim provenance (authcode stamping `client.TenantID`) is covered by the verified mint code and the unit-level user gate tests — no authcode dance is added (non-goal). That provenance is additionally pinned cross-server by the EXISTING `TestRefreshRotation_TenantIDPresentRolesAbsent` (test/refresh_rotation_claims_test.go:139-183): the authcode code-exchange and the refresh rotation both assert the wire `tenant_id` claim on real `/token` responses. The composition is complete — authcode/refresh mint→wire claim [existing test], cc mint→wire claim [A11], wire claim→rs projection [A1/A2/A12], projection→user gate [A4-A7/A15], projection→machine gate [A8-A10] — so the "no authcode dance" rests on a tested pin, not code reading.

### 3.6 R6 — wire contracts (same change)

- `cmd/snaplink-stripe-adapter/openapi.yaml`:
  - Checkout `description` (20-25): replace "`tenant_id`, when present, must match" with the exact enforcement: for user-shaped tokens the token's `tenant_id` claim must equal the request `tenant_id`; for machine tokens the claim must equal the tenant bound to the token's client; a user-flow violation returns `tenant_mismatch` (constant body, no scope attribute).
  - `CheckoutRequest.tenant_id` description (166-170): note that a user-shaped token whose claim contradicts the request tenant is rejected with `tenant_mismatch` even when the request tenant is itself bound.
  - `Forbidden` response (210-227): the working tree ALREADY carries both required edits — the description (211-218) gains the `tenant_mismatch` case AND the machine claim-consistency class ("A machine token whose `tenant_id` claim is missing or contradicts its client's bound tenant folds into the same `insufficient_scope` response; those causes are indistinguishable", 215-218); the `WWW-Authenticate` example (225) stays the `insufficient_scope` shape and the description states the `tenant_mismatch` challenge carries no `scope` attribute. R6 verifies this applied text against the spec above.
- `docs/error-codes.md` Stripe section (1034-1065): the working tree ALREADY carries the R6 contract edit — the prose (1039-1047) covers (a) the user-flow split ("a request `tenant_id` that is missing, unbound, or contradicts the token's `tenant_id` claim returns `tenant_mismatch` (403) with no `scope` attribute", 1044-1046) and (b) the machine claim-consistency denial joining `insufficient_scope` ("whose `tenant_id` claim is missing or contradicts the client's bound tenant returns `insufficient_scope` (403); the binding and claim-consistency causes stay indistinguishable", 1040-1043); the `tenant_mismatch` row (1051) reads "the response never discloses the token's or request's tenant". There was never an `insufficient_scope` ROW in the Stripe table — prose is its only home, so the R4.2 wording change applies to the prose alone (billing-row style at 1014). `tenant_mismatch` is already documented at line 87 for the general governance code — no new `Err*` family, only this adapter's first emission of the existing code. R6 verifies the applied text matches this spec.
- `docs/stripe-payment-adapter.md:37-42`: the working tree ALREADY carries the claim-equality sentence ("both flows also require the token's `tenant_id` claim to equal the tenant the request resolves to...", 39-42) without naming error codes — it stays true under the final split. R6's consistency pass verifies it: it names no error classes, and "rejects the request" covers both `tenant_mismatch` (user) and `insufficient_scope` (machine).
- `checks/adapters_check.py` (A14 enforcement, same change): two static scans join `make ci` — (a) run the same `kin-openapi validate` invocation `make docs-validate` uses (Makefile:189) over `cmd/*/openapi.yaml` (currently exactly one file; verified passing at HEAD, exit 0, so the gate adds with no pre-existing failure); (b) parse the exported wire-code const block in `cmd/snaplink-stripe-adapter/model.go` (44-55) and assert each value appears as a `` | `code` | `` row in the error-codes.md Stripe section — this row-level assertion is exactly what would have caught the prose-vs-row error above at review time.

## 4. Compatibility constraints

| Constraint | Consequence |
|---|---|
| **Sequencing vs B4-1 mint (asymmetric)** | The gates are always-on with no kill switch. The machine gate is BREAKING pre-B4-1: absent claim → fail-closed denial of every bound-client machine checkout. The user gate is INERT pre-B4-1 (D1 passes on absence). Deployment order: IdP mint live first (or same window), then the machine gate; the user gate's claim-mismatch branch cannot fire before mint exists. One mid-rollout state is SIMULTANEOUSLY availability-breaking (machine) and isolation-gaping (user): tokens minted by pre-B4-1 nodes carry no claim → machine denials until expiry, bounded by the access-token TTL — 1h default (`defaultTokenTTL`, issue_payload.go:17-19), extendable per client via `AccessTokenTTL` (token_client_credentials.go:53); a long override widens the window to a day or more (F1/F6 are two faces of this one state). |
| **User-flow wire-visible change is deliberate** | Today: missing/unbound input tenant on the user flow → 403 `insufficient_scope` + `scope="admin:write"`. After: 403 `tenant_mismatch`, no scope attribute. Clients distinguishing causes by the challenge's scope attribute must switch to the error code. This is the direction's intended change (R4.2), shipped with the openapi/error-codes updates in the same change. Residual: clients that map unknown codes to a generic failure see a UX message change on this class — the openapi/error-codes change names the mapping explicitly so console-side tables can be updated. |
| **Machine flow adds denial classes, no new bytes** | Input-mismatch rejection bytes are unchanged (existing pin); the claim-consistency class (mismatch OR absent) folds into the identical response — bound-vs-unbound client probes remain indistinguishable from scope denials, as today. |
| **Single-tenant/shared-console carve-out preserved** | A tenant-less console client (no IdP binding) mints no claim; user checkouts pass the tenant gate as today (D1). A machine client with no adapter binding stays `insufficient_scope` (short-circuit before claim check). |
| **rs projection is deployment-independent** | R1 is additive (new field, zero behavior change, no config); shippable/rollbackable ahead of the gates. |
| **rs test files stay untouched** | All 8 existing `interfaces/ssoclient/rs` test files compile and pass unmodified (A3). Adapter test files: one fixture map line + one new helper + two assertion updates + new tests. |
| **No SSO-server wire/API surface change** | No endpoints, config keys, `Err*` constants, or introspection-body changes; `populateAccessIntrospectionBody` does not echo `tenant_id` (verified — no `tenant` grep hits) and stays that way (declared non-goal). |
| **E2e must mint with `resource`** | `rs.Config.ExpectedAud` requires `aud`; the client_credentials grant only stamps `aud` when the request carries the RFC 8707 `resource` field. The e2e's `scCC` includes it; without it the middleware boundary would reject on `ErrAudienceMismatch` and prove nothing about the tenant path. |
| **Import discipline** | No new packages; `rs` stays in `interfaces`; `test/` gains one file (package `ssotest`, no `cmd/` import); `interfaces/sso` (60-file ceiling) untouched. |

## 5. Failure modes

| # | Failure | Behavior | Recovery | Pinned by |
|---|---|---|---|---|
| F1 | IdP fleet not yet at B4-1 (claim absent for bound clients) | Machine checkouts: 403 `insufficient_scope` for every bound client; user flow passes (D1) | Land in G5 order (§6); rollback = revert the gate commit | A9 (machine denial) + A15 (user pass); the sequencing itself is ops-only (§6 step 2), never declared in an automated test |
| F2 | IdP re-binds console client to tenant B; adapter config says A | User tokens claim B: input A → `tenant_mismatch`; input B → pass (the console silently switches tenants — the enforcement follows the IdP) | Reconcile adapter bindings file with the IdP binding (cold restart) | A4 (input A) / A6 (input B); the cold-restart reconciliation is an accepted ops-only scenario with NO automated test |
| F3 | IdP re-binds checkout client to B; adapter config says A | Machine flow: claim B ≠ binding A → 403 `insufficient_scope` for every request; input-tenant checks never reached | Same reconciliation; no cross-tenant checkout can be created in the interim (the direction's goal) | A8; reconciliation ops-only, never declared in an automated test |
| F4 | Adapter binds a client the IdP never bound (claim absent) | Machine flow: fail-closed denial on absence (D2); user flow unaffected | Register the IdP-side client binding | A9 (same code path as F1's machine half) |
| F5 | Oracle probe attempts | User flow: three causes byte-identical `tenant_mismatch` (A5); machine flow: claim denials byte-identical to the existing input-mismatch/scope denials (A8); no tenant value in body/headers/challenge; no metric or audit delta (denials increment no counter today, and the design adds none) | By construction; pinned by A5/A8 byte-equality assertions | A5/A8 byte-equality |
| F6 | Pre-B4-1 tokens in the wild during rolling upgrade | Machine denials until expiry; user flow passes (D1) | Bounded by token TTL — 1h default, per-client `AccessTokenTTL` override widens it (record at pre-flight, §6 step 3); "no operator action" holds only for default-TTL deployments | A9 + A15 code paths; the TTL window itself is an accepted ops-only scenario — no automated test possible or needed (the failure behavior is what A9/A15 pin) |
| F7 | JWKS/issuer drift at the adapter | Existing rs middleware behavior unchanged (401 `invalid_token` before the gates — the gates only see validated claims) | Existing JWKS cache refresh path | Existing rs tests (A3) |
| F8 | Concurrent checkout requests | Unchanged: store-level idempotency/replay/expiry semantics govern; the gates add no state | Existing behavior | Existing store-level tests |

## 6. Migration steps

1. **Land R1** (rs projection + A1-A3 tests) — independent, deployable alone, zero behavior change.
2. **Confirm mint prerequisite**: IdP fleet at B4-1; campaign T-8(a)/T-1.2 mint pin green (`docs/campaigns/implementation-gate.md` G1/G5 rows). This consumption work lands in the **G5 slot** (T-2, T-8(b–e), T-9), never before — the machine gate fails closed on absent claims. Deploying the gate mid-IdP-upgrade fails closed (safe) but the impact is INVISIBLE — denials increment no metric and no audit path exists (by design, §2); the only signal is a checkout 403-rate change. Prefer full IdP drain before the adapter gate, or accept the bounded window with a monitored 403 rate.
3. **Operator pre-flight (before deploying the gates)**: for each checkout client in `bindings.example.json`, verify the IdP-side client record's tenant binding equals the adapter binding's `tenant_id` (machine flow) and that the console client's IdP binding matches the tenants its users name (user flow). Shared-console deployments: keep the console client tenant-less (D1 carve-out preserved). Also record each checkout client's `AccessTokenTTL` and plan the denial window: a long per-client override extends it beyond the 1h default (issue_payload.go:17-19; token_client_credentials.go:53).
4. **Land R2+R3+R4+R5+R6** in one change: gates, fixtures, unit tests, e2e, openapi + error-codes updates.
5. **Post-deploy verification**: machine happy path still 201; user happy path with explicit bound tenant still 201; cross-tenant probes → 403 `tenant_mismatch` (user) / 403 `insufficient_scope` (machine); the e2e's A11 mint assertions confirm `/token` stamps the claim in the deployed fleet.
6. **Rollback**: revert the gate commit; R1 may stay (additive). No durable state is touched — no replay or backfill needed. Ordering matters: reverting the adapter gate FIRST restores today's behavior (including the cross-tenant hole); reverting the IdP mint first while the gate lives re-creates F1 (safe — fail-closed). Both intermediate states are safe; the operator must know which state they are in.

## 7. Testable acceptance mapping

| # | Acceptance (from requirements) | Design → test |
|---|---|---|
| A1 | new `tenant_claim_test.go`: JWT with `tenant_id` → `Claims.TenantID` + `HasTenantID()`; without → `""`/false; `Raw` keeps the claim | §3.1 → `interfaces/ssoclient/rs/tenant_claim_test.go` (rstest issuer + `rs.ValidateToken` through `rs.NewJWKSCache`) |
| A2 | introspection-path case: active response with/without `tenant_id` → `Claims.TenantID` / `""` | §3.1 → same new file, reusing the in-package `introspectServer` seam (introspect_test.go:17) |
| A3 | existing rs test files untouched and green | §3.1 → `go test ./interfaces/ssoclient/rs/...` with zero modifications |
| A4 | user token claim tenant-one, input tenant-other (bound) → 403 `tenant_mismatch`, no scope attr (201 under the fixture-updated baseline: `tenant-other` is bound in the same change; today's fixture lacks it, so today this input returns 403 via `binding == nil` — byte-identical to the post-change cause, hence the R4.2 pin change is cause-independent) | §3.2/§3.4 → new `TestCheckoutUserRejectsTenantClaimMismatch` (fixture `TenantBindings` gains `tenant-other`; assert status/body/challenge) |
| A5 | recorded response byte-equal across bound-other / unbound-nowhere / missing input, same token — claim-bearing tokens only: a claim-less user token holder retains the pre-existing bound→201/unbound→403 enumeration signal (the binding check predates this change; D1's pass-on-absence implies it) | §3.2 → new `TestCheckoutUserTenantMismatchIsByteIdentical`: capture three `httptest.ResponseRecorder`s, byte-compare `Code`, `Body.Bytes()`, and the `Header()` maps via DeepEqual — map comparison is order-independent, the recorder adds no Date/Content-Length, and `writeCheckoutChallenge` uses `Set`, not `Add` (http.go:380-389) |
| A6 | matching claim passes (201) | §3.4 → `TestCheckoutAuthorizesAdminUserForExplicitBoundTenant` with the fixture claim added (assertion unchanged) |
| A7 | wrong scope unchanged: 403 `insufficient_scope` + `scope="admin:write"` | §3.2 → "wrong scope" case of `TestCheckoutUserRequiresAdminScopeAndExplicitBoundTenant` (assertion unchanged) |
| A8 | machine claim mismatch → 403 `insufficient_scope`, byte-equal to the existing input-mismatch rejection | §3.3 → new `TestCheckoutMachineRejectsClaimMismatch`: claim tenant-other via a claim-map variant; record both responses and byte-compare the same `Code`/`Body.Bytes()`/`Header()`-map triple as A5 |
| A9 | machine absent claim → 403 `insufficient_scope`, same byte shape | §3.3/§3.4 → new `TestCheckoutMachineRejectsMissingTenantClaim` via the no-claim fixture variant |
| A10 | matching machine claim → 201; existing machine pins unchanged | §3.4 → fixture claim keeps `TestCheckoutUsesBoundTenantAndBillingAmount`, `TestCheckoutReplaysCompletedReservationWithoutStripeCall`, `TestCheckoutSafelyReplacesExpiredSession`, `TestCheckoutEnforcesClientBindingScopeAndReturnOrigin`, `TestCheckoutMachineRejectsCrossTenantRequest` green with zero assertion changes |
| A11 | both e2e mints return 200; wire payload carries the seeded `tenant_id` per client (`got, ok := payload["tenant_id"].(string); ok && got == <seeded>` — a missing key fails loudly); `aud` asserts as the compact string `"stripe-adapter"` (single-audience scalar per `audClaim.MarshalJSON`, ed25519_types.go:141-148) | §3.5 → `test/stripe_adapter_tenant_claim_test.go`: `scCC` ×2, payload-segment decode |
| A12 | production rs middleware projects `ClaimsFromContext().TenantID` == seeded binding; `HasTenantID()` true | §3.5 → same e2e: `rs.NewJWKSCache` + `rs.HTTPMiddleware` + stub handler |
| A13 | adapter-shaped config (ExpectedAud == minted resource) validates the minted token | §3.5 → same e2e (the A12 middleware run uses the adapter's exact config shape) |
| A14 | openapi.yaml + error-codes.md + `docs/stripe-payment-adapter.md` updated; the R6 `checks/adapters_check.py` extension is green (kin-openapi over `cmd/*/openapi.yaml` + exported-const→docs-row assertion) | §3.6 → `make ci` (docs-validate, route-contract, checks incl. the new adapters scans, race, nested modules); A14 is machine-enforced: gate green + `ErrTenantMismatch` const exists + the docs row exists — no review-only pairing |
| A15 | tenant-less console user token (no claim, D1) with bound input → 201 AND the gate selects the bound binding; same token with unbound input → 403 with the EXACT `tenant_mismatch` challenge (equality, not Contains) | §3.2/§3.4 → new `TestCheckoutUserAcceptsTenantlessConsoleToken`: mint via `testAdapterHandlerSubjectWithoutTenantClaim(t, store, billing, stripe, "user-one", "console-client", scopeAdminWrite)`; (1) input `{"tenant_id":"tenant-one", ...}` → 201, assert `billing.lastBinding.TenantID == "tenant-one"` (pattern: http_test.go:116-117) — the gate selected the bound binding, no short-circuit; (2) companion, same token, input `tenant-nowhere` → 403, challenge == `Bearer realm="stripe-adapter", error="tenant_mismatch"` (deterministic construction, http.go:380-389) — pins that absence waives only the claim comparison, never `binding == nil` (a regression deleting the nil check would let tenant-less consoles check out to unbound tenants — D3's leak); (3) optional: byte-compare the 201 with A6's claiming-token pass — absence is unobservable in the pass path |

Campaign mapping (per requirements §7): T-8(a) → A1/A2/A3; T-8(b) → A4/A5/A6/A7/A15; T-9 → A8/A9/A10 + A11/A12/A13; contracts → A14.

## 8. Engineering gates

- Budgets: `claims.go` 191 → ~205; `http.go` 402 → ~414 (`authorizeUserCheckout` 13 → ~17 lines, `authorizeMachineCheckout` 12 → ~14 — both ≤50, complexity ≤15, nesting ≤3); `model.go` +1 const. No directory/fan-out changes (`rs` non-test files unchanged; `interfaces/sso` untouched — 60-file ceiling).
- After every `.go` edit: `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .`
- Targeted: `go test ./interfaces/ssoclient/rs/... ./cmd/snaplink-stripe-adapter/...`, then `go test ./test/ -run 'TestStripeAdapterTenantClaim|TestE2E' -v`.
- Handoff: `go test ./... -race`; `make ci` (no nested-module/profile/manifest change).
- Oracle-safety review (AGENTS.md §3): user-flow tenant rejection is one constant response across all causes (A5 byte-equality); machine-flow claim rejection is byte-identical to the existing cross-tenant `insufficient_scope` (A8 byte-equality); no tenant value crosses any wire; denials increment no metric and no audit path exists on this surface — no oracle introduced. D1's pass-on-absence is a policy carve-out, not an outage fail-open (see §3.2), and the claim-less enumeration signal is pre-existing and disclosed at A5.
- Contract note: the adapter's nested `openapi.yaml` was not kin-openapi-validated by `make ci` (only `docs/openapi.yaml`, Makefile:189), and the exported-constant/docs-row pairing was review-only — `model.go:44`'s "repository contract gate" comment referenced a gate that did not exist. R6 closes both: the `checks/adapters_check.py` extension (a) runs the same `kin-openapi validate` over `cmd/*/openapi.yaml` (verified passing at HEAD, exit 0 — the gate adds with no pre-existing failure) and (b) asserts every exported wire-code const appears as a `` | `code` | `` row in the error-codes.md Stripe section. That row-level assertion is exactly what would have caught the R6 prose-vs-row error (§3.6) at review time. The docs-side R6 edits themselves are already applied in the working tree (error-codes.md:1039-1047/1051, openapi.yaml:210-227, stripe-payment-adapter.md:39-42); the gate is what R6 still adds.
