# Design: close the tenant-less user-token carve-out in authorizeUserCheckout under the B4-1 mint guarantee

Sibling spec: `cmd-snaplink-stripe-adapter-b4-1-tenantless-carveout-requirements.md` (R1-R5, A16-A19).
Prior direction: `cmd-snaplink-stripe-adapter-tenant-claim-design.md` (landed `rs.Claims.TenantID`,
`HasTenantID`, the machine-flow fail-closed gate, and the user-flow carve-out this design removes).

## 1. Evidence verification verdict

The evidence was treated as untrusted and re-checked against HEAD. Every citation verifies;
two drifts found (one new, one already recorded in the spec).

| Citation | Measured reality | Verdict |
|---|---|---|
| `http.go:236-246` — `authorizeUserCheckout` carve-out | Func spans 233-252; guard `binding == nil \|\| (claims.HasTenantID() && claims.TenantID != input.TenantID)` at 241; comment 243-248 documents the claim-less carve-out for the tenant-less console client | CONFIRMED (drift as recorded) |
| `http_test.go:452-462` — claim-less helper | Comment at 453-455 ("tenant-less console / pre-B4-1 fleet shape… (A9) and the D1 pin (A15)"), func at 456-464; the only other users are A9 (machine, line 301) and A15 (line 325) | CONFIRMED (drift as recorded) |
| `http_test.go:281-296` — A8 byte-equality baseline shape | `TestCheckoutMachineRejectsClaimMismatch` spans 265-296; comparison block 291-296 (`Code`, `Body.Bytes()`, `reflect.DeepEqual` on `Header()`) | CONFIRMED (comparison at 291-296) |
| `issue_payload.go:57-63` — unconditional mint stamp | `TenantID: subject.TenantID` at line 46 with `omitempty`, comment 43-46; `claimsWithoutEmittedKeys` (115-135) strips the attribute-bag copy so the literal wins | CONFIRMED (drift to 43-46) |
| `claims.go:83-88` — `HasTenantID` | Comment 83-86, func 87-89, `return c != nil && c.TenantID != ""` | CONFIRMED (drift to 83-89) |
| `test/stripe_adapter_tenant_claim_test.go` — T-9 harness | Exists, 200 lines; harness seeds `checkout-e2e`/`tenant-e2e` + `checkout-other`/`tenant-other`; `scCC` mints CC with RFC 8707 `resource`; A11-A13 + ResourceRequired pins | CONFIRMED |
| `token_client_credentials.go:52` (spec non-goal list) | File is `internal/handler/tokengrant/token_client_credentials.go` (not `infrastructure/defaultimpl/` — **path drift not recorded in the spec**); `TenantID: client.TenantID` at line 52 | CONFIRMED substance, path drift |
| Fan-out ceiling claim | `cmd/snaplink-stripe-adapter` holds exactly 10 non-test `.go` files (16 with tests) | CONFIRMED — edits only, no new files |
| `HasTenantID` post-change liveness | Still exercised by `interfaces/ssoclient/rs/tenant_claim_test.go:38-101` and the e2e A12/A13 pin (`test/…:146`) | CONFIRMED — method stays, no dead code |

Supporting facts re-checked and load-bearing for the design:

- **Machine flow already fail-closed** (the contrast class): `authorizeMachineCheckout` (http.go:213-231)
  rejects `claims.TenantID != binding.TenantID`, including `""`; A9 pin at http_test.go:296-315.
  The user flow is the only remaining fail-open class — the direction's problem statement is exact.
- **B4-1 mint contract**: `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-1-tenant-claims-requirements.md`
  case 5 (unbound client mints 200 with **no** `tenant_id` key, `omitempty`) and case 7 (every grant
  path stamps `tenant_id == client.TenantID`). Confirmed at lines 100 and 106-107 of that document.
- **Legacy-test deletion precedent**: `docs/campaigns/implementation-gate.md` row 3 orders
  `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` deleted as transitional defect locks — the same
  category as the A15 pin.
- **E2E boundary**: `test/` is package `ssotest`; the adapter is `package main` — not importable.
  Confirmed: no import of `cmd/` anywhere in `test/`.
- **A6 gate-pass pin exists**: `TestCheckoutAuthorizesAdminUserForExplicitBoundTenant` (http_test.go:146-165)
  mints a `tenant-one`-stamped user token and asserts 201 — the pass half R4.2 composes with.
- **All four causes share one writer call**: `writeCheckoutChallenge(writer, http.StatusForbidden,
  ErrTenantMismatch, "")` at http.go:250; `writeCheckoutChallenge` (401-411) appends `scope=` only
  when non-empty. The no-scope-attribute invariant is structural, not incidental.

**Overall verdict: the requirements spec is accurate against HEAD.** The one unrecorded drift
(path of `token_client_credentials.go`) affects a non-goal citation only and changes nothing in
this design.

## 2. Design overview

One guard-condition prefix is removed in `authorizeUserCheckout`, converting the last
fail-open tenant-isolation class in the adapter into the existing constant rejection:

```go
// before (http.go:241)
if binding == nil || (claims.HasTenantID() && claims.TenantID != input.TenantID) {
// after
if binding == nil || claims.TenantID != input.TenantID {
```

Semantics after the flip, for a user-shaped token that already passed the scope/identity guards:

| Cause | binding | claims.TenantID | input.TenantID | Result |
|---|---|---|---|---|
| Missing input tenant | nil (`TenantBindings[""]`) | any | `""` | 403 (short-circuit, unchanged) |
| Unbound input tenant | nil | any | `"tenant-nowhere"` | 403 (short-circuit, unchanged) |
| Claim mismatch | `tenant-other` | `"tenant-one"` | `"tenant-other"` | 403 (unchanged) |
| **Claim-less** (new) | `tenant-one` | `""` | `"tenant-one"` | **403 (was 201)** |
| Valid | `tenant-one` | `"tenant-one"` | `"tenant-one"` | 201 (unchanged) |

Key properties:

- **No new observable class.** The claim-less cause joins the existing three under the same
  `writeCheckoutChallenge(writer, http.StatusForbidden, ErrTenantMismatch, "")` call, so the wire
  bytes are identical across all four causes (body `{"error":"tenant_mismatch"}\n`, challenge
  `Bearer realm="stripe-adapter", error="tenant_mismatch"`, no `scope` attribute, no-store headers).
  A token holder cannot distinguish "the IdP did not bind the minting client" from "the input
  tenant is bound to someone else" — oracle-safe by construction (D3 extended to four causes).
- **Drift detection is deployment-model, not wire-level (D6).** B4-1 deliberately keeps the
  unbound-client mint claim-less (`omitempty`, entitiescmd case 5). The adapter cannot tell an
  unbound IdP client from a pre-B4-1 issuer on the wire, and does not need to: both are drift
  relative to the adapter's `TenantBindings`, both get the same constant rejection.
- **The carve-out's protected deployment becomes a migration.** A fleet running a genuinely
  tenant-less console client must bind that client to its tenant at the IdP before rollout
  (§6). The e2e's A17 mint assertion doubles as the deployment-time proof that `/token` stamps
  the claim for the bound console client; A18 pins that the unbound shape is exactly what the
  gate now rejects.
- **No config, no flag, no opt-out.** The gate is a pure removal of a condition prefix; there is
  deliberately no escape hatch — the same decision D2 already applied to the machine flow.

## 3. Concrete changes

### 3.1 R1 — gate flip and comment rewrite (`cmd/snaplink-stripe-adapter/http.go`)

- Line 241: `binding == nil || (claims.HasTenantID() && claims.TenantID != input.TenantID)` →
  `binding == nil || claims.TenantID != input.TenantID`.
- Lines 243-248: replace the comment. The carve-out sentence ("A claim-less token (tenant-less
  console client — no mint-time binding) passes when the input tenant is bound; the HasTenantID
  guard is the policy carve-out…") is deleted. The surviving comment names all four causes and
  states the invariant: the mint stamps the client binding unconditionally under B4-1
  (`infrastructure/defaultimpl/issue_payload.go:46`), so a claim-less user token is provable
  mint-time drift and fails closed with the same constant response as the other three causes;
  the `binding == nil` short-circuit still precedes the claim comparison so missing/unbound
  input tenants never reach it.
- Nothing else in the file: the scope-failure path (234-237), the machine gate (213-231), the
  challenge writer (401-411), and the headers stay byte-for-byte.

**Nil-safety constraint (must be stated in the comment).** The old guard called
`claims.HasTenantID()` — a nil-receiver-safe method. The new guard reads `claims.TenantID`
directly. This is safe only because `authorizeCheckout` (http.go:201-204) already 401s on
`!ok || claims == nil || claims.Subject == ""` before dispatching to `authorizeUserCheckout`,
and the function re-checks `claims.Subject == ""` at 236. The comment should note that the
field access is safe by the caller's nil guard; do not reintroduce a nil check inside the
guard (it would be dead code).

### 3.2 R2 — delete the A15 pin and the D1 references (`cmd/snaplink-stripe-adapter/http_test.go`)

- Delete `TestCheckoutUserAcceptsTenantlessConsoleToken` (comment 315-321, func 322-348): the
  transitional defect-test pin of the D1 carve-out, same category as `TestOIDCDiscovery` /
  `TestOIDCDiscoveryEndpoint` (deployment-gate row 3, transitional locks deleted once the
  corrected behavior is pinned).
- Update the helper comment at 453-455: `testAdapterHandlerSubjectWithoutTenantClaim` stays
  (A9 at 301 uses it), but the comment drops the "(A9) and the D1 pin (A15)" framing — it now
  mints the claim-less drift shape only ("the pre-B4-1 / unbound-client shape the gate rejects
  fail-closed").
- `tenantMismatchChallenge` (204), A4 (211-230), A5 (232-262), A6 (158-171), A7 (173-190),
  A8 (265-296), A9 (296-315), A10 (350-357) stay unchanged and green.

### 3.3 R3 — A16 unit pin: `TestCheckoutUserRejectsClaimlessToken`

New test reusing the A8 baseline-comparison shape (record first, byte-compare second):

1. **Baseline (claim-mismatch row):** `testAdapterHandlerSubject(t, …, "user-one",
   "console-client", scopeAdminWrite)` (stamps `tenant_id: "tenant-one"`); post
   `{"tenant_id":"tenant-other",…}` → assert 403, body exactly `{"error":"tenant_mismatch"}\n`,
   challenge exactly `tenantMismatchChallenge`. Record the full `httptest.ResponseRecorder`.
2. **Claim-less row:** `testAdapterHandlerSubjectWithoutTenantClaim(t, …, "user-one",
   "console-client", scopeAdminWrite)` (no `tenant_id` claim); post the bound input tenant
   `{"tenant_id":"tenant-one",…}` → assert 403, body exactly the constant body, challenge
   exactly `tenantMismatchChallenge` (equality, not `Contains` — construction is deterministic),
   and the full recorded response — `Code`, `Body.Bytes()`, and the complete `Header()` map via
   `reflect.DeepEqual` — byte-equal to the baseline.
3. **Transitivity with A5:** A5 pins bound-other == unbound == missing byte-equality; A16 pins
   claim-less == claim-mismatch. All four causes are therefore byte-identical without editing
   A5's map.
4. Comment states the pin's meaning: post-B4-1 a claim-less user token is mint-time drift
   (the mint stamps the client binding unconditionally, `issue_payload.go:43-46`) and the
   rejection is indistinguishable from every other tenant-class cause.

### 3.4 R4 — e2e extension (`test/stripe_adapter_tenant_claim_test.go`, package `ssotest`)

Harness gains two clients (constants `saConsoleClient = "console-e2e"` and
`saLegacyClient = "console-legacy"` alongside `saClientE2E`/`saClientOther`):

```go
{ ID: saConsoleClient, Secret: saSecret, Active: true,
  TenantID: "tenant-e2e", TokenStrategy: "jwt",
  AllowedScopes: []string{saScope, "admin:write"} },   // console-shaped, B4-1-bound
{ ID: saLegacyClient, Secret: saSecret, Active: true,
  TenantID: "", TokenStrategy: "jwt",
  AllowedScopes: []string{saScope, "admin:write"} },   // unbound (entitiescmd case 5)
```

- **A17 (console mint passes the gate's precondition):** `scCC(t, srv, saConsoleClient,
  saAudience)` → 200; base64url-decoded payload carries `tenant_id == "tenant-e2e"`; the
  production rs middleware with the adapter's exact config shape (`Issuer` + `JWKSCache` +
  `ExpectedAud: saAudience`, no `IntrospectURL`) yields `ClaimsFromContext().TenantID ==
  "tenant-e2e"` and `HasTenantID() == true`. The gate's pass for a stamped user token is pinned
  by A6 (unit); the gate's consumption of this exact projection by A12/A13 (same file).
- **A18 (pre-change issuer shape):** `scCC(t, srv, saLegacyClient, saAudience)` → 200; the wire
  payload carries **no** `tenant_id` key — the claim-less shape the unit-pinned gate (A16)
  rejects fail-closed. Together: a claim-less token minted by the pre-change issuer fails
  closed end to end, split across the package boundary (mint+projection here, gate decision in
  `cmd/snaplink-stripe-adapter/http_test.go` — `test/` cannot import `cmd/`).
- A note in the test comment: the CC mint proves the console mint shape because
  `buildAccessPayload` stamps the client binding identically for every grant (grant-agnostic).
- `TestStripeAdapterTenantClaim_MintAndProjection` and `TestStripeAdapterTenantClaim_ResourceRequired`
  stay unchanged and green.

### 3.5 R5 — wire contracts (same change, wording only)

- `docs/error-codes.md` (Stripe adapter section, `tenant_mismatch` row at 1051): the
  emitted-when cell gains the claim-less cause — "…or the token carries no `tenant_id` claim".
  The prose at 1044-1046 ("a request `tenant_id` that is missing, unbound, or contradicts the
  token's `tenant_id` claim") gains the claim-less clause. No new row, no other code's wording.
- `cmd/snaplink-stripe-adapter/openapi.yaml`: the authorization description (20-31) and the
  Forbidden description (215-222) gain "a user-shaped token without a `tenant_id` claim is
  rejected identically"; the `CheckoutRequest.tenant_id` description (175) stays consistent
  ("required for user-shaped tokens" already implies rejection of the absent claim). No schema
  change; `make ci` validates the YAML.

### Files

**Modify:** `cmd/snaplink-stripe-adapter/http.go` (guard + comment),
`cmd/snaplink-stripe-adapter/http_test.go` (delete A15, add A16, helper comment),
`test/stripe_adapter_tenant_claim_test.go` (two clients, A17/A18),
`cmd/snaplink-stripe-adapter/openapi.yaml`, `docs/error-codes.md`.

**Do not modify:** `infrastructure/defaultimpl/issue_payload.go:46` and all other grant-path
stamps (B4-1, correct as shipped; `omitempty` stays), `interfaces/ssoclient/rs/claims.go`
(`HasTenantID` stays live for rs tests and the e2e), `authorizeMachineCheckout` and its
A8/A9/A10 pins, the A4/A5/A6/A7 user-flow pins, the harness's existing two tests, and the
webhook/worker/relay surface.

## 4. API changes

There are **no wire-level API changes**: no endpoint, schema field, error code, config key,
audit event, or metric is added, removed, or renamed. The change is a behavioral contract
change with three observable facets, all pinned:

| Facet | Before | After | Pin |
|---|---|---|---|
| `POST /checkout` with claim-less user token + bound input tenant | `201 Created` | `403` `{"error":"tenant_mismatch"}\n`, challenge `Bearer realm="stripe-adapter", error="tenant_mismatch"` (no `scope`) | A16 (new) |
| `tenant_mismatch` cause set | 3 (missing input, unbound input, claim mismatch) | 4 (+ claim-less), all byte-identical | A5 + A16 |
| Docs (`openapi.yaml`, `error-codes.md`) | causes enumerated without the claim-less case | claim-less cause stated | A19 |

The behavioral contract for all other inputs is byte-identical: valid stamped user tokens
still 201, machine flow still `insufficient_scope`, scope failures still carry the `scope`
attribute, and the 401 `invalid_token` path is untouched.

## 5. Compatibility constraints

- **Wire byte-compatibility of the rejection:** all four causes share the single writer call
  (http.go:250); A5's map plus A16's baseline pin byte-equality. No tenant/claim/binding
  indicator may cross any wire in any variant (AGENTS.md §3 oracle-safe table).
- **Deployment-model compatibility (the hard constraint):** the change is safe only for a
  fleet in which every client referenced by `TenantBindings`/`CheckoutBindings` is tenant-bound
  at the IdP. A genuinely unbound console client now 403s all user checkouts. This is the
  intended forcing function (D1 revoked), not a regression: the same reasoning already applies
  to the machine flow.
- **No opt-out:** always-on, no new config knob. Deliberate — an escape hatch would recreate
  the probe surface the carve-out created (D3).
- **Nil-safety:** `claims.TenantID` field access is safe only because `authorizeCheckout`
  (http.go:201-204) 401s on nil claims before dispatch; the guard must not reintroduce a nil
  check (dead code) and the comment must record why.
- **`HasTenantID` stays in `rs`:** removing the adapter's call does not orphan the method —
  `interfaces/ssoclient/rs/tenant_claim_test.go` and the e2e A12/A13 pins exercise it. No
  `rs` change in this direction (specified non-goal, confirmed against the landed code).
- **Short-circuit order is preserved:** `binding == nil` still precedes the claim comparison,
  so missing/unbound input tenants behave exactly as before; the claim-less cause only fires
  when the input tenant is bound.
- **Budget ceilings:** `http.go` (423 lines) loses a prefix; `authorizeUserCheckout` stays
  20 lines, complexity and `if`-nesting unchanged. `http_test.go` (556) −34/+~35;
  `test/stripe_adapter_tenant_claim_test.go` (200) +~45. No new files in
  `cmd/snaplink-stripe-adapter` (at its 10 non-test-file fan-out ceiling — verified).

## 6. Failure modes

| Mode | Behavior | Detection / handling |
|---|---|---|
| Pre-B4-1 issuer still in the fleet (mints claim-less) | All user checkouts 403 `tenant_mismatch` (fail-closed, intended) | A18 pins the mint shape; checkout 403 rate via existing metrics; **action:** finish B4-1 mint rollout before the adapter change |
| Unbound console client (deployment never bound it) | Same 403 constant — indistinguishable from claim mismatch by design (oracle-safe) | **action:** bind the client at the IdP (entitiescmd) per §7; A17 proves the bound mint shape |
| Partial rollout (adapter ahead of IdP binding) | 403 spike for console users | Checkout 403-rate monitoring; rollback below |
| Nil claims context (defense in depth) | 401 `invalid_token` (unchanged — guard at 229-231 fires first) | Existing A-series pins; no new path |
| Accidental re-adding of a carve-out variant | New distinguishable rejection class (probe surface) | A5 + A16 byte-equality pins fail on any divergent variant; comment states the four-cause invariant |
| Future mint regression (claim no longer stamped) | Every user checkout 403s — fail-closed, no silent cross-tenant access | A17/A18 e2e plus B4-1's own mint matrix fail; the adapter degrades to denial, never to exposure |
| Rollback | Revert the one-line guard and restore A15 in the same commit | Byte-identical prior behavior; no data migration, no state |

The failure posture is deliberately asymmetric: every failure of the dependency chain
(missing stamp, unbound client, pre-B4-1 issuer) degrades to the constant 403 — never to a
201 on a possibly-wrong tenant. This mirrors the machine flow (D2) and satisfies AGENTS.md
fail-closed expectations for tenant isolation.

## 7. Migration steps

Ordered, with the B4-1 mint already live in-tree (`issue_payload.go:46` stamps the binding
unconditionally; the prior direction's gates landed):

1. **Confirm the mint guarantee** in the deployed IdP: `POST /token` for a tenant-bound client
   must carry `tenant_id` in the decoded payload (entitiescmd B4-1 case 7). In-tree proof:
   `issue_payload.go:43-46`; deploy-time proof: §7 step 4's curl shape.
2. **Inventory console clients:** every client ID appearing in the adapter's
   `TenantBindings`/`CheckoutBindings` config, plus every client the console login flow uses.
3. **Bind unbound clients at the IdP** (entitiescmd tenant binding, `TenantID` non-empty):
   single-tenant deployment → bind the console client to that tenant; multi-tenant → one
   client per tenant (or per-tenant scopes) so the binding selects the tenant the gate enforces.
   This is the D1 revocation's migration: the tenant-less shared console is not a supported
   fleet shape anymore.
4. **Pre-flight proof per client:** mint a token (any grant) and decode the payload — expect
   `tenant_id == <binding>`; an unbound client still mints 200 with no claim (entitiescmd
   case 5) — that exact shape is what the gate will reject.
5. **Ship the adapter change** (this direction) and the doc wording in one commit.
6. **Observe:** checkout 403 `tenant_mismatch` rate should be unchanged if steps 2-4 are
   complete (the only new 403 source is the claim-less shape, which step 3 eliminated).
7. **Rollback:** `git revert` of the single commit restores the guard and the A15 pin together;
   no state, config, or data migration in either direction.

## 8. Testable acceptance mapping

| Direction acceptance | Testable form | Assertions |
|---|---|---|
| T-8(c): claim-less user token on bound input tenant → 403 `tenant_mismatch` byte-identical to the claim-mismatch row; `WWW-Authenticate` without `scope`; A15 test and D1 comment deleted | R1+R2+R3 → **A16** `TestCheckoutUserRejectsClaimlessToken` | Status 403; body exactly `{"error":"tenant_mismatch"}\n`; challenge exactly `tenantMismatchChallenge`; full response (Code, body bytes, complete header map, `reflect.DeepEqual`) byte-equal to the recorded claim-mismatch baseline; A15 test and the http.go:243-248 carve-out sentence absent; A4/A5/A6/A7/A9 pins green |
| T-9: console client mints binding-stamped `tenant_id` and passes the tenant gate; claim-less token from the pre-change issuer fails closed | R4 → **A17** + **A18** | A17: `scCC(console-e2e)` → 200, wire `tenant_id == "tenant-e2e"`; production rs middleware (`Issuer`+`JWKSCache`+`ExpectedAud`) projects `TenantID == "tenant-e2e"`, `HasTenantID() == true` (gate pass composed with A6, projection with A12/A13). A18: `scCC(console-legacy)` → 200, **no** `tenant_id` key in the payload (the shape A16 rejects) |
| Contracts updated in the same change | R5 → **A19** | `error-codes.md` `tenant_mismatch` row gains the claim-less cause; openapi.yaml Forbidden + authorization descriptions gain it; `make ci` (OpenAPI validation) green |

Given/When/Then form:

1. Given a user-shaped token with no `tenant_id` claim, when `POST /checkout` names a bound
   input tenant, then 403 with the exact constant body and challenge, byte-identical to the
   claim-mismatch row (A16).
2. Given a tenant-bound console client, when the IdP mints and the adapter-shaped rs
   middleware validates, then the wire and projected `tenant_id` equal the client binding
   (A17).
3. Given an unbound client (pre-change issuer shape), when the IdP mints, then 200 with no
   `tenant_id` key — the token shape the gate rejects fail-closed (A18).

## 9. Engineering gates

- Budgets re-checked pre-edit: `http.go` 423 lines (< 500), `authorizeUserCheckout` 20 lines
  (< 50), complexity and nesting unchanged; `cmd/snaplink-stripe-adapter` at 10 non-test files
  (fan-out ceiling — edits only); no new packages; `interfaces/sso` and
  `interfaces/ssoclient/rs` untouched.
- After every `.go` edit: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`.
- Targeted: `go test ./cmd/snaplink-stripe-adapter/...`, then
  `go test ./test/ -run 'TestStripeAdapterTenantClaim' -v`.
- Handoff: `go test ./... -race` and `make ci` (nested modules, config, module validation
  unaffected — no manifest/profile change).
- Oracle-safety review (AGENTS.md §3): single constant response across all four causes,
  byte-equality pinned by A5 + A16, no tenant/claim/binding disclosure on any wire, no audit
  path on this surface (metrics only).
