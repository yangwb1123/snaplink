# Requirements Spec: consume the B4-1 mint-time tenant_id claim fail-closed in billing's resource server and quota relay

- Direction: "Consume the B4-1 mint-time tenant_id claim fail-closed in billing's resource server and quota relay" (source: `docs/architect-analysis/auto/analyses/cmd-snaplink-billing-a1788a26.json`, entry 2)
- Analysis module: `cmd/snaplink-billing`; change surface: `interfaces/ssoclient/rs` (claim projection only), `cmd/snaplink-billing` (resource-server gate + quota-relay delivery gate), `interfaces/ssoclient/quotaprojection` (delivery cross-check), `test/` (T-8(e) e2e), `cmd/snaplink-billing/README.md` (workaround statement retirement). No mint-side changes — B4-1 already stamps the claims.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `infrastructure/defaultimpl/issue_payload.go:46,87` — TenantID, Roles emitted | Line 46: `TenantID: subject.TenantID` in `buildAccessPayload`, assigned unconditionally with the comment "single-tenant stays byte-identical" (the `omitempty` on the wire performs omission); lines 86-87: `if len(subject.Roles) > 0 { payload.Roles = append([]string(nil), subject.Roles...) }` in `applyOptionalClaims` (guard + copy discipline, emitted only when non-empty). `claimsWithoutEmittedKeys` (112-134) strips duplicate `tenant_id`/`roles` from the attribute bag so the mint-time literal wins | Confirmed (line exact) |
| `interfaces/ssoclient/rs/claims.go:13` — no TenantID/Roles projection | `type Claims struct` at line 13 has no TenantID/Roles fields; `wireClaims` (93-108) has no `tenant_id`/`roles` tags (only `serving_region` at 104); `parseClaims` (113-136) projects nothing beyond the typed fields. The claims are reachable only untyped via `Raw`. `grep -i tenant interfaces/ssoclient/rs/*.go` → one comment, zero fields | Confirmed |
| `cmd/snaplink-billing/app.go:220-222` — rs.Config without tenant handling | `buildHTTPHandler`: `protected := rs.HTTPMiddleware(rs.Config{Issuer: config.Issuer, JWKSCache: jwks, ExpectedAud: config.Audience}, business)` — exactly three fields, no tenant/claim gate | Confirmed (line exact) |
| `cmd/snaplink-billing/auth.go:adminScopeGate` — scope-only gate | `adminScopeGate(required string)` at auth.go:159-168: 401 `invalid_token` when claims absent, else `matchesRequiredScope` → 403 `insufficient_scope` via `writeScopeFailure` (180-193: no-store/pragma + `WWW-Authenticate: Bearer realm="billing", error=insufficient_scope, scope=<required>`, body `{"error":"insufficient_scope"}`). No tenant input anywhere in the gate | Confirmed (line exact) |
| `cmd/snaplink-billing/quota_relay.go:quotaAuthorizer` — tenant from outbox row, not token | `quotaAuthorizer` (quota_relay.go:434-453): `AuthorizerFunc(func(ctx, tenantID)` — tenantID arrives from the relay's outbox event (`quotaprojection/http_client.go:102` `c.authorization(ctx, event.TenantID)`); it mints via `tokens.AccessToken(ctx, SourceBinding{TenantID: tenantID, ...})` and returns `Authorization{TenantID: tenantID, ...}`. The existing backstop at `http_client.go:138-146` (`authorization` — the tenant comparison at 143) only checks the authorizer's returned tenant vs the event tenant (equal by construction) — the token's own tenant_id claim is never inspected | Confirmed |
| `cmd/snaplink-billing/README.md` — '当前 Snaplink client_credentials token 不携带 tenant_id claim' | Lines 170-172 (Audit Governance section): "当前 Snaplink client_credentials token 不携带 `tenant_id` claim，因此每个事件的 source 只由可信 outbox tenant 在服务端派生，多租户授权来自 Audit Governance 的 client → tenant-scoped source → tenant 注册映射" — the documented pre-B4 workaround | Confirmed (line exact) |

Supporting facts (not cited by the direction but load-bearing for the requirements):

| Fact | Measured reality |
|---|---|
| Claim names | `shared/core/consts_wire.go:169` `KeyTenantID = "tenant_id"`; `:277` `KeyRoles = "roles"` (RFC 9068 claim names; the roles comment notes the tag-vs-const coupling guard) |
| rs extension-claim precedent | `serving_region` is the exact precedent to mirror: `Claims.ServingRegion` (claims.go:24-28) + `HasServingRegion()`/`HasServingRegionIn()` (claims.go:71-88) + `Config.AllowedServingRegions` (rs.go:103-119) enforced in BOTH validation modes (`validateClaims` claims.go:187-190, with the "Runs LAST … never becomes a probe oracle" comment at 182-186; `validateIntrospectedClaims` introspect.go:139), running LAST with an explicit ordering rationale. `wireIntrospection` (introspect.go:66-73) embeds `wireClaims`, so one wire struct change covers both modes |
| Billing-side binding store | `domains/metering/usageledger/source_binding.go:27-40` `SourceBinding{ID, ClientID, TenantID, SourceSystem, Enabled, Revision, ...}`; `SourceResolver.Resolve(ctx, clientID)` (140-160) returns the unique enabled binding, `ErrSourceBindingUnauthorized` for unknown/ambiguous — "the resolved binding tenant" in the acceptance below is `Resolve(clientID).TenantID` |
| Existing binding-vs-request cross-checks (never the token) | `interfaces/commerce/payment_ingest.go:157-169,189-196`: resolves the binding by `claims.ClientID` and compares `binding.TenantID != tenantID` (the path tenant) — the token's tenant_id plays no part. `interfaces/metering/auth.go:15-31`: `authorize(requiredScope)` = scope check + `Sources.Resolve(clientID)` rejection — same gap. Both families already hold the binding in their gate, so the drift condition is one added comparison per family |
| IdP-side projection handler | `interfaces/sso/quota.go` `ServeHTTP`: authenticates the token (machine-claim shape, scope, audience), then resolves tenant from the IdP-side quotabinding registry by (clientID, request.SourceSystem) and compares against the request-body tenant. The token's tenant_id claim is never compared — the IdP-side handler is NOT in this direction's surface (see non-goals) |
| Same workaround in shared token source | `infrastructure/auditgovernance/oauth_token_source.go:44-46`: "Tenant IDs deliberately do not partition the cache because the current Snaplink access-token wire format does not carry tenant_id" — the same pre-B4 premise in the token source the quota relay mints through |
| Drift denial response shape exists and is documented | `docs/error-codes.md:137` and `:1014` already document 403 `insufficient_scope` for machine routes including "its exact source binding is unknown/disabled … cross-tenant" with "binding causes are intentionally hidden" — the drift denial folds into the existing code, no new `Err*` |
| Relay failure semantics for authorization rejection | `interfaces/ssoclient/quotaprojection/relay.go:189,237-240`: `ErrAuthorizationRejected` → `reasonAuthorization` with bounded retry — event retained in the outbox, no permanent drop. `http_client.go:155-165` (`decodeProjectionReceipt`): 401/403 from the IdP also join `ErrAuthorizationRejected` (the join at 163) |
| Billing test seams | `cmd/snaplink-billing/auth_test.go:120-127` `serveWithClaims` injects `rs.Claims` via `rs.NewContext` (the drift-gate unit-test seam); `quota_relay_test.go` builds httptest IdP servers; `test/quota_projection_e2e_test.go:84-92` mints the relay token WITHOUT `Subject.TenantID` (the fixture T-8(e) must update); the e2e's `HTTPClient` is the same production `quotaprojection.HTTPClient` billing uses (only production consumer: `quota_relay.go:308`) |
| File budget pressure | `cmd/snaplink-billing/quota_relay.go` is 485 lines — the 500-line gate; the new check must NOT land in that file (split/extract or a new file) |

**Gap confirmation (the direction's problem is real).** B4-1's `buildAccessPayload` stamps `tenant_id` (client binding) and `roles` at mint, but the claims die at the RS boundary: `rs.Claims` does not project them, and billing's three route families (admin scope gate, payment binding checks, metering binding checks) plus the quota relay authorize on scope/binding-store alone. The IdP client binding and billing's source-binding store can therefore diverge (client re-bound at the IdP vs stale binding revision in billing) with no detection: the token carries binding evidence billing never reads. The README (170-172) and `oauth_token_source.go:44-46` still document the pre-B4 wire as if it were current.

## 2. Goal and user outcome

The G1 trust path stops being "two independent, cross-checked bindings" for billing. Concretely:

- `rs.Claims` projects `TenantID` and `Roles` (both validation modes), so any RS — billing first — can observe the mint-time binding the way it already observes `serving_region`.
- Billing's resource server rejects, with the byte-identical `403 insufficient_scope` it already emits for scope denials (no oracle), any machine token whose tenant_id contradicts the tenant billing resolves from its own source-binding store for the same client — closing both drift directions: IdP re-bound the client (claim ≠ billing binding) and billing bound a client the IdP never bound (claim absent).
- The quota relay delivers a projection only when the minted token's tenant_id equals the outbox event tenant; a mismatch or missing claim stops the delivery before any `PUT /api/v1/internal/tenant-quota/projection` leaves billing, the event stays in the durable outbox, and the relay retries with its existing bounded backoff.
- The README workaround statement is retired and replaced with the claim-verified description.

Completion marker: the direction's acceptance (T-2 billing-side pin, new billing drift test, T-8(e) quota relay equality) plus campaign G1's single-trust-path intent hold: billing consumes the mint-time claim fail-closed, and the IdP-side mint pin T-8(a) (`claims {iss/aud/scope/client_id/tenant_id/roles}`) has a billing-side consumption counterpart.

## 3. Product boundary

- Surface: `interfaces/ssoclient/rs` (Claims projection only — additive, no config), `cmd/snaplink-billing` (gate wiring + delivery check), `interfaces/ssoclient/quotaprojection` (delivery cross-check; sole production consumer is billing), `test/quota_projection_e2e_test.go`, `cmd/snaplink-billing/README.md`, plus the stale comment in `infrastructure/auditgovernance/oauth_token_source.go:44-46` (comment-only correction of the same false premise; no behavior change).
- Defaults: the billing gates are always-on, derived from the existing source-binding store — no new config knob. The single-tenant carve-out is preserved: a client with NO binding in billing's store is not tenant-gated (byte-identical to today); the fail-closed spine applies only where billing holds a binding expectation.
- Explicit non-goals (do not implement):
  - No mint-side change: `issue_payload.go` is correct as shipped (B4-1). No change to `shared/core/consts_wire.go`, `Subject` fields, or any issuer.
  - No change to `interfaces/sso/quota.go` (IdP-side projection handler) — the billing-side gate makes a drifted delivery undeliverable before it reaches the IdP; an IdP-side claim-vs-registry check is a separate direction.
  - No `rs.Config` gate (no `AllowedServingRegions`-style static tenant set): the tenant expectation is per-client and dynamic (billing's binding store), so the gate belongs to billing, not the shared RS. rs changes are projection-only.
  - No change to `OAuthTokenSource` cache partitioning (shared infrastructure; the audit relay depends on it). The per-client cached token may carry a stale tenant_id until refresh; the delivery-time cross-check is what bounds the drift window (default TTL 1h), and the relay's bounded retry converges after refresh. Documented as a known limitation in the requirements, not fixed here.
  - No new config keys, `Err*`, endpoints, OpenAPI surface, or audit event types. Drift denials reuse the documented `insufficient_scope` code (docs/error-codes.md:137,1014) and MUST NOT create an observation distinguishable from a scope denial — including in audit behavior (see R2.3). If the design adds an audit record, `audit.SetMeta`/`auditreport` classification discipline applies and the record must cover both denial classes.
  - No change to existing `interfaces/ssoclient/rs` test files; the projection must land with all existing rs tests untouched and green.

## 4. Module classification

- [x] Authorization / resource-server gate (billing drift gate, quota relay delivery gate)
- [x] OAuth/OIDC client (rs claims projection)
- [x] Testing (T-2 pin, drift-gate tests, T-8(e) e2e)
- [x] Documentation (README workaround retirement, stale comment correction)
- [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Cold module · [ ] Refactoring only

## 5. Requirements

### R1 — rs claims projection (interfaces/ssoclient/rs/claims.go)

R1.1 `Claims` gains `TenantID string` and `Roles []string`; `wireClaims` gains `TenantID string \`json:"tenant_id"\`` and `Roles []string \`json:"roles"\``; both decode paths project them: `parseClaims` (JWT) and `ValidateTokenWithIntrospect` (introspection, via the embedded `wireClaims`). `Roles` is copied on projection (decode already allocates; keep the guard+copy discipline of `issue_payload.go:86-87`).
R1.2 An absent `tenant_id`/`roles` claim decodes to the zero value (`""`/`nil`) — no `omitempty` needed on decode, no reordering, `Raw` unchanged. Existing rs tests stay byte-identical (this is the direction's stated carve-out).
R1.3 `Claims` gains `HasTenantID() bool` mirroring `HasServingRegion()` (claims.go:71-73): true iff `TenantID != ""`. Tenant IDs are non-empty by construction (binding identity validation), so presence == non-empty, same discipline as the serving-region precedent.

Acceptance:
- A1: `go test ./interfaces/ssoclient/rs/...` with zero modifications to existing test files — all green, no assertion changes.
- A2 (new, in a new `claims_test.go`): a JWT payload with `tenant_id`/`roles` decodes into `Claims{TenantID, Roles}`; the same token without the claims decodes to zero values; `HasTenantID()` false. One introspection-path case with the same assertions (wireIntrospection embeds the same wire struct).

### R2 — billing resource-server drift gate (fail-closed, byte-identical, no oracle)

R2.1 Uniform rule for every billing protected route family (admin scope gate, payment machine routes, metering routes): let `b = ledger.SourceResolver.Resolve(ctx, claims.ClientID)`.
- `b == nil` (client unbound in billing's store): no tenant gate — current behavior unchanged (single-tenant carve-out; the token's claim, if any, is not billing's concern because billing holds no binding expectation).
- `b != nil`: require `claims.HasTenantID() && claims.TenantID == b.TenantID`. A missing claim is a mismatch (fail-closed: billing binds a client the IdP does not bind — the drift class the claim exists to close). Any mismatch denies the request.

R2.2 Denial shape: the drift denial MUST be emitted through the same rejection writer the route already uses for scope denial, with the same arguments — `writeScopeFailure(ctx, http.StatusForbidden, commercehttp.ErrorInsufficientScope, <route scope>)` for admin routes (auth.go:167), `rejectPaymentMachine`/`rejectPaymentSource` for payment routes, `rejectMachine` for metering routes — so status (403), body (`{"error":"insufficient_scope"}`), headers (no-store/pragma, `WWW-Authenticate: Bearer realm="billing", error=insufficient_scope, scope=<route scope>`) are byte-identical by construction. Implementation seams: the payment gate (payment_ingest.go:157-169,189-196) and metering gate (auth.go:15-31) already hold the binding — one added condition; `adminScopeGate` (auth.go:159) gains resolver access (wiring change through `buildApplication`/`buildHTTPHandler`, which currently do not thread `services.sources` into the handler chain).
R2.3 No oracle: no tenant value, binding revision, or drift indicator may appear in the body, headers, challenge, or any observable difference vs a scope denial on the same route — including audit: the denial must not create an observation that distinguishes it from a scope denial (the payment routes' `observe` records `ErrorInsufficientScope` for both classes through the same reject functions; admin-route denials remain unrecorded at the gate, exactly as scope denials are today).

Acceptance (the direction's "new billing test", made testable in `cmd/snaplink-billing/auth_test.go` / a new `tenant_gate_test.go`, using the `serveWithClaims` seam plus a memory binding store seeded via the existing `applySourceBindings` path):
- A3: with binding `{ClientID: "billing-relay", TenantID: "tenant-a"}` in the store, a request whose claims carry `TenantID: "tenant-b"` on an admin route: status 403, body exactly `{"error":"insufficient_scope"}`, and the full recorded response (status + headers + body) byte-equal to the scope-denial response recorded for the same route in the same test; no `tenant` literal anywhere in the response.
- A4: same binding, claims WITHOUT `TenantID` → the same byte-identical denial (fail-closed on absence).
- A5: no binding in the store, claims with a `TenantID` → current behavior unchanged (scope grant still 200); claims without → unchanged. This pins the single-tenant carve-out.
- A6: the payment route family gets the same three-case matrix (matching claim passes the gate; mismatched/absent claim denies through the payment reject writer, byte-identical to its scope denial; unbound client unchanged) — either via the shared gate or the handler-level condition; the response-shape assertions repeat for one payment route.

### R3 — quota relay delivery cross-check (fail-closed)

R3.1 The quota delivery path MUST verify, before any `PUT` leaves billing, that the bearer token's `tenant_id` claim equals the outbox event tenant: present-and-equal → deliver; missing or differing → no PUT, delivery fails with `quotaprojection.ErrAuthorizationRejected` (the relay's existing class → `reasonAuthorization` bounded retry, event retained in the durable outbox; relay.go:189,237-240).
R3.2 Placement must be such that the T-8(e) e2e exercises the production check, not a test replica. Recommended seam: `quotaprojection.HTTPClient.authorization` (http_client.go:138-146), which already holds both the event tenant and the freshly minted token, decoding the JWS payload's `tenant_id` claim (payload-only decode is safe here: the token was just minted by the IdP over the trusted token endpoint, and any parse failure fails closed into the same retry class the IdP's own verification would produce). Alternative acceptable placement: an exported helper in `interfaces/ssoclient/quotaprojection` used by both billing's `quotaAuthorizer` and the e2e harness — the constraint is that the e2e runs the production code. Billing's `quotaAuthorizer` itself may stay unchanged.
R3.3 Known limitation, documented in the spec's design handoff: `OAuthTokenSource` caches one token per client; after an IdP-side re-bind, the cached token carries the old tenant_id until refresh (default TTL 1h). The cross-check rejects during that window and the relay's bounded backoff delivers after refresh — no cache change in this direction.

Acceptance (T-8(e), in `test/quota_projection_e2e_test.go`, which uses the production `HTTPClient`):
- A7: the e2e's minted token gains `Subject.TenantID: "tenant-e2e"` — the positive path delivers exactly as today (one `PUT` completes; projection revision advances).
- A8 (new negative): a token minted with `TenantID` ≠ event tenant → `relay.RunOnce` delivers 0, the IdP-side quota store is untouched (no state change), and the outbox event remains claimable (not consumed, not dead-lettered).
- A9 (new negative): a token minted without `TenantID` → same no-delivery outcome (fail-closed on absence; the outbox event is retained).
- A10 (billing unit test, `cmd/snaplink-billing`): the production cross-check rejects a mismatched/absent-claim token with `ErrAuthorizationRejected` and accepts a matching one, driven through the actual delivery seam used in production.

### R4 — T-2 billing-side claim pin

R4.1 A billing-side pin test (new `cmd/snaplink-billing/claims_pin_test.go`, package main; test-only imports of the issuer are fine) mints a client_credentials token carrying the source-binding tenant and roles via the same issuance path the SSO server uses (`defaultimpl` issuer, `Subject{ClientID, TenantID: <binding tenant>, Roles: [...]}` — mirroring the IdP's mint-time stamping), decodes it, and asserts:
- the wire claim `tenant_id` equals the source-binding tenant and `roles` is present (raw JWS payload decode), and
- billing's RS path projects them: `rs.ValidateToken` (JWKS from the same issuer) or billing's protected chain yields `Claims.TenantID == <binding tenant>` and `len(Claims.Roles) > 0`.
R4.2 The same test asserts the absent-claim token yields zero values through the same path (ties back to R1.2's byte-identical carve-out).

### R5 — documentation correction (same change)

R5.1 `cmd/snaplink-billing/README.md:170-172`: replace the "当前 Snaplink client_credentials token 不携带 tenant_id claim" workaround paragraph with the claim-verified description: the mint-time `tenant_id` claim is now consumed fail-closed by billing's resource server and quota relay; IdP client bindings and billing's source-binding store must be kept mirrored, and a mismatch/missing claim denies delivery with the existing `insufficient_scope`/retry semantics (binding causes intentionally hidden).
R5.2 `infrastructure/auditgovernance/oauth_token_source.go:44-46`: correct the stale comment ("current Snaplink access-token wire format does not carry tenant_id") to state that the cache remains per-client (not per-tenant) by design and that consumers must verify the mint-time claim at consumption time; no behavior change.

## 6. Engineering gates and verification

- Budgets: `quota_relay.go` is at 485/500 lines — the R3 check must NOT be added there; put it in `interfaces/ssoclient/quotaprojection/http_client.go` (recommended seam, no budget pressure: 199 lines) or a new file. `auth.go:159` `adminScopeGate` is ~36 lines; adding the resolver condition must keep the function ≤50 (extract a helper if needed; `writeScopeFailure` is already extracted). `claims.go` (191 lines) and `http_client.go` (199 lines) grow by fields/one check only — both comfortably inside the 500-line file budget.
- No new top-level or `internal/` packages; no import toward `cmd/`; rs/quotaprojection stay in `interfaces` (import direction intact).
- After every `.go` edit: `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .`.
- Targeted: `go test ./interfaces/ssoclient/rs/... ./interfaces/ssoclient/quotaprojection/... ./cmd/snaplink-billing/...`, then `go test ./test/ -run 'TestE2E' -v` (T-8(e) e2e).
- Handoff: `go test ./... -race` and `make ci` (nested modules, config, module validation unaffected — no manifest/profile change).
- Oracle-safety review (AGENTS.md §3): the drift denial is byte-identical to the scope denial by construction (same writer, same args); the relay mismatch collapses into the existing `ErrAuthorizationRejected` retry class; no tenant detail crosses any wire.
- Rollout sequencing: this consumption work must land only after B4-1 mint is live (campaign G1 → G5 ordering guarantees it): before the IdP stamps `tenant_id` for bound clients, the always-on billing gate would deny every bound-client machine route on the absent claim. The G5 gate row (T-2, T-8(b–e), T-9 in `docs/campaigns/implementation-gate.md`) is the landing slot; the direction's T-2 label is the billing-side pin complement to the campaign's T-8(a) mint pin.

## 7. Acceptance summary (direction contract, preserved)

| Direction acceptance | Testable form (this spec) |
|---|---|
| T-2: billing-side pin test decodes a minted client_credentials token and asserts tenant_id equals the source-binding tenant and roles is present | R4.1 → A: claims_pin_test.go wire + projection assertions |
| New billing test: token tenant_id differing from the resolved binding tenant collapses to the byte-identical 403 insufficient_scope with no oracle | R2.2/R2.3 → A3 (byte-equal recorded response), A6 (payment family); A4 extends to the missing-claim drift class |
| T-8(e): quota relay delivers only when token tenant_id == outbox event tenant | R3.1 → A7 (matching delivers), A8 (differing: 0 delivered, store untouched, event retained), A9 (absent: same), A10 (production-seam unit test) |
| All existing rs/claims tests stay byte-identical when the claim is absent (single-tenant omitempty) | R1.2 → A1 (zero test-file modifications, full rs suite green), A2 (zero-value decode cases) |
