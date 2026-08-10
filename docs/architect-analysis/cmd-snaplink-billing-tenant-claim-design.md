# Design: consume the B4-1 mint-time tenant_id claim fail-closed in billing's resource server and quota relay

- Source direction (entry 2): "Consume the B4-1 mint-time tenant_id claim fail-closed in billing's resource server and quota relay" (`docs/architect-analysis/auto/analyses/cmd-snaplink-billing-a1788a26.json`)
- Requirements: `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-requirements.md` (R1–R5)
- Status: design (every evidence citation re-verified against HEAD)

## 1. Evidence verification verdict

Every symbol cited in the requirements spec was re-checked against the repository. All are **confirmed**; three nuances the spec glosses over are recorded below and the design resolves them explicitly.

| Claim | Verified reality | Verdict |
|---|---|---|
| `issue_payload.go:46` unconditional `TenantID: subject.TenantID` + "single-tenant stays byte-identical" comment; `:86-87` Roles guard+copy | Confirmed at `infrastructure/defaultimpl/issue_payload.go` (comment at 42-45, field at 46; `applyOptionalClaims` Roles guard+copy at 86-87). `claimsWithoutEmittedKeys` strips duplicates so the mint-time literal wins | Confirmed |
| `rs/claims.go:13` `Claims` has no TenantID/Roles; `wireClaims` (93-108) no `tenant_id`/`roles` tags; `parseClaims` (113-136) no projection | Confirmed. Only `ServingRegion` is projected; `Raw` exposes the rest | Confirmed |
| `app.go:220-222` `rs.Config{Issuer, JWKSCache, ExpectedAud}` | Confirmed at `cmd/snaplink-billing/app.go:220-222` | Confirmed |
| `auth.go:159` `adminScopeGate` scope-only; `writeScopeFailure` (180-193) byte-identical 403 `insufficient_scope` | Confirmed (`auth.go:159-168`, writer at 180-193: no-store/pragma + `WWW-Authenticate: Bearer realm="billing", error=insufficient_scope, scope=<required>`, body `{"error":"insufficient_scope"}`) | Confirmed |
| `quota_relay.go:434-453` `quotaAuthorizer` takes tenant from outbox row; `http_client.go:143` backstop compares authorizer-return vs event tenant only | Confirmed (`quota_relay.go:434-453`; `http_client.go:102` `c.authorization(ctx, event.TenantID)`; `authorization` at 138-146, comparison at ~143). The token's claim is never inspected | Confirmed |
| `README.md:170-172` pre-B4 workaround text | Confirmed, line exact | Confirmed |
| `serving_region` is the exact rs precedent (both validation modes, gate runs last, no-probe-oracle) | Confirmed: `claims.go:24-28` (field), `71-88` (`HasServingRegion`/`HasServingRegionIn`), `rs.go:103-119` (`AllowedServingRegions`), `claims.go:182-190` JWT gate ("Runs LAST … never becomes a probe oracle"), `introspect.go:139` introspection gate; `wireIntrospection` embeds `wireClaims` (one wire struct covers both modes) | Confirmed |
| `oauth_token_source.go:44-46` stale "wire format does not carry tenant_id" premise | Confirmed, line exact | Confirmed |
| IdP-side projection handler never compares the claim | Confirmed (`interfaces/sso/quota.go` `ServeHTTP`: authenticate → machine-claim shape → registry resolve by (clientID, source_system) → body-tenant compare; no claim read) | Confirmed |
| `error-codes.md:137,1014` already document `insufficient_scope` incl. binding causes | Confirmed (137: tenant-quota-projection row "or its exact source binding is unknown/disabled"; 1014: commerce payment row) | Confirmed |
| `quota_relay.go` at 485/500 lines — check must not land there | Confirmed (`wc -l` = 485) | Confirmed |
| Mint side stamps `TenantID: client.TenantID` for client_credentials | Confirmed additionally: `internal/handler/tokengrant/token_client_credentials.go` `Subject{..., TenantID: client.TenantID, ...}` — the claim is the **IdP-side client binding**, which drives the multi-tenant relay constraint in §4 | Confirmed |

### 1.1 Nuances the requirements spec glosses over (design decisions in §3)

1. **`Resolve` never returns `(nil, nil)`.** `usageledger.SourceResolver.Resolve` (`domains/metering/usageledger/source_binding.go:140-160`) returns `ErrSourceBindingUnauthorized` for unknown/disabled/ambiguous clients — there is no "no binding" success branch. The requirements' R2.1 "`b == nil` → no gate" is therefore implemented as the *error branch* (`errors.Is(err, ErrSourceBindingUnauthorized)`), and the pass-through carve-out applies **only to admin routes** (payment/metering already deny unbound clients with their existing shapes — see §3.2.2/§3.2.3).
2. **Metering's existing binding-denial shape differs from its scope-denial shape.** `interfaces/metering/auth.go:30-31` denies unknown bindings with body code `metering_source_unauthorized` (challenge `insufficient_scope`) — a distinct observable class. To satisfy the no-oracle requirement (R2.3), the drift denial on metering routes must use the **scope-denial shape** (`rejectMachine(403, ErrorInsufficientScope, ErrorInsufficientScope, requiredScope)`), which is a different call than the binding-denial shape. The gate order below makes this byte-identical by construction.
3. **The relay cross-check makes a shared multi-tenant relay client non-viable.** `client_credentials` mints `tenant_id` = the IdP-side client's single `TenantID`. A relay client serving N tenants today (README quota section: "该 relay 使用单独的 client_credentials 客户端…每租户 source_system 由前缀+租户 ID 派生") can match at most one tenant under T-8(e); a client with no IdP tenant binding mints no claim at all → every delivery pauses (fail-closed on absence). The migration must include per-tenant relay clients (§5) and the README quota section must be updated alongside R5.1.
4. **Admin-gate resolver store outage is new surface.** Admin routes never touch the binding store today. The fail-open-with-log decision (AGENTS.md §3 fail-open list: tenant-suspension lookup outage) and its pin test are design additions beyond R2 (A11).

## 2. Design overview

One additive projection + three fail-closed consumption points + docs, all internal to the Go tree:

```text
B4-1 mint (unchanged)                    billing consumption (this change)
┌────────────────────────┐      ┌─────────────────────────────────────────────┐
│ buildAccessPayload     │      │ rs.Claims.TenantID/Roles + HasTenantID      │  R1 (projection)
│  tenant_id=client.     │─────▶│   (JWT + introspection, serving_region      │
│  TenantID, roles       │      │    precedent; additive, no config)          │
└────────────────────────┘      ├─────────────────────────────────────────────┤
                                │ admin gate    (auth.go)        R2.1/R2.2    │
                                │ payment gates (payment_ingest.go) R2.1      │
                                │ metering gate (interfaces/metering) R2.1    │
                                │ relay delivery (quotaprojection             │
                                │   http_client.go authorization) R3          │
                                └─────────────────────────────────────────────┘
```

- **Fail-closed spine**: wherever billing's source-binding store holds a binding for `claims.ClientID`, the token's `tenant_id` claim must be present and equal to the binding tenant; absence and mismatch are the same denial. Where billing holds no binding (admin routes only — see §1.1.1), behavior is byte-identical to today.
- **No-oracle**: every drift denial is emitted through the route's existing rejection writer with the exact arguments its scope denial uses — same status/body/headers/challenge, byte-identical by construction; nothing tenant-specific crosses any wire; audit behavior is unchanged (payment's `observe` already records `ErrorInsufficientScope` for both classes; admin/metering gate denials are unrecorded, as today).
- **Zero new surface**: no config keys, no `Err*`, no endpoints, no OpenAPI rows, no audit event types, no mint-side changes, no `rs.Config` gate (the tenant expectation is per-client/dynamic, so the gate belongs to billing, not the shared RS).

## 3. Concrete changes

### 3.1 R1 — rs claims projection (`interfaces/ssoclient/rs/claims.go`)

- `Claims` gains `TenantID string` and `Roles []string` (fields placed after `ServingRegion`, before `RenewAfter`; doc comments state they are the RFC 9068 mint-time binding claims, echoed by introspection, empty when the AS didn't mint them).
- `wireClaims` gains `TenantID string \`json:"tenant_id"\`` and `Roles []string \`json:"roles"\`` (tags are literals, mirroring the `serving_region` tag; no `omitempty` — decode treats absence as zero value).
- `parseClaims` projects both into the returned `Claims`. `Roles` needs no defensive copy: `json.Unmarshal` allocates fresh slices per decode (the issue_payload.go:86-87 guard+copy discipline applies at mint; decode-side projection cannot alias a caller-owned slice).
- `Claims` gains `HasTenantID() bool` mirroring `HasServingRegion()`: `c != nil && c.TenantID != ""`. Tenant IDs are non-empty by construction (binding identity validation), so presence == non-empty.
- `wireIntrospection` embeds `wireClaims`, so the introspection path projects both claims with **zero extra code**; `validateClaims`/`validateIntrospectedClaims` are untouched (no rs.Config gate — §2).
- File impact: `claims.go` 191 → ~210 lines; all 8 existing rs test files untouched and green (A1).

### 3.2 R2 — billing resource-server drift gate

Rule for every billing protected route family: let `b, err := resolver.Resolve(ctx, claims.ClientID)`.

- `errors.Is(err, ErrSourceBindingUnauthorized)` (unbound/disabled/ambiguous): admin routes pass (carve-out, today's behavior); payment/metering routes deny with their existing shapes (unchanged).
- other error (store outage): admin routes **fail open with a log line** (new; decision 4 in §1.1); payment/metering keep today's 503 (`ErrorUnavailable`/`ErrorUnavailable`).
- binding resolved: require `claims.HasTenantID() && claims.TenantID == b.TenantID`; otherwise deny with the **scope-denial shape** of the route family.

#### 3.2.1 Admin routes (`cmd/snaplink-billing/auth.go`)

Wiring: the resolver is `services.sources` (`*ledger.SourceResolver`), already built in `buildDomainServices` and available at `mountCommerceAPI` (`paymentSources` param, `app.go:188-189`).

- Add to `auth.go` a minimal interface (implementation-side guard, per AGENTS.md §4: guards live with implementations):

```go
// tenantResolver resolves a client's server-owned source binding; nil-safe
// implementations return ErrSourceBindingUnauthorized for unbound clients.
type tenantResolver interface {
    Resolve(context.Context, string) (*ledger.SourceBinding, error)
}
```

- Change `newAdminContractRouter(inner core.Router) (*contractRouter, error)` → `newAdminContractRouter(inner core.Router, resolve tenantResolver) (*contractRouter, error)`; store `resolve` on `contractRouter` and pass it through `register` → `adminScopeGate(scope, resolve)`.
- `adminScopeGate` (auth.go:159-168) becomes:

```go
func adminScopeGate(required string, resolve tenantResolver) core.MiddlewareFunc {
    return func(ctx core.HandlerContext) {
        claims, ok := rs.ClaimsFromContext(ctx.Request().Context())
        if !ok || claims == nil {
            writeScopeFailure(ctx, http.StatusUnauthorized, core.ErrInvalidToken, "")
            return
        }
        if !matchesRequiredScope(claims, required) {
            writeScopeFailure(ctx, http.StatusForbidden, commercehttp.ErrorInsufficientScope, required)
            return
        }
        if !adminTenantBindingMatches(ctx, claims, resolve) {
            writeScopeFailure(ctx, http.StatusForbidden, commercehttp.ErrorInsufficientScope, required)
        }
    }
}
```

with a new extracted helper (keeps the gate ≤50 lines and gives the fail-open decision one home). `core.HandlerContext` exposes no logger, so the helper logs through a package-level `*log.Logger` mirroring the module's stderr style (main.go/relay.go build `log.New(os.Stderr, programName+": ", 0)`); the log is incidental to the decision and tests assert the pass-through, not the line:

```go
// adminGateLog mirrors the module's stderr logger style (see relay.go).
var adminGateLog = log.New(os.Stderr, programName+": ", 0)

// adminTenantBindingMatches applies the fail-closed drift gate to admin
// routes: a client billing holds a binding expectation for must present a
// tenant_id claim equal to that binding. Unbound clients (the single-tenant
// carve-out) pass; a binding-store outage fails OPEN with a log (availability
// precedent: tenant-suspension lookup outage) — the gate detects drift, it is
// not an availability oracle. The denial itself is byte-identical to the
// scope denial above (same writer, same args) so it never becomes one either.
func adminTenantBindingMatches(ctx core.HandlerContext, claims *rs.Claims, resolve tenantResolver) bool {
    if resolve == nil || claims == nil || claims.ClientID == "" {
        return true
    }
    binding, err := resolve(ctx.Request().Context(), claims.ClientID)
    if errors.Is(err, ledger.ErrSourceBindingUnauthorized) {
        return true // unbound: no binding expectation, no tenant gate
    }
    if err != nil {
        adminGateLog.Printf("admin tenant gate resolver error (fail open): %v", err)
        return true
    }
    return claims.HasTenantID() && claims.TenantID == binding.TenantID
}
```

- Call-site updates: `app.go:197` passes `services.sources`; the 4 existing `auth_test.go` call sites pass a shared memory resolver helper (`ledger.NewSourceResolver(ledger.NewMemoryStore())` — no bindings seeded, so all existing tests keep their exact expectations; `serveWithClaims` uses `ClientID: "console"` → unbound → carve-out pass).

#### 3.2.2 Payment routes (`interfaces/commerce/payment_ingest.go`)

Both binding gates already hold the resolved binding — one added condition each, inside the existing rejection OR:

- `paymentSourceProvider` (157-169): add `!claims.HasTenantID() || claims.TenantID != binding.TenantID` to the failure OR → existing `rejectPaymentOrderRead` (unchanged, already `ErrorInsufficientScope`, `observe` already records `ErrorInsufficientScope` — audit identical for both classes).
- `paymentSourceEvidence` (189-196): same added condition → existing `rejectPaymentSource`.

#### 3.2.3 Metering routes (`interfaces/metering/auth.go`)

In `authorize` (15-31), after the successful `Resolve` and before `ctx.Set(bindingContextKey, binding)`:

```go
// Drift gate (fail-closed): the token's mint-time tenant binding must equal
// the server-owned binding. Missing claim == mismatch. Emitted with the
// SCOPE-denial shape (not metering_source_unauthorized) so a drifted client
// is byte-indistinguishable from a scope denial (binding causes hidden).
if !claims.HasTenantID() || claims.TenantID != binding.TenantID {
    rejectMachine(ctx, http.StatusForbidden, ErrorInsufficientScope, ErrorInsufficientScope, requiredScope)
    return
}
```

Placement after resolve is load-bearing: it preserves the unbound-client shape (`metering_source_unauthorized`, as today) and the store-outage shape (503, as today) — only the binding-present drift class changes, and it takes the scope-denial bytes.

### 3.3 R3 — quota relay delivery cross-check (`interfaces/ssoclient/quotaprojection/http_client.go`)

New unexported helpers in `http_client.go` (199 → ~225 lines; `quota_relay.go` untouched at 485/500):

```go
// verifyBearerTenant fails closed when the bearer token does not carry a
// tenant_id claim equal to the outbox event tenant. The token was minted by
// the IdP over the trusted token endpoint moments ago, so a payload-only
// decode suffices: any parse failure is a mismatch, never a pass, and the
// token's signature is verified by the IdP on the receiving end anyway.
func verifyBearerTenant(bearerToken, tenantID string) error {
    payload, ok := jwsPayload(bearerToken)
    if !ok {
        return ErrAuthorizationRejected
    }
    var claims struct {
        TenantID string `json:"tenant_id"`
    }
    if err := json.Unmarshal(payload, &claims); err != nil || claims.TenantID != tenantID {
        return ErrAuthorizationRejected
    }
    return nil
}

// jwsPayload extracts and base64url-decodes the payload segment of a compact
// JWS (RFC 7515 §2). Only shape is checked here — verification is the
// receiver's job.
func jwsPayload(token string) ([]byte, bool) {
    segments := strings.Split(token, ".")
    if len(segments) != 3 {
        return nil, false
    }
    payload, err := base64.RawURLEncoding.DecodeString(segments[1])
    if err != nil {
        return nil, false
    }
    return payload, true
}
```

In `authorization` (http_client.go:138-146), after the existing tenant/source/token sanity checks and before returning:

```go
if err := verifyBearerTenant(authorization.BearerToken, tenantID); err != nil {
    return Authorization{}, err // ErrAuthorizationRejected
}
```

Why this seam: `Publish` (http_client.go:102) is the only caller; `HTTPClient` is the production delivery path (`buildQuotaRelay`, quota_relay.go:308) and the same object the T-8(e) e2e drives — the e2e therefore exercises the production check. `ErrAuthorizationRejected` is already the relay's bounded-retry class: `classifyPublishError` (relay.go:237-240) maps it to `reasonAuthorization` + pause, the event stays in the durable outbox with a jittered backoff (`relay.go:189,250-259`), never dropped. `quotaAuthorizer` stays unchanged (R3.2). A 401/403 from the IdP already joins the same class (`decodeProjectionReceipt`, http_client.go:163), so a drifted delivery is indistinguishable from an IdP-side rejection — by construction.

### 3.4 R4 — billing-side claim pin (`cmd/snaplink-billing/claims_pin_test.go`)

New test (package `main`; test-only import of `defaultimpl` issuer is permitted): mint via `issuer.Issue(ctx, &core.Subject{ClientID: "billing-relay", TenantID: <binding tenant>, Roles: [...]}, scopes)` — the same subject shape the IdP's client_credentials handler stamps — then:

1. raw JWS payload decode asserts wire `tenant_id` == binding tenant and `roles` present;
2. `rs.ValidateToken` (JWKS from the same issuer) or the protected chain yields `Claims.TenantID == <binding tenant>` and `len(Claims.Roles) > 0`;
3. a subject without `TenantID`/`Roles` yields zero values through the same path (R1.2 byte-identical carve-out).

### 3.5 R5 — documentation (same change)

- `cmd/snaplink-billing/README.md:170-172`: replace the "当前 … 不携带 tenant_id claim" workaround with the claim-verified description (mint-time claim consumed fail-closed; IdP client bindings and billing's source-binding store must stay mirrored; mismatch/absence → existing `insufficient_scope`/retry semantics, causes hidden).
- `cmd/snaplink-billing/README.md` quota section (~185-190): add the per-client constraint — a quota relay client's IdP-side tenant binding determines which tenant it can deliver for; multi-tenant deployments register one client per tenant (decision 3, §1.1).
- `infrastructure/auditgovernance/oauth_token_source.go:44-46`: comment-only correction — the cache stays per-client by design; consumers must verify the mint-time claim at consumption time.
- `docs/error-codes.md:137,1014`: add a clause to the two existing `insufficient_scope` rows ("or the token's mint-time tenant binding contradicts the server-owned binding"); no new row, no new `Err*`.

## 4. Compatibility constraints

| Constraint | Consequence |
|---|---|
| **Sequencing vs B4-1 mint** | The gates are always-on with no kill switch (R2's "no new config knob"). Shipping them before the IdP fleet stamps `tenant_id` denies every bound-client machine route (absent claim) and pauses every quota delivery. Deployment order: IdP mint live first (or same window), billing consumption second. Tokens minted by pre-B4-1 nodes during a rolling upgrade carry no claim → denied until expiry (short TTL) — the window is bounded by token TTL. |
| **rs projection is deployment-independent** | R1 is additive (new fields, zero behavior change, no config); it can ship ahead of everything and roll back freely. |
| **Single-tenant carve-out preserved** | Admin routes for clients with no billing-side binding: byte-identical to today (A5). Payment/metering unbound clients: unchanged (already denied with their existing shapes). |
| **Shared multi-tenant quota relay client breaks** | The claim is the IdP client's single tenant; deliveries for any other tenant pause with `reasonAuthorization`. Operators must register one relay client per tenant (or accept single-tenant relay). This is the only behavior regression for existing deployments, and it is exactly the drift the direction intends to make undeliverable. |
| **`OAuthTokenSource` cache staleness** | The relay's cached token (per-client, default TTL 1h) may carry a stale `tenant_id` after an IdP re-bind; the cross-check rejects and the relay's bounded backoff delivers after refresh. Documented limitation, not fixed here (R3.3). |
| **rs tests stay untouched** | All 8 existing `interfaces/ssoclient/rs` test files compile and pass unmodified (A1). Billing test files: 4 mechanical call-site updates for `newAdminContractRouter` + new tests; `serveWithClaims` fixtures unaffected (carve-out). |
| **No wire/API surface change** | No HTTP routes, OpenAPI rows, config keys, error codes, or audit event types; `interfaces/sso/quota.go` untouched (IdP-side claim check is a separate direction, explicit non-goal). |
| **Import discipline** | No new packages; `rs`/`quotaprojection` stay in `interfaces`; `auth.go` imports `domains/metering/usageledger` (allowed: composition → domains → shared flow); no import toward `cmd/`. |

## 5. Failure modes

| # | Failure | Behavior | Recovery |
|---|---|---|---|
| F1 | IdP fleet not yet at B4-1 (claim absent for bound clients) | All bound-client machine routes: 403 `insufficient_scope`; quota relay pauses (`reasonAuthorization`); audit relay unaffected | Ship in G5 order (§6); rollback = revert the R2/R3 commit (outbox retained — zero data loss) |
| F2 | IdP re-binds client to tenant B; billing store says A | Admin/payment/metering A-family routes: byte-identical 403 `insufficient_scope`; relay: 0 delivered for A events, bounded retry | Operator reconciles: correct the IdP client binding or update billing's source-bindings file (cold restart); relay converges after retry/cache refresh |
| F3 | Billing bound a client the IdP never bound (claim absent) | Same as F2 (fail-closed on absence — the class the claim exists to close) | Register the IdP-side binding |
| F4 | Billing binding-store outage on admin routes | Admin: fail open with log (new decision, A11); payment/metering: 503 as today | Store health; no new denial class on admin |
| F5 | Cached relay token carries stale tenant_id (TTL window) | Cross-check rejects; `reasonAuthorization` bounded retry; event retained | Automatic after token refresh (≤ TTL); no operator action |
| F6 | Relay token not a compact JWS / payload undecodable | `verifyBearerTenant` fails closed → `ErrAuthorizationRejected` → retry, no PUT | If persistent: token endpoint/credential misconfiguration; visible in delivery retry logs |
| F7 | Oracle leak attempt | Drift denial bytes == scope-denial bytes on the same route (same writer, same args); relay mismatch == IdP 401/403 class; no tenant value in body/headers/challenge/audit | By construction; pinned by A3/A6/A12 byte-equality assertions |
| F8 | Concurrent relay replicas | Unchanged: store claim/lease semantics (`SKIP LOCKED`, lease fencing) govern; the cross-check is inside `Publish`, after claim | Existing behavior |

## 6. Migration steps

1. **Land R1** (rs projection + A1/A2 tests) — independent, deployable alone, zero behavior change.
2. **Confirm mint prerequisite**: IdP fleet at B4-1; campaign T-8(a)/T-1.2 mint pin green (`docs/campaigns/implementation-gate.md` G1/G5 rows). This consumption work lands in the **G5 slot** (T-2, T-8(b–e), T-9), never before.
3. **Operator pre-flight (before deploying R2/R3)**: for each quota relay client, ensure the IdP-side client record has a tenant binding equal to the tenant(s) it serves; multi-tenant deployments register one relay client per tenant (§4). Verify billing's `source-bindings.example.json`/config mirrors the IdP bindings.
4. **Land R2+R3+R4+R5** in one change: gates, relay check, pin tests, e2e fixture update (T-8(e)), README/comment/error-codes doc updates.
5. **Post-deploy verification**: machine routes still 200 for matching clients; quota relay delivers (revision advances); `readyz` green; no new `reasonAuthorization` pauses beyond the F5 window; admin fail-open logs absent during healthy operation.
6. **Rollback**: revert the R2/R3 commit; R1 may stay. Outbox events were retained throughout — no replay or backfill needed.

## 7. Testable acceptance mapping

| # | Acceptance (from requirements) | Design → test |
|---|---|---|
| A1 | rs suite green with zero test-file modifications | R1.1/R1.2 → `go test ./interfaces/ssoclient/rs/...` unmodified |
| A2 | new `claims_test.go`: JWT + introspection decode with/without `tenant_id`/`roles`; `HasTenantID()` false on absence | R1.3 → new `interfaces/ssoclient/rs/claims_test.go` |
| A3 | admin route, binding `{billing-relay, tenant-a}`, claim `tenant-b` → 403, body exactly `{"error":"insufficient_scope"}`, recorded response byte-equal to same-route scope denial, no tenant literal | R2.2 → `cmd/snaplink-billing/tenant_gate_test.go` (seeded memory store via `applySourceBindings`-equivalent + `serveWithClaims` seam; record both responses and byte-compare) |
| A4 | same binding, claim absent → same byte-identical denial (fail-closed) | R2.2 → same test file |
| A5 | no binding, with/without claim → unchanged (scope grant still 200) | R2.1 carve-out → same test file (pin both claim states) |
| A6 | payment family three-case matrix; response-shape assertions repeat for one payment route | R2.2 → `interfaces/commerce/payments_test.go` (or billing e2e-level) — matching passes; mismatched/absent → byte-equal to `rejectPaymentOrderRead` scope denial; unbound unchanged |
| A7 | e2e token gains `Subject.TenantID: "tenant-e2e"`; positive path delivers exactly as today | R3 → `test/quota_projection_e2e_test.go` fixture parametrized by minted `TenantID` |
| A8 | token `TenantID` ≠ event tenant → `RunOnce` delivers 0, IdP quota store untouched, event retained (not consumed/dead-lettered) | R3 → same e2e, negative case (assert store revision unchanged + event attempts incremented/retry scheduled) |
| A9 | token without `TenantID` → same no-delivery outcome | R3 → same e2e, absence case |
| A10 | billing unit test drives the production seam: mismatch/absence → `ErrAuthorizationRejected`; match → accepted | R3.2 → new `cmd/snaplink-billing/tenant_claim_relay_test.go`: real `quotaprojection.HTTPClient` + `quotaAuthorizer` with a stub `ClientCredentialsTokenSource` minting chosen-claim tokens (httptest IdP or payload-only asserted) |
| A11 | *(design addition)* admin gate binding-store error → fail open with log, route passes | §3.2.1 → `tenant_gate_test.go`: resolver stub returning a non-unauthorized error → 200 |
| A12 | *(design addition)* metering family three-case matrix; drift denial byte-equal to metering scope denial (not `metering_source_unauthorized`) | §3.2.3 → `interfaces/metering` test: matching passes; mismatched/absent → recorded response equals scope-denial record; unbound keeps `metering_source_unauthorized` |
| R4 | billing-side claim pin: wire `tenant_id`/`roles` + rs projection; absent → zero values | §3.4 → `cmd/snaplink-billing/claims_pin_test.go` |

Campaign mapping (per requirements §7): T-2 → R4/A3/A4; "new billing test" → A3/A6; T-8(e) → A7/A8/A9/A10; byte-identical-absent → A1/A2.

## 8. Engineering gates

- Budgets: `quota_relay.go` untouched (485/500). `auth.go` 194 → ~215 (gate helper extracted; `adminScopeGate` stays ≤50). `claims.go` 191 → ~210. `http_client.go` 199 → ~225. `interfaces/metering/auth.go` `authorize` gains 5 lines (≤50). No directory/fan-out changes (`quotaprojection` 5 → 5 non-test files; `rs` untouched file count).
- After every `.go` edit: `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .`
- Targeted: `go test ./interfaces/ssoclient/rs/... ./interfaces/ssoclient/quotaprojection/... ./interfaces/commerce/... ./interfaces/metering/... ./cmd/snaplink-billing/...`
- Cross-server: `go test ./test/ -run 'TestE2E' -v` (T-8(e) negative cases included)
- Handoff: `go test ./... -race`; `make ci` (no nested-module/profile/manifest change).
- Oracle-safety review (AGENTS.md §3): byte-identical writers (A3/A6/A12 byte-equality pins); relay collapse into `ErrAuthorizationRejected` (A10); no tenant detail on any wire; no new audit distinction.
