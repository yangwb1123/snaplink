All four review targets are now verified against HEAD. Here is the adversarial review.

---

# Adversarial review: oracle-safe denial matrix and trust decisions

## 1. A11 admin fail-open on binding-store outage — verdict: **keep fail-open, but fix two factual defects and harden the log**

### 1a. Fail-open vs fail-closed: the design's choice is the coherent one

**AGENTS.md classification.** The fail-open list explicitly names "tenant-suspension lookup outage" — a server-owned tenant-state lookup whose outage blocks otherwise-valid requests. The drift gate's `Resolve` is the same structural class, and the design's citation is letter-exact. The fail-closed list ("signatures/validation") does **not** cover this: the RS's cryptographic gates (issuer/aud/exp/signature, `rs.go`/`validateClaims`) run independently of the binding store and keep failing closed during an outage. The drift gate is a two-party consistency cross-check, not claim validation — the claim was already signature-validated.

**Fail-closed-for-tenant-bearing is incoherent — this is the decisive argument.** The proposed variant would deny claim-bearing tokens during an outage while the helper's error branch (`err != nil → return true`) still passes claim-less tokens. That *inverts* the fail-closed spine (absence == mismatch == deny): absence would become *less* strict than presence, and the outage behavior would depend on the IdP's mint state (pre-B4-1 tokens pass, post-B4-1 tokens deny). The only coherent alternatives are fail-open-for-all (design) or fail-closed-for-all. Fail-closed-for-all turns the **usage** ledger store into a hard availability dependency of admin routes that read only the **commerce** store (plans/subscriptions/wallet/ledger, `interfaces/commerce/api.go:52-67`) — a new outage surface with no security gain, since a drifted client during outage gets exactly today's (status-quo-ante) behavior on a route family that is client-hygiene-gated, not tenant-scoped.

**Blast radius is bounded.** During the same outage, the data plane stays closed: metering `authorize` returns 503 (`auth.go:35-38`), and payment returns 403 via the existing failure OR (`payment_ingest.go:157-169`). The material harm the claim exists to close — tenant-scoped data access — is still blocked; only the admin surface opens.

**But the design misstates the payment behavior — fix F4/§3.2.** Verified: `paymentSourceProvider` treats `err != nil` inside the same OR as every other binding failure → `rejectPaymentOrderRead` → **403 `insufficient_scope`**, not 503. Only metering returns 503. The matrix rows (F4, §3.2 bullet 2) saying "payment/metering keep today's 503" are wrong for payment. This matters for the argument: payment already fails closed with the scope-denial bytes on store outage, so admin is the *only* family needing the availability carve-out, and the design's own rationale should say so. Bonus: payment's store-outage 403 is byte-identical to the drift denial, so the outage class was already collapsed before this change.

### 1b. `adminGateLog` — no wire leak, but three hardening requirements

- **Class/timing exposure is operator-side only.** The line reveals "binding-store outage + admin traffic flowing" to stderr readers; it is never wire-visible, and the gate's denial/pass bytes are unchanged. AGENTS.md *mandates* logging on fail-open ("Fail open with audit/logging"), so the line is the required audit trail, not a leak.
- **No tenant/client identifiers in the formatted error — verified.** `Resolve` returns the raw store error; the postgres wrap is `fmt.Errorf("usageledger/postgres: list source bindings: %w", err)` (`bindings.go:101`) — no client ID; `MemoryStore` returns only `ctx.Err()`. `%v` is currently identifier-free. Still, pin it: log a static message and drop `%v`, or add an A11 assertion that the captured log line contains no `client_id`/`tenant_id` substring.
- **Per-request logging is log amplification.** Any valid admin-token holder can force one stderr line per request during an outage, and the line stream becomes a request-rate fingerprint of the outage. Replace with windowed/rate-limited logging (one line per outage epoch + rate counter). This preserves the AGENTS.md-mandated record without amplification.
- **Test hygiene:** `adminGateLog` is a package var; A11's fail-open test will print to test stderr. Redirect it to `io.Discard` in the test and restore after.

**Ops note (not a leak):** the drift check adds a usage-store round-trip to *every* admin request, including the happy path — a new latency/availability dependency on a store admin routes never touched before. The fail-open preserves correctness during outage, but a slow-failing pool (not a refused connection) will add seconds per admin request. Consider a short bounded-timeout resolver wrapper or a degraded-readiness flag; at minimum, document the latency budget in §3.2.1.

## 2. R3 `jwsPayload`/`verifyBearerTenant` — **sound; both claims verified**

**No attacker-controlled token can reach `verifyBearerTenant`.** Verified the complete provenance chain:
- `c.authorization` has exactly one caller in the package: `Publish` (`http_client.go:102`; grep confirms no other call site).
- The token is produced only by `authorizer.Authorize` → billing's `quotaAuthorizer` (`quota_relay.go:434-453`) → `OAuthTokenSource.AccessToken` (`oauth_token_source.go`), which returns the cached value or a fresh `fetchToken` POST to the operator-configured token endpoint (`secureEndpoint` enforces https except dev loopback). The outbox event contributes only `TenantID` (used as the *comparison value*) and a `SourceSystem` derived from the prefix and validated locally via `TenantSourceID`; no `OutboxEvent` field can influence `BearerToken`. The only `Authorizer` implementation in the repo is `quotaAuthorizer` (the e2e and billing tests drive the same production `HTTPClient`), so a malicious authorizer requires operator code — out of threat model.
- **Defense in depth confirmed:** the receiving IdP verifies the signature (`quota.go` `authenticate` → `validateAnyToken`), so even a hypothetically forged payload is rejected at the IdP with 401 → `decodeProjectionReceipt` → `ErrAuthorizationRejected` — the same class, same bounded retry. Payload-only decode is sound *given provenance*.
- **absence == mismatch holds exactly.** `validateDelivery` runs before `authorization` and `ValidateQuotaTenantID` rejects `""` and whitespace (`tenant_user.go:238-242`), so the comparison value is always non-empty; a token without the claim yields `"" != tenantID` → identical `ErrAuthorizationRejected`. Shape checks are fail-closed for non-compact (≠3 segments), padded, or undecodable payloads — matching the mint's `base64.RawURLEncoding` (`issue_payload.go` `writeB64Segment`).

**Residual notes (non-blocking):**
- `json.Unmarshal` last-key-wins on a duplicated `tenant_id` is unreachable: the mint emits a single struct and `claimsWithoutEmittedKeys` strips the attribute-bag duplicate. A one-line comment would close the question.
- The check runs *before* the PUT, so drifted events never reach the IdP — the IdP audit stream will simply lack projection events for that client. That is the intended effect; the durable record is the outbox failure reason `reasonAuthorization`, which is a pre-existing class shared with IdP 401/403s (`relay.go:237-240`), so no new observable class is created.
- **Coverage gap worth an explicit line:** the retention-projection path (`PlatformTokenSource` → Audit Governance) is a separate token source and is *not* subject to the cross-check. It is plausibly out of scope (its tenant authority is the Audit Governance service's own registry, and the retention relay validates the entitlement snapshot against the event tenant in `commercialRetentionPolicy`), but the design should state this explicitly instead of leaving the seam implied.
- F5 (stale cache) is correctly bounded by TTL/refresh skew (`cacheToken`), and the e2e fixture at HEAD mints *without* `TenantID` (`test/quota_projection_e2e_test.go` ~line 68) — confirming that the A7 fixture change is load-bearing and R3 must not ship before the mint is live (the design's G5 sequencing is correct and verified).

## 3. Residual information channels — two real defects found

### 3a. error-codes.md clause targets are wrong: 137 is the wrong row; 1086 is missing

- **Row 137 is the SSO projection-ingress row** ("Tenant quota projection ingress", `PUT /api/v1/internal/tenant-quota/projection`). Verified: `interfaces/sso/quota.go` `ServeHTTP` authenticates → machine-claims → registry resolve → body-tenant compare; the token's `tenant_id` claim is **never read**. Adding "or the token's mint-time tenant binding contradicts the server-owned binding" to row 137 documents a cause that *cannot occur at that endpoint* — a factual error in a public contract doc that would mislead operators into believing the ingress performs a claim cross-check it does not. **Drop 137 from the clause plan.**
- **Row 1086 (metering `insufficient_scope`) is missing from the plan.** The metering drift denial emits exactly `insufficient_scope` (`auth.go:23-26` shape), and the metering row documents only "not a client-credentials identity or lacks the route's exact scope". After R2, that row is inaccurate public contract. **Add the clause to 1086 and to 1014** (1014 is correctly targeted — payment).
- Disclosure-class check: the rows already name binding causes ("its exact source binding is unknown/disabled", "individual mismatch causes are intentionally hidden"), so the clause is the same disclosure class; it names the drift cause publicly but the wire bytes stay identical. Acceptable; keep the clause minimal and accurate.

### 3b. Payment `observe()` — audit class is byte-identical; one precision fix

Verified: the drift condition joins the *existing* failure OR in `paymentSourceProvider`/`paymentSourceEvidence`, so both drift and binding denials flow through the same `rejectPaymentOrderRead`/`rejectPaymentSource` → same `MutationRecord` args (Operation/TenantID/ResourceType/ResourceID/Outcome/ErrorCode — no timing/attempt fields, `deps.go:79-86`) → byte-identical audit. **However**, in production billing no `MutationObserver` is wired (`app.go:191-196` leaves `Deps.Observer` nil), so *no* payment denial is audited in production either way; the design's "payment's observe already records `ErrorInsufficientScope` for both classes" is only true where an observer exists (tests). Harmless, but state it precisely: the invariant is "no new audit event type, error code, or record shape", which holds. Metering drift denials are unrecorded at `authorize` level — consistent with today's metering scope denials.

### 3c. Timing/ordering — exists, reveals nothing beyond the status code

Scope denial precedes `Resolve`; drift denial follows it (admin + metering; payment's drift denial joins the existing post-resolve OR, so it has today's binding-denial latency). The only measurer is a holder of a valid, scope-sufficient token — who already knows their own scope and claim, and can therefore infer "binding mismatch" from the 403 alone. The timing channel adds zero information beyond the status code, and the 200-vs-403 split is the gate's designed behavior. The one *new* artifact is the per-request store lookup on all admin requests (see §1b ops note) — availability, not an oracle. A12's three-case matrix already pins the ordering; consider also asserting that the drift denial happens without reading any path tenant (it does — the gate runs before `ctx.Set(bindingContextKey, …)` and any handler tenant read).

## 4. Tenant literals in denials — clean, with one confirmation

- **Admin:** `writeScopeFailure` emits body `{"error":"insufficient_scope"}` and challenge `Bearer realm="billing", error=insufficient_scope[, scope=<required>]` plus no-store/pragma; the drift helper takes no tenant argument and formats no tenant into the log (verified error shapes, §1b). Byte-identical to the scope denial by construction (same writer, same args).
- **Payment:** `rejectPaymentMachine` — realm `billing`, no tenant; the `observe` record's TenantID is the client-supplied path param, pre-existing and identical for today's binding denials.
- **Metering:** the drift gate emits `rejectMachine(403, ErrorInsufficientScope, ErrorInsufficientScope, requiredScope)` — realm `metering`, no tenant, no source system, no binding id. Ordering verified against `auth.go:15-38`: claims → subject/scope → resolve → **[new drift gate]** → `ctx.Set`. Placement after resolve-success is load-bearing and correct: unbound keeps `metering_source_unauthorized`, outage keeps 503, drift takes the scope-denial bytes. All five metering routes go through `authorize` (`api.go:46-52`), so coverage is uniform.
- **Relay:** no denial body exists; the outbox reason is the pre-existing `reasonAuthorization` class.

One addition to the test plan: A11 should assert not only the 200 pass-through but also that the captured log line contains neither `client_id` nor `tenant_id` substrings — that is the cheapest possible pin on the only server-side record the new decision produces.

## Summary of required changes

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | F4/§3.2 wrongly state payment returns 503 on store outage; it returns 403 `insufficient_scope` via the existing OR | Medium (factual, weakens the fail-open rationale) | Correct the matrix; use it as evidence that admin is the only family needing the carve-out |
| 2 | error-codes clause targets row 137 (SSO ingress — drift check never runs there); misses row 1086 (metering) | High (public-contract accuracy) | Drop 137; add clause to 1014 and 1086 |
| 3 | `adminGateLog` per-request logging is amplification + outage fingerprint; `%v` of raw store error unpinned | Medium | Windowed/rate-limited logging; static message (or A11 identifier-freedom assertion); test redirects logger |
| 4 | Fail-closed-for-tenant-bearing would invert absence==mismatch during outages | Design decision | Keep fail-open; document the inversion argument in §3.2.1 (currently only the suspension precedent is cited) |
| 5 | "observe already records for both classes" is test-only true (no production observer wired) | Low | Rephrase to the real invariant: no new event type/error code/record shape |
| 6 | Retention-projection token path not covered by R3 cross-check | Low | One explicit out-of-scope line in §3.3 |
| 7 | Per-request store lookup on all admin requests (latency/availability) | Low (ops) | Note bounded-timeout/cached-resolver option in §3.2.1 |

Net verdict: the design's fail-open decision survives adversarial review — it is AGENTS.md-consistent (tenant-suspension precedent), coherent (fail-closed-for-tenant-bearing inverts the fail-closed spine), and bounded (data plane stays closed during the same outage); the `jwsPayload` cross-check is provenance-sound and absence==mismatch holds exactly; no tenant literal can reach any denial body/header/challenge; and the residual channels found are two doc-target defects (137 wrong, 1086 missing), one matrix fact error (payment 503), and three hardening items on the fail-open log.
