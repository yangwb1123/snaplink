Every finding is resolved with concrete spec text and all citations re-verified line-exact. Summary:

## Verdict — revision resolves all open findings

The design doc (`docs/architect-analysis/cmd-snaplink-stripe-adapter-tenant-claim-design.md`, 229→237 lines) was revised and every citation mechanically re-verified against the current tree.

**(a) test_strategy — all three fixed**
- **D1 pin**: new `TestCheckoutUserAcceptsTenantlessConsoleToken` spec'd concretely in §3.4 (4 steps: no-claim mint via `testAdapterHandlerSubjectWithoutTenantClaim(t, store, billing, stripe, "user-one", "console-client", scopeAdminWrite)`; bound input → 201 + `billing.lastBinding.TenantID == "tenant-one"` binding-selected assertion (pattern: http_test.go:116-117); companion `tenant-nowhere` → 403 with challenge **equal to** `Bearer realm="stripe-adapter", error="tenant_mismatch"` — pins `binding == nil` survives; optional 201 byte-compare vs A6) + new **A15 row** in §7 + T-8(b) mapping updated + F1/F6 coverage.
- **A11 aud shape**: §3.5 and the A11 row now assert the **compact string** `aud == "stripe-adapter"` (single-audience scalar, `audClaim.MarshalJSON` ed25519_types.go:141-148) and `got, ok := payload["tenant_id"].(string); ok && got == <seeded>` so a missing claim fails loudly.
- **Citation**: `writeCheckoutChallenge` corrected to **http.go:380-389** (verified: func 380, `writeJSON` call 388, closing brace 389 — one past the reviewer's 380-388; corrected for line-exactness).
- Also: §5 gained a **Pinned-by column** (F1→A9+A15, F2→A4/A6, F3→A8, F6→A9+A15, ops-only scenarios declared), §3.5 cites the existing `TestRefreshRotation_TenantIDPresentRolesAbsent` (139-183) pin, A5/A8 pin the DeepEqual `Code`/`Body.Bytes()`/`Header()`-map mechanism.

**(b) wire_compat — R6 2.1-2.3 and A14 fixed**
- 2.1: §3.6 now states there is **no `insufficient_scope` row** — prose only (1039-1047) — and specs the prose rewrite for the split + machine claim-consistency class.
- 2.2: Forbidden description spec now includes the machine claim-consistency class joining the cause enumeration.
- 2.3: `docs/stripe-payment-adapter.md:37-42` added to R6 scope.
- A14: §3.4/§8 reworded honestly (`model.go:44`'s "repository contract gate" never existed) + concrete gate spec: extend `checks/adapters_check.py` with (a) `kin-openapi validate` over `cmd/*/openapi.yaml` (verified passing at HEAD, exit 0) and (b) exported-const→`| code |`-row assertion. A14 = gate green + const exists + row exists.
- **Discovery during verification**: the working tree *already* carries the R6 contract edits (uncommitted: error-codes.md prose 1039-1047 + `tenant_mismatch` row 1051; openapi.yaml Forbidden 210-227; stripe-payment-adapter.md 39-42). The design now cites the applied text and scopes R6's remainder to verification + the gate + the still-pending checkout-description (20-25) replacement.

**(c) security — all five fixed**
- §3.4: **"STAYS `insufficient_scope`"** with the scope-branch-first reasoning (http_test.go:147-155; `billing:checkout:create` lacks `admin:write`).
- **TTL bound**: "short TTL" replaced with 1h default (`defaultTokenTTL`, issue_payload.go:17-19) + per-client `AccessTokenTTL` override (token_client_credentials.go:53) in §4, F6, §6 step 3.
- **D1 policy carve-out** classification sentence in §3.2 + §8 (not an outage fail-open).
- **A5 claim-bearing-only** scope statement in §2, A5 row, §8.
- **A4 fixture-updated-baseline** parenthetical rewritten (today returns 403 via `binding == nil`; byte-identical post-change).
- Residuals folded in: F1/F6 simultaneity (§1.1/§4), post-mint newly-bound console (§1.1), rollback ordering (§6 step 6), invisible mid-upgrade impact + monitored 403 rate (§6 step 2), UX-mapping residual (§4).

**Citation re-verification**: 60+ checks pass; the revision also corrected pre-existing wrong citations found during the pass (newAdapterHandler 39-65/Config 59-62, validate.go:105-110, introspect 33-66/literal 47-61 + wireIntrospection 71-76, trio 198-233/212-222/224-233, test seam 286-339/279-284, pin tests 172-189/191-199, claimsWithoutEmittedKeys 116-138, wireClaims 93-108, parseClaims 113-136, openapi 166-170, model.go 44-55, validIdentity 362-372, error-codes 1034-1065). Stale-sweep: CLEAN. Docs-only change — no Go gates applicable.
