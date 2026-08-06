I've verified the design's acceptance mapping against the actual repository. Here's the assessment.

## 1. AC-2: in-repo predicate vs the cross-repo 422 gate

**The in-repo predicate (decoded `tenant_id` claim == client-store fixture tenant) is a genuine cross-layer comparison, not a tautology** — the expected value comes from `ClientStore.AddSeed`, the observed value from the wire claim, so the comparison spans the full chain (handler → `Subject` → payload → JWS → decode).

- **Missing claim**: caught — absent/`""` ≠ seeded tenant (e.g. `"acme"`). ✓
- **Misbound wrong value**: caught — `"other"` ≠ `"acme"`. ✓
- **Misbound to request-derived tenant**: caught *only if* the harness's request-context tenant differs from the client's tenant. The default e2e harness wires no tenant middleware (`test/testkit/testkit.go` has no tenant wiring; the resolver only activates with a tenant store, `options_httpstack.go:118-121`), so a request-tenant misbinding yields `""` and fails. But if the test runs in a tenant-mismatched harness where request tenant == client tenant, this specific failure mode is masked. The test should use a client fixture whose tenant differs from any request-derived tenant — that is the strongest in-repo form.

**Without the external gate**: the predicate catches missing/misbound claims, but it cannot execute the sink's 422 gate. That gate is cross-repo by construction (B1-8 sink repo; the direction explicitly excludes sink-repo work). The in-repo relay (`infrastructure/auditgovernance/relay.go:255`) only *classifies* a received 400/422 as `deliveryDead` — it is a consumer of the sink's response, not a producer, so it can't generate the 422. **Verdict: the in-repo predicate is sufficient for missing/misbound claim detection; the "fixture accepted by sink ingest" half of AC-2 is inherently cross-repo evidence.**

## 2. Per-signer fixed-clock tests vs "all 10 mint sites"

**The "covering all 10 mint sites" characterization does not hold for the mapped tests.** I confirmed the 10 sites exactly (8 in `internal/handler/tokengrant` — authcode:125, refresh:278, device:89, ciba:107, jwt_bearer:102, saml2_bearer:110, client_credentials:42, exchange_stages:395 — plus login `server_login.go:118` and native-sso `server_native_sso.go:193`; `server_helpers.go`/`server_oauth.go:197` matches are policy inputs, not mint sites).

The `serving_region_test.go` pattern (`infrastructure/defaultimpl/serving_region_test.go`) is **issuer-level**: it calls `iss.Issue(ctx, &sso.Subject{...})` with a *hand-built Subject* across Ed25519/ECDSA/RSA. It pins the shared `ed25519Payload` emission and Validate round-trip, but covers **zero mint sites**. Only AC-1's e2e contract file exercises the wire path, and the region precedent it mirrors covers ~3–4 of the 10 sites (login direct-mint, `/token` authcode, refresh rotation). The other 6–7 sites' `Client.TenantID → Subject.TenantID` threading is **evidence-only** (requirements-stage code read). This is a bounded residual — the design is emission-only with "zero mint-site changes," so the pre-existing threading is untouched — but if the acceptance stage asserts "tenant_id at all 10 mint sites," that specific claim is not falsifiable by the mapped tests; it needs per-grant wire tests (table-driven over the 8 grants + login + native-sso) or an explicit evidence-only caveat.

**Fixed clocks**: a design addition, not part of the existing pattern (the serving-region tests use no clocks). Implementable — `Clock`/`With*Clock` exist in `issue_payload.go`. Fixed clocks make exp/iat deterministic and support claim-set comparison; note `jti` is random (`ed25519_issue.go:35`), so AC-5's "byte-identical" can only be claim-set-level (key absence + payload diff modulo jti/iat), which the empty-input case achieves.

## 3. ID-token-absent boundary test

**Falsifiable in the correct direction**: it fails on over-inclusion (claims leaking into ID tokens) and passes vacuously when the feature is absent — acceptable, since presence is covered by AC-1/AC-2. Two requirements for it to be actually falsifying:

- **Must be per-signer across all three signers.** `ed25519IDPayload` is shared (`ed25519_types.go:138`), but each `IssueIDToken` assembles it with its own inline literal (`ed25519_issue.go:91`, `ecdsa_issue.go:67`, `rsa_issue.go:58`). The serving-region precedent explicitly pins all three ("per-issuer drift points") — a single-signer absent test would miss an ECDSA/RSA literal leak.
- **Should assert absence both top-level and in `ext`** (ID tokens carry `Extra` there), guarding against a naive implementation stuffing the claim into the extras map.

Structural bonus: the introspection boundary is already safe by enumeration — `populateAccessIntrospectionBody` (`protocols/oauth/introspect_body.go`) copies claims one-by-one, so `TokenClaims` gaining `TenantID`/`Roles` cannot leak into introspection without explicit code. Note this is asymmetric with the region precedent (`populateIntrospectionServingRegion` echoes region); nothing in the mapped acceptance pins introspection absence — that design decision is evidence-only.

## 4. Acceptance items whose tests depend on evidence-only assertions

| Item | Executable part | Evidence-only residual |
|---|---|---|
| **AC-2 (T-1.2)** | In-repo predicate (missing/misbound) | The "no 422" outcome — cross-repo sink gate, unexecutable here; relay only classifies |
| **AC-3 "never Host"** | Discovery half: metadata issuer is Host-derived via `requestBaseURL` (`server_discovery_config.go:62`), so a different-Host e2e **fails pre-change** — genuinely falsifying. Config unit tests (panic on sentinel+allowlist, config-load error) are the falsifiers for the token half | Token-iss half: the e2e harness always sets `WithIssuer` (`testkit.go:136`), so token `iss` == allowlisted value passes **even with no allowlist mechanism at all**. R4 makes the fallback structurally unreachable (allowlist requires non-sentinel issuer), so "never Host" is enforced by construction-time rejection — the discovery extension alone cannot distinguish a working allowlist from a WithIssuer-only build. The empty-mode "byte-identical legacy" also needs a diff/golden test, not just presence |
| **AC-4 (kid)** | Header kid present + equals JWKS kid | Passes before *and* after the change (kid already exists) — regression guard, not a feature falsifier; "unchanged" vs previous release is untestable |
| **AC-5** | omitempty omission + Validate round-trip empty | Release-level byte identity untestable (jti/iat); proxy is sound for an additive-with-omitempty change |
| **All-10-mint-sites breadth** | Only grants exercised by the e2e contract file | Remaining sites' threading rests on the requirements-stage evidence read |
| **Roles absent on client_credentials** (C1) | — | No mapped test pins this boundary; the compile-time guards (`accessors_handlers.go:362-369`) prove interface satisfaction, not claim behavior. If the hook were wrongly added to `ClientCredentialsDeps`, no acceptance test fails. A cheap client-credentials e2e (tenant_id present, roles absent) would close it |

**Two additional test-authoring requirements for the mapped tests to actually falsify:**
- AC-1's roles assertion must **seed** roles via a wired permissions provider (testkit wires none) — otherwise the fail-open seam returns `[]` and the assertion passes vacuously. It must also use an end-user grant (authcode), since client-credentials omits roles by design.
- AC-1's `aud` assertion requires RFC 8707 resource indicators — `Aud` is set only when `Subject.Resources` is non-empty (`applyOptionalClaims`), so a bare authcode token has no `aud` and an unconditional assertion would false-negative.

**Bottom line**: AC-2's in-repo predicate catches missing/misbound claims without the external gate (with the request-tenant-harness caveat); the "per-signer tests cover all 10 mint sites" claim is false — they cover the shared emission path × 3 signers, with at most 3–4 sites exercised end-to-end; the ID-token-absent test is one-directionally falsifiable and must be per-signer; and the genuinely evidence-only items are AC-2's 422 outcome, AC-3's token-iss/"never Host" half (unless the construction/config unit tests are the primary falsifier), the client-credentials roles-absent boundary, and the all-10-sites breadth.
