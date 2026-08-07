Verification complete. All code citations traced against HEAD (`ea351a86`), with behavior confirmed by running the scope gate suites. Findings below.

# Verification report: default-off byte-compatibility claim

## 1. Registry seam — VERIFIED with one mapping caveat

`server_token.go:121-125` is exactly the scope-split preamble of `dispatchTokenGrant`. The seam runs *before* every gate and branch: `denyTokenScopeCombo` (:128), `dispatchCustomGrant`, `checkGrantRateLimit`, then the 7-case switch. All 8 minting branches funnel through it:

| Branch | Scope path | Covered by seam at :121-125 |
|---|---|---|
| authorization_code | split `scopes` → `HandleAuthCodeGrant` | yes |
| refresh_token | raw `req.Scope` → `HandleRefreshGrant` | yes (seam splits/checks it first) |
| device_code | no scope in token request | yes (no-op — scopes come from stored entry) |
| CIBA | no scope in token request | yes (no-op) |
| token_exchange / txn-token | `req.Scope` → exchange request | yes |
| client_credentials | split `scopes` | yes |
| jwt_bearer | split `scopes` | yes |
| **saml2_bearer** | **NOT a switch case** — dispatched via `customGrantHandlers[GrantTypeSAML2Bearer]` (server_setup.go:283-295), which runs after the seam | yes |

Single `/token` route confirmed (`server_routes.go:180`), and `dispatchTokenGrantWithQuota` (quota.go:411) delegates straight into `dispatchTokenGrant`. **Caveat**: the "8 branches" claim is only true because SAML2 rides the custom-grant registry; an implementer grepping the switch for SAML2 will miss it — the design should state this mapping. Coverage nuance: authcode/device/CIBA mint from *login-time stored entries*, not token-request scope, so the seam can't see those scopes. The "pre-wiring authcodes" failure mode is real and named, but its resolution is not in the artifact.

## 2. Default-path byte-compat — VERIFIED (correction #1 is necessary and sufficient)

Every existing grant-branch `invalid_scope` rejection emits plain `core.ErrorBody(ErrInvalidScope)` + 400 — client_credentials:36, refresh:364, authcode:202, jwt_bearer:90, saml2:98, exchange:453, exchange_stages:324/345. Confirmed `errorBody` (handlers.go:399) wraps `ErrorBodyWithTrace`, so a seam using it would inject `trace_id` and drift. The design's A-1b pin (emit `core.ErrorBody` directly, status 400) reproduces the existing body byte-for-byte across all branches. Unwired (`nil` registry) = no-op preserves the default path structurally.

## 3. Protocol triggers vs OIDC standard scopes — PARTIALLY VERIFIED, one unbacked claim

- **Verified**: `openid` (consts_wire.go:241) and `device_sso` (:246) are the only allowlist-bypass constants in `GrantedScopes` (oauthvalidate/scope.go:103-107); e2e `TestScope_*` suites (including `TestScope_ClientCredentials_UnrestrictedPassthrough` with `anything`/`api:read` fixtures) pass on HEAD. The seam exempting exactly these two preserves mintability.
- **NOT BACKED**: "OIDC standard scopes absent from the eight-scope matrix stay mintable under the documented bypasses." `profile`/`email`/`address`/`phone`/`offline_access` are **not** bypass constants and **not** in the matrix. The artifact lists "OIDC standard scopes not in matrix" as a failure mode but documents **no bypass mechanism** — the deliverable is a 15-line summary. Under an enabled registry, direct-mint grants (client_credentials, jwt_bearer, exchange) requesting `profile` would be rejected with 400; only stored-entry flows would accidentally pass. The design needs an explicit mechanism (Memory pre-seeds OIDC scopes, `openid`-presence exemption, or mandatory `extra_scopes` guidance) — and `offline_access` is minted in webauthn device flows (cmd/sso-server/serverwebauthn/webauthn.go:87,146), which must be named in the bypass.

## 4. Migration order — UNVERIFIABLE as delivered

The artifact enumerates "9 failure modes" and "8 ordered migration steps ending in `make ci`" but specifies **neither**. The three named risks are real: default-off means an unconfigured replica keeps old behavior (config-drift divergence); an `extra_scopes` typo yields false 400s; mixed enabled/disabled replicas mint vs reject the same scope. The config pattern is feasible — config-reference has precedent for opt-in `enabled` blocks with explicit "byte-identical" guarantees (e.g., `keys.introspection_signing.enabled`, `connections.domain_verification.enabled`) — but "observable behavior preserved at every step" cannot be checked against a sequence that isn't in the deliverable.

## 5. Supporting claims — VERIFIED

- **Eight-scope matrix**: commerce 4 (consts.go:24-27) + metering 2 (consts.go:12-13) + `audit:event:write` (billing config.go:22, exact-enforced :360) + `admin:*` (admin/middleware.go:31) = 8. `admin:*` prefix-match semantics confirmed at domains/tokenpolicy/evaluate.go:203 (`scopePresent`, trailing-`*`).
- **Budgets**: `interfaces/sso` has exactly 60 non-test files (ceiling true); `options_misc.go` is 496 lines with a named split plan; new packages (`protocols/oauth/scoperegistry`, `interfaces/scopecontract`) are import-flow-legal and need `layerName()` classification.
- **Billing mapping**: contractRouter→403 map (auth.go:27-58), `adminScopeGate`→`insufficient_scope` (:159-166), `serveWithClaims` test pattern exists (auth_test.go:40,83).
- **Zero registry presence today**: no `ScopeRegistry`/`scope-matrix` hits outside campaigns/proposals.

**Bottom line**: the byte-compat core (seam placement, plain-`ErrorBody` emission, nil-registry no-op, openid/device_sso exemption) is code-verified and sound. Two deliverable gaps must be closed before implementation: (a) the OIDC-standard-scope bypass is asserted but undocumented, and (b) the 8-step migration sequence exists only as a count — both need concrete specification (and the SAML2-via-custom-registry mapping should be stated explicitly).
