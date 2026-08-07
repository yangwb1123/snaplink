All verification complete. Here is the audit report.

---

## Verification report: 12 GWT cases vs. HEAD

`go build ./... && go vet ./...` clean at HEAD. All 12 cases map to concrete, named test functions whose underlying pieces (real service, memory store, issuer, grant drivers, CLI entry point, exit codes) exist. **The RED/GREEN flags are verifiable for 8 of 12 cases as stated; 4 rows carry classification defects** — two fixture pins are missing from the spec (making "rest GREEN" false as literally written) and two rows' RED flags are mis-stated.

### JWT-bearer row (the specific ask)

| Claim | Verdict |
|---|---|
| `GrantJWTBearer` exists | **Confirmed** — `shared/core/consts_oauth.go:25`, `"urn:ietf:params:oauth:grant-type:jwt-bearer"` |
| `sso.WithJWTBearerGrant` seam exists | **Confirmed** — `interfaces/sso/options_grants.go:98` (exact line). Nil validator = no-op; dispatch chain fully live: `sso_wiring.go:205` → accessor `server_token.go:487` → `server_token.go:179-180` (`case GrantJWTBearer`) → `tokengrant.HandleJWTBearerGrant` (token_jwt_bearer.go:38); unwired ⇒ 501, wired ⇒ real mint |
| Zero concrete validators in repo | **Confirmed** — `JWTAssertionValidator` (token_jwt_bearer.go:31-36) has no implementor; the only `ValidateAssertion` in-repo is `infrastructure/saml`'s SAML2-seam one. No `token_jwt_bearer_test.go`; `test/jwt_client_assertion_test.go:105-107` drives `grant_type=client_credentials` + `client_assertion` (private_key_jwt auth, not the grant). Design's material correction is accurate |
| No in-repo Ed25519 validator reusable | **True in the narrow sense** — nothing implements the seam. Nuance: `Ed25519JWTIssuer.Validate` (ed25519_validate.go) is a self-issued-token RS verifier (wrong contract), but `securityverify.VerifyCompactJWS` (jwks_verify.go:72) is a reusable raw Ed25519 JWS primitive a new validator can call; `WorkloadIdentityValidator` is cloud-specific. So "no validator" holds; "no verification code" would be overstated |
| ~40-line fixture is minimal | **Confirmed credible** — delta vs. other grants = keygen (~2) + sign helper (~10, pattern at jwt_client_assertion_test.go:95-99) + `ValidateAssertion` impl (~18-25, less via `VerifyCompactJWS`) + 1-line wiring ≈ 30-40. Nothing existing can be dropped in |

### Case-by-case classification audit

| Case | Test function | Claimed | Verified |
|---|---|---|---|
| 1 | `TestTenantClaimsE2E_CreateAndMint` (create/get half) | GREEN | **OK** — dispatch :44-52, exit-2 guards :158-165, `doWrite`→1 (:317-320), `CreateTenant` id-required/AlreadyExists (:194+) |
| 2 | same (token half) | tenant_id RED, rest GREEN | **FLAGGED** — rest-GREEN includes `aud`, absent at HEAD without `resource` (see F-1) |
| 3 | `TestTenantClaimsE2E_IssuerCoherence` | hedged | **FLAGGED** — GREEN only with an unpinned `WithEd25519Issuer` fixture detail (F-2); the design's hedge ("resolveIssuer already returns the configured value today") is beside the point |
| 4 | `TestTenantClaimsE2E_StatusRoundTrip` | GREEN | **OK** — `SetTenantStatus` :315, nil-safe revoke |
| 5 | `TestTenantClaimsE2E_UnboundClientOmitsTenantID` | GREEN | **OK** — absence assertion passes pre- and post-R0 (omitempty guard) |
| 6 | `TestTenantClaimsE2E_UsageValidation` | GREEN | **OK** — exit 2/2/1 paths all verified |
| 7 | `TestTenantClaimContract_PerGrantMatrix` | tenant_id RED | **FLAGGED** — `aud` member again (F-1); `kid/iss/scope/client_id` GREEN verified |
| 8 | `TestTenantClaimContract_IntrospectionEchoes` | RED | **OK** — introspection echoes decoded claims (region precedent :218-247); no tenant_id claim at HEAD |
| 9 | `TestTenantClaimContract_RolesClaim` | RED (both halves) | **FLAGGED** — positive half RED verified; negative half (no `roles` key) is GREEN-always, not RED (F-3) |
| 10 | `TestTenantClaimContract_RolesLookupErrorFailOpen` | RED | **FLAGGED** — vacuously GREEN at HEAD; no mint-time lookup exists for the error to flow through (F-4) |
| 11 | `TestTenantClaimContract_IssuerCoherence` | GREEN | **FLAGGED** — GREEN only with the same unpinned issuer-name detail as case 3 (F-2) |
| 12 | existing `tenants_test.go` + `users_test.go` | GREEN | **OK** — both suites exist (`TestRunTenants_ListSuccess`, `TestRunUsers_*`) |

### Flags

**F-1 — Cases 2/7: `aud` is not in the green set as stated.** `aud` is emitted only via RFC 8707 resources (`applyOptionalClaims`, issue_payload.go:116-120 `if len(subject.Resources) > 0`). A plain `/token` POST mints a token with **no `aud` claim at HEAD**; the case-2/7 "claims contain iss/aud/scope/client_id" assertion fails at HEAD for a fixture reason. All seven grants thread `Resources` (authcode:126, refresh:289, device:97, ciba:122, exchange:392), so sending `resource=https://api.example` on every leg fixes it — but neither the requirements nor the design states that pin, and the region precedent it's modeled on never asserts `aud`.

**F-2 — Cases 3/11: GREEN at HEAD requires `WithEd25519Issuer("https://sso.test")` on the issuer, which is unpinned and omitted as written.** The minted token's `iss` is the JWT issuer's own construction-time name (`ed25519_jwt_issuer.go`: default `sso.DefaultIssuer`, set via `WithEd25519Issuer`); `sso.WithIssuer` feeds only discovery (`server_discovery_config.go:264-265`) and `resolveIssuer` (authz responses, server_discovery.go:251-258) — it never reaches the token (verified: no override in `sso_wiring.go`, `authHookIssuer`, or `tokenpolicy` wrappers). R2 as written (`NewEd25519JWTIssuer` + `WithIssuer`) mints `iss: "snaplink-sso"`, making case 3's `iss == "https://sso.test"` and case 11's equality chain RED at HEAD for a fixture reason. The design's row-3 hedge ("RED-pre-R0 only if fallback removal is the mechanism") is mis-reasoned: the fallback removal never affects the minted token under any wiring. Correct statement: **GREEN at HEAD, provided the fixture pins the issuer name** — the Host-independence half is genuinely green today (iss is a construction-time constant). Under the cmd path this works (`build_signing_issuers.go` wires `WithEd25519Issuer(srv.Issuer)`), so the gap is spec-side, not product-side.

**F-3 — Case 9: the negative half is GREEN-always, not RED.** "Same subject with no assignment yields no `roles` key" passes trivially at HEAD (no roles claim exists anywhere) and is a regression guard for R0's nil-vs-empty discipline — same class as case 5. Only the positive half (`roles == ["admin","auditor"]`) is RED-pre-R0. The design's "(both halves)" is wrong.

**F-4 — Case 10: RED-pre-R0 is not achievable as stated.** At HEAD, tokengrant imports no permissions provider and no mint-time lookup exists, so the erroring provider is never consulted; "provider error → 200 with roles omitted, byte-identical to the no-roles case" passes **vacuously** pre-R0. The assertion only becomes meaningful post-R0 (where it must stay green if R0 is fail-open — the actual guard). If the intent was to assert the provider was consulted and the failure landed only in audit, that assertion has no seam to observe pre-R0 at all and cannot be written until R0 lands. The design's failure-mode F2 has the same flaw: there is no error path to flow through pre-R0.

**Net:** the design's central claims — the jwt-bearer row needs a real in-test Ed25519 validator wired via `WithJWTBearerGrant` (~40-line delta), and the 12-case mapping with a clean pre-R0 red-split (tenant_id/roles assertions red, everything else green) — hold *only after* pinning the two fixture details (F-1 `resource` threading, F-2 `WithEd25519Issuer`), and the red-split must be restated for cases 9-negative and 10 (GREEN-vacuous, not RED). Cases 1, 4, 5, 6, 8, 12 and the RED halves of 2/7/9 are all achievable exactly as classified.
