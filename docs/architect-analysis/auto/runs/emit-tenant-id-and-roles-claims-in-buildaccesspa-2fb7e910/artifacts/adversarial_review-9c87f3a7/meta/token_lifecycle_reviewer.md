Trace complete. Report written to `docs/architect-analysis/auto/runs/emit-tenant-id-and-roles-claims-in-buildaccesspa-2fb7e910/artifacts/adversarial_review-9c87f3a7/meta/token_lifecycle_trace.md`. Summary:

## Lifecycle trace (all 13 Subject sites verified against HEAD `718345d6`)

**Where `TenantID` would be carried:** every seam already stamps `client.TenantID` — `mintAccessToken` (server_login.go:118), all 8 token-endpoint grants (authcode :136 / refresh :291 / cc :52 / device :99 / ciba :124 / jwt-bearer :112 / saml2-bearer :123 / exchange :399), plus native-SSO :190, agent-delegation :185, silent-renewal :210 (break-glass :257 deliberately `""`). Since `buildAccessPayload` is shared, the design's unconditional `tenant_id` projection hits all of them.

**Where `Roles` would be silently dropped:** everywhere except the design's `mintAccessToken` wiring. The **only real drift path** is `direct-mint login → refresh rotation`: `finishLoginDirectMint` (server_finish_login.go:176) → `mintAndRecordDirectLogin` (server_login_client.go:390) → `mintAccessToken`; the direct-mint branch always issues a server-managed refresh token (server_finish_login.go:216-223), and the record (`oauthspi.RefreshToken`, full field list verified) has **no Roles field** — so the first rotation via `refreshRotatedSubject` (token_refresh.go:287) re-mints roles-absent. Re-emission paths (silent renewal, native SSO, exchange) re-mint from `TokenClaims`/id-token payloads that structurally never carried roles (`claimsFromPayload` enumerates fields only) — no drift there.

## Threading through refreshRotatedSubject: YES, no discipline violation

Roles thread as a **propagated-unchanged lineage field** — the exact AuthorizationDetails/AMR pattern (persist at original grant, re-stamp unchanged), which is what the chain-preservation disciplines at token_refresh.go:272-320 already encode. It must *not* follow ServingRegion's mint-time re-stamp (tokengrant has no roster access), and a live re-resolution was rejected: it would add roles to code-flow rotations (mirror-image drift) unless the record carried an origin marker anyway.

**Minimal seams (net ~10 additive lines + 2 store migrations):** `RefreshToken.Roles` + `RefreshAuthContext.Roles` (oauthspi/refresh_token.go) → `IssueRefreshTokenParams` + `buildRefreshTokenEntry` → `s.issueRefreshToken` (server_oauth.go:61) → direct-mint site as a **same-line edit** at server_finish_login.go:223 (`Roles: result.Roles`, carrier = `AuthResult.Roles json:"-"`, 0 new lines in the exactly-500 file) → `refreshRotateFamily` (:275) → `refreshRotatedSubject` (:287). Stores: memory 1 line; Redis **zero** (whole-struct JSON); sqlite + postgres get a v5/v6-class `roles` column migration (amr JSON-TEXT pattern) — the design's "no data migration" claim must be amended. Authcode/device/ciba/exchange refresh issuers need **no change** (empty roles by R4).

## Contract pins (both halves)

1. **Roles-absent (code-exchange + rotation)** — extend `test/refresh_rotation_claims_test.go` with a tenant-bound client: assert rotated token carries `tenant_id` but no `roles`.
2. **Roles-preserved (direct-mint rotation)** — new test using the `TestRcov2L_RichLogin` harness + `WithJITMembership`/`WithTenantUserStore` (rootcov_options_test.go:92-93): login token `roles:["member"]` → rotated token same vector.
3. **Collapse table** in failure modes: one `omitempty` absence shape for non-member / lookup failure (needs an error-injecting `TenantUserStore` stub — `MemoryTenantUserStore.Get` can't error) / no store / token-endpoint families.

Also verified while tracing: the metrics nil-guard hazard doesn't exist (`ObserveTokenPolicyRoleResolutionError` is nil-receiver-safe, metrics_token.go:115), and the `tenant_id` `ext`-collision + "NOT a token claim" doc-comment fixes from the review remain open design amendments.
