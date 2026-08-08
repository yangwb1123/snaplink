I now have the complete independent inventory. Let me compile the final report.

---

# Migration inventory re-run: steps 5 and 3.1 — independent verification report

Method: read-only greps over the working tree (`HEAD 8948632c`, plus untracked WIP in `cmd/sso-ctl/apiclient`). All line numbers re-verified against current file contents.

## 1. Shared helpers — convert-once vs. per-call-site (test/handle_introspect_test.go)

| Helper | Shape | Verdict |
|---|---|---|
| `postIntrospect` (:81-100) | Single JSON-encode helper; **one conversion point** covers all 9 in-file call sites (:106, :128, :145, :166, :178, :190, :221 + introspection tests) | Convert once ✓ |
| `postRevoke` (:229-240) | Same; one conversion covers 6 call sites (:248, :257, :271, :279, :286) | Convert once ✓ |
| `TestIntrospect_AcceptsBasicAuth` (:196-202) | Direct JSON post (`req.Header.Set("Content-Type","application/json")` at :202) — **per-call-site conversion needed** | Separate ✓ (design lists it) |
| `test/introspection_jwt_test.go` `postIntrospectAccept` (:61-70) | **Separate helper** with its own JSON post at :70; does NOT reuse `postIntrospect` | Design lists :70 ✓ |

No file outside `handle_introspect_test.go` reuses `postIntrospect`/`postRevoke` (verified via grep).

## 2. Complete JSON-post sweep (design says "~25 files / ~45 posts"; item 2 lists 12 files)

**Design-listed (12 files, 31 posts) — all confirmed present** (auth_code :124/:484, claims_param :352, credential_health :397, oauth_bind :276, handle_token :59/:87/:284, refresh_token :118/:342/:375/:496, refresh_rotation_claims :57, rar :265/:429/:480/:527, introspection_jwt :70, handle_device :66/:111/:130/:187/:200/:312/:342/:361, mfa :175/:200, handle_introspect 3 posts). Note: item 2 alone lists only 5 of handle_device's 8 posts — :130/:312/:342 survive only via R5.1's separate list.

**MISSED in `test/` — 7 files, 17 posts, all expect success (200/201/403) → break `make ci`:**

| File | Posts | Endpoint |
|---|---|---|
| `test/handle_par_test.go` | :112, :352 (expect 201) | /par |
| `test/introspect_batch_signed_test.go` | :101, :139, :163, :223, :245+header :248 (expect 200) | /token/introspect |
| `test/introspection_cache_invalidation_test.go` | :105 (introspect), :122 (revoke) (expect 200) | /token/introspect, /token/revoke |
| `test/pkce_test.go` | :130, :421, :441 (expect 200) | /token |
| `test/oidc_test.go` | :228 (expect 200) | /token |
| `test/frontend_contract_test.go` | :207, :325 via `fcPost`→`fcPathToken` (expect 200) | /token |
| `test/region_residency_mfa_test.go` | :143 (expect **403** residency block), :173 (expect 200) via `completeMFAFromRegion` helper (:95-108) | /auth/mfa |

Measured total: **19 test/ files / 48 posts**, not "~25 files". Verified-clean: scope_authorization (JSON only to /auth/login), router_backend_matrix (`matrixJSON` only login), token_no_store, jwt_client_assertion*, spiffe_svid, token_exchange_*, chaos/ha/dr/backendsemantics, testkit (JSON only /auth/login).

**MISSED entirely — `interfaces/sso` tests: 24 files, 94 `rcovDo`/`rcovPostJSON` calls to the 8 endpoints** (all through `sso.NewServer` → default-strict; shared helper `rcovDo` at `rootcov_flow_test.go:155-175` sets JSON CT for any body). Only 2 of the 94 are nil-body CIBA-gate probes that stay green (404/501 fire before bind); the other **92 break**. Files: rootcov2_assertion (8+1 direct at :201-208), rootcov2_cluster (5), rootcov2_device_errors (12), rootcov2_extensions (11), rootcov_flow (10, incl. JSON rows in the Basic-precedence tables :598/:621/:627), workload_identity_clientauth (7), user_lifecycle_authentication (6), rootcov2_exchange (6), rootcov_misc (4), rootcov_token_policy (4), rootcov2_exchange_more (3), rootcov2_handlers (2), rootcov_discovery (2), server_conditional_access_groups (2), feature_gates (2, green), break_glass_routes (1), federated_authorization (1), login_transaction (1), quota (1), rootcov2_discovery (1), rootcov2_tenant_roles (1), rootcov_extra (1), rootcov_token_policy_enforce (1), rootcov_trusted_devices (1), server_conditional_access (1, `/auth/mfa` :325).

**MISSED — `protocols/oauth` handler tests: 3 breaks** (`handle_par_test.go` :182, :227, :243 — RAR/claims tests with `newCtx(..., core.ContentTypeJSON, ...)` expecting `400 invalid_authorization_details`/`201`; under strict they get 400 invalid_request or 400). I checked handler order: nil-store 500/501 tests (introspect :115, par :54/:63, revoke :93, ciba :70/:79) and bad-body 400 tests fire **before** or collapse to the same 400 → stay green. So only 3 of the 41 `ContentTypeJSON` ctx uses break.

## 3. Deps implementers (step 3.1) — no implementer beyond protocols/oauth + interfaces/sso

- Production: **`*sso.Server` only** (handlers.go :35/:99/:104, server_extensions.go :289; `RoutesDeps` union grant_handler.go:36 embeds all four). `oauth.MountRoutes` has **no in-repo production caller**.
- Test fakes: **four fake types, not six** — `introspectDeps` (handle_introspect_test.go:28, `var _ IntrospectDeps` :78), `parDeps` (:17/:38), `revokeDeps` (:19/:58), `cibaDeps` (:18/:47). `introspect_cache_test.go` and `introspect_geo_test.go` **define no Deps fake** — they reuse `introspectDeps` (cache :67, geo :39), so editing the shared type covers them. Design's "six fakes" overstates by two; no missed compile site.
- Verified none elsewhere: `VerifyJWTClientAssertion` (a member of all four) exists only in protocols/oauth, its 4 test files, and interfaces/sso accessors; other packages' `ResolveIssuer`/`ClientStoreAccessor` hits are their own unrelated interfaces (federation, caep, oidc, selfservice); `test/` references none of the four.

## 4. gensdk sibling — ordering pin and OpenAPI sharing

- **Ordering constraint: pinned ✓** — sibling §4 "MUST land before the server form-only flip (T-9(d))", F8 sequencing gate, §6 steps 8-12; billing design step 8 "before/with step 3" is consistent.
- **No shared requestBody component ✓** — all 8 credential requestBodies are inline `content:` blocks; schemas (TokenRequest, IntrospectRequest, RevokeRequest, PARRequest, DeviceCodeRequest, DeviceVerifyRequest, MFACompleteRequest, CIBABackchannelRequest) are referenced only by their own credential path. Dropping `application/json` from the 8 paths is fully contained.
- **Sibling drift found**: gensdk E7 claims "Only `postToken` (openapi.yaml:1100-1102) is form-only" — **false**: /token also declares `application/json` at :1139-1143. The billing design's "all eight declare both" is the accurate claim.

## 5. Missed sites that break `make ci` (race = `go test -race ./...` covers test/, interfaces/sso, protocols/oauth)

1. `test/` — 7 files / 17 posts (§2 table).
2. `interfaces/sso/` — 24 files / 92 posts (§2).
3. `protocols/oauth/handle_par_test.go` — 3 sites (§2).

**Breaking but not `make ci`-red (shipped consumers the design's "every in-repo JSON post" claim also misses):**
4. **`cmd/sso-ctl/apiclient` (untracked WIP)**: `token.go` `mint()` (:71), `revoke()` (:236, incl. post-revoke introspect), `runT8d` (:282, byte-identical `{"error":"invalid_scope"}` assert), `runT9` (:334, byte-identical `401 {"error":"invalid_client"}` assert) all POST JSON via `apiclient.Do` (apiclient.go:119). Against a strict server every leg fails; stub-based check_test.go stays green.
5. **gensdk 4-op vs 8-site mismatch**: committed clients emit `{ body }` (JSON) for `postMFAComplete` (/auth/mfa, client.ts:2823, client.py:2217), `postDeviceCode` (/device/code, :2848/:2237), `postDeviceVerify` (/device/verify, :2858/:2245) — all flipped by the server module but explicitly excluded from `usesFormBody` ("handlers still accept JSON" — false post-flip). Generated-SDK device/MFA flows 400 after the flip, and the OpenAPI form-only rewrite (8 paths) drifts from client emission (4 ops). The sibling's F-A prerequisite (`setFormField` `json.RawMessage` case) is also absent from the billing design's steps — form-PAR with `authorization_details`/`claims` silently binds nil without it.

**Design corrections:** "~25 files/~45 posts" → 19 test files/48 posts + 24 interface files/92 posts + 3 protocol sites; "six fakes" → four types; section-2 item-2's "complete sweep" claim is false; handle_device item-2 list omits :130/:312/:342 (covered only via R5.1).
