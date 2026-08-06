All evidence gathered. Here is the audit report.

---

# B4-4 design audit: migration + acceptance mapping

Verdict: the seam analysis, openapi/SDK cross-checks, consumer inventory, and budget claims hold; **three material gaps** invalidate the "byte-identical" and "gate-clean" claims as written (RAR-over-PAR field loss, a ~3.5x migration-scope miss, and a red intermediate commit), plus one factual error about the fuzz target.

## 1. Inverted compat test + ~20-file migration byte-identity — NOT CONFIRMED (2 gaps)

**1a. HIGH — RAR-over-PAR cannot migrate with assertions unchanged; the new binder silently drops `authorization_details`/`claims`.**
- `parRequestForm` has `AuthorizationDetails json.RawMessage` and `Claims json.RawMessage` (`protocols/oauth/handle_par.go:100,106`). `formIntoStruct.setFormField` (`protocols/oauth/oauthwire/bind.go:126-150`) has no `json.RawMessage` case → the field is **silently skipped**, not rejected.
- `ValidateAuthorizationDetails` treats empty as "no RAR" (`protocols/oauth/oauthvalidate/rar.go:154-156` returns `nil,nil`) → a form POST carrying `authorization_details` is accepted **without** RAR constraints: a silent, security-relevant downgrade, not an error.
- Consequences for the design's own migration list:
  - `test/handle_par_test.go` `parThenLogin` (:337) pushes RAR via `/par` and asserts the access token carries the claim (:394-405, :452-466). Converting to form drops the field → assertions break.
  - `protocols/oauth/handle_par_test.go` has 3 JSON RAR posts asserting `400 invalid_authorization_details` / `201` with RAR stored (:174-250) — they'd become `400 invalid_request` / `201`-without-RAR.
- The behavior table (§1.3) covers only CT dispatch, not field-level fidelity; §3 failure modes omit this. **Required fix:** either the strict binder gains a `json.RawMessage`-from-form-string path (with tests), or RAR-over-PAR is explicitly excluded with a documented, non-silent contract change. The SDK `PARRequest` also carries `authorization_details`/`claims` (client.py:927-928), so step 7 is underspecified for exactly these fields.

**1b. HIGH — migration scope miss: the surface is ~46 files / ~165 posts, not ~20 files / ~45-56.**
- `test/`: 40 same-line JSON posts + ~8 separate-CT posts (e.g. `handle_device_test.go:111`, `handle_introspect_test.go:201`, `region_residency_mfa_test.go:102`, `introspection_jwt_test.go:66`) across 16 files — not "56 lines / 20+".
- **Entirely absent from step 5** (which says "across `test/`"): `interfaces/sso/` has **96 `rcovPostJSON` calls to seam endpoints across 24 files** (`rootcov2_*` 62, `user_lifecycle_authentication_test.go` 6, `workload_identity_clientauth_test.go` 7, `federated_authorization_test.go`, `login_transaction_test.go`, `quota_test.go`, `break_glass_routes_test.go`, `bcl_failure_admin_test.go`, conditional-access and trusted-devices tests), and `protocols/oauth/` has **27 JSON posts across 6 files** (`handle_revoke_test.go` 10, `handle_introspect_test.go` 7, `handle_par_test.go` 6, `handle_ciba_test.go` 3, `introspect_cache_test.go` 1).
- Conversely, ~10 files in the design's list contain zero seam JSON posts (`jar_test.go` posts JSON only to `/auth/login`; `prompt_test.go`, `acr_values_test.go`, `form_post_response_mode_test.go`, `login_hint_test.go`, `resource_indicators_test.go`, `tenant_middleware_test.go`, `server_validate_test.go`, `router_backend_matrix_test.go`, `region_residency_test.go`, `iss_response_test.go`), while `handle_token_test.go` (3), `credential_health_test.go` (1), `refresh_rotation_claims_test.go` (1) are missing. The "enumeration is a migration step" hedge covers file-list accuracy, not the missed package classes.
- Good news on byte-identity for everything *not* involving RawMessage: verified all other migrated payloads are flat string/bool/int/[]string (`trust_device`, `approve`, `requested_expiry *int`, `resource`/`tokens` arrays, PKCE/refresh/auth-code bodies) — all form-representable with identical bind results.

## 2. ~30 JSON-native non-credential consumers — CONFIRMED

- 36 actual `BindParams(` call sites across 23 files (admin 10, commerce 9, selfservice 15, adminuser 2) — "~30" is accurate; wallet adjustments at `interfaces/commerce/wallet.go:68` uses the seam as claimed.
- Regression coverage exists and is untouched by the design: `wallet_test.go` (3 JSON posts incl. adjustments at :43-45), `payments_test.go`/`branding_test.go` via `serveJSON`, `internal/adminuser/handlers_test.go` (10 tests, JSON `newCtx` at :91-95), selfservice suites.
- The variant approach is sound; `protocols/oauth/bind_extra_test.go` (`TestBindParamsJSONDefault`, `TestBindParamsContentTypeWithCharset`, `TestBindParamsRejectsTrailingJSONValue`) already locks the dual-mode alias and stays green — the design should state explicitly that these are kept.

## 3. Fuzz re-seeding — plan correct, one factual error, one contradiction

- The re-seed plan (drive `BindParamsFormOnly` + retain a `BindParams` target; non-form CT must error and never panic; JSON seeds move to the error corpus; `ctSelector%4` covers form/json/text-plain/missing) encodes the new contract correctly. Only `FuzzBindParams` covers the binder (`protocols/oauth/oauthwire/fuzz_test.go` is `BearerToken`/`BasicClientCreds` only) — F7 confirmed.
- **Factual error:** the design claims the old fuzz target "is expected to fail semantically after the seam change until step 4 lands". It cannot fail — it calls package-local `BindParams` = the `aliases.go:97` alias, which the design itself keeps dual-mode. It silently keeps passing while losing credential-endpoint coverage. The "fail" framing is wrong; the same-commit requirement is still right (coverage, not gate, is at stake).
- Contradiction: step ordering (seam=1, fuzz=4) vs. the same-commit note in "Pre-existing state".

## 4. OpenAPI 10-op + Python SDK 7-method — CONFIRMED, two minor notes

- All 8 credential ops document an `application/json` request body alongside form (postMFAComplete :640, postToken :1099, postIntrospect :1277, postRevoke :1344, postPAR :1473 — operationId is `postPAR`, postDeviceCode :1540, postBackchannel :1601, postDeviceVerify :1848); the 2 admin compromise ops are JSON-only with a trivial `{reason}` schema (:5004, :5501) whose Go structs use `json:"reason"` — form conversion is exact. The 10-op figure is correct.
- SDK: exactly 7 credential methods (`post_mfa_complete` :2216, `post_device_code` :2236, `post_device_verify` :2244, `post_par` :2260, `post_token` :2280, `post_introspect` :2284, `post_revoke` :2288), all via `_request` (JSON hardcoded at :1450-1453). ✓
- `make ci` gates that touch openapi (`route-contract`, `sdk-surface check`) validate only route/operationId existence (`ops/scripts/sdk_surface.py:95-109`), so the request-body edits cannot trip them. ✓
- Note: `PARRequest` (SDK) nested `authorization_details`/`claims` make the step-7 hand-fix non-trivial and dependent on resolving finding 1a.

## 5. Engineering budgets — file ceilings confirmed; gate-clean ordering FAILS as written

- `interfaces/sso`: exactly 60 non-test `.go` files (ceiling); design adds zero files there. ✓ New test file in `protocols/oauth/oauthwire/` (existing package, no `bind_test.go` collision). ✓ No new packages, no new Err\*, no config knobs. ✓
- **Gate-clean order breaks at step 1:** `make ci` runs `race` = `go test -race -count=1 ./...`, which includes `test/` (package `ssotest`). After the seam switch alone, `TestFormEncoded_JSONStillWorks` (asserts 200 on JSON at `test/oauth_bind_test.go:272`) fails → step 1 is not gate-clean. The compat inversion (step 2) must be in the same commit; the design's pre-existing-state note requires only the fuzz re-seed in that commit, and its step ordering contradicts even that.
- **AGENTS.md §5 rule 6 compliance:** "Update contracts in the same change" — the openapi/AGENTS.md:113 rewrite is a contract change for existing endpoints and must land with the seam commit, not as later step 6.
- Correct minimal gate-clean split: **commit A** = seam + `requestContentType` + compat-test inversion + seam unit tests + fuzz re-seed + AGENTS.md:113 + openapi; **commit B** = test migration (~46 files); **commit C** = Python SDK; then race + `test/` E2E + `make ci`. `TestE2E` exists (`test/e2e_test.go`). ✓

## Required design updates (before execution)

1. Resolve the RawMessage question for `/par` (binder support vs. explicit contract loss) and adjust the behavior table, failure modes, and acceptance mapping accordingly.
2. Expand the migration step to all three test classes (`test/` ~16 files, `interfaces/sso/` 24 files, `protocols/oauth/` 6 files) with the RAR tests handled per (1).
3. Re-state the commit ordering: seam+compat+fuzz+docs as one commit; drop the "expected to fail" fuzz claim.
4. Note in step 7 that `PARRequest`'s nested fields depend on (1).

Everything else — constant-time sites, no-store-before-bind on all 10 handlers, MFA `mfa_invalid` collapse (`server_mfa.go:254-260`), introspect 401 `invalid_client`, DCR/login/revoke-all exclusions, audit-provisioner untouched — verified exact.
