# Requirements Spec: B4-4 — Enforce application/x-www-form-urlencoded on credential endpoints

- Direction: B4-4 (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-entitiescmd-631f0c1d.json`, entry 3)
- Module label: `cmd/sso-ctl/entitiescmd` (analysis-file label; the direction is cross-cutting — actual owning layers are `protocols/oauth/oauthwire` + `interfaces/sso` + `protocols/oauth`, per DIRECTORY_MAP rows "protocols/ — identity-protocol use-cases" and "interfaces/sso — the Server API")
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `protocols/oauth/oauthwire/bind.go:28-53` — `BindParams` accepts JSON and defaults missing/unexpected Content-Type to JSON | `func BindParams` spans lines 27–53. Comment "JSON is accepted as a non-standard convenience" (18–19) and "Empty body + no Content-Type is treated as JSON for backward compatibility" (24–25). `switch ct` at 37: `case "application/x-www-form-urlencoded"` (38) → `ParseForm`+`formIntoStruct`; `default:` (43–45) → `decodeSingleJSON` for `application/json`, missing CT, and anything unexpected | Confirmed (the direction's `:28-53` is the function span; exact) |
| `interfaces/sso/server_token.go:29` — `bindOAuthParams` on `/token` | `bindOAuthParams(ctx, &req)` at line 30 inside `handleToken` (line 29 is `var req oauth.TokenRequest`); `tokenNoStoreHeaders(ctx)` at line 22 | Confirmed (drift 1 line) |
| `interfaces/sso/server_device.go:53,242` — other bind sites | `bindOAuthParams` at line 53 (`handleDeviceCode`, POST `/device/code`) and line 242 (`handleDeviceVerify`, POST `/device/verify`, user_code+approve struct) | Confirmed (exact) |
| `interfaces/sso/server_mfa.go:255` — bind site | `bindOAuthParams` at line 255 inside `parseMFACompleteRequest` (POST `/auth/mfa`). Bind error collapses to `400 mfa_invalid` via `s.authzErrorBody` (256–258) — NOT `invalid_request` | Confirmed, with error-shape nuance (see R1) |
| `interfaces/sso/server_admin_handlers.go:293` — bind site | `bindOAuthParams` at line 293 inside `handleAdminCompromiseCredential` (POST `/api/v1/admin/credentials/{type}/compromise`, admin:write, `400 invalid_request` on bind error) | Confirmed (exact) |
| shared/security/client_secret.go — constant-time compare already exists | `CompareClientSecret` (line 19) and `ConstantTimeStringEq` (line 25) present; no work | Confirmed |
| `internal/handler/tokengrant/token_client_credentials.go:21` — cc issues no refresh_token | Comment at lines 21–23: "no refresh token, and no id_token are issued" in `HandleClientCredentialsGrant` | Confirmed (exact) |
| `interfaces/sso/server_token.go:21` — `tokenNoStoreHeaders` already set | `tokenNoStoreHeaders(ctx)` at line 22, before `requireDeps`/bind. All other credential bind sites stamp no-store before parsing too: `handle_revoke.go:68`, `handle_par.go:55`, `handle_introspect.go:112`, `handle_ciba.go:76`, `server_device.go:42`, `server_mfa.go:195`, `server_admin_handlers.go:282`, `options_admin.go:403` | Confirmed (drift 1 line; stronger than cited — every bind site is covered) |
| `cmd/sso-ctl/apiclient/apiclient.go:102` — CLI sends JSON only to `/api/v1/admin/*`, never to OAuth credential endpoints | `req.Header.Set("Content-Type", "application/json")` at line 102, applied whenever `body != nil`. CLI call inventory (`entitiescmd/tenants.go`, `entitiescmd/users.go`, `tokenscmd/tokens.go`, `sessionscmd/sessions.go`) hits only `/api/v1/admin/{tenants,users,tokens}/*`. Those routes are served by the **admin gRPC-gateway** (`cmd/sso-server/build_http.go:192-216` `adminGatewayExactPaths` → `registerAdminGateway`), which unmarshals JSON itself — none of them pass through `oauthwire.BindParams` | Confirmed (CLI unaffected; mechanism detail newly verified) |
| "Repo-wide sweep of JSON callers of /token required before flipping the default" | Sweep inventory measured: `test/oauth_bind_test.go:263-283` `TestFormEncoded_JSONStillWorks` explicitly asserts the JSON fallback (must be inverted); `handle_introspect_test.go` JSON helpers `postIntrospect` (82–100) / `postRevoke` (228–240) used by the 401 regression tests (174–196); `handle_token_test.go:59,87,284`; `auth_code_test.go:124,484`; `pkce_test.go:130,421,441`; `refresh_token_test.go:118,342,375,496`; `claims_param_test.go:352`; `oidc_test.go:228`; `handle_device_test.go:66,130,187,200,312,342,361`; `rar_test.go:265,429,480,527`; `handle_par_test.go:112,352`; `mfa_test.go:175`, `credential_health_test.go:397`; `introspect_batch_signed_test.go:101,139,163,223`; `introspection_cache_invalidation_test.go:105,122`; `refresh_rotation_claims_test.go:55`. Generated SDKs emit JSON to credential endpoints: `cmd/gensdk/gen_ts_runtime.go:158-159` (`Content-Type: application/json` + `JSON.stringify` for the client-auth ops selected by `tsUsesClientAuth`, gen_ts.go:101: postToken/postIntrospect/postRevoke/postPAR) and `cmd/gensdk/gen_py.go:103` | Confirmed — the sweep is real and larger than the direction's prose implies; §5 R5 inventories it |
| — (not cited in direction) global `BindParams` default flip blast radius | 44 non-test call sites total. Beyond the credential endpoints, `oauth.BindParams` is used by JSON-first surfaces: `interfaces/commerce/*` (subscriptions.go×4, payments.go×2, wallet.go, plans.go, payment_ingest.go — the last **requires** JSON: `normalizedJSON(ctx)` gate at payment_ingest.go:99, def at 215–218), `interfaces/admin/*` (8 files, 12 sites), `protocols/selfservice/*` (8 files: signup, verify_email, password_reset, email_change, data_export, selfserviceaccount/*), `internal/adminuser/handlers.go`×2. `/auth/login` is separately JSON-only (`rejectNonJSONLogin`, server_login.go:27) and does NOT use BindParams | New finding — a global default flip is wire-breaking for non-credential consumers; enforcement must be scoped to the credential parsing surface (see §5 decision) |
| T-8(b)(c)(e) / T-9 acceptance IDs | Campaign IDs (not literal test names). T-8(b): JSON body → 400; T-8(c): missing CT → 400; T-8(e): unexpected CT → 400; T-9: introspection caller-auth regression | Confirmed (self-contained in the direction text; restated testably in §5) |
| T-9 ordering claim "/introspect without credentials still returns 401 invalid_client before any body parsing" | Measured reality: `HandleIntrospect` binds the body (handle_introspect.go:120) **before** `authenticateIntrospectClient` (133); same order in `handleToken` (server_token.go:30 vs 35). Today an unauthenticated JSON-body introspect 401s only because JSON binds successfully; under T-8(b) the same request must 400. The retained regression for the form wire is unchanged: bind succeeds → auth gate → 401 | Confirmed with precedence conflict — resolved in R4 so T-8(b) and T-9 are jointly satisfiable |
| No existing unit tests for `BindParams` in `protocols/oauth/oauthwire` | Only `auth_code_handler_test.go`, `client_creds_test.go`, `refresh_token_test.go`, `token_exchange_helpers_test.go`, `fuzz_test.go` (bearer/basic fuzzers). Behavior is pinned indirectly by `test/oauth_bind_test.go` (`TestFormEncoded_*` family — the happy paths that must stay green) | Confirmed — strict-binder unit tests must be added in `oauthwire` |
| CIBA | `HandleBackchannelAuth` binds via `BindParams` (handle_ciba.go:87) at POST `/backchannel-authentication` (`PathBackchannelAuth`, shared/core/consts.go:33). RFC 8623 mandates form encoding; all CIBA tests already send form (`ciba_hardening_test.go:44-73`, `ciba_ping_test.go:67`, `ciba_push_test.go:115`) | Confirmed — CIBA is form-conformant already; enforcement is a no-op for its tests |
| OpenAPI contract | `docs/openapi.yaml` declares `application/json` alongside `application/x-www-form-urlencoded` for the request bodies of `/token` (line 988+), `/token/introspect` (1223+), `/token/revoke` (1327+), `/par` (1448+), `/device/code` (1523+), `/device/verify` (1820+), `/auth/mfa` (607, 643–646) | Confirmed — contract doc must drop the JSON variants (AGENTS.md §5.6) |

## 2. Goal and user outcome

RFC 6749 §3.2 / RFC 7662 §2.1 / RFC 7009 §2.1 / RFC 8628 §3.1 / RFC 9126 mandate `application/x-www-form-urlencoded` for OAuth credential endpoints. Today `oauthwire.BindParams` accepts `application/json` and — worse — defaults **missing** Content-Type and any unexpected Content-Type (multipart, text/plain, …) to JSON, so a bare POST with no Content-Type bypasses form semantics entirely on `/token`, `/token/introspect`, `/token/revoke`, `/par` (and the device/MFA/admin/CIBA bind sites). This keeps the endpoints open to JSON/multipart smuggling shapes and cacheability confusion (a no-Content-Type credential POST can be served stale by intermediaries that see no Vary/Content-Type signal).

Completion marker: every credential endpoint rejects `application/json`, missing Content-Type, and unexpected Content-Type with its canonical 400 error (`invalid_request`, or `mfa_invalid` on `/auth/mfa`) before any credential logic runs, while every form-urlencoded happy path and all existing grant tests stay green, and the introspection caller-auth 401 gate remains reachable for every form-encoded unauthenticated request.

## 3. Product boundary

- Surface: server wire contract (`protocols/oauth/oauthwire` + `protocols/oauth` handlers + `interfaces/sso` bind sites). Default: enforced unconditionally (this is a hardening change, not an opt-in; there is no config knob).
- Explicit non-goals (do not implement):
  - No change to `/auth/login`: it is JSON-only today (`rejectNonJSONLogin`, server_login.go:27) and stays that way. The SPA/login flow is untouched.
  - No change to non-credential `BindParams` consumers: `interfaces/commerce/*` (payment_ingest **requires** JSON — `normalizedJSON` gate), `interfaces/admin/*`, `protocols/selfservice/*`, `internal/adminuser/*` keep their current dual-mode/JSON wire semantics byte-identical. This is the wire-compat regression boundary; a global default flip in `BindParams` is rejected (see §5 decision).
  - No change to client-authentication ordering on `/token` (body parse → client auth, today's order, stays).
  - No new config keys, no new routes, no new `Err*` codes (the 400 shapes already exist), no changes to the no-store/`Cache-Control` behavior (already present at every site).
  - No SDK surface changes beyond what the caller sweep requires (`cmd/gensdk` emission of form bodies for credential ops).
  - Not in scope: B4-1 (tenant_id/roles claims) and B4-2 (scope registry) from the same analysis file.

## 4. Module classification

- [x] OAuth/OIDC/protocol flow (wire hardening)
- [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Infrastructure/config · [ ] Cold module · [ ] Refactoring only

Owning layers: `protocols/oauth/oauthwire` (the parsing surface), `protocols/oauth` (`handle_introspect.go`, `handle_par.go`, `handle_revoke.go`, `handle_ciba.go`), `interfaces/sso` (bind sites in server_token.go, server_device.go, server_mfa.go, server_admin_handlers.go, options_admin.go). Dependency direction unchanged: `interfaces/sso` → `protocols/oauth` → `shared/core`; no upward import introduced.

## 5. Requirements

### R1 — Credential endpoints accept only `application/x-www-form-urlencoded`

The parsing surface of the following endpoints must reject any other Content-Type before credential/request processing:

| Endpoint | Handler / bind site | Bind-failure response |
|---|---|---|
| POST `/token` | `handleToken`, server_token.go:30 | `400 invalid_request` |
| POST `/token/introspect` | `HandleIntrospect`, handle_introspect.go:120 | `400 invalid_request` |
| POST `/token/revoke` | `HandleRevoke`, handle_revoke.go:75 | `400 invalid_request` |
| POST `/par` | `HandlePAR`, handle_par.go:66 | `400 invalid_request` |
| POST `/device/code` | `handleDeviceCode`, server_device.go:53 | `400 invalid_request` |
| POST `/device/verify` | `handleDeviceVerify`, server_device.go:242 | `400 invalid_request` |
| POST `/auth/mfa` | `parseMFACompleteRequest`, server_mfa.go:255 | `400 mfa_invalid` (existing collapse; AGENTS.md oracle table) |
| POST `/backchannel-authentication` (CIBA) | `HandleBackchannelAuth`, handle_ciba.go:87 | `400 invalid_request` |

Reconciliation D3 (binding): the two admin:write compromise endpoints (`/api/v1/admin/credentials/{type}/compromise` at server_admin_handlers.go:293 and `/api/v1/admin/crypto/{id}/compromise` at options_admin.go:414) are **excluded** from this table — non-RFC-mandated bearer-admin control-plane APIs with JSON-only declared contracts; they keep dual-mode `BindParams`/`bindOAuthParams` exactly as today (JSON accepted, unchanged). See `docs/architect-analysis/b4-4-credential-form-sdk-binder-reconciliation.md` §3 D3. The strict surface is therefore **eight** endpoints.

Content-Type comparison is parameter-tolerant exactly as today (`bind.go:31-35` strips `;charset=…` etc., so `application/x-www-form-urlencoded; charset=UTF-8` still binds; `application/json; charset=utf-8` still rejects). Form parsing keeps `r.ParseForm` + `formIntoStruct` semantics unchanged (multi-value and space-separated `scope` handling, bool/int/slice field subset).

**Mechanism decision (evidence-backed):** the enforcement is added to the credential parsing surface — a strict form-only binder (e.g. `oauthwire.BindParamsFormOnly` / a strict flag) used by the eight sites above — while `BindParams`' dual-mode default remains for non-credential consumers. Rationale: a global default flip in `BindParams` breaks JSON-required consumers (`interfaces/commerce/payment_ingest.go:99` gates on `normalizedJSON`; `interfaces/admin/*`, `protocols/selfservice/*`, `internal/adminuser/*` are JSON-first) — a wire-compat regression AGENTS.md §1 forbids — and would require migrating 44 non-test call sites, far beyond this direction's effort and acceptance. The direction's "sweep of JSON callers of /token before flipping the default" is satisfied by R5 for credential endpoints.

### R2 — Missing and unexpected Content-Type are rejected

- Missing `Content-Type` header → same 400 as R1 (the "empty body + no Content-Type is treated as JSON" default at bind.go:24-25 is removed for the credential surface; there is no JSON default branch anymore).
- Unexpected Content-Type (`multipart/form-data`, `text/plain`, `application/octet-stream`, `application/json`, …) → same 400.
- A valid form-encoded body with an empty body (e.g. `Content-Type: application/x-www-form-urlencoded` and no fields) continues to reach the existing per-endpoint validation (e.g. `/token` → 400 `invalid_request` for missing `grant_type`), unchanged.

### R3 — Form-urlencoded happy paths and all existing grant tests stay green

Every grant and credential flow keeps passing on the form wire: client_credentials, authcode, refresh (with rotation), device (initiate + poll + approve), PAR → authorize, introspection (single + opt-in batch with repeated form `tokens` fields), revocation (idempotent 200), MFA complete, CIBA, `test/oauth_bind_test.go` `TestFormEncoded_*` family, `test/scope_registry_test.go` (already form, lines 106-137), `test/ciba_*` (already form). The two admin compromise endpoints keep passing on **both** wires unchanged (dual-mode, reconciliation D3). HTTP Basic precedence over body credentials (AGENTS.md §3, `test/oauth_bind_test.go` `TestFormEncoded_BasicAuthOverridesBodyCreds`) is unchanged.

### R4 — T-9 regression: introspection caller auth is retained

Preserved verbatim from the direction: *"T-9 regression retained: /introspect without credentials still returns 401 invalid_client before any body parsing."*

Testable interpretation (resolves the precedence conflict measured in §1): today's order is body-parse → client auth (handle_introspect.go:120 → 133). Under R1/R2 an unauthenticated **JSON** request necessarily 400s at the parse stage — that is the direction's own T-8(b) mandate and is the intended precedence change. The retained regression is: **for every request whose body binds on the form wire, an unauthenticated /token/introspect returns `401 invalid_client`, never `400 invalid_request` and never a 200**; the existing regression tests (`TestIntrospect_RejectsMissingCreds`, `TestIntrospect_RejectsWrongSecret`, `TestIntrospect_AcceptsBasicAuth` — test/handle_introspect_test.go:174-215) migrate to form-encoded bodies and stay green, with `authenticateIntrospectClient` (handle_introspect.go:202) untouched. The alternative reading — moving client auth ahead of body parsing — is rejected: body-credential authentication (`client_id`/`client_secret` in the body, exercised by the `postIntrospect` helpers and presupposed by the AGENTS.md invariant "HTTP Basic wins over body credentials on /token, /introspect, /revoke, /par") would become unreachable.

### R5 — Caller sweep: migrate every in-repo JSON caller of credential endpoints

Required before the enforcement lands, so `make ci` stays green:

1. **Tests** — convert the JSON posts in §1's sweep inventory to `application/x-www-form-urlencoded` bodies (url.Values encoding of the same fields), including the `postIntrospect`/`postRevoke` helpers (test/handle_introspect_test.go:82-100, 228-240), `postForm`-style helpers, and the `/auth/mfa` JSON posts (`mfa_test.go:175`, `credential_health_test.go:397`). Byte-for-byte same assertions, same status codes; only the wire changes.
2. **Invert the JSON-fallback test** — `TestFormEncoded_JSONStillWorks` (test/oauth_bind_test.go:263-283) becomes the negative case: `application/json` on `/token` → 400 `invalid_request`.
3. **Generated SDKs — DEFERRED (reconciliation D1/D2, binding)**: no `cmd/gensdk` or `docs/sdks/*` change in this workstream. The generated SDKs' form emission for the seven in-surface credential ops is delivered by the gensdk workstream (`docs/architect-analysis/cmd-gensdk-b4-4-credential-form-design.md`), driven by `op.ContentType` (not the `tsUsesClientAuth` 4-op list — it omits postDeviceCode/postDeviceVerify/postMFAComplete). The gensdk serializers' value rules are the binding wire contract this workstream's server semantics must match. The two admin compromise SDK ops stay JSON (D3).
4. **OpenAPI** — drop the `application/json` requestBody variant from the **eight** strict paths: `/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/code`, `/device/verify`, `/auth/mfa`, **and `/backchannel-authentication`** (D5: the CIBA path is dual-content and its server site is strict; the earlier "seven paths" undercounted). Do **not** touch the two admin compromise paths (JSON-only, dual-mode — D3). Form stays the sole request content type on the eight strict paths.
5. **Do NOT migrate** (out of scope by design): `/auth/login` (JSON-only), `interfaces/commerce/*`, `interfaces/admin/*`, `protocols/selfservice/*`, `internal/adminuser/*` — their wire semantics are untouched by the scoped mechanism.

### Testable acceptance (Given/When/Then)

T-8(b) — JSON body (new negative tests in `test/oauth_bind_test.go` or `test/credential_content_type_test.go`, httptest harness as today):

1. Given a valid grant request body (client_credentials, authcode exchange, refresh, device poll, PAR, introspect, revoke) sent as `application/json`, when posted to `/token`, `/token/introspect`, `/token/revoke`, `/par`, then 400 with `{"error":"invalid_request"}` in every case and no token issued / no side effect (no revocation, no PAR stored, no device code minted).
2. Given the same JSON bodies on `/device/code` and `/device/verify`, then 400 `invalid_request`.
3. Given the same on `/auth/mfa`, then 400 `mfa_invalid` (byte-identical to the existing MFA-failure envelope, details only in `mfa_failure` audit).
4. Given the same on `/auth/mfa`, then 400 `mfa_invalid` (byte-identical to the existing MFA-failure envelope, details only in `mfa_failure` audit).

   (Reconciliation D3: the former case-4 row for `/api/v1/admin/credentials/{type}/compromise` and `/api/v1/admin/crypto/{id}/compromise` is removed — those two endpoints are a declared non-goal: they stay dual-mode, JSON accepted. The generated `adminCompromiseCredential`/`adminReportCryptoKeyCompromise` SDK ops remain JSON byte-identical.)

T-8(c) — missing Content-Type:

5. Given any of the eight strict endpoints with a bare `http.Post`-style request (no Content-Type header) and a JSON-shaped or form-shaped body, then 400 with the endpoint's canonical error (invalid_request, or mfa_invalid on `/auth/mfa`).
6. Given missing Content-Type with an empty body on `/token`, then 400 `invalid_request` (the old JSON-default path is gone).

T-8(e) — unexpected Content-Type:

7. Given `multipart/form-data`, `text/plain`, and `application/octet-stream` bodies on `/token`, `/token/introspect`, `/token/revoke`, `/par`, then 400 `invalid_request` in all twelve combinations.
8. Given `application/x-www-form-urlencoded; charset=UTF-8` (parameter-tolerant parse), then the request binds and proceeds (200/expected result), proving the media-type comparison strips parameters.

Form happy paths and regression (R3/R4):

9. Given the full `TestFormEncoded_*` family (test/oauth_bind_test.go) and `test/scope_registry_test.go` + `test/ciba_*` + grant-suite tests, when run unmodified (they already use form), then all stay green.
10. Given the sweep-migrated tests from R5.1 (authcode, pkce, refresh, claims, oidc, device, rar, par, mfa, introspect incl. batch, introspection cache invalidation, token 401s), when run, then all assertions unchanged and green on the form wire.
11. Given `TestIntrospect_RejectsMissingCreds` / `TestIntrospect_RejectsWrongSecret` migrated to form bodies, then still 401 `invalid_client` (T-9).
12. Given an unauthenticated form-encoded `/token/introspect` with a valid token field, then 401 `invalid_client` — the auth gate is reached for every bindable request (T-9).
13. Given HTTP Basic + form body on `/token`, `/token/introspect`, `/token/revoke`, `/par`, then Basic wins over body credentials exactly as `TestFormEncoded_BasicAuthOverridesBodyCreds` asserts today.
14. Given the credential-endpoint error responses (400/401), then `Cache-Control: no-store` + `Pragma: no-cache` are present (already stamped before parsing at every site — regression-pinned).
15. Given the generated SDKs regenerated per R5.3, then `postToken`/`postIntrospect`/`postRevoke`/`postPAR` emitted code sends form-encoded bodies and the SDK's emit tests pass against a server with the enforcement on.

Unit level:

16. Given `oauthwire` strict binder unit tests (new file in `protocols/oauth/oauthwire/`), then: form CT → binds; `application/json` → error; missing CT → error; `multipart/form-data` → error; `application/x-www-form-urlencoded; charset=UTF-8` → binds; empty body with form CT → binds empty (per-endpoint validation downstream); JSON body with trailing garbage under form CT → `ParseForm` error path.

## 6. Engineering-gate constraints (verified)

- **Budgets**: no new packages; `oauthwire/bind.go` (140 lines) grows by one strict entry point — stay under the 500-line file / 50-line function / complexity 15 / nesting 3 budgets. No `interfaces/sso` new files needed if the strict binder lives in `oauthwire` (aliased through `protocols/oauth` as today); `interfaces/sso` is at its 60-file ceiling, so the bind sites only change the call target, never file count.
- **Oracle safety**: the ten bind-failure responses reuse existing bodies (`invalid_request` / `mfa_invalid`); no new distinguishable output is introduced. `/auth/mfa` keeps the `mfa_invalid` collapse per the AGENTS.md oracle table ("Any MFA failure → 400 mfa_invalid").
- **Wire compatibility**: non-credential `BindParams` consumers (commerce/admin/selfservice) are byte-identical by design (§5 decision); the CLI is unaffected (gRPC-gateway admin routes, verified).
- **Headers**: no-store/Pragma stamping stays at the top of every handler, before parsing — the documented middleware order and probe-outside-rate-limiting posture are untouched.
- **Dependency direction**: enforcement is added in `protocols/oauth/oauthwire`; `interfaces/sso` continues to import downward; nothing imports `cmd/`.

## 7. Files

### Create

```text
protocols/oauth/oauthwire/bind_strict.go — strict form-only binder (form CT → ParseForm →
    formIntoStruct; any other/missing CT → error), factored so BindParams can delegate or stay
    separate; package doc updated to drop the "JSON convenience" claim for the strict surface.
protocols/oauth/oauthwire/bind_strict_test.go — unit acceptance cases 16.
test/credential_content_type_test.go — endpoint-level negative tests (cases 1–8) on the
    existing httptest harness pattern (test/oauth_bind_test.go newFormHarness).
```

### Modify

```text
interfaces/sso/server_token.go:30, server_device.go:53,242, server_mfa.go:255,
    server_admin_handlers.go:293, options_admin.go:414 — switch the credential bind sites
    to the strict binder via bindOAuthParams (server_jar.go:304) or a strict sibling.
protocols/oauth/handle_introspect.go:120, handle_par.go:66, handle_revoke.go:75,
    handle_ciba.go:87 — same switch for the protocol-layer sites (via the oauth alias).
protocols/oauth/aliases.go:97 — alias the strict binder alongside BindParams.
test/oauth_bind_test.go — TestFormEncoded_JSONStillWorks inverted to the JSON-rejection
    negative; JSON posts converted to form in the TestFormEncoded_* helpers if any.
test/handle_introspect_test.go, handle_token_test.go, auth_code_test.go, pkce_test.go,
    refresh_token_test.go, refresh_rotation_claims_test.go, claims_param_test.go,
    oidc_test.go, handle_device_test.go, rar_test.go, handle_par_test.go, mfa_test.go,
    credential_health_test.go, introspect_batch_signed_test.go,
    introspection_cache_invalidation_test.go — R5.1 wire migration (fields identical).
test/introspection_jwt_test.go, test/frontend_contract_test.go — R5.1 additions (gate F5):
    both post JSON to credential paths (introspection_jwt_test.go:70 `postIntrospectAccept`
    used at :89/:162/:180; frontend_contract_test.go:106 `fcPost` → /token at :207/:325).
cmd/gensdk/gen_ts_runtime.go:158-159, gen_py.go:103, cmd/gensdk/emit_test.go, docs/sdks/typescript/client.ts,
    docs/sdks/python/client.py — do NOT modify: SDK form emission is the gensdk workstream's deliverable
    (reconciliation D1/D2); this workstream's former R5.3 step is withdrawn.
docs/openapi.yaml — R5.4: drop application/json requestBody variants on the eight strict paths
    (incl. /backchannel-authentication; not the two admin compromise paths).
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go's dual-mode default (lines 37-45) — non-credential
    consumers depend on it; the strict surface is additive.
cmd/gensdk/*, docs/sdks/* — SDK emission is the gensdk workstream's exclusive deliverable
    (reconciliation D1/D2); this workstream does not modify the generator, runtimes, or
    committed SDK artifacts.
interfaces/sso/server_login.go — /auth/login stays JSON-only.
interfaces/commerce/*, interfaces/admin/*, protocols/selfservice/*,
    internal/adminuser/* — JSON/dual-mode wire semantics unchanged.
interfaces/sso/server_admin_handlers.go:293, options_admin.go:414 — the two admin
    compromise sites stay dual-mode (reconciliation D3).
shared/security/client_secret.go, internal/handler/tokengrant/token_client_credentials.go,
    tokenNoStoreHeaders — verified present; no work.
```

Confirm file/function/directory frozen ceilings before implementation.

## 8. Dependencies and compatibility

- New/changed SPI: `oauthwire.BindParamsFormOnly` (naming TBD at implementation) + `protocols/oauth` alias; no interface changes, no store changes.
- New option/store wiring: none.
- New YAML/env keys: none.
- Storage migration: none.
- HTTP/proto compatibility: **breaking by design** — the eight credential endpoints stop accepting `application/json`/missing/unexpected Content-Type (400). Any out-of-tree client that sent JSON or omitted Content-Type to `/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/*`, `/auth/mfa`, or `/backchannel-authentication` must send form-encoded; all in-repo consumers are migrated by R5. The two admin compromise endpoints are **not** affected (dual-mode, D3) — out-of-tree admin callers keep sending JSON.
- Rollout/rollback: single-commit behavior change; revert restores the JSON default. Documented in CHANGELOG as a hardening/breaking wire change.

## 9. Documentation

- [x] `docs/openapi.yaml` — remove the `application/json` requestBody variants from the eight strict paths: `/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/code`, `/device/verify`, `/auth/mfa`, `/backchannel-authentication` (D5); add a form-only note (schema already exists for form); do not touch the two admin compromise paths (D3).
- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [x] `docs/error-codes.md` — no new `Err*`; verify the `invalid_request` row(s) do not document JSON acceptance on these endpoints; add a line noting credential endpoints accept form only (if the doc currently implies otherwise).
- [x] CHANGELOG — breaking wire-change entry.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./protocols/oauth/oauthwire/... -run 'TestBindStrict|Fuzz' -v   # new unit surface
go test ./test/ -run 'TestFormEncoded_|TestToken_|TestIntrospect_|TestRevoke_|TestPAR|TestDevice|TestMFA|TestCIBA' -v
go test ./cmd/gensdk/... -run TestEmit -v                             # regenerated SDKs
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

Pre-existing failures to report separately: none known in the cited surface; `checks/directory_fanout.py` state unchanged by this spec (no new packages).
