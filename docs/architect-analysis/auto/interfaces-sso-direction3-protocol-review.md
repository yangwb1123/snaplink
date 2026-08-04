# Protocol Review — interfaces/sso Direction 3 design (thin-delegate sinking) against the live wire surface

Input under review: `docs/auto/interfaces-sso-direction3-design.md` (route-mount
sinking, admin-surface extraction, file-ceiling ratchet). The design is a
behavior-preserving refactor; the review verifies (a) the wire surface the
refactor must not change, (b) the design's own protocol-adjacent claims
(gates, routes, constants), and (c) the current compliance posture of the
protocols in scope, so the refactor's acceptance gates can be pinned to the
right invariants.

Baseline: `ai-dev/prompts/README.md` evidence standard; `AGENTS.md` §2/§3 as
regression boundaries; prior review format follows
`interfaces-apidocs-direction1-protocol-review.md`.

## Review method and what actually ran

- `python cli.py check-routes` — ran at this revision: `PASS: route/OpenAPI
  contract (241 runtime routes, 322 documented operations)`.
- `go test ./protocols/oauth/ -run 'TestHandlePAR|TestHandleRevoke|TestBindParams' -count=1` — ran: `ok`.
- `go test ./protocols/oidc/ -run 'EndSession|JARM|UserInfo|SilentRenewal' -count=1` — ran: `ok`.
- `go test ./protocols/caep/ -run 'TestReceiver|TestStream' -count=1` — ran: `ok`.
- Source inspection of every cited location (all **Verified** unless marked):
  `interfaces/sso/server_token.go`, `server_token_clientauth.go`,
  `server_login.go`, `server_discovery.go`, `server_discovery_config.go`,
  `server_device.go`, `server_pairwise.go`, `handlers.go`,
  `internal/handler/tokengrant/{token_authcode,token_refresh,token_device,token_ciba}.go`,
  `protocols/oauth/{handle_par,handle_revoke,handle_introspect,paramlimits}.go`,
  `protocols/oidc/{handle_userinfo,handle_silent_renewal,metadata,jarm}.go`,
  `protocols/caep/{receiver_receive,security_event_token}.go`,
  `infrastructure/saml/`, `protocols/scim/`, `domains/authenticators/webauthn/`,
  `directory_fanout_test.go`, `docs/openapi.yaml`, `docs/error-codes.md`,
  `docs/feature-matrix.md`, `docs/sso/oidc-conformance.md`,
  `test/oidc-conformance/README.md`.
- Full `go test ./...` / `make ci` were NOT run: this review changes no code;
  the per-`.go`-edit mandatory gates are not applicable.

## 1. Protocol/profile scope and authoritative references

The change is route-mount relocation; the wire surface is the OAuth 2.0 /
OIDC family plus the optional protocol modules. Standards actually in scope:

| Reference | Relevance |
|---|---|
| RFC 6749 (OAuth 2.0), RFC 6750 (Bearer), RFC 7009 (Revocation), RFC 7662 (Introspection), RFC 7591/7592 (DCR), RFC 7636 (PKCE), RFC 8414 (AS Metadata), RFC 8628 (Device), RFC 8693 (Token Exchange), RFC 8705 (mTLS), RFC 8707 (Resource Indicators), RFC 9101 (JAR), RFC 9126 (PAR), RFC 9207 (iss), RFC 9396 (RAR), RFC 9449 (DPoP), RFC 9472 (JWT Introspection), RFC 9470 (step-up ACR), RFC 7521/7523 (client assertion / JWT-bearer), RFC 7522 (SAML-bearer), RFC 9068 (JWT access tokens), RFC 9321 (Txn-Token), RFC 9728 (Protected Resource Metadata) | Core wire contracts; every route and gate the refactor must leave byte-identical |
| OIDC Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0, Front/Back-Channel Logout 1.0, Session Management 1.0, Form Post Response Mode 1.0, JARM, CIBA Core 1.0 | OIDC surface served from `interfaces/sso` + `protocols/oidc` |
| OAuth 2.0 Security BCP (RFC 9700), OAuth 2.1 (profile), FAPI 2.0 Security Profile | Refresh-family reuse, sender constraints, strict-mode narrowing |
| RFC 8417 (SET), RFC 8935/8936 (SSF), RFC 9491 (CAEP token-revocation), RFC 9493 (Subject Identifiers), OpenID Federation 1.0 | `protocols/caep`, federation mounts |
| SAML 2.0 Core/Web SSO/SLO; RFC 7643/7644 (SCIM 2.0); W3C WebAuthn Level 2 | Nested modules / optional surfaces |
| OIDF conformance suite (gitlab.com/openid/conformance-suite) | Harness only; **no certification** (see §5) |

## 2. Compliance matrix

Legend: requirement level per the governing reference (MUST/SHOULD/MAY);
status per this revision's code. `sso/…` = `interfaces/sso/…`,
`tokengrant/…` = `internal/handler/tokengrant/…`.

### 2.1 Discovery and metadata

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M1 | OIDC Discovery 1.0 §4: issuer + endpoint set | `buildBaseMetadata` (sso/server_discovery_config.go:75-108); `handleOIDCDiscovery` (server_discovery.go:179) | **Verified — compliant** | Issuer = `WithIssuer` override else request base URL; §4.3 canonicalization inherited from `middleware.BaseURL` (no trailing slash) | `oidc_discovery_test.go`, `rootcov2_discovery_test.go` |
| M2 | RFC 8414 §3: `/.well-known/oauth-authorization-server` | `mountDiscovery` registers both paths on the SAME handler (server_discovery.go:18-26); OIDC doc is a compatible superset | **Verified — compliant** | Superset is legal (§2: "additional fields MAY"); document includes `response_types_supported: ["code","token"]` (direct-mint branch) — honest advertisement, narrowed to `code` under OAuth 2.1 strict (`oauth21_strict_test.go`) | `oidc_discovery_test.go` |
| M3 | RFC 8414 §2.1 `signed_metadata` | `signDiscoveryMetadata` (server_discovery_config.go:22-44), JWS of finalized claims | **Verified — compliant** | Opt-in (`WithMetadataSigner`) | `signed_metadata_test.go` |
| M4 | RFC 9126 §5 PAR endpoint + `require_pushed_authorization_requests` | `applyGrantEndpoints` (server_discovery_config.go:233-258); flag flips when ANY registered client has `RequirePAR` | **Verified — compliant** | AS-wide boolean semantics acknowledged (strictest-possible-promise) | `require_par_test.go` |
| M5 | RFC 9101 §10.5 `request_parameter_supported` / `require_signed_request_object` | `applyClientAuthAndRequestParams`, `applyStaticClaimsAndSecurity` | **Verified — compliant** | `request_uri` flips true only when a fetcher is wired; alg list = `security.AsymmetricJWSAlgValues()` — advertises exactly what the wire accepts | `jar_test.go` |
| M6 | RFC 8414 §2 client-auth methods on token/introspect/revoke/par | `applyClientAuthAndRequestParams` (server_discovery_config.go:110-159) | **Verified — compliant** | Revocation list omits `none` — matches implementation (see F4) | `discovery_auth_methods_test.go` |
| M7 | RFC 9728 protected-resource metadata | `PathProtectedResourceMetadata` (shared/core/consts.go:57-62), opt-in | **Verified — compliant** | — | `protected_resource_metadata_test.go` |
| M8 | RFC 8414 §2.1: signed_metadata MUST match plaintext fields | signing runs after every `apply*` layer (buildOIDCConfiguration:34-53) | **Verified — compliant** | — | `signed_metadata_test.go` |

### 2.2 Authorization endpoint (`/auth/login`)

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M9 | RFC 6749 §4.1.1 code issuance; `state` echoed on success AND error | `authzErrorBodyWithState` (server_discovery.go:318-331) | **Verified — compliant** | — | `iss_response_test.go` |
| M10 | RFC 9207 §2: `iss` on every authorization response | `resolveIssuer` + `authzErrorBody` (server_discovery.go:242-316); `authorization_response_iss_parameter_supported=true` | **Verified — compliant (adapted)** | Server is a JSON BFF, not a 302 redirect; `iss` travels in the JSON body, not the redirect query — acknowledged adaptation in the RFC 9207 comment block (server_discovery.go:230-241). See F3 | `iss_response_test.go` |
| M11 | OIDC Core §3.1.2.1: `prompt=none` silent renewal; §3.1.2.6 `login_required` | `HandleSilentRenewal` (protocols/oidc/handle_silent_renewal.go:78-121); auth_time/AMR preserved from original login | **Verified — compliant** | — | `handle_silent_renewal_test.go`, `prompt_test.go` |
| M12 | OIDC Core §3.1.2.5: response modes | `renderFormPostResponse` (server_discovery.go:340-353), `isValidResponseMode`; JARM modes fail closed when no signer | **Verified — partial** | `query`/`fragment` are accepted but not applied server-side (JSON BFF — the SPA handles delivery); `form_post` renders the auto-submit HTML. See F3 | `form_post_response_mode_test.go`, `jarm_test.go` |
| M13 | JARM (JWT Secured Authorization Response Mode) | `protocols/oidc/jarm.go`; modes `jwt/query.jwt/fragment.jwt/form_post.jwt` advertised only when `jarmSigner` wired | **Verified — compliant** | Fail-closed without signer (`invalid_request`) | `jarm_test.go` |
| M14 | OIDC Core §3.1.2.1 response types | `finishLoginDispatch` (server_finish_login.go:50-55): `code` + direct-mint `token`; everything else `unsupported_response_type` | **Verified — declared boundary** | Implicit/hybrid intentionally unsupported (see §5) | `oidc-conformance` module allowlist |
| M15 | RFC 6749 §10.2 CSRF / origin defense | `rejectNonJSONLogin` (415 for form-encoded), `rejectDisallowedLoginOrigin` (server_login.go:26-31) | **Verified — compliant** | Stricter than spec (JSON-only body gate) | `origin_validation_test.go` |

### 2.3 Token endpoint (`/token`)

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M16 | RFC 6749 §5.1: `Cache-Control: no-store` on success AND error | `tokenNoStoreHeaders(ctx)` first statement of `handleToken` (server_token.go:17-19) and of every credential endpoint | **Verified — compliant** | — | `token_no_store_test.go` |
| M17 | RFC 6749 §2.3.1: HTTP Basic wins over body | `authenticateTokenClient` (server_token_clientauth.go:146-152); same precedence on /introspect /revoke /par | **Verified — compliant** | — | `oauth_bind_test.go`, `jwt_client_assertion_endpoints_test.go` |
| M18 | RFC 6749 §5.2 oracle collapse | unknown/expired/consumed code, client mismatch, redirect_uri mismatch, PKCE failure, DPoP jkt mismatch all → 400 `invalid_grant` (`authCodeValidate`, tokengrant/token_authcode.go:131-190) | **Verified — compliant** | §5.2 defines no `invalid_redirect_uri` for token endpoint — correct collapse | `auth_code_test.go`, `rootcov2_*` |
| M19 | RFC 7636 PKCE; verifier bounds | length bounds + `VerifyPKCE` collapse to `invalid_grant` (token_authcode.go:167-175); S256-only in OAuth 2.1 strict / FAPI enforce | **Verified — compliant** | — | `pkce_test.go`, `pkce_allowlist_test.go`, `oauth21_strict_test.go` |
| M20 | RFC 6749 §6 refresh; BCP §4.13 single-use + family reuse kill | `HandleRefreshGrant` (token_refresh.go:90-131): atomic `Consume`, `DeleteFamily` fail-closed on reuse, grace-window idempotent replay | **Verified — compliant** | — | `refresh_token_family_test.go`, `refresh_grace_test.go` |
| M21 | RFC 6749 §6 scope subset; expansion forbidden | `refreshResolveScopes` — expansion → distinct `invalid_scope` (not an oracle) | **Verified — compliant** | — | `refresh_token_test.go` |
| M22 | RFC 9449 DPoP (issuance side) | `captureSenderConstraint` (server_token.go:283-338): typ/htm/htu/iat/jti, nonce challenge `use_dpop_nonce`, JKT binding; token_type=DPoP via `DPoPTokenTypeOr` | **Verified — compliant** | DPoP opt-in per request (never required unless FAPI enforce) | `dpop_test.go`, `dpop_nonce_test.go`, `dpop_clock_skew_test.go` |
| M23 | RFC 8705 §3 certificate-bound tokens (`cnf.x5t#S256`) | `captureSenderConstraint` mtls leg; mutually exclusive with DPoP | **Verified — compliant** | — | `mtls_bound_test.go` |
| M24 | RFC 8707 resource indicators | client allowlist check → `invalid_target` (server_token_clientauth.go:186-190); RFC 9396 `authorization_details` carried through grants + rotations | **Verified — compliant** | — | `resource_indicators_test.go`, `rar_test.go` |
| M25 | RFC 8693 token exchange; §4.1 `act` chain | `HandleTokenExchangeGrant` (tokengrant/token_exchange.go:107+); cycle detection, chain-store, JTI replay, RFC 9470 ACR step-up | **Verified — compliant** | — | `token_exchange_test.go`, `token_exchange_actor_replay_test.go`, `token_exchange_acr_test.go` |
| M26 | RFC 7523 JWT-bearer grant; RFC 7522 SAML-bearer | `HandleJWTBearerGrant`, `SAML2BearerValidator` (opt-in) | **Verified — compliant** | SAML bearer lives in the nested `infrastructure/saml` module | `saml_bearer_grant_test.go` |
| M27 | RFC 9321 Transaction Token | `dispatchTokenExchangeOrTxnToken` (server_token.go:229-243), `protocols/oauth/txntoken` | **Verified — compliant** | Opt-in | `txntoken` tests |
| M28 | RFC 9068 §2.2 claim preservation | auth_time/AMR/ACR from original login through code exchange, refresh rotation, silent renewal, CIBA approval, token exchange | **Verified — compliant** | — | `refresh_rotation_claims_test.go`, `claims_acr_test.go` |
| M29 | RFC 7521/7523 §2.2 client-assertion auth (`private_key_jwt`) | `verifyJWTClientAssertion` (server_pairwise.go:171-227): iss==sub, aud==AS issuer, exp+max-lifetime, nbf, jti replay, alg allowlist BEFORE verify | **Verified — compliant** | Failure → 401 `invalid_client` (AGENTS.md §3) | `jwt_client_assertion_test.go`, `jti_replay_test.go` |
| M30 | RFC 8705 §2 `tls_client_auth` / `self_signed_tls` | `authenticateMTLSClient` (server_token_clientauth.go:243-288): DN/SAN binding or JWK public-key match, optional revocation check (fail-open) | **Verified — compliant** | mTLS *binding* is not counted as FAPI client-auth (deliberate, comment at server_token.go:368-372) | `mtls_revocation_test.go` |
| M31 | RFC 6749 §4.4 client_credentials confidential-only | `denyPublicClientCredentials` (server_token.go:339-356) | **Verified — compliant** | mTLS-only clients exempt (auth already proven) | `client_creds_test.go` |
| M32 | RFC 6749 §5.2: unknown grant_type | `dispatchTokenGrant` default → 400 `unsupported_grant_type` + `supported_grants` list | **Verified — compliant** | — | `handle_token_test.go` |
| M33 | Rate limiting of grants | `checkGrantRateLimit` (server_token.go:389-399) | **Non-compliant error code** | 429 with body `{"error":"unsupported_grant_type"}` — see F2 | `ratelimit_e2e_test.go` (status only) |

### 2.4 Introspection, revocation, DCR

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M34 | RFC 7662 §2.1 client auth; §2.2 inactive → `{"active":false}` | `HandleIntrospect` (protocols/oauth/handle_introspect.go:109); no metadata on inactive | **Verified — compliant** | — | `handle_introspect_test.go`, `introspection_cache_invalidation_test.go` |
| M35 | RFC 9472 JWT introspection | `Accept: application/token-introspection+jwt` (openapi.yaml:1194) | **Verified — compliant** | Opt-in | `introspection_jwt_test.go`, `introspection_sign_test.go` |
| M36 | RFC 7009 §2.2 always-200 on valid creds | `HandleRevoke` (protocols/oauth/handle_revoke.go:67-107); hint-driven dual-tier, cache eviction | **Verified — compliant** | — | `handle_revoke_test.go`, `mtls_revocation_test.go` |
| M37 | RFC 7009 §2.1 public-client revocation | `authenticateRevokeClient` requires creds or assertion | **Verified — deviation (documented)** | Public clients (auth `none`) get 401; discovery list omits `none` — self-consistent, see F4 | `handle_revoke_test.go` |
| M38 | RFC 7591 DCR; RFC 7592 read/update/delete | `handle_register.go`; rate-limit-gated | **Verified — compliant** | No software-statement processing (declared, RFC 7591 §2.4) | `handle_register_test.go`, `handle_register_mgmt_test.go` |
| M39 | RFC 9126 PAR | `HandlePAR` (protocols/oauth/handle_par.go:54); `urn:ietf:params:oauth:request_uri:` response, 90s expiry, Basic-wins auth | **Verified — compliant** | — | `handle_par_test.go`, `require_par_test.go` |
| M40 | RFC 9101 JAR + §6.4 JWE | `server_jar.go`, `securityverify/jar_fetch.go`, `shared/security/jwe.go` | **Verified — compliant** | `request_uri` fetch opt-in; request-object length caps (`paramlimits.go`) | `jar_test.go`, `jar_fetch_test.go`, `jwe_test.go` |

### 2.5 Userinfo, logout, sessions

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M41 | OIDC Core §5.3 userinfo (JSON / signed / encrypted) | `HandleUserInfo` (protocols/oidc/handle_userinfo.go:41-77); no-store; RFC 6750 §3 bearer challenge | **Verified — compliant** | — | `oidc_userinfo_test.go`, `userinfo_signed_test.go`, `jwe_response_test.go` |
| M42 | OIDC Core §5.5 claims projection | `ProjectIDTokenClaims` at login + exchange | **Verified — compliant** | — | `claims_param_test.go` |
| M43 | OIDC Core §3.1.3.6 `at_hash` | required when access token accompanies id_token (protocols/oidc/types.go:28-33) | **Verified — compliant** | — | `oidc_test.go` |
| M44 | RP-Initiated Logout 1.0 §2 | `HandleEndSession` (protocols/oidc/handle_end_session.go): id_token_hint sig-checked, exact-match redirect allowlist, 204 on reject | **Verified — compliant** | 204 (no redirect) on missing/unmatched URI is the spec's "SHOULD NOT redirect" | `handle_end_session_test.go` |
| M45 | Back-Channel Logout 1.0 §2.1; Front-Channel Logout 1.0 | logout-token issuer + notifier; FCL iframe render; `sid` threading; advertised only when wired | **Verified — compliant** | — | `backchannel_logout_test.go`, `frontchannel_logout_test.go`, `bcl_multirp_test.go` |
| M46 | Session Management 1.0 `check_session_iframe` | opt-in, advertised only when enabled | **Verified — compliant** | — | `sid_test.go` |

### 2.6 Device, CIBA

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M47 | RFC 8628 §3.2 response (device_code, user_code, verification_uri[_complete], expires_in, interval) | `respondDeviceCode` (server_device.go:105-120) | **Verified — compliant** | — | `handle_device_test.go` |
| M48 | RFC 8628 §3.5 poll sentinels | `devicePollGate` (tokengrant/token_device.go:113-151): `authorization_pending`, `slow_down`, `access_denied`, `expired_token`→`invalid_grant`, client binding | **Verified — partial** | `slow_down` never grows the interval by 5s (MUST) — see F1 | `rootcov2_device_errors_test.go` |
| M49 | OIDC CIBA Core §7 backchannel + poll | `handle_ciba.go`, `cibaPollGate` (tokengrant/token_ciba.go:178-216); ping/push modes when notifiers wired; `backchannel_user_code_parameter_supported=false` | **Verified — partial** | Same `slow_down` interval-growth gap (CIBA §7.1 MUST) — see F1; unknown auth_req_id collapses to `expired_token` (documented oracle choice) | `ciba_hardening_test.go`, `ciba_ping_test.go`, `ciba_push_test.go` |

### 2.7 CAEP / SSF / Federation

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M50 | RFC 8417 §2.2/2.3 SET shape (`typ=secevent+jwt`, iss, jti, iat/exp, events) | `security_event_token.go`; `DefaultSETTTL=2min` | **Verified — compliant** | — | `stream_adversarial_test.go` |
| M51 | RFC 8935/8936 receiver: trusted-iss allowlist, alg-before-verify, typ gate, strict aud, temporal window, jti replay fail-closed | `receiver_receive.go:101-240` | **Verified — compliant** | Missing temporal claims rejected fail-closed (stricter than RFC 8417's optional exp) | `ssf_receiver_test.go`, `receiver_test.go` |
| M52 | RFC 9491 token-revoked event; CAEP session-revoked/token-claims-change | `event_mapper.go`, `broadcaster.go` | **Verified — compliant** | — | `caep_integration_test.go`, `webhook_revocation_test.go` |
| M53 | RFC 9493 subject identifiers | opaque `{format:opaque,id}` only | **Verified — declared subset** | email/iss_sub/phone formats v2 | `transmitter_test.go` |
| M54 | OpenID Federation 1.0 §8/§9 entity config, fetch, resolve, listing, historical keys | `server_federation.go` + `domains/federation` | **Verified — compliant** | Opt-in; fetch vouches only for operator-configured keys | `federation_test.go`, `federation_e2e_test.go` |

### 2.8 SAML, SCIM, WebAuthn (nested/optional surfaces)

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M55 | SAML 2.0 Web SSO (IdP + SP), SLO (front/back channel), metadata | `infrastructure/saml/` (own go.mod): assertion signer, metadata handler, fan-out, SP SLO | **Verified** | Nested module — stock binary wiring is separate (`serverbuild*`); core repo ships path literals only | `saml_test.go`, `saml_slo_test.go` |
| M56 | SCIM 2.0 (RFC 7643/7644): Users/Groups CRUD, PATCH, filters, sorting, paging, bulk, ETag | `protocols/scim/` (`filter.go`, `bulk.go`, `etag.go`, `dispatch.go`), `/api/v1/scim/v2/*` | **Verified** | Module surface; conformance suite not run | `scim` package tests, `scim_deprovision_login_test.go` |
| M57 | WebAuthn L2 ceremonies, attestation policy, conditional UI, primary passwordless login | `domains/authenticators/webauthn/` | **Verified** | Attestation/MDS policy configurable | `webauthn_primary_login_test.go`, `me_mfa_webauthn_test.go` |

### 2.9 Profiles

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M58 | OAuth 2.1 (profile): code-only, S256, PKCE for public clients | `responseTypesFor`/`codeChallengeMethodsFor` strict mode; direct-mint rejected | **Verified** | Opt-in | `oauth21_strict_test.go` |
| M59 | FAPI 2.0 Security Profile (enforce/inspect) | `enforceFAPITokenRules` (server_token.go:356-404), discovery narrowing (`applyFAPIEnforceDiscovery`) | **Verified** | Sender-constraint requirement enforced only in enforce mode; inspection audits | `fapi_compliance_test.go`, `fapi_profile_test.go` |

## 3. Findings

Sorted by severity. Protocol findings (F) describe the live surface; design
findings (D) describe the direction-3 plan and its acceptance criteria.

### F1 — Device/CIBA `slow_down` never increases the poll interval by 5 seconds (Medium, RFC 8628 §3.5 / CIBA Core §7.1 MUST)

- **Evidence**: `devicePollGate` (tokengrant/token_device.go:129-135) returns
  `slow_down` when `now.Sub(dc.LastPoll) < dc.Interval` but never mutates
  `dc.Interval`; `cibaPollGate` (token_ciba.go:187-193) is identical on
  `r.Interval`. `server_device.go:315` comment concedes: "slow_down: device
  polled faster than Interval (RFC says +5s)".
- **Requirement level**: MUST — RFC 8628 §3.5 and CIBA Core 1.0 §7.1 both state
  "the interval MUST be increased by 5 seconds for this and all subsequent
  requests".
- **Impact**: bounded — the *client* is told to slow down, and a conforming
  client that implements the RFC's own +5 s client-side rule converges; but the
  *server* never enforces the growing backoff, so a non-conforming or
  adversarial poller keeps the fast-poll cadence (throttle bypass) and the
  server-side state diverges from the RFC's contract. No credential oracle or
  data-loss impact.
- **Corrective behavior**: persist `Interval += 5s` on each `slow_down`
  response (both stores), and pin with a test asserting the interval in the
  store grows across consecutive fast polls. Wire-visible: none beyond the
  documented response.

### F2 — Grant rate-limit response mislabels the grant type as unsupported (Medium, RFC 6749 §5.2)

- **Evidence**: `checkGrantRateLimit` (server_token.go:389-399) writes
  `429` + `{"error":"unsupported_grant_type"}` when the per-grant limiter
  trips. The codebase already has the correct code for this situation:
  `ratelimit.ErrRateLimited`, used with 429 by the DCR quota gate
  (`quota.go:172-175`).
- **Requirement level**: RFC 6749 §5.2 defines `unsupported_grant_type` as
  "the authorization grant type is not supported"; a rate-limited grant *is*
  supported. The wire code misdescribes the failure, and is inconsistent
  with the same server's own rate-limit error vocabulary.
- **Impact**: a conforming client may treat the response as permanent
  (unsupported) and stop retrying; telemetry and client-side error handling
  misattribute the cause. The 429 status is correct (RFC 6585), the body is not.
- **Corrective behavior**: use a rate-limit-specific error code (or the
  generic `invalid_request`), document it in `docs/error-codes.md` +
  `docs/openapi.yaml` in the same change, and extend
  `ratelimit_e2e_test.go` to assert the body code, not just the status.

### F3 — Authorization endpoint is a JSON BFF, not a redirect-based endpoint (Medium, documented deviation)

- **Evidence**: `/auth/login` returns a JSON body `{code, state, iss, ...}`
  (server_login.go; `authzErrorBody` family); OIDC Core §3.1.2.5 prescribes
  delivery by redirecting the user agent to `redirect_uri` with parameters in
  the query/fragment. `response_mode=query|fragment` are accepted but not
  applied server-side (the SPA performs delivery); `form_post` is the only
  server-rendered delivery mode. RFC 9207 `iss` is adapted into the JSON body
  (comment at server_discovery.go:230-241).
- **Requirement level**: OIDC Core §3.1.2.5 (MUST for the wire shape of the
  authorization response).
- **Impact**: standard server-side OIDC RP libraries that perform the native
  redirect dance cannot interoperate directly with this endpoint; only a
  JS frontend (or the SDK) can consume it. The OIDF conformance harness
  bridges this with browser-driven login, so the deviation is not visible to
  the harness. Deliberate product decision (BFF shape), documented in code.
- **Corrective behavior**: none required if BFF is the product; must (a) stay
  documented in `docs/sso/oidc-conformance.md`, (b) keep `iss` and `state`
  stamping on every response path (including the pre-bind 415/403 gates —
  currently done via `authzErrorBody`), and (c) be named in any RFP
  response as a deviation from OIDC Core §3.1.2.5.

### F4 — Public clients cannot use `/token/revoke` (Info, RFC 7009 §2.1)

- **Evidence**: `authenticateRevokeClient` (protocols/oauth/handle_revoke.go:127-160) requires credentials or a JWT assertion; `AuthenticateClientCreds` (sso/handlers.go:41-57) rejects empty secret. Discovery consistently omits `none` from `revocation_endpoint_auth_methods_supported` (M6).
- **Requirement level**: RFC 7009 §2.1 ("in cases where client credentials are part of the request") permits public-client revocation with `client_id` only; the spec is ambiguous enough that requiring auth is a defensible, self-consistent policy.
- **Impact**: public-client RPs (SPAs) must revoke via the user-facing session endpoints (`/token/revoke-all`, `/me/sessions/...`) instead; SDK callers should be told the boundary. No oracle impact (401 `invalid_client` is uniform).
- **Corrective behavior**: document the policy in the openapi `/token/revoke`
  description; optionally accept `client_id`-only for clients with
  `token_endpoint_auth_method=none` and validate token-to-client binding.

### F5 — Discovery issuer depends on forwarded headers (Info, operational)

- **Evidence**: `handleOIDCDiscovery` comment (server_discovery.go:43-47): operators behind a TLS-terminating proxy MUST forward `X-Forwarded-Proto`, else the advertised issuer is `http://` and RPs refuse per OIDC Discovery §4.3. Trusted-proxy gating exists (`security.trusted_proxies`, `ForwardedHeadersTrusted`).
- **Impact**: misconfiguration yields a hard interop failure at the RP, not a subtle one — acceptable, but worth an operator checklist item in `docs/deployment.md`.

### F6 — `response_types_supported` includes the direct-mint `token` branch (Info)

- **Evidence**: `responseTypesFor` (server_discovery_config.go:8-14) and `docs/sso/oidc-conformance.md` ("Runtime mode … `token` is the server's direct-mint branch"). OAuth 2.1 strict / FAPI enforce narrow to `code`.
- **Impact**: honest advertisement (the server does accept `response_type=token`), but a client implementing OAuth 2.0 implicit with `token` gets a JSON-bodied direct-mint response, not a fragment redirect — same BFF caveat as F3. Keep the conformance doc's response-type boundary table in sync whenever strict mode changes.

### Design findings (direction 3)

### D1 — Spec acceptance grep is under-specified and counts the wrong population (High, gate-correctness)

- **Evidence**: spec §改进一 acceptance: `grep -c "func (s \*Server) handle" interfaces/sso/*.go` drops from 234 to ≤ 125. The design re-measured: the literal grep matches **254** (20 body-bearing multi-arg helpers like `handleDeviceTokenGrant(ctx, client, …)`, `handleLivez(w, r)` are not delegates and stay). Applied literally, the acceptance either fails (254 − 109 = 145 > 125) or tempts deletion of non-delegates.
- **Impact**: the gate would not measure what it claims; a compliant implementation could be marked failed (or a non-compliant one passed).
- **Corrective behavior**: adopt the design's anchored sole-parameter filter (Decision 1) and update the spec text in the same change that lands 改进一; pin the count in a committed test (`TestMaintainability_`-style) rather than a grep.

### D2 — Spec acceptance references a `dirFileCountExemptions` entry for `interfaces/admin` that does not exist (Medium, gate-correctness)

- **Evidence**: spec §改进二 acceptance: "fan-in counts for `interfaces/admin` do not exceed its frozen `dirFileCountExemptions` value". `directory_fanout_test.go:50-61` has **no entry** for `interfaces/admin`; its 10 files sit at the default cap 10. The design already corrected placement (append to `deps.go`, 177 lines — the only admin file with ≥300 lines of headroom; `middleware.go` 492 / `connections.go` 498 are at budget).
- **Impact**: acceptance wording is unfulfillable as written; adding an exemption entry would violate AGENTS.md §2 ("exemption maps never grow").
- **Corrective behavior**: reword the acceptance to "the default cap (10) with no exemption entry; `ls interfaces/admin/*.go | grep -v _test | wc -l` ≤ 10", and keep mount code inside `deps.go` under the 500-line budget.

### D3 — Gate-closure semantics are the refactor's highest wire-risk (Medium, needs a pinned test)

- **Evidence**: design Decision 1 rule: pass method values (`s.selfServiceGateOn`, …) to `MountRoutes`, never a `.Load()` result — correct: capturing the value at boot freezes the atomic and breaks hot-reload byte-identity (`degradation_test.go`, `feature_gate_hotreload_test.go`). The rule is load-bearing for every gated surface (self-service, CAEP, branding, admin API).
- **Impact**: a single `.Load()` capture silently converts a runtime-flippable gate into a boot-time decision — feature-off deployments could serve routes that should 404 (or vice versa), and route-set drift would not appear in `check-routes` (routes are registered either way; gating is per-request).
- **Corrective behavior**: in addition to the design's nil-gate panic, require a test that flips a gate at runtime (SIGHUP / feature-gates path) and asserts the gated route's 404↔200 transition for at least one relocated mount per owning package.

### D4 — Placement table verified correct (Info)

- **Evidence**: re-measured at this revision: `protocols/oauth` 12 files = exemption 12; `platform/audit` 16 = exemption 16; `domains/federation` 24 = exemption 24; `protocols/oidc`, `protocols/caep`, `protocols/selfservice`, `domains/permissions` at default cap 10; `interfaces/admin` 10 with no entry; `interfaces/sso` 60 = exemption 60. Only `platform/configaudit` (8), `platform/netpolicy` (6), `platform/lifecycle/rebac` (7), `platform/lifecycle/wasmauthz` (4), `platform/lifecycle/webhook` (9) may take new `mount.go` files. The design's ceiling-aware placement table is accurate.
- **Corrective behavior**: none; keep `fileSizeExemptions` empty as the design does.

### D5 — Wire-invisibility guard: `check-routes` plus a route-set golden test (Info)

- **Evidence**: `python cli.py check-routes` PASS (241 routes / 322 documented operations) at this revision is the contract the refactor must preserve. It validates route↔OpenAPI lockstep but not gating (see D3) nor middleware order (AGENTS.md: probes outside rate limiting; documented middleware order preserved).
- **Corrective behavior**: run `python cli.py check-routes` and the full `go test ./... -race` + `make ci` in the landing commit; add a committed route-inventory test (method × path × gate-surface) so the 241-route set is pinned, not just diffed against OpenAPI.

## 4. Priority conformance tests

Ordered by (severity of the gap × cheapness to pin):

1. **Device + CIBA `slow_down` interval growth** (F1): poll twice within `Interval`, assert the store's interval grew by 5 s and the second response is still `slow_down`. Extend `rootcov2_device_errors_test.go` + `ciba_hardening_test.go`.
2. **Grant rate-limit error body** (F2): assert 429 body code is not `unsupported_grant_type` after the fix; today pin the status in `ratelimit_e2e_test.go`.
3. **Public-client revocation boundary** (F4): assert the documented 401 `invalid_client` (or, after policy change, token-bound revocation) in `handle_revoke_test.go`.
4. **Relocated-mount gate hot-reload** (D3): flip each relocated surface's gate at runtime; assert route 404↔200 per owning package.
5. **Route-set golden inventory** (D5): method × path × gate table equal to today's 241-route set, committed alongside 改进一/二.
6. **Discovery parity between the two well-known URLs** (M2): assert byte-identical bodies from `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` (already implied by the shared handler + cache; make it explicit in `oidc_discovery_test.go`).

## 5. Declared unsupported features and certification evidence

Declared unsupported (documented, not defects):

- OIDC **implicit** and **hybrid** response types (`id_token`, `id_token token`, `code id_token`, `code token`, `code id_token token`) → `unsupported_response_type`; the OIDF harness module allowlist excludes them (`test/oidc-conformance/README.md`).
- `prompt=select_account` / `prompt=login` distinctions — accepted but lowered to the default interactive path (discovery advertises only `none` [+ `consent` when a ConsentStore is wired]).
- CIBA `user_code` parameter — advertised `backchannel_user_code_parameter_supported: false`.
- RFC 9493 subject-identifier formats beyond `opaque`; JWE-encrypted SETs — v2.
- RFC 7591 §2.4 software-statement assertions.
- Standalone OIDF `userinfo` module (only as part of `basic`).
- Device/CIBA `slow_down` +5 s interval growth (F1 — currently a gap, not a declared non-goal).

Certification evidence (per `docs/sso/oidc-conformance.md`, verified at this
revision):

- **No OpenID Foundation certification listing exists.** The repository has a
  headless Docker-Compose OIDF harness (`test/oidc-conformance/`) that is NOT
  part of `make ci`, has no committed pass report, and produced one
  smoke-topology run (59 SUCCESS steps, one expected failure:
  `VerifyClientManagementCredentials` needs an HTTPS client-management URL
  unavailable in an HTTP-only local topology). That is smoke evidence, not an
  OIDF result.
- Correct claims to make: "implements OAuth 2.0 / OIDC code flow per RFC …,
  with repository protocol tests"; never "OpenID Certified" / "FAPI
  Certified". An RFP response must name commit, configuration, and any
  official result relied upon.

## 6. Verdict on the design's protocol impact

The direction-3 refactor is **wire-invisible by construction and by gate**:
routes, paths, methods, error codes, and middleware order are preserved
(constants are `core.Path*` re-exports; `check-routes` PASS is the current
baseline; gating stays closure-driven). The two spec-level acceptance defects
(D1, D2) must be corrected in the spec text as the design proposes, and the
refactor must land with the D3/D5 tests so the 241-route × gate × hot-reload
surface is machine-pinned. No protocol finding (F1–F6) blocks the refactor;
F1 and F2 are small, high-value wire fixes that should land either before or
with 改进一 (they touch `tokengrant`/`server_token.go`, which the refactor does
not move).
