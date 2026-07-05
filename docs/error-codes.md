# Error Code Catalog

Every error response from the SSO server's HTTP REST surface carries a
stable `error` code in the JSON body. SPAs and downstream services
should branch on the code, **never** on the human-readable
`error_description` (which may change between versions).

```json
{ "error": "invalid_credentials" }
```

When the server has extra detail it includes `error_description`:

```json
{ "error": "invalid_request", "error_description": "json: cannot unmarshal" }
```

**Opt-in localization**: when an operator wires `sso.WithLocalizer` (see
`shared/i18n`), the authorization-endpoint error surface (e.g.
`/auth/login`) additionally carries `error_description_localized` — the
translated string for `error` in the locale picked from the request's
`Accept-Language` header, falling back to the already-resolved
`recommended_language` geo hint:

```json
{
  "error": "invalid_credentials",
  "error_description_localized": "El nombre de usuario o la contraseña que ingresaste es incorrecto."
}
```

This field is absent unless a Localizer is configured AND it has a
translation for that code/locale — an unconfigured server's responses are
byte-identical to today. Still branch on `error`, never on either
description field.

Defined as Go constants in `consts.go` (and in the per-handler files
for the audit / permission code subsets) — grep there if you need the
exact emission site.

---

## Authentication (`/auth/*`, `/userinfo`, `/logout`)

| Code                                  | HTTP | Emitted when                                                       | Client should                              |
|---------------------------------------|------|--------------------------------------------------------------------|--------------------------------------------|
| `invalid_request`                     | 400  | Request body fails to parse, or required field absent              | Fix the request payload                    |
| `missing_client_id`                   | 400  | `client_id` omitted from a request that requires it                | Include `client_id`                        |
| `invalid_credentials`                 | 401  | Username/password mismatch, code mismatch, or other auth failure   | Re-prompt for credentials                  |
| `invalid_password`                    | 400  | `POST /me/password`: the current password did not match            | Re-prompt for the current password         |
| `invalid_client`                      | 401  | Any client-authentication failure on `/token`, `/par`, `/backchannel-authentication`: unknown `client_id` OR bad secret (RFC 6749 §5.2 — one code for both, so the error never reveals which `client_id`s exist) | Check the client id + secret |
| `inactive_client`                     | 403  | Client exists but `Active: false` in config                        | Operator re-enables the client             |
| `tenant_mismatch`                     | 403  | Client is bound to a tenant the request didn't resolve to          | Use the right hostname / tenant context    |
| `region_not_allowed`                  | 403  | Serving region is outside the tenant's data-residency `AllowedRegions` | Route the request to an allowed region |
| `residency_violation`                 | 403  | Operation would place tenant data outside its residency boundary   | Use a region within the tenant's policy    |
| `authenticator_not_allowed_for_client`| 403  | Client's `allowed_authenticators` list excludes this provider      | Use a method the client permits            |
| `passwordless_required`              | 400  | Client's `allow_passwordless_only` is true and `provider=password` was requested — every OTHER provider (`webauthn`, `totp`, phone/email, ...) stays available | Use `provider=webauthn` (passkey) instead |
| `risk_denied`                         | 403  | `RiskScorer` returned `DecisionDeny`                               | Step up auth, or wait + retry              |
| `conditional_access_denied`           | 403  | Zero-trust conditional-access (CAP) engine wired with `enforce: true` and a matched policy's verdict is deny | Step up auth, or wait + retry |
| `unsupported_provider`                | 400  | `provider` field is not a registered authenticator name            | Use a valid provider name                  |
| `unknown_provider`                    | 400  | OAuth/OIDC callback received an unknown provider in `state`        | Restart the auth flow                      |
| `unsupported_grant_type`              | 400  | `/token` received an unrecognized `grant_type`                     | Use a supported grant type                 |
| `unauthorized_client`                 | 400  | Client's DCR-registered `grant_types` list excludes the requested `grant_type` (RFC 6749 §5.2 / RFC 8693 §4.5); empty `grant_types` = unrestricted | Register the client with the needed grant type or remove the restriction |
| `invalid_callback`                    | 400  | OAuth callback body malformed                                      | Restart the auth flow                      |
| `callback_failed`                     | 401  | OAuth provider rejected the exchange                               | Restart the auth flow                      |
| `login_required`                      | 400  | `prompt=none` was requested but no live session can fulfill the silent renewal (missing/bad `id_token_hint`, session ended, or hint bound to a different client) | Fall back to the visible login flow        |
| `interaction_required`                | 400  | (reserved) `prompt=none` set when the AS needs UI interaction to proceed                                            | Fall back to the visible login flow        |
| `consent_required`                    | 200  | A `ConsentStore` is wired and the user has not yet granted the requested scopes (or `prompt=consent` forced re-consent). HTTP 200 so SPAs can distinguish it from a transport error. Always carries `iss`. The consent UI records the grant via `ConsentStore.RecordConsent`, then retries the login. | Show your consent dialog; retry after grant |
| `account_selection_required`          | 400  | (reserved) `prompt=none` set when account-picker UI is required                                                     | Fall back to the visible chooser           |
| `unmet_authentication_requirements`   | 400  | The RP supplied `acr_values` but the authenticator's `AchievedACR` is absent or not in that set (OIDC Core §3.1.2.6 / §5.5.1.1) | Route user through a stronger authentication method or re-prompt |
| `email_not_verified`                  | 403  | Login succeeded but the account's email has not completed self-service verification, and the deployment requires it before minting a session | Complete the email verification flow, then retry login |

### Code delivery (`/auth/send-code`)

| Code                            | HTTP | Emitted when                                            |
|---------------------------------|------|---------------------------------------------------------|
| `provider_and_target_required`  | 400  | Either `provider` or `target` missing from request body |
| `provider_does_not_send_codes`  | 400  | Named provider doesn't implement `CodeSender`           |
| `send_failed`                   | 500  | Downstream SMS / email delivery error                   |
| `resend_too_soon`               | 429  | A code was already sent to this target within the cooldown window (default 60 s); prevents send-code amplification attacks |

### Logout

| Code                            | HTTP | Emitted when                                                 |
|---------------------------------|------|--------------------------------------------------------------|
| `session_id_or_bearer_required` | 400  | Logout call has neither a `session_id` body nor a bearer hdr |

### Account lockout

| Code             | HTTP | Emitted when                                                                          | Client should                         |
|------------------|------|---------------------------------------------------------------------------------------|---------------------------------------|
| `account_locked` | 423  | `AccountLockout` reports the (client_id, identifier) key is past the failure threshold | Wait until the lock expires, then retry |

### WebAuthn ceremony (`/webauthn/{registration,login}/{begin,finish}`)

| Code                  | HTTP | Emitted when                                                                                          | Client should                                          |
|-----------------------|------|------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `session_invalid`     | 404  | `session_id` is unknown / expired, or the user record disappeared mid-ceremony (unknown-session + unknown-user collapsed for oracle-leak resistance) | Restart the ceremony from the matching `/begin`        |
| `ceremony_failed`     | 400  | go-webauthn rejected the attestation / assertion (parse failure, bad signature, challenge mismatch, counter regression) | Retry the ceremony; check the authenticator + origin   |
| `attestation_denied`  | 403  | The operator's attestation policy rejected the authenticator: either its AAGUID is not on the allowlist (or is on the denylist), OR the credential conveyed no attestation (format `none` — a downgrade an active policy refuses). The credential was NOT persisted. The specific AAGUID + policy mode + a machine-readable `reason` (`aaguid_not_permitted` \| `attestation_format_none`) are in the `webauthn_attestation_denied` audit event, never on the wire | Use an approved authenticator (an operator-curated model) that conveys attestation |
| `ceremony_failed`     | 400  | (also) With MDS root validation wired (`webauthn.attestation.mds`), go-webauthn's `VerifyAttestation` rejected the attestation because its certificate chain does not root in the FIDO Metadata Service (e.g. a self-signed `x5c` asserting an allowlisted AAGUID, or an AAGUID with no FIDO-validated metadata entry). This surfaces through the same `ceremony_failed` (attestation verification failure) path — oracle-safe, no distinct wire code | Use a genuine FIDO-certified authenticator |

**Attestation policy** (`webauthn.attestation`, opt-in): when an operator
configures `policy_mode: allowlist|denylist`, registration is gated on the
authenticator's AAGUID (the public authenticator-model identifier carried in
the attestation's authenticator data) AFTER go-webauthn verifies the
attestation statement. An active policy REQUIRES `conveyance: direct` (or
`enterprise`) — the server fails to boot otherwise — and REJECTS any credential
that conveyed no attestation (format `none`, which go-webauthn accepts with no
signature check), so a client cannot downgrade to slip a denylist or spoof an
allowlisted AAGUID under `none`. A rejection returns the generic
`attestation_denied` (403) — the registering user learns their authenticator
isn't approved, not the policy internals; the rejected AAGUID, the gating mode,
and a machine-readable `reason` (`aaguid_not_permitted` | `attestation_format_none`)
are surfaced ONLY in the `webauthn_attestation_denied` audit event (the AAGUID
is a public model identifier, not a secret). A successful registration emits
`webauthn_registered` (audit) carrying the registered AAGUID for operator
allowlist curation. The default (`conveyance: none`, `policy_mode: off`)
introduces no new wire behavior — it accepts any authenticator exactly as
before.

**Assurance — what this gate does and does NOT give you** (do not over-claim):
with a policy active and a verified attestation statement, go-webauthn verifies
the attestation *signature* and, in the basic/x5c path, matches the AAGUID to
the attestation certificate.

- **WITH FIDO MDS root validation** (`webauthn.attestation.mds` — a downloaded
  FIDO Metadata Service blob, by `file` or `fetch_url`), the AAGUID gate is
  **ADVERSARY-RESISTANT**. go-webauthn's `VerifyAttestation` validates the
  attestation certificate *chain* up to the FIDO root (the blob's own signing
  chain is JWS-verified to the FIDO root at boot — a tampered or wrong-root
  blob fails loud at startup) and rejects an AAGUID with no FIDO-validated
  metadata entry, so a crafted self-signed `x5c` asserting an allowlisted
  AAGUID is **rejected** (its chain doesn't root in the MDS). The loaded
  metadata is a startup snapshot — the FIDO MDS rotates ~monthly, so reload by
  restarting with a fresh blob (or run go-webauthn's `providers/cached`
  fetch+refresh provider out-of-band).
- **WITHOUT an MDS source** (the default), the AAGUID gate is NOT
  cryptographically adversary-resistant: a determined attacker can craft a
  self-signed `x5c` (or self/`none` attestation) asserting an allowlisted
  AAGUID. So without MDS this is an OPERATIONAL control — honest-client gating,
  audit visibility of which AAGUIDs registered, and blocking non-attesting
  software authenticators — NOT a defense against a hostile registrant.

### WebAuthn passwordless PRIMARY login (`/auth/login` `provider=webauthn`)

Opt-in via `webauthn.primary_auth_enabled` (requires `webauthn.enabled`).
Registers a `core.Authenticator` under the name `webauthn` in the SAME
`s.authenticators` registry every other provider uses — a client selects it
with `{"provider": "webauthn", "credential": {"session_id": "...",
"assertion": "..."}}`, obtaining `session_id` from the existing
UNAUTHENTICATED `POST /webauthn/login/conditional/begin` (discoverable
credential / passkey autofill; no username). Purely additive: password login
and WebAuthn-as-second-factor (step-up MFA) are unchanged either way.

| Code                | HTTP | Emitted when                                                                                                       | Client should                                     |
|----------------------|------|---------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| `session_invalid`    | 404  | `session_id` is unknown/expired, or the resolved passkey's user vanished mid-ceremony — the SAME oracle-safe collapse the standalone WebAuthn ceremony endpoints use (§ above); a caller cannot tell "no such session" from "no such user" apart, nor tell it reached this via `/auth/login` vs. `/webauthn/login/conditional/finish` | Restart from `POST /webauthn/login/conditional/begin` |
| `invalid_credentials`| 401  | `session_id`/`assertion` missing, or the assertion failed verification for any OTHER reason (bad signature, challenge mismatch, cloned authenticator) | Restart the ceremony                              |

### MFA orchestration (`/auth/login`, `/auth/mfa`)

| Code            | HTTP | Emitted when                                                                                                                          | Client should                                              |
|-----------------|------|---------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| `mfa_required`  | 200  | `/auth/login` accepted the primary credential but the RiskScorer returned `DecisionRequireMFA` and `WithMFAProvider` is wired         | Read `mfa_challenge_id` + `mfa_methods`; POST `/auth/mfa`  |
| `mfa_invalid`   | 400 / 404 | `/auth/mfa` could not complete the challenge (unknown id, expired, already consumed, unsupported method, wrong factor — all collapsed by anti-enumeration) | Restart the auth flow from `/auth/login`                |

### Self-service TOTP enrollment (`/me/mfa/totp/begin`, `/me/mfa/totp/confirm`)

| Code                            | HTTP | Emitted when                                                                                                              | Client should                                          |
|---------------------------------|------|--------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `totp_invalid_code`             | 400  | `/me/mfa/totp/confirm` could not verify the code: wrong/expired code OR a malformed secret — collapsed by anti-enumeration | Re-check the device clock and re-enter the current code |
| `totp_enrollment_not_supported` | 501  | The wired `MFAEnrollmentStore` is not a `TOTPEnrollmentWriter`, or no `TOTPEnroller` is wired                            | Not a client error — operator must wire enrollment      |
| `webauthn_registration_failed`  | 400  | `/me/mfa/webauthn/finish` could not complete: expired/unknown session, bad attestation, or malformed body — collapsed (cause in logs) | Retry the passkey registration from begin               |

### Account recovery (`/auth/forgot-password`, `/auth/reset-password`)

| Code            | HTTP | Emitted when                                                                                                                         | Client should                                  |
|-----------------|------|------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| (none)          | 200  | `/auth/forgot-password` ALWAYS returns 200 `{status:"sent"}` — unknown identifier / no delivery address / send failure are indistinguishable (anti-enumeration) | Tell the user "if the account exists, a reset was sent" |
| `reset_invalid` | 400  | `/auth/reset-password` could not complete: unknown / expired / already-consumed token, user gone, or set-password error — all collapsed (cause in the audit log) | Request a new reset from `/auth/forgot-password` |
| `account_exists` | 409  | `POST /auth/register` (opt-in self-service signup) was called with a username that already exists — signup never overwrites an existing account | Choose a different username, or sign in / recover the password |
| `password_policy_violation` | 400 | `POST /auth/register` (or `POST /me/password`) supplied a password rejected by the wired `PasswordPolicyValidator` | Choose a password meeting the operator's policy |
| `registration_denied`   | 403  | `POST /auth/register` was rejected by a wired `RegistrationGate` (e.g. CAPTCHA, allow/deny-list, abuse heuristic) | Retry through the gate's expected flow (e.g. solve the CAPTCHA) |
| `verification_invalid`  | 400  | `POST /auth/verify-email` (mandatory signup email verification) got an unknown / expired / already-consumed token, or the username was claimed between register and verify — all collapsed | Restart signup from `POST /auth/register` |
| `confirmation_required` | 400  | `POST /me/account/erase` was called for a real (non dry-run) deletion without `confirm` matching the caller's own subject | Re-submit with `confirm` set to the subject |
| `email_change_invalid`  | 400  | `POST /me/email/verify` got an unknown / expired / already-consumed token, or one belonging to a different user — all collapsed | Restart from `POST /me/email/change` |
| `invitation_invalid`    | 400  | `POST /me/invitations/accept` got an unknown / expired / already-consumed org-invitation token — all collapsed (cause in logs) | Request a fresh invitation from an org admin |

### Authorization (`/auth/login`, `/par`)

These codes follow the OAuth 2.0 + RFC 9126 PAR + RFC 7636 PKCE wire vocabulary so off-the-shelf RP libraries (e.g. AppAuth, oauth4webapi, MSAL) recognize them without remapping.

| Code                         | HTTP | Emitted when                                                                            | Client should                                       |
|------------------------------|------|-----------------------------------------------------------------------------------------|-----------------------------------------------------|
| `access_denied`              | 400  | RFC 6749 §4.1.2.1 — the resource owner / AS refused the authorization request           | Surface to the user; do not auto-retry              |
| `invalid_redirect_uri`       | 400  | `redirect_uri` parameter doesn't match any of the client's registered values            | Operator fixes the client config or RP             |
| `invalid_scope`              | 400  | Requested scope set is not a subset of the client's `AllowedScopes`                     | Drop the disallowed scopes, retry                   |
| `unsupported_response_type`  | 400  | `response_type` not in the AS-supported set (or implicit blocked by OAuth 2.1 strict)   | Use a supported value (`code`)                      |
| `invalid_pkce_method`        | 400  | `code_challenge_method` not in `S256` or `plain` (or blocked by strict mode)            | Use S256                                            |
| `pkce_required`              | 400  | Client has `RequirePKCE` set (or OAuth 2.1 strict) and the request omitted PKCE         | Add `code_challenge` + `code_challenge_method`      |
| `invalid_request_uri`        | 400  | RFC 9126 PAR — `request_uri` is unknown, expired, consumed, or bound to a different RP  | Re-POST `/par` for a fresh one                      |
| `par_not_configured`         | 501  | `/par` hit but no `WithPARStore` wired                                                  | Operator wires the store                            |
| `invalid_request_object`     | 400  | RFC 9101 JAR — `request` / `request_uri` carried a signed or encrypted request object that failed to parse / verify / decrypt (bad signature, unknown alg, wrong key, JWE decryption failure)  | Fix the JWT / JWE; verify it's signed by a key in the client's `JWKS` (and encrypted to the AS's `use:enc` JWK when JWE)  |
| `invalid_authorization_details` | 400  | RFC 9396 RAR — `authorization_details` parameter is malformed (not a JSON array, element missing `type`, or element `type` not in the client's `allowed_authorization_details_types`)  | Drop the offending element or get its type allowlisted on the client                            |
| `insufficient_user_authentication` | 401 (RS) / 400 (AS exchange) | RFC 9470 — caller demanded `acr_values` the subject_token's existing ACR doesn't satisfy. On `/token` grant=token-exchange and on resource-server `WWW-Authenticate` challenges. | Route user through `/auth/login` with the same `acr_values` to step up    |

**FAPI 2.0 profile** (`oauth.compliance.profile: fapi_2`, enforce mode): a baseline violation (no PAR, unsigned request object, non-S256 PKCE, non-code response type, or bearer/non-sender-constrained token) is rejected with the standard `invalid_request` (`error_description` carries the failed `fapi:<rule>` id; SPAs branch on `error`, operators on the audit event). No new wire code is introduced — every violation maps onto the existing OAuth vocabulary. In inspection mode (`inspection_only: true`) nothing is rejected; each violation only emits the `fapi_compliance_violation` audit event (`fapi_rule` / `fapi_detail` / `fapi_mode` metadata) and increments `sso_fapi_violations_total{rule,mode}`.

**SPIFFE JWT-SVID token-exchange** (`spiffe.enabled`, `WithSPIFFEJWTSVID`): a SPIFFE JWT-SVID presented as a token-exchange `subject_token` (`subject_token_type=urn:ietf:params:oauth:token-type:jwt`, `sub` a `spiffe://` URI) is validated against the operator-supplied SPIRE trust-bundle JWKS with a strict asymmetric alg-allowlist (no `alg=none`), strict audience binding, and a trust-domain check. **No new wire code is introduced** — EVERY validation failure (bad signature, `alg=none`, wrong audience, wrong trust domain, expired, malformed `sub`) collapses to the standard `invalid_grant`, indistinguishable on the wire (oracle-leak hardening, AGENTS.md §2). A successful acceptance emits the INTERNAL `spiffe_jwt_svid_accepted` audit event (`spiffe_trust_domain` / `spiffe_namespace` / `spiffe_service_account` metadata); rejections are deliberately NOT audited per-cause (that would re-open the oracle).

**Cross-tenant B2B collaboration token-exchange** (`WithExternalUserStore` + `WithTenantCollaborationStore`, `domains/tenant`): a token-exchange whose `subject_token` was issued to a client in a DIFFERENT tenant than the exchanging client requires BOTH an explicit `TenantCollaboration` trust row (the guest tenant opts in to accepting guest tokens from the subject's home tenant) AND a matching `GuestRecord` registering that exact subject as a guest. **No new wire code is introduced** — a missing trust row or registration collapses to the standard `invalid_grant` (oracle-leak hardening: no signal about WHICH check failed, or that a cross-tenant boundary was even involved); a requested scope outside the guest's registered `Roles` is the standard `invalid_scope`. Either store left unwired (the default) is a complete no-op — byte-identical to a build without this feature; same-tenant exchanges are always unaffected. A successful cross-tenant hop emits the INTERNAL `cross_tenant_token_exchange` audit event with BOTH the guest-tenant context (`client_id`, `guest_tenant_id`) and the originating home-tenant identity (`original_subject`, `original_tenant`) so a SIEM can always trace the action back to its home account.

**RFC 9321 Transaction Tokens** (`txn_token.enabled`, `WithTransactionTokens`): an internal caller mints a short-lived, workload-identity-bound Txn-Token by sending the SAME `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` request as an ordinary RFC 8693 exchange, but with `requested_token_type=urn:ietf:params:oauth:token-type:txn-token` — every other `requested_token_type` is unaffected. **No new wire code is introduced**: a missing/malformed `subject_token`, `subject_token_type`, or `request_context` collapses to `invalid_request`; an `audience` not naming exactly this deployment's configured Trust Domain is `invalid_target`; an invalid/expired `subject_token` (an ordinary access token on the first hop, or a previously-issued Txn-Token on a chained/nested hop) or an act-chain deeper than 10 hops collapses to `invalid_grant` — the SAME codes the ordinary token-exchange grant already returns for its own subject_token/target gates, so the two are indistinguishable on the wire. When the feature is unconfigured (`txnTokenIssuer` unwired), a `requested_token_type` naming the Txn-Token URN falls straight through to the ordinary token-exchange handler's existing `invalid_request` collapse for an unrecognized type — byte-identical to a build without this feature. See `protocols/oauth/txntoken`.

**Cloud workload-identity client authentication** (`WithWorkloadIdentityProviders`): a client registered with `token_endpoint_auth_method=workload_identity` authenticates at `/token` by presenting a cloud-issued identity token as `client_assertion` with `client_assertion_type=urn:snaplink:params:oauth:client-assertion-type:workload-identity`, instead of a `client_secret` or `private_key_jwt`. The token is verified against the CLOUD provider's OWN published JWKS (GCP fully implemented today — `https://www.googleapis.com/oauth2/v3/certs`, issuer `https://accounts.google.com`; AWS/Azure are documented follow-ups in `securityverify`'s package doc), with a strict alg-allowlist, issuer + audience binding (aud MUST equal this server's issuer, mirroring the `private_key_jwt` requirement), and the mapped identity MUST equal the client's registered `Client.Attributes[workload_identity_subject]` exactly. **No new wire code is introduced** — EVERY failure (bad signature, wrong issuer/audience, expired, unknown/unmapped identity, subject mismatch, unconfigured provider) collapses to the standard `invalid_client`, the SAME response `private_key_jwt` failures already return (oracle-leak hardening, AGENTS.md §3).

### Token endpoint (`/token`)

| Code                          | HTTP | Emitted when                                                                            | Client should                                 |
|-------------------------------|------|-----------------------------------------------------------------------------------------|-----------------------------------------------|
| `invalid_grant`               | 400  | Auth code / refresh / device / PAR / PKCE failure — collapses every cause into one wire response (oracle-leak hardening, AGENTS.md) | Treat as terminal for that grant; restart flow |
| `invalid_target`              | 400  | RFC 8693 — `resource` / `audience` not in the client's `AllowedResources`              | Drop or correct the resource indicator        |
| `authorization_code_not_configured` | 501 | `grant_type=authorization_code` hit but no `WithAuthCodeStore` wired               | Operator wires the store                      |
| `refresh_token_not_configured` | 501 | `grant_type=refresh_token` hit but no `WithRefreshTokenStore` wired                    | Operator wires the store                      |
| `device_code_not_configured`  | 501  | `grant_type=urn:ietf:params:oauth:grant-type:device_code` hit but no `WithDeviceCodeStore` wired | Operator wires the store              |
| `device_secret_not_configured`| 501  | `device_sso` scope requested on `/token` but no `WithDeviceSecretStore` wired (OpenID Native SSO 1.0) | Operator wires the store              |
| `ciba_not_configured`         | 501  | `/backchannel-authentication` or `grant_type=urn:openid:params:grant-type:ciba` hit but no `WithCIBA` wired | Operator wires the store              |

### AI-agent identity + delegation grant (`/token` `grant_type=urn:snaplink:params:oauth:grant-type:delegation`)

Opt-in (`sso.WithAgentDelegationGrant`; domains/tokenexchange/agentidentity) — an
AI agent redeems a previously-created, human-authorized `AgentSession` for an
access token whose `sub` is the agent's own identity and whose `act` claim
(RFC 8693 §4.1) points back to the delegating human. Unwired, this
`grant_type` is never registered and falls through to the ordinary
`unsupported_grant_type` response below — byte-identical to a build without
this feature. No new error codes: every failure reuses the SAME codes the
other grants above use, for the SAME oracle-leak reasons.

| Code             | HTTP | Emitted when                                                                            | Client should                                 |
|------------------|------|-------------------------------------------------------------------------------------------|-----------------------------------------------|
| `invalid_request`| 400  | `agent_session_id` omitted                                                                | Include `agent_session_id`                    |
| `invalid_grant`  | 400  | The `AgentSession` is unknown, expired, or revoked; its `Agent` is unregistered; or the human's live entitlement could not be resolved — ALL collapse to this one code (oracle-leak hardening) | Treat as terminal; the human must re-authorize the agent |
| `invalid_scope`  | 400  | The three-way intersection (agent policy ∩ session grant ∩ live human entitlement) came out empty, or the caller's requested `scope` includes a value outside that intersection | Request a narrower (or no) `scope`            |

### Device flow + CIBA poll (`/device/code`, `/device/verify`, `/backchannel-authentication`, `/token`)

| Code                    | HTTP | Emitted when                                                              | Client should                                            |
|-------------------------|------|---------------------------------------------------------------------------|----------------------------------------------------------|
| `authorization_pending` | 400  | RFC 8628 §3.5 / CIBA Core §11 — user hasn't confirmed yet; poll again at `interval` | Keep polling, respect the AS-supplied interval         |
| `slow_down`             | 400  | RFC 8628 §3.5 / CIBA Core §11 — caller polled faster than the AS-supplied interval | Add 5 seconds to the interval, then keep polling         |
| `expired_token`         | 400  | RFC 8628 §3.5 / CIBA Core §11 — `device_code` / `auth_req_id` TTL elapsed (also unknown/consumed id — collapsed for anti-enumeration) | Restart the flow with a fresh request |
| `access_denied`         | 400  | RFC 8628 §3.5 / CIBA Core §11 — the user explicitly denied the request    | Surface to the user; do not auto-retry                   |

### CIBA backchannel authentication (`/backchannel-authentication`)

| Code                    | HTTP | Emitted when                                                              | Client should                                            |
|-------------------------|------|---------------------------------------------------------------------------|----------------------------------------------------------|
| `unknown_user_id`       | 400  | OIDC CIBA Core §13 — no hint supplied, or no `login_hint` / `id_token_hint` / `login_hint_token` resolved to a known user (collapsed for anti-enumeration) | Verify the hint identifies an enrolled user              |
| `missing_user_code`     | 400  | Reserved — user-code delivery mode is not implemented (poll mode only)    | Use a hint instead of `user_code`                        |

### Client lookup

| Code                | HTTP | Emitted when                                                                            |
|---------------------|------|-----------------------------------------------------------------------------------------|
| `client_not_found`  | 404  | Direct client lookup (admin RPC, DCR management) returned `ErrNoSuchClient`            |

### Dynamic Client Registration (`/register`, `/register/{client_id}`)

| Code                          | HTTP | Emitted when                                                                            | Client should                                 |
|-------------------------------|------|-----------------------------------------------------------------------------------------|-----------------------------------------------|
| `invalid_client_metadata`     | 400  | RFC 7591 §2 — `POST /register` (or a `PUT /register/{client_id}` update) submitted client metadata that failed validation | Fix the offending metadata field, retry       |
| `registration_not_configured` | 501  | `POST /register` or `GET`/`PUT`/`DELETE /register/{client_id}` hit but no `WithDynamicClientRegistration` wired | Operator enables dynamic client registration  |

---

## Tokens (`/userinfo`, `/permissions/me`, `/roles/me`, `/menus/me`)

| Code             | HTTP | Emitted when                                          | Client should                       |
|------------------|------|-------------------------------------------------------|-------------------------------------|
| `missing_token`    | 401  | `Authorization: Bearer ...` header absent                                                          | Send the bearer                                            |
| `invalid_token`    | 401  | Token signature invalid / expired / revoked / tenant suspended                                     | Re-authenticate                                            |
| `invalid_dpop_proof` | 400  | DPoP header present but proof JWT fails verification (bad sig, htm/htu/iat/jti)                  | Regenerate the proof                                       |
| `use_dpop_nonce`   | 400 (AS) / 401 (RS) | DPoP nonce required but missing / invalid; fresh nonce delivered via `DPoP-Nonce` header | Retry with the new nonce embedded in the proof's `nonce` claim |
| `user_not_found`   | 404  | Token is valid but the subject id has no User record                                               | Recreate the user (admin) or rebind                        |
| `unauthorized`     | 401  | Generic auth check failure (admin middleware)                                                      | Re-authenticate                                            |
| `server_error`     | 500  | `/userinfo` could not produce the encrypted response the client registered (`userinfo_encrypted_response_alg`): no encrypter wired, no usable `use:enc` JWK, or a crypto failure. Undifferentiated by design (no missing-key vs crypto-failure oracle) — never downgrades to cleartext | Check the client's `JWKS` carries a usable `use:enc` key and the AS has a response encrypter wired; retry |

---

## Permissions

| Code                                | HTTP | Emitted when                                          |
|-------------------------------------|------|-------------------------------------------------------|
| `permission_provider_not_configured`| 501  | `/permissions/me`/`/roles/me`/`/menus/me` hit when no `permissions.Provider` is wired |
| `permission_lookup_failed`          | 500  | Provider returned an error during lookup              |

---

## Audit (`/api/v1/audit/events*`)

| Code                     | HTTP | Emitted when                                                       |
|--------------------------|------|--------------------------------------------------------------------|
| `audit_not_enabled`      | 500  | API hit but `audit.api_enabled: false` (or no recorder configured) |
| `audit_event_not_found`  | 404  | Specific event id queried but absent / evicted from the sink       |

---

## Realtime admin event stream (`/api/v1/admin/events/stream`)

| Code                 | HTTP | Emitted when                                                              |
|----------------------|------|----------------------------------------------------------------------------|
| `event_stream_busy`  | 503  | The broker is already serving `events.max_subscribers` live connections    |

No admin-scope-specific code: a missing/invalid bearer or insufficient scope
falls through to the same 401/403 the rest of `/api/v1/admin/*` uses.

## Config audit (`/api/v1/admin/config/*`)

| Code                          | HTTP | Emitted when                                                                                         |
|-------------------------------|------|-------------------------------------------------------------------------------------------------------|
| `config_audit_not_available`  | 501  | `.../running`\|`.../applied`\|`.../diff` hit with no `WithConfigSnapshots` wired, or `.../history` hit with no `WithConfigAuditStore` wired |
| `invalid_request`             | 400  | `.../history?since=` is not RFC3339, or `?limit=` is not an integer                                    |

---

## Network policy (`/api/v1/netpolicy/*`)

| Code                       | HTTP | Emitted when                                                       |
|----------------------------|------|--------------------------------------------------------------------|
| `netpolicy_not_configured` | 500  | API hit but `network.api_enabled: false` (or no store configured)  |
| `netpolicy_not_found`      | 404  | Policy name queried but absent from store                          |

---

## Generic event/webhook egress engine (`/api/v1/admin/webhooks/*`)

Opt-in (`sso.WithWebhookEngine`) admin surface for the `platform/lifecycle/webhook`
egress engine: operators register a destination URL + a set of
`audit.EventType` values they want pushed, HMAC-signed per-subscription
(`X-Signature`, same scheme as the audit-log webhook and CAEP). Not mounted
without a wired engine. GET is `admin:read`; POST/DELETE are `admin:write`
via the default `AdminMiddleware` method-scope rule.

| Code                             | HTTP | Emitted when                                                                                     |
|-----------------------------------|------|---------------------------------------------------------------------------------------------------|
| `webhook_not_configured`         | 500  | Any `/api/v1/admin/webhooks/*` route hit with no `WithWebhookEngine` wired (defensive; routes are only mounted when one is) |
| `invalid_request`                | 400  | `POST .../subscriptions` body is malformed JSON, or fails `EventSubscription.Validate` (missing/non-https `url`, empty `event_types`, or empty `secret`) |
| `webhook_deadletter_not_found`   | 404  | `POST .../deadletters/{id}/replay` on an unknown dead-letter id                                    |
| `webhook_subscription_not_found` | —    | Reserved wire code (`core.ErrWebhookSubscriptionNotFound`) for an unknown subscription id; `DELETE .../subscriptions/{id}` is currently idempotent (200 regardless), so no handler emits this yet |
| `internal_error`                 | 502  | `POST .../deadletters/{id}/replay` could not resolve the subscription, or the replay POST itself failed — the entry stays queued for a later retry |

---

## Admin break-glass sessions (`/api/v1/admin/break-glass*`)

Break-glass (emergency support) admin sessions: a bounded, audited window
in which a support admin acts on behalf of a target user. SOC 2
CC6.1/CC6.2, PCI DSS 7.2, HIPAA §164.312(a) evidence chain. Gated by the
same `admin:read`/`admin:write` scopes as the rest of `/api/v1/admin/*`;
mounted only when a `BreakGlassStore` is wired.

| Code                              | HTTP | Emitted when                                                                                   |
|------------------------------------|------|-------------------------------------------------------------------------------------------------|
| `break_glass_reason_required`     | 400  | `POST /api/v1/admin/break-glass` omitted (or blank) the mandatory ticket/incident `reason`      |
| `break_glass_ttl_exceeded`        | 400  | Requested `ttl_seconds` exceeds the 1-hour cap (`core.MaxBreakGlassTTL`)                        |
| `break_glass_self_approval`       | 400  | `POST .../{id}/approve` called by the same admin who created the pending grant                  |
| `break_glass_not_pending`         | 409  | `POST .../{id}/approve` targets a grant that is not `pending` (already active/revoked/expired)  |
| `break_glass_not_impersonable`    | 403  | `POST .../{id}/impersonate` on a `readonly`-scope grant (only impersonate/escalate can mint a bearer — structural) |
| `break_glass_not_active`          | 409  | `POST .../{id}/impersonate` on a grant that is not `active` (pending/expired/revoked)           |
| `break_glass_not_owner`           | 403  | `POST .../{id}/impersonate` by an admin other than the grant's designated `admin_user_id`       |
| `impersonation_unavailable`       | 500  | `POST .../{id}/impersonate` could not mint the bearer (no token issuer resolvable / issuance failed) |
| `break_glass_target_privileged`   | 403  | `POST /api/v1/admin/break-glass` (impersonate/escalate) or `POST .../{id}/impersonate` on a target that holds an admin scope — impersonating an admin is a hard refusal (no acting with the admin's own boundary) |
| `not_found`                       | 404  | Unknown break-glass session id, or no `BreakGlassStore` wired                                    |

---

## Admin governance framework

Four independently opt-in admin-plane governance mechanisms
(`platform/lifecycle/admingovernance`). None change behavior unless explicitly
configured — see `docs/config-reference.md` for the `admin_write_quota`,
`admin_change_approval`, `admin_destructive_actions`, and
`admin_ip_allowlist` config sections.

### Generic change-approval workflow (`/api/v1/admin/changes*`)

Generalizes the break-glass propose/approve/self-approval-refusal shape
beyond emergency-access grants to arbitrary admin mutation types: an admin
proposes an `action_type` + payload, a DIFFERENT admin approves it, and —
when the deployment registered an `Applier` for that `action_type` — the
approval immediately applies the change. Gated by the same
`admin:read`/`admin:write` scopes as the rest of `/api/v1/admin/*`; mounted
only when an `ApprovalStore` is wired (`WithChangeApprovalStore`).

| Code                                | HTTP | Emitted when                                                                                     |
|--------------------------------------|------|---------------------------------------------------------------------------------------------------|
| `change_reason_required`            | 400  | `POST /api/v1/admin/changes` omitted (or blank) the mandatory `reason`                            |
| `change_action_type_required`       | 400  | `POST /api/v1/admin/changes` omitted (or blank) `action_type`                                     |
| `change_action_type_not_allowed`    | 400  | `action_type` is not in the configured `admin_change_approval.action_types` allow-list             |
| `change_self_approval`              | 400  | `POST .../{id}/approve` (or `.../reject`) called by the same admin who proposed the change         |
| `change_not_pending`                | 409  | `POST .../{id}/approve` or `.../reject` targets a change that is not `pending` (already decided)   |
| `not_found`                          | 404  | Unknown change-request id, or no `ApprovalStore` wired                                             |

### Transport-level checks (`AdminMiddleware`, all of `/api/v1/admin/*`)

These three run in `interfaces/admin.Middleware.HTTPMiddleware`, before any
handler — the SAME choke point every REST admin request passes through,
including the grpc-gateway-proxied tenant/client/user/token/permission CRUD
services. Each is wired via a setter on the constructed `AdminMiddleware`
(`SetWriteQuota` / `SetDestructiveActions` / `SetIPAllowlist`), not an
`sso.Option` — mirroring the existing `SetRateLimit`/`SetAdminTokenStore`
convention. All are local literals (not `core.Err*`) because this layer has
no `core.HandlerContext` to hang a `core.ErrorBody` off.

| Code                                  | HTTP | Emitted when                                                                                     |
|-----------------------------------------|------|-----------------------------------------------------------------------------------------------|
| `admin_ip_denied`                     | 403  | `SetIPAllowlist` is configured and the request's IP/geo fails the allow-list (checked BEFORE bearer auth) |
| `destructive_confirmation_required`   | 409  | `SetDestructiveActions` classifies (method, path) as destructive and the request is missing `X-Confirm: true` |
| `admin_write_quota_exceeded`          | 429  | `SetWriteQuota` is configured and the acting tenant/admin has exhausted its fixed-window write budget (carries `Retry-After`) |

---

## Credential compromise-response (`/api/v1/admin/credentials/{type}/compromise`)

Emergency compromise-response: an operator declares a credential class leaked,
force-rotating it OFF schedule with NO overlap window so the leaked version is
retired from the verify set instantly. Returns the new version's GOVERNANCE
metadata only — NEVER the secret. Gated by the same `admin:write` scope as the
rest of `/api/v1/admin/*`; mounted only when `WithCredentialCompromise` is
wired. Emits `admin_credential_compromised` with the compliance evidence chain
(`credential_type`, `credential_reason`, `credential_old_version`,
`credential_new_version`).

| Code                                 | HTTP | Emitted when                                                                                          |
|--------------------------------------|------|------------------------------------------------------------------------------------------------------|
| `compromise_reason_required`         | 400  | The mandatory `reason` was omitted or blank — an unexplained compromise is itself an audit finding    |
| `credential_compromise_unsupported`  | 400  | The class's rotator cannot instantly retire its secret (implements `CredentialRotator` but not `CompromiseRotator`) — the framework refuses rather than leave the leaked secret accepted through an overlap |
| `not_found`                          | 404  | Unknown credential `{type}` (never registered), or no compromise scheduler wired                      |
| `internal_error`                     | 500  | Minting the replacement failed — the OLD credential keeps serving; retry                              |

---

## Cryptographic material inventory (`/api/v1/admin/crypto/keys`)

Read-only catalog of every cryptographic key the server knows about (signing
keys, JWE keys, KMS-backed keys, manually-registered trust anchors), plus an
emergency compromise-report endpoint. Mounted only when `WithCryptoInventory`
is wired. Reporting a compromise is INVENTORY BOOKKEEPING/ALERTING, NOT the
authoritative key revocation — see `platform/lifecycle/cryptoinventory`'s
package doc; it best-effort triggers the owning concern's own retirement
mechanism (a signing-key issuer's `RetireKey`/`DropVerifyKey`, or
`platform/lifecycle/rotation`'s emergency `Compromise` path) when one is
wired. Emits `admin_crypto_key_compromised` with the compliance evidence chain
(`crypto_key_id`, `crypto_key_reason`, `crypto_key_source`).

| Code                          | HTTP | Emitted when                                                                                     |
|-------------------------------|------|---------------------------------------------------------------------------------------------------|
| `compromise_reason_required`  | 400  | The mandatory `reason` was omitted or blank — an unexplained compromise is itself an audit finding |
| `not_found`                   | 404  | Unknown key `{id}` (no registered Source currently reports it), or no inventory wired              |
| `internal_error`              | 500  | The inventory's Source(s) could not be read                                                        |

### Token portfolio bulk-revoke (`POST /api/v1/admin/tokens/revoke`)

Revocation-storm protection for the admin bulk-revoke workflow. Neither code is
a credential oracle — the caller is an authenticated admin (admin:write).

| Code                                 | HTTP | Emitted when                                                                                          |
|--------------------------------------|------|------------------------------------------------------------------------------------------------------|
| `bulk_revoke_confirmation_required`  | 409  | The batch is large enough (over the soft cap) — or is a client-wide revoke that can't be pre-counted — to demand an explicit `confirm: true` |
| `bulk_revoke_batch_too_large`        | 409  | The batch exceeds the hard cap and must be narrowed (a subject/client revoke that would wipe more than the storm ceiling), even with `confirm` |

## User lifecycle state machine (`/api/v1/admin/users/:id/lifecycle`)

The user-lifecycle state machine (`WithUserLifecycle`). GET (`admin:read`)
returns the account's current state, the states reachable from it in one legal
move, and the transition history; POST (`admin:write`) requests a transition
validated against the legal-transition table. The states are
`invited → active → {suspended, inactive} → archived → purged`; the legal edges
are INVITED→{ACTIVE, ARCHIVED}, ACTIVE→{SUSPENDED, INACTIVE, ARCHIVED},
SUSPENDED→{ACTIVE, ARCHIVED}, INACTIVE→{ACTIVE, ARCHIVED}, ARCHIVED→{ACTIVE,
PURGED}, and PURGED is terminal. A user with no record is implicitly `active`.
Every applied transition emits `admin_user_lifecycle_changed` (`target_user`,
`from_state`, `to_state`, `reason`); the optional auto-deprovisioning sweep
(`WithUserAutoDeprovision`, OFF by default) advances dormant accounts through
ACTIVE→INACTIVE→ARCHIVED with `system` as the actor. Routes are mounted only when
the store AND a `UserProvider` are wired. None of these codes is a credential
oracle — the caller is an authenticated admin.

| Code                             | HTTP | Emitted when                                                                                     |
|----------------------------------|------|--------------------------------------------------------------------------------------------------|
| `illegal_lifecycle_transition`   | 400  | The requested target state is not reachable from the account's current state per the legal-transition table |
| `unknown_lifecycle_state`        | 400  | The requested `state` is not a recognized lifecycle state value                                  |
| `lifecycle_state_conflict`       | 409  | The account's state changed between the read and the write (a concurrent transition) — re-read and retry |
| `invalid_request`                | 400  | The `:id` path segment or the `state` body field is missing/blank                                |
| `not_found`                      | 404  | The `UserProvider` has no user with that `:id`                                                    |

---

## Identity linking / account-merge safety (`/me/identities`)

Self-service identity linking (`domains/identitylink`, `WithIdentityLinkStore`).
GET lists the caller's own ACTIVE linked external identities (federated IdP
subjects, or another local account folded in); DELETE unlinks one. Both are
credential-adjacent (`no-store` headers) and require the SAME bearer-validated
`/me/*` authentication as every other self-service endpoint. Routes are
mounted only when a `Store` is wired — byte-identical to a build without the
feature.

The DELETE guards against unlinking a user's LAST remaining authentication
method: it is refused when the identity being removed is the caller's only
active link AND the account has no other usable method (checked via the
optional `PasswordCredentialStore` extension `identitylink.PasswordPresenceChecker`;
a store that doesn't implement it is treated as "no password", failing
CLOSED so a user is never silently locked out). Every successful unlink emits
`identity_unlinked` (`identity_id`, `provider`).

`domains/identitylink.MergePolicy` is a separate, related extension point (not
an HTTP endpoint): the decision seam for when a login flow discovers that an
external identity is already linked to a DIFFERENT local account than the one
currently resolving. The stock `/auth/login` handler does not invoke it — a
custom authenticator/login integration retrieves it via
`Server.IdentityMergePolicy` / `Server.IdentityLinkStore` and calls
`identitylink.Resolve` itself. The default `RejectPolicy` always refuses (safe
default); the reference `LinkOnlyMergePolicy` merges ONLY the identity link
records onto the winning account (sessions/consents/tokens are NOT merged —
see the package doc). Both outcomes are recorded via
`identitylink.RecordMergeDecision` as `identity_merged` / `identity_merge_rejected`.

| Code                            | HTTP | Emitted when                                                                                     |
|----------------------------------|------|---------------------------------------------------------------------------------------------------|
| `invalid_request`                | 400  | The `:id` path segment on DELETE is missing/blank                                                 |
| `not_found`                       | 404  | The link id is unknown, already unlinked, or belongs to a DIFFERENT user (oracle-safe: one response either way) |
| `identity_unlink_last_method`     | 409  | Removing this link would leave the account with no remaining way to authenticate                  |

---

## Compliance reporting (`/api/v1/admin/compliance/*`)

Reporting/aggregation layer over data already recorded elsewhere (`platform/audit`,
`domains/permissions`, `core.ConsentStore`) — see `protocols/compliance`. No new
error codes: every failure reuses `invalid_request` / `internal_error`. All four
are opt-in and admin-gated (GET routes `admin:read`, the sweep trigger `admin:write`).

| Endpoint | Mounted when | Notes |
|---|---|---|
| `GET .../soc2-evidence` | an audit recorder is wired (`WithAuditRecorder`) | SOC2 evidence pack: current role assignments (CC6.1), admin mutations since `?since=` (CC8.1, default last 90d), token/session/credential revocations (CC6.2/CC6.3). Best-effort: a failing section is listed in the response body's `errors`/`skipped`, never a 500, EXCEPT a malformed `?since=` which is `400 invalid_request`. |
| `GET .../data-map` | always, when the admin API is on | GDPR Art. 30 processing-activity record. Static/code-derived — no query parameters, no failure mode beyond the admin gate itself. |
| `GET .../consents` | a `ConsentStore` AND a `UserProvider` are wired | Every currently-active (non-expired) OAuth consent grant, system-wide. A store failure is `500 internal_error`. |
| `POST .../retention-sweep` | `WithDataRetentionSweep` configured `Enabled: true` | Triggers one automated data-retention sweep pass on demand (session-TTL cleanup, dormant-account flag/erase, audit-retention count). Body `{"dry_run": bool}` is optional and can only ADD a dry run, never remove an operator-configured one; a malformed body is `400 invalid_request`. Per-step failures are best-effort (`errors` in the response), never abort the whole sweep. |

---

## Server / configuration

These indicate operator misconfiguration; clients shouldn't try to
recover from them, just surface to operations.

| Code                              | HTTP | Emitted when                                                 |
|-----------------------------------|------|--------------------------------------------------------------|
| `internal_error`                  | 500  | Unrecoverable bug or downstream failure                      |
| `server_misconfigured`            | 500  | A handler reached a state requiring a dep that isn't wired   |
| `session_manager_not_configured`  | 500  | Login succeeded auth but no SessionManager exists            |
| `client_store_not_configured`     | 500  | Login attempted but no ClientStore exists                    |
| `no_token_strategy`               | 500  | Client's `token_strategy` doesn't match any registered issuer |
| `not_supported`                   | 501  | SDK-exported code (`sso.ErrNotSupported`) for a feature an embedder's handler chooses not to implement; the stock server never emits it |

---

## SAML 2.0 (`/saml/*`, `/auth/saml/callback`)

SAML 2.0 is supplied by an operator's SEPARATE/forked module (the
SAML/XML/DSig dependency stays out of the core go.mod). The codes below
are the stable wire vocabulary that module SHOULD emit; the core ships
the constants (`ErrSAML*` in `core/consts.go`) and the dep-free handler
registry, not the protocol handlers. SAML is inert unless
`saml.handler` names a registered factory — until then these codes
never appear.

| Code                     | HTTP | Emitted when                                                                 | Client should                          |
|--------------------------|------|------------------------------------------------------------------------------|----------------------------------------|
| `saml_assertion_invalid` | 400  | A returned SAML assertion fails validation — bad signature, wrong audience/issuer, expired, or replayed (causes SHOULD be collapsed onto this one code to avoid an oracle, AGENTS.md §2) | Restart the SAML SSO flow              |
| `saml_request_invalid`   | 400  | (IdP side) A malformed/forged AuthnRequest, an ACS URL not in the SP's registered allowlist, or an unknown/expired/consumed pending request / invalid session at `/saml/sso/finish` (all collapsed onto this one code — oracle-safe, AGENTS.md §2) | Restart the SAML SSO flow              |
| `saml_assertion_failed`  | 500  | (IdP side) The server could not mint/sign an assertion — the per-tenant signing key can't drive XML-DSig (e.g. an Ed25519 issuer; goxmldsig has no EdDSA method) or the signing operation errored. Fails CLOSED (no cross-tenant key fallback) | Operator configures an RSA/ECDSA SAML signing key |
| `saml_not_configured`    | 501  | A SAML endpoint was hit but no SAML handler is wired (`saml.handler` empty)   | Operator enables + registers SAML      |

---

## OpenID Shared Signals receiver (`/ssf/receive`)

The opt-in CAEP/SSF push-delivery receiver (RFC 8935) — the inbound half
of Shared Signals — consumes signed Security Event Tokens from CONFIGURED
trusted upstream transmitters and revokes local access for the mapped
subject. Mounted only when `WithCAEPReceiver` is wired (config
`caep.receiver.enabled`); the route 404s otherwise.

**Wire shape note:** unlike every other endpoint, the SSF error body uses
the RFC 8935 §2.4 key **`err`** (not `error`) plus an optional
`description`. The `err` codes below are DELIBERATELY COARSE — every trust
failure (bad signature, untrusted issuer, wrong audience, expired,
replayed) collapses to one code so the endpoint reveals no oracle of which
gate failed (AGENTS.md §2). A VALID SET is always **acked (202)** even when
it maps to no local subject or carries only unknown events; only the
failures below return a 400.

| Code              | HTTP | Emitted when                                                                                  |
|-------------------|------|-----------------------------------------------------------------------------------------------|
| `invalid_request` | 400  | The request body is not a parseable compact-JWS SET (malformed / empty / oversized)           |
| `invalid_key`     | 400  | The SET could not be authenticated: bad signature, untrusted/unknown `iss`, wrong `aud`, wrong `typ`, expired, or replayed (all collapsed onto this one code — oracle-safe) |

A transient internal failure AFTER full validation (a resolve/revoke store
outage) returns `internal_error` (500, see Server / configuration) so the
transmitter retries rather than the receiver silently dropping a real
revocation.

---

## OpenID Federation 1.0 §8 Federation Fetch (`/fetch`)

The opt-in §8 Federation Fetch endpoint — this server acting as a federation
SUPERIOR / INTERMEDIATE, issuing SIGNED Subordinate Statements about its
operator-configured subordinates. Mounted only when `WithFederationEntity`
is wired AND at least one subordinate is configured (`federation.subordinates`);
the route 404s otherwise (and the Entity Configuration advertises no
`federation_fetch_endpoint`).

**Wire shape note:** the error body is the OpenID Federation 1.0 §8 federation
error response — a JSON object with `error` + optional `error_description`. The
JSON member names coincide with the OAuth error shape, but the CODE catalog is
the federation one (`not_found` / `invalid_request`), and — unlike a credential
endpoint — the response carries NO `no-store` (federation membership is public
metadata). On success the body is the signed Subordinate Statement itself (a
compact JWS, `application/entity-statement+jwt`), not JSON.

| Code              | HTTP | Emitted when                                                                                  |
|-------------------|------|-----------------------------------------------------------------------------------------------|
| `invalid_request` | 400  | The required `sub` query parameter is missing, OR a supplied `iss` does not equal this server's entity id |
| `not_found`       | 404  | The requested `sub` is not a configured subordinate of this entity — NO statement is issued (this server vouches only for operator-configured subordinates) |

A signing failure AFTER the subordinate is matched returns `internal_error`
(500, see Server / configuration).

---

## SCIM 2.0 (`/api/v1/scim/v2/*`, RFC 7644 §3.12 `scimType`)

The SCIM 2.0 provisioning surface (RFC 7643 schema / RFC 7644 protocol)
mounted under `/api/v1/scim/v2`. `/Users` always mounts; `/Groups` mounts
only when `scim.groups.enabled` (it requires a `permissions.Provider`).

**Wire shape note:** SCIM errors are a SEPARATE taxonomy from the OAuth
`error` catalog above. The body is the RFC 7644 §3.12 error envelope served
as `application/scim+json`:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "userName already exists"
}
```

`status` is the HTTP status repeated as a STRING. `scimType` is the
machine-readable refinement code (RFC 7644 §3.12, Table 9) — connectors
branch on `scimType` (and `status`), NEVER on the human-readable `detail`.
`scimType` is present only on the 4xx cases below; it is OMITTED on
404/405/500. The codes the handler actually emits:

| `scimType`      | HTTP | Emitted when                                                                                  |
|-----------------|------|-----------------------------------------------------------------------------------------------|
| `invalidValue`  | 400  | A required value is missing or malformed — e.g. `userName` (User) / `displayName` (Group) absent, a non-integer/negative `startIndex`/`count`, an empty PATCH `Operations` array, or a typed PATCH value that doesn't match its attribute |
| `invalidSyntax` | 400  | The request body is not valid SCIM JSON (create/replace) or not a valid SCIM PATCH body       |
| `uniqueness`    | 409  | A uniqueness constraint was violated — the resulting `userName` already belongs to another user, or a server-minted id already exists |
| `mutability`    | 400  | A read-only attribute was altered — a PUT/PATCH body carrying an `id` different from the resource's own id (`id` is server-assigned, read-only) |
| `invalidPath`   | 400  | A PATCH `path` is unparseable or names an attribute this surface doesn't support (a value filter, a schema-URN-qualified path, or an unsupported `name.<sub>`) |
| `noTarget`      | 400  | A PATCH `remove` op specified no `path` (there is no addressable attribute to act on)          |
| `invalidFilter` | 400  | A `?filter=` expression (list/search) is unparseable or uses an unsupported construct          |

Statuses WITHOUT a `scimType` (RFC 7644 Table 9 defines no refinement
code for them):

| HTTP | Emitted when                                                                                  |
|------|-----------------------------------------------------------------------------------------------|
| 404  | Unknown resource id (GET/PUT/PATCH/DELETE on a missing User/Group), an unknown nested path, or any SCIM path that matches no route |
| 405  | A method not allowed on a known collection/resource route                                      |
| 500  | An unexpected backing-store error (the `detail` carries the store message — the surface is admin-only, so no oracle risk) |

**Admin auth (401/403) does NOT use the SCIM envelope.** The whole surface
is gated by the AdminMiddleware, which fronts the SCIM handler: a missing /
invalid bearer is a **401** and an insufficient scope (`admin:read` on GET,
`admin:write` on POST/PUT/PATCH/DELETE) is a **403**, both carrying the
OAuth-style `{"error": ...}` body (`missing_token` / `invalid_token` /
`forbidden`, see Auth / OAuth above) plus a `WWW-Authenticate: Bearer
realm="admin"` challenge — the request never reaches the SCIM handler, so it
never gets a `scim+json` body.

---

## Rate limiting + payload

| Code                | HTTP | Emitted when                                          | Headers                  |
|---------------------|------|-------------------------------------------------------|--------------------------|
| `rate_limited`      | 429  | `ratelimit.Middleware` blocked the request            | `Retry-After: <seconds>` |
| `payload_too_large` | 413  | `sso.WithBodyLimit(N)` exceeded by Content-Length or stream |                          |

---

## Disaster recovery / degraded service (`sso.WithDegradationManager`)

The degraded-service gate (opt-in via `sso.WithDegradationManager`) refuses the
request classes the active DR mode sheds. Probes (`/livez`, `/readyz`,
`/metrics`) and the DR control endpoint (`/api/v1/admin/dr/mode`) always pass so
the replica stays observable and recoverable. Per mode: `read_only` refuses
mutating writes except the token plane (`/token`, `/token/introspect`);
`auth_only` refuses everything but the `/auth/*` + `/token*` + `/.well-known/*`
plane; `local_only` refuses remote-dependent endpoints (`/auth/home-realm`,
`/fetch`, `/ssf/receive`); `maintenance` refuses every non-probe request.

| Code               | HTTP | Emitted when                                                        | Headers                  |
|--------------------|------|--------------------------------------------------------------------|--------------------------|
| `service_degraded` | 503  | The active DR mode refuses the request class                       | `Retry-After: <seconds>` |
| `invalid_mode`     | 400  | `POST /api/v1/admin/dr/mode` given a mode outside the fixed enum   |                          |

---

## SDK webhook signature verification (outbound webhooks)

The outbound webhook transports (audit `WebhookSink`, MFA/CIBA push) can
sign every delivery with HMAC-SHA256 (`X-Signature: t=<unix>,v1=<hex>`,
Stripe/Svix style) when a `signing_secret` is configured. `security.
VerifyWebhookSignature` is a receiver-side helper for a peer service to
authenticate those deliveries — it returns the sentinels below. These are
**SDK Go errors, not HTTP wire codes**: they never appear in any response
this SSO server emits (it is the sender, not the receiver), and they carry
no `error`/`error_description` JSON body.

| Sentinel                       | Returned when                                                        |
|--------------------------------|---------------------------------------------------------------------|
| `ErrWebhookSignatureMalformed` | Header missing/garbled — absent `t`/`v1` part, or non-hex `v1`       |
| `ErrWebhookSignatureMismatch`  | Recomputed HMAC (constant-time `hmac.Equal`) differs — wrong secret or tampered body |
| `ErrWebhookSignatureExpired`   | Signed timestamp outside the caller's tolerance (freshness check; skipped when tolerance <= 0) |

---

## SDK resource-server token validation (`interfaces/ssoclient/rs`)

The `rs` package is the resource-server (RS) side of the SDK: a microservice
consuming this server's access tokens uses it to validate them (locally via
JWKS or remotely via RFC 7662 introspection) and to verify RFC 9449 DPoP
proofs, without re-implementing the AS's security gates. Like the webhook
sentinels above, these are **SDK Go errors, not HTTP wire codes** — branch on
them with `errors.Is`. The package's own `HTTPMiddleware` deliberately
collapses all of them to the standard RFC 6750 `WWW-Authenticate:
error="invalid_token"` challenge on the wire, so a caller-visible 401 can
never become a token-validation oracle.

| Sentinel                 | Returned when                                                                 |
|--------------------------|--------------------------------------------------------------------------------|
| `ErrConfig`              | `Config` cannot support the requested operation (missing `Issuer`, no key source for local mode, no `IntrospectURL` for remote mode) |
| `ErrTokenMalformed`      | Token is not a 3-segment compact JWS, a segment fails to decode, or a REQUIRED claim (RFC 9068 §2.2 `exp`) is absent |
| `ErrTokenTypeMismatch`   | JOSE header `typ` is not the RFC 9068 access-token type (`at+jwt` / `application/at+jwt`) — e.g. an ID token or logout token presented as an access token |
| `ErrSignatureInvalid`    | `alg` outside the allowlist, unknown `kid`, or JWS signature verification failed — one sentinel for the whole class so callers cannot build an oracle distinguishing "unknown key" from "bad signature" |
| `ErrIssuerMismatch`      | `iss` differs from `Config.Issuer`                                             |
| `ErrAudienceMismatch`    | `aud` does not contain `Config.ExpectedAud`                                    |
| `ErrTokenExpired`        | `exp` is in the past beyond `Config.MaxClockSkew`                              |
| `ErrTokenNotYetValid`    | `nbf` or `iat` is in the future beyond `Config.MaxClockSkew`                   |
| `ErrTokenInactive`       | RFC 7662 introspection answered `{"active": false}`                            |
| `ErrIntrospection`       | The introspection round-trip itself failed (transport error, non-200, unparseable body) — distinct from `ErrTokenInactive` so callers can choose their AS-outage fail mode separately from a genuine rejection |
| `ErrDPoPInvalid`         | Any RFC 9449 proof failure: malformed proof, bad signature, `htm`/`htu` mismatch, stale `iat`, missing `ath` binding, key thumbprint != token `cnf.jkt`, or a `cnf`-bound token presented without a proof |
| `ErrDPoPReplayed`        | The proof `jti` was already seen inside its acceptance window                  |
| `ErrInsufficientScope`   | `CheckScope`/`CheckAnyScope` found a required scope absent                     |
| `ErrSubjectMissing`      | `RequireSubject` found no `sub` claim (e.g. a `client_credentials` token reaching a user-only endpoint) |

---

## Conventions

- **Stability:** codes here are stable wire contract — adding new codes
  is fine, renaming / removing existing ones is a major-version break.
- **HTTP status mapping:** the table shows the typical status emitted
  by today's handlers. New codes follow standard semantics (4xx =
  client error, 5xx = server error). Don't rely on the exact status
  for branching — branch on the `error` code.
- **`error_description`:** human-readable, may include unstable detail
  (raw parser errors, downstream messages). Do NOT parse it
  programmatically.
- **Adding a new code:** declare in `consts.go` (or the per-handler
  file if it's handler-local), update this catalog in the same commit.
  CI's `make ci` doesn't (yet) enforce the catalog-vs-consts.go
  symmetry, but a future check can.
