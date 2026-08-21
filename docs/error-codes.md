# Error Code Catalog

Every error response from the SSO server's HTTP REST surface carries a
stable `error` code in the JSON body. API clients and downstream services
should branch on the code, **never** on the human-readable
`error_description` (which may change between versions).

The server provides no built-in SPA. “Client” in this catalogue includes
separately deployed login/admin/self-service frontends as well as direct API
consumers.

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

When the Tracing middleware populated a W3C trace ID for the request,
error responses emitted via `interfaces/sso`'s `errorBody`/
`authzErrorBody`/`authzErrorBodyDesc` helpers also carry `trace_id` —
the same value returned in the `X-Trace-Id` response header — so a
client can hand support one identifier that correlates directly to
server-side audit/trace records:

```json
{ "error": "invalid_request", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736" }
```

`trace_id` is omitted entirely (not an empty string) when no trace
context is available, e.g. requests that bypass the Tracing
middleware. Not every error-writing call site is wired yet — see
`shared/core/error_body.go` (`ErrorBodyWithTrace`) and
`interfaces/sso/handlers.go` (`errorBody`) for the current coverage.

Defined as Go constants in `consts.go` (and in the per-handler files
for the audit / permission code subsets) — grep there if you need the
exact emission site.

---

## First-run setup (`/api/v1/setup*`, opt-in via `setup_wizard.enabled`)

| Code                    | HTTP | Emitted when                                                                 | Client should                                   |
|-------------------------|------|------------------------------------------------------------------------------|-------------------------------------------------|
| `not_found`             | 404  | `GET /api/v1/setup/status` or `POST /api/v1/setup` while `setup_wizard.enabled=false` (no setup surface exists) | Not applicable — the wizard is disabled |
| `already_initialized`   | 409  | `POST /api/v1/setup` after an admin already exists — the setup API is single-use and locks so it can't be replayed to plant a second admin | Stop; use the external admin frontend or admin API. This server does not mount `/admin/` UI assets |
| `invalid_request`       | 400  | `POST /api/v1/setup` body fails to parse, or `admin.username`/`admin.password` (min 8 chars) missing | Fix the payload |
| `internal_error`        | 500  | Provisioning the first admin failed (a store write errored)                  | Retry; check server logs                        |

`GET /api/v1/setup/status` returns `{"initialized":bool,"setup_required":bool}` and is intentionally detail-free (anti-enumeration).

---

## Authentication (`/auth/*`, `/userinfo`, `/logout`)

| Code                                  | HTTP | Emitted when                                                       | Client should                              |
|---------------------------------------|------|--------------------------------------------------------------------|--------------------------------------------|
| `invalid_request`                     | 400  | Request body fails to parse, or required field absent              | Fix the request payload                    |
| `missing_client_id`                   | 400  | `client_id` omitted from a request that requires it                | Include `client_id`                        |
| `invalid_credentials`                 | 401  | Username/password mismatch, OTP/magic-link mismatch (including a code invalidated after its fifth failed attempt), or other auth failure | Re-prompt for credentials; request a new code after repeated failures |
| `invalid_password`                    | 400  | `POST /me/password`: the current password did not match            | Re-prompt for the current password         |
| `invalid_client`                      | 401  | Any client-authentication failure on `/token`, `/par`, `/backchannel-authentication`: unknown `client_id` OR bad secret (RFC 6749 §5.2 — one code for both, so the error never reveals which `client_id`s exist) | Check the client id + secret |
| `inactive_client`                     | 403  | Client exists but `Active: false` in config                        | Operator re-enables the client             |
| `tenant_mismatch`                     | 403  | Client is bound to a tenant the request didn't resolve to          | Use the right hostname / tenant context    |
| `region_not_allowed`                  | 403  | Serving region is outside the tenant's data-residency `AllowedRegions` | Route the request to an allowed region |
| (SDK sentinel) `region.ErrInvalidRegion` | — | `region.ValidateID`/`ValidatePolicy` and the policy stores' `Set` reject a malformed region ID (uppercase, spaces, underscores, leading/trailing `-`, >63 chars) at write time — region IDs are exact-match governance keys, so a typo must be loud, never silently normalized | Use canonical lowercase DNS-label IDs (`eu-west-1`, `us-east-1`) |
| `residency_violation`                 | 403  | Operation would place tenant data outside its residency boundary   | Use a region within the tenant's policy    |
| `quota_exceeded`                      | 403  | Tenant has reached its per-resource quota (sessions on login; clients on DCR `/register`). Governance code, not a credential oracle | Raise the tenant's quota, or reset usage |
| `forbidden`                           | 403  | Delegated org-admin surface (`/me/organizations/{tenant_id}/*`): the caller is not a `TenantRoleAdmin` of the path tenant. Tenant-absent, not-a-member, and member-but-not-admin ALL collapse to this one code (anti-enumeration — no branch reveals which) | Only an org admin may manage that org |
| `last_org_admin`                      | 409  | Delegated org-admin surface: removing or demoting the org's FINAL admin (including self-removal / self-demotion) was refused — it would orphan the org | Appoint another admin before removing/demoting the last one |
| `authenticator_not_allowed_for_client`| 403  | Client's `allowed_authenticators` list excludes this provider      | Use a method the client permits            |
| `passwordless_required`              | 400  | Client's `allow_passwordless_only` is true and `provider=password` was requested — every OTHER provider (`webauthn`, `totp`, phone/email, ...) stays available | Use `provider=webauthn` (passkey) instead |
| `risk_denied`                         | 403  | `RiskScorer` returned `DecisionDeny`                               | Step up auth, or wait + retry              |
| `conditional_access_denied`           | 403  | Enforced conditional-access policy denied interactive login, or required step-up cannot run because MFA dependencies are unavailable | Complete the required step-up, or ask an administrator to correct the policy/MFA configuration |
| `unsupported_provider`                | 400  | `provider` is neither a registered authenticator name nor a dispatchable enterprise-connection id — unknown, disabled, other-tenant, and misconfigured connections ALL collapse to this one code (anti-enumeration — no branch reveals which) | Use a valid provider name                  |
| `unknown_provider`                    | 400  | OAuth/OIDC callback received an unknown provider in `state`        | Restart the auth flow                      |
| `unsupported_grant_type`              | 400  | `/token` received an unrecognized `grant_type`                     | Use a supported grant type                 |
| `unauthorized_client`                 | 400  | Client's DCR-registered `grant_types` list excludes the requested `grant_type` (RFC 6749 §5.2 / RFC 8693 §4.5); empty `grant_types` = unrestricted | Register the client with the needed grant type or remove the restriction |
| `invalid_callback`                    | 400  | OAuth callback body malformed                                      | Restart the auth flow                      |
| `callback_failed`                     | 401  | OAuth provider rejected the exchange                               | Restart the auth flow                      |
| `login_required`                      | 400  | `prompt=none` was requested but no live session can fulfill the silent renewal (missing/bad/non-ID-token hint, the hint's exact `sid` ended, or hint bound to a different client) | Fall back to the visible login flow        |
| `interaction_required`                | 400  | `prompt=none` matched a conditional-access step-up policy, but silent mode cannot display MFA UI | Fall back to the visible login flow and complete step-up |
| `consent_required`                    | 200 / 400 | HTTP 200: interactive login has no matching `ConsentStore` grant (or `prompt=consent` forced re-consent). HTTP 400: `prompt=none` attempted to expand the ID-token hint's bound scopes, resources, or authorization details, which requires UI. Always carries `iss`. | Show consent in an interactive flow, then retry |
| `account_selection_required`          | 400  | (reserved) `prompt=none` set when account-picker UI is required                                                     | Fall back to the visible chooser           |
| `unmet_authentication_requirements`   | 400  | The RP supplied `acr_values` but the authenticator's `AchievedACR` is absent or not in that set (OIDC Core §3.1.2.6 / §5.5.1.1) | Route user through a stronger authentication method or re-prompt |
| `email_not_verified`                  | 403  | Login succeeded but the account's email has not completed self-service verification, and the deployment requires it before minting a session | Complete the email verification flow, then retry login |
| `password_expired`                    | 403  | Login succeeded (password matched) but `PasswordPolicyConfig.MaxAgeDays` is set and the credential has aged past that window. Not a credential oracle — the password already verified; this is a policy-state signal | Route the user through a forced change-password flow, then retry login |
| `hook_rejected`                       | 403  | A fail-closed authentication-pipeline Hook rejected the request or returned an unclassified internal error | Do not retry unchanged; contact the operator |
| `hook_timeout`                        | 503  | A fail-closed authentication-pipeline Hook exceeded its independent timeout | Retry later; operator checks Hook health |
| `profile_incomplete`                  | 403  | The built-in profile-completion Hook found a required authenticated-user attribute empty | Complete the required profile fields, then retry |

Tenant quota storage also exposes `core.ErrInvalidQuotaOperation` as an SDK Go
sentinel, not an HTTP code. A `TenantQuotaStore` returns it for an empty or
whitespace-padded tenant ID, an unknown resource dimension, a non-positive or
unrepresentable delta, a nil quota, a negative limit, or a token-rate limit
that cannot be expanded safely into the 60-second rolling window. HTTP callers
must not expose the diagnostic text; the existing `quota_exceeded` wire code is
reserved for valid operations that cross a configured hard limit.

### Tenant quota projection ingress

`PUT /api/v1/internal/tenant-quota/projection` is mounted only when the stock
server's projection ingress is enabled. It accepts a client-credentials access
token for the configured exact audience with
`tenant-quota:projection:write`. The validated token `client_id` and exact
`source_system` select a server-owned tenant binding; `tenant_id` in the JSON
body is only a consistency assertion and can never select a tenant. Every
success and error carries `Cache-Control: no-store` and `Pragma: no-cache`.

| Code | HTTP | Emitted when | Client should |
|------|------|--------------|---------------|
| `invalid_token` | 401 | The bearer is missing/invalid, is not an access token, or fails DPoP/mTLS validation | Obtain a valid machine access token; inspect the `tenant-quota-projection` bearer challenge |
| `invalid_request` | 400 | The media type/body is invalid or oversized, an unknown JSON field is present, the tenant id is invalid, or the projection has an invalid revision/limit | Correct the strict JSON request |
| `insufficient_scope` | 403 | The validated token lacks exact client-credentials claim shape, audience, or scope, or its exact source binding is unknown/disabled | Reconcile the machine grant and versioned server-side source binding; binding causes are intentionally hidden |
| `tenant_mismatch` | 403 | An authorized `(client_id, source_system)` binding resolves a different tenant than the body assertion | Send the entitlement for the tenant bound to that source; the response does not disclose its id |
| `quota_revision_conflict` | 409 | The current projection revision already exists with different quota content | Stop retrying the equivocated revision and repair the producer's monotonic sequence |
| `quota_projection_unavailable` | 503 | The projection store failed after authentication, binding, and input validation | Retry with bounded backoff and inspect SSO readiness/storage health |

An older projection or a byte-equivalent replay is not an error: it returns
HTTP 200 with `applied:false`. Control-plane source updates are batch-atomic and
monotonic. A stale, same-revision-equivocating, or otherwise invalid desired
generation leaves the last-good bindings live but degrades `/readyz`; an exact
current generation or valid next revision clears that degraded state.

### Code delivery (`/auth/send-code`)

| Code                            | HTTP | Emitted when                                            |
|---------------------------------|------|---------------------------------------------------------|
| `provider_and_target_required`  | 400  | Either `provider` or `target` missing from request body |
| `provider_does_not_send_codes`  | 400  | Named provider doesn't implement `CodeSender`           |
| `send_failed`                   | 500  | Downstream SMS / email delivery call failed; built-in stores conditionally revoke the undelivered value and release its cooldown so the caller can retry immediately |
| `resend_too_soon`               | 429  | A code was already sent to this target within the cooldown window (default 60 s); prevents send-code amplification attacks |

Send-budget exhaustion intentionally emits no distinct error: the endpoint
returns the normal HTTP 200 `{"status":"sent"}` body while suppressing delivery.
This keeps tenant/identity quota state and target existence from becoming an
authentication oracle. Defaults are 20 sends per tenant-scoped identity and
1,000 per tenant every 24 hours.

### Logout

| Code                            | HTTP | Emitted when                                                 |
|---------------------------------|------|--------------------------------------------------------------|
| `session_id_or_bearer_required` | 400  | Logout call has neither a `session_id` body nor a bearer hdr |

### Account lockout

| Code             | HTTP | Emitted when                                                                          | Client should                         |
|------------------|------|---------------------------------------------------------------------------------------|---------------------------------------|
| `account_locked` | 403  | The per-account failure threshold was reached, SCIM/core marked the verified user inactive, or a wired lifecycle store says the verified user is not `active` (including a fail-closed lifecycle read error) | Stop automatic retries; wait for temporary lock expiry or have an operator restore the account |

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
with `{"provider": "webauthn", "credential": {"session_id": "...", "assertion": "..."}}`,
obtaining `session_id` from the existing
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

### Trusted devices (`/me/devices*`, `/auth/login`)

| Code                                  | HTTP | Emitted when                                                                                                                                | Client should                                                    |
|----------------------------------------|------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `insufficient_user_authentication`     | 403  | `POST /me/devices/trust` was called with a bearer token that did not complete an MFA step-up THIS session (`amr` lacks `mfa`) — RFC 9470. Named explicitly (not collapsed) because this is a legitimate step-up demand on the caller's own account, not a credential-guessing surface. | Complete `/auth/mfa` first, then retry with the resulting token   |
| `not_found`                            | 404  | Any `/me/devices*` route hit with no `TrustedDeviceStore` wired, or `DELETE /me/devices/{id}` for an id not owned by the caller (or unknown) — both collapse to the same 404, oracle-safe | Not a client error when unwired; otherwise the grant is already gone |

`POST /auth/login` never surfaces a trusted-device-specific error: an unknown, expired, wrong-user, or wrong-client `device_token` is indistinguishable from an absent one and silently falls through to the ordinary `mfa_required` challenge (same anti-enumeration discipline as `RecoveryCodeStore.Consume`). A successful skip records the `mfa_skipped_trusted_device` audit event instead of a wire-visible signal.

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

### User notifications (`/me/notifications*`)

| Code | HTTP | Emitted when | Client should |
|---|---|---|---|
| `notification_store_unavailable` | 503 | The notification inbox, preference store, or SSE broker is not wired or returned an operational error | Keep the rest of the account portal available; retry the notification operation later |

Marking an unknown notification, including one owned by a different subject,
returns the existing `not_found` code. This prevents the endpoint from becoming
a cross-account notification-ID oracle.

### Authorization (`/auth/login`, `/par`)

These codes follow the OAuth 2.0 + RFC 9126 PAR + RFC 7636 PKCE wire vocabulary so off-the-shelf RP libraries (e.g. AppAuth, oauth4webapi, MSAL) recognize them without remapping.

| Code                         | HTTP | Emitted when                                                                            | Client should                                       |
|------------------------------|------|-----------------------------------------------------------------------------------------|-----------------------------------------------------|
| `access_denied`              | 400  | RFC 6749 §4.1.2.1 — the resource owner / AS refused the authorization request           | Surface to the user; do not auto-retry              |
| `invalid_redirect_uri`       | 400  | `redirect_uri` parameter doesn't match any of the client's registered values            | Operator fixes the client config or RP             |
| `invalid_scope`              | 400  | Requested scope set is not a subset of the client's `AllowedScopes`; OR (when `security.scope_limit.max_count` is configured) the `scope` parameter carries more space/array-separated tokens than the configured cap; OR (when `oauth.scope_registry.enabled` is set) an effective `/token` scope is not registered by the global scope registry — same plain body `{"error":"invalid_scope"}`, no new error surface, oracle-safe | Drop the disallowed scopes (or reduce the scope count), retry |
| `unsupported_response_type`  | 400  | `response_type` not in the AS-supported set (or implicit blocked by OAuth 2.1 strict)   | Use a supported value (`code`)                      |
| `invalid_pkce_method`        | 400  | `code_challenge_method` not in `S256` or `plain` (or blocked by strict mode)            | Use S256                                            |
| `pkce_required`              | 400  | Client has `RequirePKCE` set (or OAuth 2.1 strict) and the request omitted PKCE         | Add `code_challenge` + `code_challenge_method`      |
| `invalid_request_uri`        | 400  | RFC 9126 PAR — `request_uri` is unknown, expired, consumed, or bound to a different RP  | Re-POST `/par` for a fresh one                      |
| `par_not_configured`         | 501  | `/par` hit but no `WithPARStore` wired                                                  | Operator wires the store                            |
| `invalid_request_object`     | 400  | RFC 9101 JAR — `request` / `request_uri` carried a signed or encrypted request object that failed to parse / verify / decrypt (bad signature, unknown alg, wrong key, JWE decryption failure)  | Fix the JWT / JWE; verify it's signed by a key in the client's `JWKS` (and encrypted to the AS's `use:enc` JWK when JWE)  |
| `invalid_authorization_details` | 400  | RFC 9396 RAR — `authorization_details` parameter is malformed (not a JSON array, element missing `type`, or element `type` not in the client's `allowed_authorization_details_types`); OR (when `security.rar_limits.*` is configured) the payload exceeds the configured max serialized size, top-level element count, or nesting depth — checked BEFORE the payload is fully unmarshaled; OR (when `security.rar_catalog_check.enabled` is true on PAR) a verifiable API resource is unknown, mismatched, or cannot be resolved | Drop the offending element, get its type allowlisted, register the API resource, or shrink/flatten the payload |
| `insufficient_user_authentication` | 401 (RS) / 400 (AS) | RFC 9470 — caller demanded `acr_values` the subject token's existing ACR does not satisfy; or refresh-time conditional access / continuous verification requires a new step-up. On `/token` token-exchange or refresh grants and on resource-server `WWW-Authenticate` challenges. | Route user through `/auth/login` to step up; do not retry the same refresh token automatically |

**FAPI 2.0 profile** (`oauth.compliance.profile: fapi_2`, enforce mode): a baseline violation (no PAR, unsigned request object, non-S256 PKCE, non-code response type, or bearer/non-sender-constrained token) is rejected with the standard `invalid_request` (`error_description` carries the failed `fapi:<rule>` id; API clients branch on `error`, operators on the audit event). No new wire code is introduced — every violation maps onto the existing OAuth vocabulary. In inspection mode (`inspection_only: true`) nothing is rejected; each violation only emits the `fapi_compliance_violation` audit event (`fapi_rule` / `fapi_detail` / `fapi_mode` metadata) and increments `sso_fapi_violations_total{rule,mode}`.

**SPIFFE JWT-SVID token-exchange** (`spiffe.enabled`, `WithSPIFFEJWTSVID`): a SPIFFE JWT-SVID presented as a token-exchange `subject_token` (`subject_token_type=urn:ietf:params:oauth:token-type:jwt`, `sub` a `spiffe://` URI) is validated against the operator-supplied SPIRE trust-bundle JWKS with a strict asymmetric alg-allowlist (no `alg=none`), strict audience binding, and a trust-domain check. **No new wire code is introduced** — EVERY validation failure (bad signature, `alg=none`, wrong audience, wrong trust domain, expired, malformed `sub`) collapses to the standard `invalid_grant`, indistinguishable on the wire (oracle-leak hardening, AGENTS.md §3). A successful acceptance emits the INTERNAL `spiffe_jwt_svid_accepted` audit event (`spiffe_trust_domain` / `spiffe_namespace` / `spiffe_service_account` metadata); rejections are deliberately NOT audited per-cause (that would re-open the oracle).

**Cross-tenant B2B collaboration token-exchange** (`WithExternalUserStore` + `WithTenantCollaborationStore`, `domains/tenant`): a token-exchange whose `subject_token` was issued to a client in a DIFFERENT tenant than the exchanging client requires BOTH an explicit `TenantCollaboration` trust row (the guest tenant opts in to accepting guest tokens from the subject's home tenant) AND a matching `GuestRecord` registering that exact subject as a guest. **No new wire code is introduced** — a missing trust row or registration collapses to the standard `invalid_grant` (oracle-leak hardening: no signal about WHICH check failed, or that a cross-tenant boundary was even involved); a requested scope outside the guest's registered `Roles` is the standard `invalid_scope`. Either store left unwired (the default) is a complete no-op — byte-identical to a build without this feature; same-tenant exchanges are always unaffected. A successful cross-tenant hop emits the INTERNAL `cross_tenant_token_exchange` audit event with BOTH the guest-tenant context (`client_id`, `guest_tenant_id`) and the originating home-tenant identity (`original_subject`, `original_tenant`) so a SIEM can always trace the action back to its home account.

**RFC 9321 Transaction Tokens** (`txn_token.enabled`, `WithTransactionTokens`): an internal caller mints a short-lived, workload-identity-bound Txn-Token by sending the SAME `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` request as an ordinary RFC 8693 exchange, but with `requested_token_type=urn:ietf:params:oauth:token-type:txn-token` — every other `requested_token_type` is unaffected. **No new wire code is introduced**: a missing/malformed `subject_token`, `subject_token_type`, or `request_context` collapses to `invalid_request`; an `audience` not naming exactly this deployment's configured Trust Domain is `invalid_target`; an invalid/expired `subject_token` (an ordinary access token on the first hop, or a previously-issued Txn-Token on a chained/nested hop) or an act-chain deeper than 10 hops collapses to `invalid_grant` — the SAME codes the ordinary token-exchange grant already returns for its own subject_token/target gates, so the two are indistinguishable on the wire. When the feature is unconfigured (`txnTokenIssuer` unwired), a `requested_token_type` naming the Txn-Token URN falls straight through to the ordinary token-exchange handler's existing `invalid_request` collapse for an unrecognized type — byte-identical to a build without this feature. See `protocols/oauth/txntoken`.

**Cloud workload-identity client authentication** (`WithWorkloadIdentityProviders`): a client registered with `token_endpoint_auth_method=workload_identity` authenticates at `/token` by presenting a cloud-issued identity token as `client_assertion` with `client_assertion_type=urn:snaplink:params:oauth:client-assertion-type:workload-identity`, instead of a `client_secret` or `private_key_jwt`. The token is verified against the cloud provider's own published JWKS: GCP uses its fixed issuer/JWKS preset; AWS uses an operator-configured OIDC issuer (typically an EKS issuer); Azure uses the tenant-scoped issuer/JWKS preset derived from the configured tenant ID. All providers enforce a strict asymmetric alg allowlist plus issuer, audience and mapped-subject binding. **No new wire code is introduced** — every failure (bad signature, wrong issuer/audience, expired, unknown/unmapped identity, subject mismatch, unconfigured provider) collapses to the standard `invalid_client`, the same response used for `private_key_jwt` failures (oracle-leak hardening, AGENTS.md §3).

**DPoP authorization-code binding** (RFC 9449 §10): an optional `DPoP: <proof>` header on `POST /auth/login` with `response_type=code` binds the issued authorization code to that proof's JWK thumbprint. A malformed/invalid proof on `/auth/login` itself fails the login with `invalid_dpop_proof` (or `use_dpop_nonce` when §8 nonce enforcement is wired) — see the `/userinfo` table below for those two codes' shape, which is identical here. **No new wire code is introduced for the exchange-side gate** — on the subsequent `POST /token` `authorization_code` exchange, a missing DPoP proof or a proof under a different key than the one bound at `/auth/login` collapses to the standard `invalid_grant`, indistinguishable from every other auth-code failure (oracle-leak hardening, AGENTS.md §3). Omitting the `DPoP` header at `/auth/login` leaves the code unbound and the exchange-side gate never fires — fully backwards compatible.

### Token endpoint (`/token`)

| Code                          | HTTP | Emitted when                                                                            | Client should                                 |
|-------------------------------|------|-----------------------------------------------------------------------------------------|-----------------------------------------------|
| `invalid_grant`               | 400  | Auth code / refresh / device / PAR / PKCE failure, including a refresh denied by the current conditional-access policy — collapses every sensitive cause into one wire response (oracle-leak hardening, AGENTS.md) | Treat as terminal for that grant; restart flow |
| `invalid_target`              | 400  | RFC 8693 — `resource` / `audience` not in the client's `AllowedResources`              | Drop or correct the resource indicator        |
| `authorization_code_not_configured` | 501 | `grant_type=authorization_code` hit but no `WithAuthCodeStore` wired               | Operator wires the store                      |
| `refresh_token_not_configured` | 501 | `grant_type=refresh_token` hit but no `WithRefreshTokenStore` wired                    | Operator wires the store                      |
| `device_code_not_configured`  | 501  | `grant_type=urn:ietf:params:oauth:grant-type:device_code` hit but no `WithDeviceCodeStore` wired | Operator wires the store              |
| `device_secret_not_configured`| 501  | `device_sso` scope requested on `/token` but no `WithDeviceSecretStore` wired (OpenID Native SSO 1.0) | Operator wires the store              |
| `ciba_not_configured`         | 501  | `/backchannel-authentication` or `grant_type=urn:openid:params:grant-type:ciba` hit but no `WithCIBA` wired | Operator wires the store              |

**Content-Type strictness (opt-in)** — with `server.require_form_content_type: true`
(or `sso.WithCredentialFormOnly(true)`), `/token`, `/token/introspect`,
`/token/revoke`, and `/par` reject a JSON body, a missing Content-Type, or
any other media type with **415** and the SAME `invalid_request` code above
(plain `{"error":"invalid_request"}` envelope, byte-identical on all four
endpoints, `Cache-Control: no-store` + `Pragma: no-cache` on every response).
The 415 fires before the body is read and before client authentication, so it
never distinguishes credential state; malformed percent-encoding under a form
Content-Type still returns `400 invalid_request` via the normal bind path. No
new error code is introduced.

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
| `invalid_grant`         | 400  | Device `device_code` is unknown, expired, consumed, or bound to another client — every terminal cause collapses to this code | Restart the device flow |
| `expired_token`         | 400  | CIBA Core §11 — `auth_req_id` TTL elapsed (also unknown/consumed id — collapsed for anti-enumeration) | Restart the CIBA flow with a fresh request |
| `access_denied`         | 400  | RFC 8628 §3.5 / CIBA Core §11 — the user explicitly denied the request    | Surface to the user; do not auto-retry                   |

### CIBA backchannel authentication (`/backchannel-authentication`)

| Code                    | HTTP | Emitted when                                                              | Client should                                            |
|-------------------------|------|---------------------------------------------------------------------------|----------------------------------------------------------|
| `invalid_request`       | 400  | More than one user hint, non-positive `requested_expiry`, or `user_code` supplied while no verifier is wired | Correct the request and retry                            |
| `unknown_user_id`       | 400  | OIDC CIBA Core §13 — no hint supplied, or the one supplied hint did not resolve to a known user (collapsed for anti-enumeration) | Verify the hint identifies an enrolled user              |
| `missing_user_code`     | 400  | The wired verifier requires a fresh CIBA user code for this client/user    | Prompt the user for their dedicated CIBA code            |
| `invalid_user_code`     | 400  | The wired verifier rejected the supplied CIBA user code                    | Discard it and collect a fresh code; do not auto-retry   |

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

The admin permission gRPC service maps resource catalog sentinels as follows:
`ErrResourceExists` → `AlreadyExists`, `ErrResourceNotFound` → `NotFound`, and
`ErrInvalidResource` → `InvalidArgument`. Resource deletion is idempotent for
missing IDs. When PAR resource-catalog enforcement is enabled, an unknown or
mismatched verifiable API resource is returned as the existing
`invalid_authorization_details` OAuth error.

Separation-of-duty sentinels are mapped by the admin permission service as
follows. The REST gateway exposes the corresponding gRPC status mapping.

| Identifier | gRPC / HTTP | Emitted when |
|---|---|---|
| `ErrRoleConflict` | `FailedPrecondition` / 400 | An assignment or session activation contains two or more roles from one declared conflict set |
| `ErrRoleNotAssigned` | `FailedPrecondition` / 400 | A session activation names a role not assigned to the subject |
| `ErrInvalidConflictSet` | `InvalidArgument` / 400 | A conflict set is empty, has fewer than two roles, or repeats a role code |

---

## Audit (`/api/v1/audit/events*`)

| Code                     | HTTP | Emitted when                                                       |
|--------------------------|------|--------------------------------------------------------------------|
| `audit_not_enabled`      | 500  | API hit but `audit.api_enabled: false` (or no recorder configured) |
| `audit_event_not_found`  | 404  | Specific event id queried but absent / evicted from the sink       |

### Bulk export (SDK Go errors, `platform/audit/auditexport`)

The `auditexport` package builds and verifies self-contained, tamper-evident
audit bundles (used by `sso-ctl audit-export`). These are **SDK Go errors,
not HTTP wire codes**: they never appear in any response this server emits
and carry no `error`/`error_description` JSON body.

| Sentinel               | Returned when                                                        |
|------------------------|---------------------------------------------------------------------|
| `ErrNilPager`          | `BuildExportBundle` called with a nil `QueryPager`                   |
| `ErrNilBundle`         | `VerifyExportBundle` called with a nil bundle                        |
| `ErrUnsupportedFormat` | Bundle `FormatVersion` differs from the reader's supported version  |

Chain-integrity failures (a tampered event, a broken segment, or a head-hash
mismatch) surface as descriptive `platform/audit` chain errors ("hash
mismatch", "chain break") from the reused verifiers, not as new sentinels.

### SOC2 evidence pack (SDK Go errors, `platform/audit/auditreport`)

The `auditreport` package (used by `sso-ctl soc2-report`) packages a
previously-built, previously-verified `auditexport.ExportBundle` into a
control-area evidence report. It defines **no new sentinels of its own**:
`BuildSOC2Report` and `VerifyAndBuildSOC2Report` both return the existing
`auditexport.ErrNilBundle` on a nil bundle, and `VerifyAndBuildSOC2Report`
propagates whatever chain-verification error `auditexport.VerifyExportBundle`
returns on a tampered/unverifiable bundle unchanged — it never re-implements
or re-wraps that check. Same non-wire-code caveat as above.

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
| `config_apply_approval_required` | 400  | `POST .../config/apply` or `.../config/rollback` (the declared peer-config baseline write path, `platform/configaudit`) issued without `?approve=true` — the mandatory misoperation barrier, refused before any state is touched |
| `config_apply_conflict`       | 409  | `POST .../config/apply`: the server-recomputed sha256 does not match `digest`; or `POST .../config/rollback`: supplied `expected_version_id` is stale — both leave the baseline unchanged |
| `config_apply_no_previous`    | 409  | `POST .../config/rollback`: no applied baseline exists, or the latest baseline has no predecessor to restore |
| `config_rollback_not_available` | 501  | `POST .../config/rollback`: an `expected_version_id` CAS rollback was requested but the configured backend does not implement the atomic conditional-rollback extension |
| `config_canary_not_available` | 501  | `POST .../config/apply?canary=true`: the deployment has no atomic canary store and injected health probes |
| `config_canary_in_progress`   | 409  | A canary is observing; concurrent apply or rollback is refused until it confirms or rolls back |
| `config_canary_no_baseline`   | 409  | `canary=true` was requested before an applied baseline existed, so no safe predecessor was available |
| `config_canary_conflict`      | 409  | The canary candidate is no longer the latest applied version; automatic rollback refuses to touch a newer baseline |

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

## Back-channel logout failure governance (`/api/v1/admin/backchannel-logout/failures*`)

Mounted only when `backchannel_logout.failure_queue.backend` is `memory` or
`redis`. Entries are tenant-scoped for tenant-resolved admin requests. GET is
`admin:read`; replay POSTs are `admin:write`.

| Code | HTTP | Emitted when |
|---|---|---|
| `bcl_failure_not_found` | 404 | The requested failure id is unknown or belongs to another tenant; both cases deliberately collapse to one response |
| `bcl_replay_in_progress` | 409 | Another worker or administrator owns the unexpired replay lease |
| `bcl_delivery_failed` | 502 | The freshly signed replay exhausted its delivery attempts; the entry was rescheduled and remains queryable |
| `internal_error` | 500 | Queue list/claim/storage access failed |

A `207` response means the RP accepted the replay but queue cleanup failed.
The entry remains recoverable; replay is safe because logout processing is
session/subject idempotent and every attempt carries a newly signed token/JTI.

---

## ReBAC relationship-tuple engine (`/api/v1/admin/rebac/check`)

Opt-in (`sso.WithRebacEngine`) ONE-route operational-debugging surface for
the `platform/lifecycle/rebac` Zanzibar-style relationship-based access
control (ReBAC) primitive: `GET .../check?object=&relation=&subject=`
answers whether `subject` has `relation` on `object`, walking direct tuples
plus one level of group-membership indirection. admin:read. This is a THIRD,
independent authorization model alongside `domains/permissions` (RBAC) and
`domains/conditionalaccess` (attribute-based) — none of the three consult
each other, and rebac is not wired into `/auth/login` or any other built-in
gate; an operator consults `rebac.Engine.Check` from their own integration
code. Not mounted without a wired engine.

| Code                    | HTTP | Emitted when                                                                                       |
|-------------------------|------|-----------------------------------------------------------------------------------------------------|
| `rebac_not_configured`  | 500  | `GET /api/v1/admin/rebac/check` hit with no `WithRebacEngine` wired (defensive; the route is only mounted when one is) |
| `invalid_request`       | 400  | `object`, `relation`, or `subject` query parameter missing                                          |
| `internal_error`        | 500  | The wired `RelationTupleStore` returned an error while resolving the Check                          |

---

## Pluggable WASM authorization engine (`/api/v1/admin/wasmauthz/check`)

Opt-in (`sso.WithWASMAuthzEngine`) ONE-route operational-debugging surface for
the `platform/lifecycle/wasmauthz` pluggable, WebAssembly-hosted
authorization-decision engine: `POST .../check` (JSON body — a
`wasmauthz.Request`) evaluates the operator-supplied WASM policy module and
returns its `wasmauthz.Decision`. admin:read (a read-only decision probe,
despite POST). This is a FOURTH, independent authorization model alongside
`domains/permissions` (RBAC), `domains/conditionalaccess` (attribute-based),
and `platform/lifecycle/rebac` (Zanzibar-style ReBAC) — none of the four
consult each other, and wasmauthz is not wired into `/auth/login` or any
other built-in gate; an operator consults `wasmauthz.Engine.Authorize` from
their own integration code. Not mounted without a wired engine. See
`docs/wasmauthz.md` for the ABI contract a WASM policy module must implement.

| Code                        | HTTP | Emitted when                                                                                       |
|------------------------------|------|-----------------------------------------------------------------------------------------------------|
| `wasmauthz_not_configured`  | 500  | `POST /api/v1/admin/wasmauthz/check` hit with no `WithWASMAuthzEngine` wired (defensive; the route is only mounted when one is) |
| `invalid_request`           | 400  | The request body is not valid JSON (fails to bind to `wasmauthz.Request`)                          |
| `internal_error`            | 500  | The wired `wasmauthz.Engine`'s `Authorize` call failed — a guest trap, a malformed JSON decision, an out-of-bounds guest pointer, or the per-call timeout firing. FAIL-CLOSED: any real integration calling `Engine.Authorize` directly must treat this same failure as a denial, never as "inconclusive, so allow" (see `docs/wasmauthz.md`) |

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

### Token portfolio bulk-revoke (`POST /api/v1/admin/tokens/bulk-revoke`)

Revocation-storm protection for the admin bulk-revoke workflow. Neither code is
a credential oracle — the caller is an authenticated admin (admin:write).

| Code                                 | HTTP | Emitted when                                                                                          |
|--------------------------------------|------|------------------------------------------------------------------------------------------------------|
| `bulk_revoke_confirmation_required`  | 409  | The batch is large enough (over the soft cap) — or is a client-wide revoke that can't be pre-counted — to demand an explicit `confirm: true` |
| `bulk_revoke_batch_too_large`        | 409  | The batch exceeds the hard cap and must be narrowed (a subject/client revoke that would wipe more than the storm ceiling), even with `confirm` |

## Admin LOCAL user CRUD (`POST /api/v1/admin/local-users`, `POST/GET/PUT/DELETE /api/v1/admin/local-users/:id`)

Operations to create, read, update, and delete LOCAL (password-authenticated)
user accounts. Named `local-users` (not `users`) because `cmd/sso-server`'s
admin gRPC-gateway claims the literal `/api/v1/admin/users` shape for its own
federated/external-identity `UserAdminService` (see
`docs/openapi.yaml`'s `/api/v1/admin/users` entry) — the outer mux would
otherwise route every request at that path to the gateway, permanently
shadowing this handler (the class of bug fixed by giving this surface its own
path; see the bulk-revoke fix, commit `fdebea60`, for the identical pattern).

Routes are mounted only when a `UserProvider` IS wired AND the `UserProvider`
implements the optional
`UserPaginationProvider`/`UserByUsernameProvider`/`UserByEmailProvider`
extensions (for user creation, the store must also implement
`PasswordCredentialStore` and optionally `MFAEnrollmentStore`). None of these
codes are credential oracles — the caller is an authenticated admin (admin:write).

| Code                | HTTP | Emitted when                                                                                     |
|---------------------|------|---------------------------------------------------------------------------------------------------|
| `user_conflict`     | 409  | Create or update would produce a collision on a uniqueness constraint (username, email) — the caller should re-read and retry with different values |
| `not_found`         | 404  | The `UserProvider` has no user with that `:id`                                                    |
| `invalid_request`   | 400  | The `:id` path segment or required body fields are missing/blank                                  |
| `internal_error`    | 500  | The `UserProvider` returned an unexpected error                                                    |

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

Only `active` may authenticate or continue using end-user credentials. Primary,
MFA and federated-continuation login denial is `403 account_locked`; denial of
an authorization-code, refresh, device, CIBA, token-exchange, JWT-bearer,
SAML-bearer or agent-delegation grant collapses to `400 invalid_grant`;
access-token use validates `sub` and every `act` link and fails as
`401 invalid_token`; and introspection returns `200 {"active":false}`. Store
read errors take the same fail-closed paths. `client_credentials` is not a user
grant and is unaffected. In the stock server, entering any non-active state also
synchronously destroys live sessions and deletes refresh tokens across all
clients before the transition request returns.

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

`domains/identitylink.MergePolicy` is the decision seam for when a federated
login discovers that an external identity is already linked to a DIFFERENT
local account. The stock binary wires it into both static and
connection-backed OIDC federation; custom authenticators can reuse the same
Server accessors. The default `RejectPolicy` always refuses (safe default);
the reference `LinkOnlyMergePolicy` atomically merges ONLY identity-link
records onto the winning account (sessions/consents/tokens are NOT merged).
Both outcomes are recorded via
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
| `unsupported_version`             | 400  | The request's `Accept-Version` header names a value not in `WithAPIVersioning`'s configured list |

**API versioning / deprecation** (ADR-0008, opt-in): `WithAPIVersioning("v1", ...)`
enables `Accept-Version` request-header negotiation — a request that sends no
`Accept-Version` header (every client today) is completely unaffected; a
request that sends the header must name a supported value or gets
`400 unsupported_version` before its route handler runs. `WithAPIDeprecation`
and `WithRouteDeprecation` add the `Deprecation` + RFC 8594 `Sunset` (+
optional `Link: <url>; rel="sunset"`) response headers to the whole API or to
specific endpoints/prefixes; omitting both means no response ever carries
these headers. `WithAPIVersionPreview` mounts `GET /api/v2alpha/version`, the
ADR's one example route proving the `/api/v2alpha` path-prefix mechanism
works — it is not a commitment to a full v2 API surface. All four are
independently opt-in and unmounted/off by default.

---

## SAML 2.0 (`/saml/*`, `/auth/saml/callback`)

SAML 2.0 is supplied by the repository-maintained, opt-in nested module
`infrastructure/saml` (module path `github.com/yangwb1123/snaplink/saml`), keeping the
SAML/XML/DSig dependency out of the root module's `go.mod`. A custom
composition binary imports the module and registers its handler factory. The
codes below are the stable wire vocabulary that module SHOULD emit; the root
module ships the constants (`ErrSAML*` in `shared/core/consts.go`) and the
dependency-free handler registry, not the protocol handlers. SAML is inert
unless `saml.handler` names a registered factory — until then these codes never
appear.

| Code                     | HTTP | Emitted when                                                                 | Client should                          |
|--------------------------|------|------------------------------------------------------------------------------|----------------------------------------|
| `saml_assertion_invalid` | 400  | A returned SAML assertion fails validation — bad signature, wrong audience/issuer, expired, or replayed (causes SHOULD be collapsed onto this one code to avoid an oracle, AGENTS.md §3) | Restart the SAML SSO flow              |
| `saml_request_invalid`   | 400  | (IdP side) A malformed/forged AuthnRequest, an ACS URL not in the SP's registered allowlist, or an unknown/expired/consumed pending request / invalid session at `/saml/sso/finish` (all collapsed onto this one code — oracle-safe, AGENTS.md §3) | Restart the SAML SSO flow              |
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
gate failed (AGENTS.md §3). A VALID SET is always **acked (202)** even when
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

## OpenID Federation 1.0 §8.3 Resolve (`/.well-known/openid-federation-resolve`)

This opt-in endpoint returns `{"chain":["<compact-jws>", ...]}` after resolving
`sub` to a configured trust anchor. Unlike public entity/fetch metadata, every
response sets `Cache-Control: no-store` and `Pragma: no-cache`.

| Code | HTTP | Emitted when |
|---|---:|---|
| `invalid_request` | 400 | The required `sub` query parameter is missing |
| `not_found` | 404 | The resolver is unavailable/disabled, or the entity is unknown, unfetchable, invalid, or does not form a trusted chain; all cases collapse to the same response |

The route is mounted only when the Federation entity and an enabled resolver
are wired. Trust anchors are configured out of band and are never fetched from
the entity under evaluation.

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
`forbidden`, see Auth / OAuth above) plus a
`WWW-Authenticate: Bearer realm="admin"` challenge — the request never reaches the SCIM handler, so it
never gets a `scim+json` body.

---

## Tenant commerce SDK (`interfaces/commerce`)

The commerce HTTP package is an opt-in SDK surface; the stock `sso-server`
does not mount it. A composition that calls `RegisterRoutes` MUST put the
admin bearer middleware (or an equivalent policy gateway) in front of the
management routes. GET operations require `admin:read`; POST/PATCH operations
require `admin:write`. The handlers themselves do not duplicate that upstream
authorization check.

The machine payment routes are separate and remain absent until the composition
registers each route with a non-nil, fail-closed scope gate. The order snapshot
route requires `billing:payment:order:read`; the normalized event route requires
`billing:payment:write`. The stock `ClientCredentialsScopeGate` accepts only a
validated client-credentials identity (`sub == client_id`) carrying the exact
route scope. Missing validated claims return `invalid_token` (401); a user
identity or missing scope returns `insufficient_scope` (403). Both use
`WWW-Authenticate: Bearer realm="billing"` and name the route's exact scope.
The event endpoint accepts a normalized JSON fact, not a raw provider webhook;
unknown fields, provider signatures, secrets, checkout credentials, and card
data are rejected as `invalid_request`.

Every response written by a commerce handler, success or error, carries
`Cache-Control: no-store` and `Pragma: no-cache`. The stock payment-event gate
stamps the same headers on its 401/403 responses. Admin authentication happens
before the handlers, so the upstream admin middleware owns its own rejection
headers.

| Code | HTTP | Emitted when | Client should |
|------|------|--------------|---------------|
| `commerce_invalid_plan` | 400 | A plan is missing identity/name, has an invalid status or billing interval, a negative grace period, or an invalid limit grant | Correct the immutable plan version and retry |
| `commerce_invalid_money` | 400 | Currency is not a three-letter uppercase code or minor units are negative | Send integer minor units with an uppercase currency code |
| `commerce_plan_not_found` | 404 | The requested `(plan_id, version)` does not exist | Select a published plan version |
| `commerce_plan_conflict` | 409 | The immutable `(plan_id, version)` already exists with different content | Publish a new version; do not overwrite a version |
| `commerce_plan_retired` | 409 | A subscription operation targets a retired plan | Select an active plan version |
| `commerce_invalid_subscription` | 400 | Subscription identity, tenant, plan reference, status, revision, or period is invalid | Correct the subscription request |
| `commerce_subscription_not_found` | 404 | A subscription id does not exist | Refresh the tenant's subscription list |
| `commerce_entitlement_not_found` | 404 | No entitlement snapshot exists for the tenant | Create or repair the tenant subscription |
| `commerce_tenant_subscribed` | 409 | The tenant already has a live subscription | Mutate the existing subscription instead of creating another |
| `commerce_transition_denied` | 409 | The requested subscription status transition is not allowed | Reload state and choose a valid transition |
| `commerce_revision_conflict` | 409 | `expected_revision` does not match the current aggregate revision | Reload the aggregate and retry with its current revision |
| `commerce_invalid_ledger_entry` | 400 | Ledger identity/currency/amount/idempotency is invalid, or entry kind and amount sign disagree | Correct the adjustment payload |
| `commerce_insufficient_funds` | 409 | A debit or negative adjustment would overdraw the wallet | Top up the wallet or reduce the debit |
| `commerce_wallet_overflow` | 409 | Applying an entry would overflow the integer minor-unit balance | Stop and reconcile the ledger |
| `commerce_wallet_frozen` | 423 | A debit/adjustment is refused because chargeback handling froze the wallet | Resolve the chargeback before further debits |
| `commerce_idempotency_conflict` | 409 | An idempotency key or provider event id was replayed with different immutable content | Reuse a key only for the same immutable business command or fact |
| `commerce_invalid_payment` | 400 | A top-up order or normalized payment fact has invalid identity, provider binding, currency, amount, event type, or occurrence time | Correct the normalized order/event fields |
| `commerce_payment_not_found` | 404 | The payment order does not exist, or belongs to a different path tenant | Refresh the tenant's order list; cross-tenant details are intentionally hidden |
| `commerce_payment_event_not_found` | 404 | A requested provider event is absent in the payment store | Refresh payment state before retrying |
| `commerce_payment_state_conflict` | 409 | A capture/refund/rejection cannot apply to the current order state or totals | Reconcile provider and local order state |
| `commerce_unavailable` | 503 | The request context was canceled or its deadline expired | Retry with backoff if the caller deadline permits |
| `insufficient_scope` | 403 | A machine payment bearer is not a client-credentials identity with the route's exact `billing:payment:order:read` or `billing:payment:write` scope, or its server-owned binding is unknown, disabled, stale/revised where applicable, cross-tenant, cross-provider, not `payment:<provider>`, or declares any allowed dimension | Use a dedicated adapter client and reconcile its enabled, dimensionless tenant/provider binding; individual mismatch causes are intentionally hidden |
| `invalid_request` | 400 | Body/path tenant mismatch, malformed body, invalid currency/query bound, missing required field, wrong payment-event media type, or an unknown normalized-event field | Correct the request without adding raw provider material |
| `internal_error` | 500 | An unclassified commerce dependency error reached the HTTP adapter | Retry and inspect operator logs/audit records |

Automatic settlement also defines the internal sentinels
`commerce.ErrInvalidRenewal` and `commerce.ErrRenewalClaimLost`. They are not
HTTP error codes: the worker logs an invalid command/mutation as an operator
configuration or invariant failure, while a lost or expired lease leaves the
subscription and wallet unchanged so a current worker generation can reclaim
it safely.

`commerce.ErrPaymentSourceUnauthorized` is also an internal domain/store
sentinel, never a distinct wire code. The HTTP adapter maps it to the same
`403 insufficient_scope` response used by the pre-transaction identity/scope
and binding checks. PostgreSQL raises it when the binding id/revision or any
client, tenant, provider, enabled, or empty-dimensions fact fails its in-
transaction `FOR SHARE` revalidation; callers cannot distinguish those causes.

---

## Stripe payment adapter (`cmd/snaplink-stripe-adapter`)

This optional process has a separate OpenAPI contract at
`cmd/snaplink-stripe-adapter/openapi.yaml`. Checkout authentication first uses
the shared resource-server middleware; its missing/invalid token response is
`invalid_token` (401). A valid machine token without the exact
`billing:checkout:create` scope, whose `client_id` has no unique tenant
binding, or whose `tenant_id` claim is missing or contradicts the client's
bound tenant returns `insufficient_scope` (403); the binding and
claim-consistency causes stay indistinguishable. On the user flow, a missing
exact `admin:write` scope keeps `insufficient_scope`, while a request
`tenant_id` that is missing, unbound, or contradicts the token's `tenant_id`
claim — or a user token carrying no `tenant_id` claim — returns
`tenant_mismatch` (403) with no `scope` attribute. Checkout
responses are always `no-store`/`no-cache`.

| Code | HTTP | Emitted when | Client should |
|------|------|--------------|---------------|
| `tenant_mismatch` | 403 | A user-shaped token's `tenant_id` claim contradicts the request `tenant_id`, the request `tenant_id` is missing or names an unbound tenant, or the token carries no `tenant_id` claim | Retry with the correct tenant context; the response never discloses the token's or request's tenant |
| `invalid_request` | 400 | Checkout JSON is malformed/overspecified, identity is invalid, or a return URL is outside the exact origin allowlist | Correct only `order_id`, `success_url`, and `cancel_url`; never add tenant/amount/provider fields |
| `billing_unavailable` | 502 | The authoritative Billing order cannot be read or validated | Retry with backoff; inspect Billing/token dependency health |
| `provider_unavailable` | 502 | Stripe checkout creation fails or returns an invalid response | Retry the exact request; the stable provider idempotency key prevents a second session |
| `order_not_pending` | 409 | Billing says the order is no longer pending or already has a provider order id | Reload the order and do not create another checkout session |
| `checkout_conflict` | 409 | An existing order reservation has different return URLs, amount/currency, idempotency identity, or Stripe session facts | Stop and reconcile the immutable order/session mapping |
| `invalid_signature` | 400 | Stripe raw-body HMAC, signature header, rotation secret, or ±5 minute timestamp window fails | Do not retry from an application client; verify endpoint secret and host clock |
| `invalid_event` | 400 | A signed supported Stripe event cannot be projected into a complete minimal fact | Inspect bounded operational logs and the Stripe event schema/version |
| `event_conflict` | 409 | The same Stripe event id already exists with a different raw-payload SHA-256 digest | Treat as a security/integrity incident; do not overwrite the inbox row |
| `unavailable` | 503 | Durable inbox/mapping persistence or another local dependency failed | Retry with backoff; Stripe may safely redeliver identical events |

A valid but unsupported Stripe event returns 204 and is not stored. A supported
event that was already stored with the same digest returns the same 200 success
as its first delivery. Relay failures have no additional wire code: facts stay
durable and retry forever with a bounded category in operational logs.

---

## Machine usage and entitlement SDK (`interfaces/metering`)

This opt-in API-only surface runs after `rs.HTTPMiddleware`. Every route
requires a validated client-credentials identity (`sub == client_id`), then an
exact machine scope: `metering:write` for usage/reservation mutations and
`billing:entitlement:read` for the narrow current-entitlement read. The signed
`client_id` must resolve to exactly one enabled server-side binding. Tenant and
source identity are never accepted from a path, query, body, or forwarded
header. Unknown, disabled, ambiguous, stale, and concurrently revised bindings
fail closed; usage mutations revalidate binding revision and allowed dimension
inside the same Memory/PostgreSQL transaction.

Machine request bodies are strict JSON capped at 64 KiB. Append and reserve do
not accept a period: append derives a canonical calendar month from a bounded
`occurred_at` (server time when omitted), while reserve uses the current server
month. Commit takes dimension, quantity, period, and occurrence time from the
reservation. Every success and error carries `Cache-Control: no-store` and
`Pragma: no-cache`; 401/403 authorization failures also carry an RFC 6750
`WWW-Authenticate: Bearer realm="metering"` challenge.

| Code | HTTP | Emitted when | Client should |
|------|------|--------------|---------------|
| `invalid_token` | 401 | The request did not pass the resource-server middleware or validated claims are absent | Obtain and present a valid access token for the billing audience |
| `insufficient_scope` | 403 | The bearer is not a client-credentials identity or lacks the route's exact scope | Use a dedicated machine client granted the documented exact scope |
| `metering_source_unauthorized` | 403 | The client binding is unknown, disabled, ambiguous, stale/revised, or fails its in-transaction evidence check | Stop writes and reconcile the server-side source binding; retries with stale evidence cannot succeed |
| `metering_dimension_not_allowed` | 403 | The resolved binding does not allow the requested usage dimension | Provision that dimension for the machine client or use an authorized client |
| `metering_invalid_fact` | 400 | Quantity/dimension/time/metadata is invalid, `occurred_at` is future or over 35 days old, or a caller tries invalid period semantics | Correct the usage fact; never send a period |
| `metering_invalid_reservation` | 400 | Reservation identity, quantity, TTL, or lifetime is invalid | Send a TTL from 1 through 86400 seconds and valid positive quantity |
| `metering_reservation_not_found` | 404 | The reservation is absent or is owned by another tenant/source binding | Treat the opaque ID as unavailable; cross-tenant details are intentionally hidden |
| `metering_reservation_conflict` | 409 | Commit/release is incompatible with the reservation state, expiry, or immutable fact | Reload reservation state and stop changing immutable retry fields |
| `metering_idempotency_conflict` | 409 | An ID or `Idempotency-Key` was reused for different immutable usage semantics | Reuse a key only for the exact same command |
| `metering_quota_exceeded` | 409 | Committed plus reserved usage would exceed the entitlement hard limit | Reduce/release usage or change the tenant entitlement |
| `metering_counter_overflow` | 409 | Applying the quantity would overflow the signed usage counter | Stop and inspect/reconcile the usage ledger |
| `metering_period_closed` | 409 | A fact/reservation/commit targets a finalized monthly period | Do not mutate closed billing periods; use an operator-controlled adjustment workflow |
| `metering_entitlement_missing` | 403 | The tenant's active entitlement has no grant for the requested dimension | Add the dimension to the subscribed plan/entitlement |
| `metering_entitlement_not_found` | 404 | The bound tenant has no current entitlement snapshot | Provision or repair the tenant subscription |
| `request_too_large` | 413 | A strict machine JSON body exceeds 64 KiB | Reduce bounded metadata and retry |
| `metering_unavailable` | 503 | Binding/entitlement state is unavailable or an entitlement projection is inconsistent with the resolved tenant | Retry with backoff; alert operators if the condition persists |
| `invalid_request` | 400 | JSON/media type is invalid, an unknown field (including tenant/source/period) is present, a required idempotency header is missing, or GET/DELETE carries unsupported input | Send only the documented fields and required `Idempotency-Key` |
| `internal_error` | 500 | An unclassified metering dependency error reached the HTTP adapter | Retry and inspect operator logs/audit records |

---

## Rate limiting + payload

| Code                | HTTP | Emitted when                                          | Headers                  |
|---------------------|------|-------------------------------------------------------|--------------------------|
| `rate_limited`      | 429  | `ratelimit.Middleware`/`DynamicMiddleware` blocked the request (`security.rate_limit.*`), the narrow `POST /register` client-registration limiter did (`security.client_registration_rate_limit.*`), or an authenticated tenant exhausted `tenant.resource_quota.limits[].max_token_rate` at `/token` | `Retry-After: <seconds>`; the tenant token-quota response also carries `Cache-Control: no-store` and `Pragma: no-cache` |
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
Stripe/Svix style) when a `signing_secret` is configured.
`security.VerifyWebhookSignature` is a receiver-side helper for a peer service to
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
collapses all of them to the standard RFC 6750
`WWW-Authenticate: error="invalid_token"` challenge on the wire, so a caller-visible 401 can
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
| `ErrPolicyNotFound`      | `ThreatPolicyStore.Get`/`Delete` called with a name that does not exist in the store |

---

## Active ITDR threat policy (`domains/threataction`)

Sentinel errors returned by the threat-policy store and used internally by
`ThreatExecutors` — these are **not** HTTP wire codes. The admin CRUD handlers
at `/api/v1/admin/threat-policies/*` translate them to HTTP 404 on the wire.

| Sentinel               | Returned when                                                                |
|------------------------|------------------------------------------------------------------------------|
| `ErrPolicyNotFound`    | `ThreatPolicyStore.Get`/`Delete` called with a name that does not exist      |

`PUT /api/v1/admin/threat-policies/:name` also returns these HTTP wire codes:

| Code              | HTTP | Returned when                                                                | Remediation |
|-------------------|------|-------------------------------------------------------------------------------|-------------|
| `invalid_request` | 400  | Request body is not valid JSON                                              | Fix the request payload |
| `invalid_policy`  | 400  | Body decoded fine but is semantically invalid: `action` outside the known `Action` consts (`noop`/`suspend`/`revoke`/`step_up_mfa`/`notify`/`challenge`, or empty), `rate_limit.max` or `rate_limit.per_window` negative, or `conditions.operator` outside `""`/`eq`/`gt`/`lt`/`exists` when `conditions.key` is set. `error_description` names the specific violated field | Fix the named field and retry |

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
  CI enforces bidirectional catalog/constant coverage through
  `TestErrorCodesDocumented` in `docs/docscheck/error_codes_test.go`
  (with its named exceptions); `TestSentinelErrorsDocumented` covers
  sentinel errors.
