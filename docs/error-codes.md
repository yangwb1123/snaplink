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
| `invalid_client`                      | 401  | `client_id` does not resolve in the client store                   | Check the configured client                |
| `invalid_client_secret`               | 401  | Token endpoint received a bad client secret                        | Rotate or correct the secret               |
| `inactive_client`                     | 403  | Client exists but `Active: false` in config                        | Operator re-enables the client             |
| `tenant_mismatch`                     | 403  | Client is bound to a tenant the request didn't resolve to          | Use the right hostname / tenant context    |
| `authenticator_not_allowed_for_client`| 403  | Client's `allowed_authenticators` list excludes this provider      | Use a method the client permits            |
| `risk_denied`                         | 403  | `RiskScorer` returned `DecisionDeny`                               | Step up auth, or wait + retry              |
| `unsupported_provider`                | 400  | `provider` field is not a registered authenticator name            | Use a valid provider name                  |
| `unknown_provider`                    | 400  | OAuth/OIDC callback received an unknown provider in `state`        | Restart the auth flow                      |
| `unsupported_grant_type`              | 400  | `/token` received an unrecognized `grant_type`                     | Use a supported grant type                 |
| `invalid_callback`                    | 400  | OAuth callback body malformed                                      | Restart the auth flow                      |
| `callback_failed`                     | 401  | OAuth provider rejected the exchange                               | Restart the auth flow                      |
| `login_required`                      | 400  | `prompt=none` was requested but no live session can fulfill the silent renewal (missing/bad `id_token_hint`, session ended, or hint bound to a different client) | Fall back to the visible login flow        |
| `interaction_required`                | 400  | (reserved) `prompt=none` set when the AS needs UI interaction to proceed                                            | Fall back to the visible login flow        |
| `consent_required`                    | 400  | (reserved) `prompt=none` set when consent UI is required                                                            | Fall back to the visible consent step      |
| `account_selection_required`          | 400  | (reserved) `prompt=none` set when account-picker UI is required                                                     | Fall back to the visible chooser           |

### Code delivery (`/auth/send-code`)

| Code                            | HTTP | Emitted when                                            |
|---------------------------------|------|---------------------------------------------------------|
| `provider_and_target_required`  | 400  | Either `provider` or `target` missing from request body |
| `provider_does_not_send_codes`  | 400  | Named provider doesn't implement `CodeSender`           |
| `send_failed`                   | 500  | Downstream SMS / email delivery error                   |

### Logout

| Code                            | HTTP | Emitted when                                                 |
|---------------------------------|------|--------------------------------------------------------------|
| `session_id_or_bearer_required` | 400  | Logout call has neither a `session_id` body nor a bearer hdr |

### Account lockout

| Code             | HTTP | Emitted when                                                                          | Client should                         |
|------------------|------|---------------------------------------------------------------------------------------|---------------------------------------|
| `account_locked` | 423  | `AccountLockout` reports the (client_id, identifier) key is past the failure threshold | Wait until the lock expires, then retry |

### MFA orchestration (`/auth/login`, `/auth/mfa`)

| Code            | HTTP | Emitted when                                                                                                                          | Client should                                              |
|-----------------|------|---------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| `mfa_required`  | 200  | `/auth/login` accepted the primary credential but the RiskScorer returned `DecisionRequireMFA` and `WithMFAProvider` is wired         | Read `mfa_challenge_id` + `mfa_methods`; POST `/auth/mfa`  |
| `mfa_invalid`   | 400 / 404 | `/auth/mfa` could not complete the challenge (unknown id, expired, already consumed, unsupported method, wrong factor — all collapsed by anti-enumeration) | Restart the auth flow from `/auth/login`                |

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

### Token endpoint (`/token`)

| Code                          | HTTP | Emitted when                                                                            | Client should                                 |
|-------------------------------|------|-----------------------------------------------------------------------------------------|-----------------------------------------------|
| `invalid_grant`               | 400  | Auth code / refresh / device / PAR / PKCE failure — collapses every cause into one wire response (oracle-leak hardening, AGENTS.md) | Treat as terminal for that grant; restart flow |
| `invalid_target`              | 400  | RFC 8693 — `resource` / `audience` not in the client's `AllowedResources`              | Drop or correct the resource indicator        |
| `authorization_code_not_configured` | 501 | `grant_type=authorization_code` hit but no `WithAuthCodeStore` wired               | Operator wires the store                      |
| `refresh_token_not_configured` | 501 | `grant_type=refresh_token` hit but no `WithRefreshTokenStore` wired                    | Operator wires the store                      |
| `device_code_not_configured`  | 501  | `grant_type=urn:ietf:params:oauth:grant-type:device_code` hit but no `WithDeviceCodeStore` wired | Operator wires the store              |
| `ciba_not_configured`         | 501  | `/backchannel-authentication` or `grant_type=urn:openid:params:grant-type:ciba` hit but no `WithCIBA` wired | Operator wires the store              |

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

## Network policy (`/api/v1/netpolicy/*`)

| Code                       | HTTP | Emitted when                                                       |
|----------------------------|------|--------------------------------------------------------------------|
| `netpolicy_not_configured` | 500  | API hit but `network.api_enabled: false` (or no store configured)  |
| `netpolicy_not_found`      | 404  | Policy name queried but absent from store                          |

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

---

## Rate limiting + payload

| Code                | HTTP | Emitted when                                          | Headers                  |
|---------------------|------|-------------------------------------------------------|--------------------------|
| `rate_limited`      | 429  | `ratelimit.Middleware` blocked the request            | `Retry-After: <seconds>` |
| `payload_too_large` | 413  | `sso.WithBodyLimit(N)` exceeded by Content-Length or stream |                          |

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
