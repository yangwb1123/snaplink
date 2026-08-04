# MFA subsystem — identity-protocol review

Reviewer role: identity-protocol expert (`ai-dev/prompts/protocol_expert.md`).
Input: the MFA subsystem analysis in
`docs/architect-analysis-mfa-subsystem-review.md`, re-verified against current
code, discovery metadata, OpenAPI, error-codes docs, and tests at this
revision. This review maps the implemented behavior to exact specification
sections and requirement levels; it does not re-derive the earlier analysis's
three proposals (which are adopted here as findings 1–3 with one factual
correction each where evidence demanded it).

Checks that actually ran for this revision:

- `go test ./test/ -run 'TestMFA|TestMyMFA|TestTOTPEnroll|TestWebAuthnRegister|TestDiscovery_MFA|TestRecovery' -count=1` — ok
- `go test ./protocols/selfservice/selfserviceaccount/ ./infrastructure/defaultimpl/defaultmfa/ ./domains/authenticators/... ./shared/spi/... -count=1` — ok
- `go test ./interfaces/sso/ -run 'TestMFA|TestAmr|TestWithMFAMethod' -count=1` — ok

---

## 1. Protocol/profile scope and authoritative references

The MFA subsystem touches these standards. Everything else (SAML, SCIM,
CAEP/SSF, CIBA) is out of scope for this review.

| Protocol | Scope in Snaplink | Authoritative reference |
|---|---|---|
| OAuth 2.0 | `/auth/login` continuation, token responses, `state` preservation, `Cache-Control` on credential endpoints | RFC 6749 §3.1.2.6 (`state`), §4.1 (auth code), §5.1 (no-store) |
| OIDC Core 1.0 | `amr`/`acr`/`auth_time` claims on minted tokens; discovery metadata | OIDC Core §2 (ID token claims), §5.1 (claims), §3 (discovery); RFC 8176 |
| RFC 8176 | AMR values incl. the `mfa` multi-factor marker | RFC 8176 §2 |
| RFC 9470 | `insufficient_user_authentication` step-up demand | RFC 9470 §2 |
| RFC 6238 / RFC 4226 | TOTP factor (login + step-up + self-service enrollment) | RFC 6238 §4.2, §5.1, §5.2; RFC 4226 §5.3 |
| W3C WebAuthn L2/L3 + FIDO CTAP2 | WebAuthn step-up factor + passkey registration (`/me/mfa/webauthn/*`, `/webauthn/*`) | WebAuthn §5.1, §6.1, §6.2, §7.2; implemented via go-webauthn |
| RFC 9068 | JWT access tokens; auth context preserved through refresh | RFC 9068 §2.2 |
| NIST SP 800-63B | advisory: reauthentication before authenticator changes (§5.2.9), single-use OTP (§5.1.4.2 / A.2) | advisory profile guidance, not a wire contract |

Profile notes: MFA is an opt-in stock-binary capability
(`identity.mfa`, feature-matrix row `conditional`). The wire contract is the
`/auth/login → mfa_required → /auth/mfa → (login response)` continuation plus
the `/me/mfa/*` self-service surface. **No OIDF or FIDO certification is
claimed or evidenced anywhere in the tree.**

---

## 2. Compliance matrix

Status: **Compliant** (implemented per spec), **Stricter** (exceeds the
spec's minimum), **Optional** (spec-permitted choice), **Gap** (missing
behavior this review flags), **Drift** (docs vs. code disagreement).

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test evidence |
|---|---|---|---|---|---|
| 1 | RFC 6238 §4.2 + §5.1: TOTP algorithm; 6-digit, 30 s step, SHA-1; secret ≥128 bit (160 rec) | `domains/authenticators/totp.go` `hotp`, `verifyCodeStep`, `GenerateTOTPSecret` (20 bytes = 160 bit); `OTPAuthURL` emits `algorithm=SHA1&digits=6&period=30`, base32-no-pad | Compliant | none | `totp_test.go` `TestTOTP_RFC6238Vectors` runs RFC 6238 Appendix B SHA-1 vectors; `test/me_mfa_totp_enroll_test.go` re-derives codes independently |
| 2 | RFC 4226 §5.3 dynamic truncation | `hotp()` (offset nibble, 31-bit mask, mod 10^digits) | Compliant | none | `TestTOTP_RFC6238Vectors` |
| 3 | RFC 6238 §5.2 verification window / skew | ±1 step (`WithTOTPSkew`), full-loop constant-time compare (`subtle.ConstantTimeCompare`, no early break) | Compliant | Time-step resynchronization not implemented — permitted for TOTP (only HOTP §5.2 mandates resync) | `TestTOTPAuthenticator_AcceptsCodeWithinSkewWindow`, `TestTOTPAuthenticator_StrictSkewRejectsDrift` |
| 4 | OTP single-use | `WithTOTPConsumedStore`: confirmed replay fail-closed, store error fail-open; **default is window-reuse** | Optional | NIST 800-63B treats OTP as single-use; strict one-time semantics require operator opt-in. Documented in `totp.go` | `totp_test.go` consumed-store tests |
| 5 | WebAuthn §7.2 per-ceremony challenge + session single-use | `webauthn.go` `beginLogin`/`FinishLogin`; session `Take` (atomic, single-use, TTL default 5 min, `webauthn_session.go`) | Compliant (delegated to go-webauthn) | none | `webauthn_test.go`, `mfa_test.go` `TestMFA_HappyPath` |
| 6 | WebAuthn §6.2.3 / FIDO cloned-authenticator counter | `ErrClonedAuthenticator` rejects signCount regression before re-persisting | Stricter | go-webauthn leaves disposition to the RP; Snaplink fails the ceremony | `assertion_regression_test.go` |
| 7 | WebAuthn user verification for step-up | `webauthn/mfa.go` `Begin` pins UV (`VerificationRequired` on options **and** session) regardless of primary-login config | Stricter | a second factor must verify the user, not merely presence | `mfa_test.go`, `webauthn/mfa_test.go` |
| 8 | WebAuthn subject binding on step-up | `WebAuthnMFAProvider.Verify` rejects session-resolved user ≠ `SubjectID` (`ErrWebAuthnMFASubjectMismatch`) | Compliant | — | `webauthn/mfa_test.go` |
| 9 | RFC 8176 §2 `amr`, incl. `mfa` marker | `internal/handler/amr.go` `AmrForResult` + `WithMFAMethod`; TOTP maps to `otp`, password to `pwd`, step-up appends `mfa`; folded into minted tokens on the `/auth/mfa` resume | Compliant | `webauthn` passes through as an unregistered custom amr value (RFC 8176 permits extension values; note for strict RPs) | `amr_test.go`, `test/mfa_test.go` |
| 10 | OIDC `auth_time` / ACR on step-up mint | `server_finish_login.go` `AuthTime: time.Now()` at mint (i.e. the step-up instant), `ACR: result.AchievedACR`; refresh captures `RefreshAuthContext{AMR, ACR, AuthTime}` (RFC 9068 §2.2) | Compliant | Step-up does **not** raise ACR (see finding 5) | `credential_health_test.go`, `region_residency_mfa_test.go` |
| 11 | RFC 6749 §3.1.2.6 `state` through the continuation | `buildMFAChallengeResponse` echoes `state`; frozen `login.Request` resumes it | Compliant | — | `test/mfa_test.go` |
| 12 | RFC 6749 §5.1 no-store on credential endpoints | `tokenNoStoreHeaders` at top of `handleLogin` (covers `mfa_required`) and `handleMFAComplete`; `TokenNoStoreHeaders` on every `/me/mfa/*` handler | Compliant | — | handler-level; `test/me_mfa_totp_enroll_test.go` |
| 13 | Oracle-safe failure collapse at `/auth/mfa` | `verifyMFAFactor` collapses unknown/expired/consumed challenge, wrong method, wrong factor, and lockout to one `400 mfa_invalid`; `Consume` is atomic delete (single-use), replay → same shape | Compliant | 404-vs-400 status split for unwired deployments (finding 4) | `TestMFA_WrongCode_Returns_mfa_invalid`, `TestMFA_UnknownChallengeID`, `TestMFA_Replay_AlreadyConsumed`, `TestMFA_UnsupportedMethod`, `TestMFA_SecondFactorLockout` |
| 14 | Single-use recovery codes as a factor | `recovery_mfa_provider.go` `Verify` → `RecoveryCodeStore.Consume`; regenerate revokes prior batch first | Compliant | — | `test/mfa_recovery_test.go` (happy path + replay → `mfa_invalid`) |
| 15 | Trusted-device skip grant (MFA bypass) | minted only from a token whose `amr` contains `mfa`; `trustedDeviceAllowsSkip` fails **closed** on store error (opposite of risk-scorer fail-open, deliberate) | Compliant | — | `test/mfa_test.go` `TestMFA_TrustDevice_*` |
| 16 | RFC 9470 step-up demand | `trusted_devices.go` `HandleTrustMyDevice`: 403 `insufficient_user_authentication` when `amr` lacks `mfa` | Compliant | applied on a self-service API, not an authorization endpoint (adaptation, documented) | `trusted_devices_test.go` |
| 17 | Discovery metadata | `mfa_endpoint` + `mfa_methods_supported` emitted **only** when Provider + ChallengeStore both wired; aggregated for multi-provider | Compliant | these are custom extension claims — OIDC Discovery 1.0 defines no MFA step-up fields (finding 5) | `test/mfa_discovery_test.go` |
| 18 | Step-up before self-service enrollment commit | `HandleTOTPEnrollConfirm` / `HandleWebAuthnRegisterFinish` gate on bearer only (`MeSubjectOrChallenge`); possession proof uses a secret/session minted in the same bearer session | **Gap** | NIST 800-63B §5.2.9 (reauthenticate before binding new authenticators); inconsistent with #16 within the same surface | no negative test exists; current tests use a password-only token |
| 19 | Challenge-issuance throttling | `issueMFAChallenge` has no per-subject budget; `Begin` fan-out fires per issuance (push `transport.Send` + PENDING row at `maxWait*2`); lockout counts only verify failures | **Gap** | MFA-fatigue/spam surface (finding 1) | `TestMFA_SecondFactorLockout` proves the lockout is verify-only |
| 20 | Error-code contract for `/me/mfa/*` | handlers emit 501+`totp_enrollment_not_supported`, 501+`not_found` (WebAuthn, recovery), 404+`not_found` (delete), 400+`invalid_request` (missing `session_id`); routes are gated at mount | **Drift** | the 501 branches are unreachable through the stock router; docs document them (finding 3) | `TestTOTPEnroll_NotMountedWithoutEnroller` (expects **404**, not 501) |

---

## 3. Findings

### Finding 1 — High — Enrollment commits require no step-up; a stolen bearer token can bind an attacker-controlled factor

- **Requirement level**: NIST SP 800-63B §5.2.9 (reauthentication before
  authenticator-management changes); consistency with the codebase's own RFC
  9470 step-up gate (matrix #16) and with password change (which re-verifies
  `current_password`).
- **Location**: `protocols/selfservice/selfserviceaccount/mfa.go`
  `HandleTOTPEnrollConfirm` (lines ~100–152); `security.go`
  `HandleWebAuthnRegisterFinish` (lines ~142–172). Both use only
  `MeSubjectOrChallenge`. The begin legs mint no credential and are correctly
  left ungated.
- **Interop/security impact**: a session thief (password-only login token)
  can enroll their own TOTP secret or passkey, then defeat the MFA step-up on
  the next login. The confirm leg's "proof of possession" verifies against a
  secret minted in the same compromised session, so it is not a step-up.
  Verified: the existing e2e tests (`test/me_mfa_totp_enroll_test.go`,
  `test/me_mfa_webauthn_register_test.go`) enroll with a plain password
  token and expect 201.
- **Corrective behavior**: return 403 `insufficient_user_authentication`
  (reuse `security.ErrInsufficientUserAuthentication`, the exact check
  `HandleTrustMyDevice` uses) from the two commit legs when the bearer
  token's `amr` lacks `mfa`; update `docs/error-codes.md`, `docs/openapi.yaml`,
  and `docs/feature-matrix.md`; step up in the existing e2e tests. Wire shape
  for legitimate callers unchanged.

### Finding 2 — Medium — Unbounded challenge issuance enables push spam / MFA fatigue

- **Requirement level**: RFC 6749 §5.1-adjacent credential-endpoint
  discipline; operational security (MFA-fatigue is a documented account-takeover
  vector; NIST 800-63B §5.2.9 threat guidance). Not a wire-contract violation.
- **Location**: `interfaces/sso/server_mfa.go` `issueMFAChallenge` +
  `buildMFAChallengeResponse`; `infrastructure/defaultimpl/defaultmfa/push_mfa_provider.go`
  `Begin` (persists PENDING at `ExpiresAt: now.Add(p.maxWait*2)` and calls
  `transport.Send`); `verifyMFAFactor`/`mfaLockoutKey` (lockout counts only
  verify failures — confirmed by `TestMFA_SecondFactorLockout`).
- **Interop/security impact**: a caller holding the primary credential (or a
  leaked one) can replay `DecisionRequireMFA` logins and fire a real push per
  issuance, exhausting the victim's attention (fatigue) and accumulating
  PENDING approval rows. No issuance budget exists on the path; the only
  rate limiters in the server are per-grant-type on `/token` and per-IP on
  signup.
- **Corrective behavior** (adopting the earlier analysis): per-subject
  issuance budget in a namespace distinct from `mfaLockoutKey`; when
  exhausted, keep the `mfa_required` wire shape byte-identical and skip the
  per-method `Begin` fan-out (the SPI already defines a missing
  `mfa_method_data` entry as non-fatal), recording the reason in the
  `mfa_failure` audit. No new distinguishable error shape; verify failures
  still hit the existing lockout untouched.

### Finding 3 — Medium — `/me/mfa/*` error-code contract drift, with a correction: the 501 branches are unreachable in the stock binary

- **Requirement level**: repository contract discipline (`docs/error-codes.md`
  is a public contract; AGENTS.md requires error-code rows for emitted codes).
- **Location**: `interfaces/sso/server_me.go` `mountSelfServiceCredentials`
  gates every `/me/mfa/*` route at mount: TOTP begin/confirm mount only when
  `TOTPEnrollmentWriter` + `totpEnroller` are both wired; recovery codes only
  with `recoveryCodeStore`; WebAuthn only with `webauthnRegistrar`. Handlers
  in `protocols/selfservice/selfserviceaccount/{mfa,security}.go` retain 501
  branches for nil dependencies.
- **Correction to the prior analysis**: the earlier review called the 501s
  "the documented convention" for unwired stores. Verified against the router:
  the **reachable** unwired behavior is a bare 404 (route not mounted) —
  `TestTOTPEnroll_NotMountedWithoutEnroller` asserts exactly that — so
  `docs/error-codes.md` documents three 501 rows (`totp_enrollment_not_supported`,
  `not_found` on WebAuthn, `not_found` on recovery) that the stock binary
  never emits. The 501 branches are reachable only via direct SDK handler
  invocation with a nil-dep `Deps`.
- **Reachable-but-undocumented responses**: `DELETE /me/mfa/{id}` →
  404 `not_found` (doc's `not_found` row is scoped to `/me/devices*`);
  missing `session_id` on `/me/mfa/webauthn/finish` → 400 `invalid_request`
  (the `webauthn_registration_failed` row claims malformed input collapses);
  `GET /me/mfa` and `POST/GET /me/mfa/recovery-codes` have no rows at all,
  though `docs/openapi.yaml` specifies them.
- **Corrective behavior**: decide one convention — (a) document the 501s as
  SDK-only behavior and add rows for the reachable responses (404 `not_found`
  for unwired/missing/foreign factor, 400 `invalid_request` for malformed
  input), or (b) mount the routes unconditionally and keep 501 as the wire
  signal — then add the missing rows (`GET /me/mfa`,
  `POST/GET /me/mfa/recovery-codes`, delete, malformed-input) and lock the
  exact (status, code) pairs with table-driven handler tests.

### Finding 4 — Low — `/auth/mfa` status-code split fingerprints an unwired deployment

- **Location**: `interfaces/sso/server_mfa.go` `handleMFAComplete` — unwired
  Provider/Store → 404 with `mfa_invalid` body; every wired failure → 400
  with the identical body. The 404 is returned because the route is registered
  unconditionally.
- **Impact**: a probe can distinguish "deployment without MFA" (404) from
  "MFA misconfigured or failing" (400) by status alone; body shape is
  identical. Documented in `docs/openapi.yaml` and `docs/error-codes.md`.
- **Corrective behavior**: acceptable as-is (documented); if strict
  anti-fingerprinting is required, return 400 for both (a one-line change
  with a discovery test update). Optional.

### Finding 5 — Info — Non-standard discovery claims and no ACR elevation on step-up

- `mfa_endpoint` / `mfa_methods_supported` are custom extension claims on the
  OIDC discovery document (`protocols/oidc/metadata.go`). OIDC Discovery 1.0
  defines no MFA step-up fields, so extensions are the only option; strict
  validators will ignore them. Interop note only.
- Step-up completes with `ACR: result.AchievedACR` unchanged
  (`server_finish_login.go`); a deployment that wants step-up to raise ACR
  (e.g. `acr_values`-driven policies) must implement that in the risk
  decision layer. Not a deviation from any normative section.
- WebAuthn step-up always demands user verification and rejects counter
  regression — both stricter than the minimum; no downgrade path found from
  MFA-completed tokens to non-MFA tokens (refresh context, auth-code replay,
  and trusted-device grants all carry/require the `mfa` AMR; the trust-skip is
  fail-closed on store error).

---

## 4. Priority conformance tests, declared unsupported features, certification evidence

### Priority conformance tests (in priority order)

1. **Enrollment step-up gate** (cross-server, `test/`): password-only token →
   403 `insufficient_user_authentication` on `/me/mfa/totp/confirm` and
   `/me/mfa/webauthn/finish`; after completing `/auth/mfa`, the identical
   calls → 201. Updates the two existing enrollment e2e tests to step up
   first (acceptance for finding 1).
2. **Issuance budget** (unit, `interfaces/sso`): M rapid
   `DecisionRequireMFA` logins for one subject with a push provider wired
   produce exactly the budgeted `transport.Send` calls and PENDING rows;
   response bodies across the budget boundary are byte-identical in shape;
   audit records each suppressed `Begin`; the factor-verify lockout counter
   is untouched (acceptance for finding 2).
3. **Error-code parity table** (table-driven, `selfserviceaccount`): exact
   (status, code) for every reachable `/me/mfa/*` branch — unwired (404 route
   or documented 501 per decision), cross-user/missing delete (404
   `not_found`), missing `session_id` (400 `invalid_request`), wrong/malformed
   TOTP code (400 `totp_invalid_code`), bad attestation (400
   `webauthn_registration_failed`) — one-to-one with the updated
   `docs/error-codes.md` rows, plus a docscheck-style scan (acceptance for
   finding 3).
4. **RFC 6238 Appendix B vectors** — already present and passing
   (`TestTOTP_RFC6238Vectors`); extend to the SHA-256/SHA-512 columns only if
   those variants are ever added (currently out of scope).
5. **Oracle sweep on `/auth/mfa`** — extend the existing collapse tests with a
   matrix run (unknown/expired/consumed × wrong method × wrong factor ×
   locked × malformed body) asserting identical bodies; already largely
   covered by `TestMFA_*`.

### Declared unsupported features

- HOTP (counter-based) — deliberate (`totp.go` doc).
- TOTP SHA-256/SHA-512 variants — RFC 6238 §1.2 mandates SHA-1; variants are
  optional and rarely interop with mainstream apps.
- TOTP time-step resynchronization (windowed resync) — permitted for TOTP.
- WebAuthn `largeBlob` **write** (detection only via `RequestLargeBlobSupport`);
  enterprise attestation is accepted via conveyance config but not a focus.
- MFA enrollment via unauthenticated ceremony; device-trust skip grants
  without an `mfa` AMR; strict single-use TOTP without operator opt-in.

### Remaining certification evidence

- **No OIDF or FIDO certification is claimed** (no published current result
  exists in the tree), and this review does not assert one.
- WebAuthn conformance rests on go-webauthn (v0.17.x per code comments) plus
  in-repo ceremony tests; there is no evidence of running the FIDO2 server
  conformance tool against a deployed Snaplink instance.
- TOTP interop is evidenced by RFC 6238 Appendix B vectors, the
  `otpauth://` provisioning shape, and the independent re-derivation in
  `test/me_mfa_totp_enroll_test.go`; no cross-implementation matrix
  (Google Authenticator / 1Password / Authy) exists.
- Discovery interop for the custom `mfa_endpoint` claim is untested against
  third-party RP libraries; the claim is additive and unknown fields are
  ignored by spec-compliant RPs.
