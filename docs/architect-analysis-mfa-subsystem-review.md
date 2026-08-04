# MFA subsystem review — evidence-backed improvement points

Reviewed against `docs/feature-matrix.md` (capability `identity.mfa`, "MFA
orchestration" row) and `docs/error-codes.md` (MFA orchestration, TOTP
enrollment, trusted-devices sections).

Scope note: the requested paths `domains/mfa/` and `interfaces/sso/me_mfa.go`
do not exist. The subsystem is spread across:

- orchestration: `interfaces/sso/server_mfa.go`, `interfaces/sso/server_mfa_trust.go`
- SPI: `shared/spi/mfa.go`
- self-service `/me/mfa/*`: `protocols/selfservice/selfserviceaccount/mfa.go`, `security.go`
- factors: `domains/authenticators/totp_mfa.go`, `domains/authenticators/webauthn/mfa.go`
- implementations: `infrastructure/defaultimpl/defaultmfa/` (push, multi, recovery, composite)

---

## 1. Unbounded MFA-challenge issuance enables push-notification spam / MFA fatigue

### Problem

Every `/auth/login` that reaches `DecisionRequireMFA` mints a fresh single-use
challenge and pre-fires `Begin` for **every** supported method before the user
picks one. With push wired, `Begin` immediately sends a push notification and
persists a PENDING approval. The per-subject brute-force lockout only counts
factor-*verify* failures, so a caller who knows the primary credential (or is
replaying a leaked one) can trigger unlimited `mfa_required` issuances — each
firing a real push to the victim's device (MFA-fatigue / notification spam) and
leaving a PENDING approval row that lives `maxWait*2` until lazy prune. No
issuance budget or throttle exists anywhere on this path (the only rate limiters
in the server are per-grant-type on `/token` and per-IP on signup).

### Evidence

| File | Symbol | Fact |
|---|---|---|
| `interfaces/sso/server_mfa.go` | `issueMFAChallenge` | Mints + persists a challenge with no per-subject rate limit or cap; called from `server_finish_login.go:146` and `server_login_client.go:187,245` |
| `interfaces/sso/server_mfa.go` | `buildMFAChallengeResponse` | Calls `Begin` for every supported method on every issuance |
| `interfaces/sso/server_mfa.go` | `verifyMFAFactor` / `mfaLockoutKey` | Lockout (`security.AccountLockout`) fires only on factor-verify failure — never on issuance |
| `infrastructure/defaultimpl/defaultmfa/push_mfa_provider.go` | `PushMFAProvider.Begin` | `transport.Send` + PENDING row with `ExpiresAt: now.Add(p.maxWait * 2)` |
| `docs/error-codes.md` §MFA orchestration | `mfa_required` row | Documents no issuance throttle |

### Proposed behavior

Add a per-subject challenge-issuance budget (e.g. N issuances per window, in a
namespace distinct from `mfaLockoutKey`). When the budget is exhausted, keep
the wire shape byte-identical (`mfa_required` + `mfa_challenge_id` +
`mfa_methods`) but skip the per-method `Begin` fan-out — the SPI already
defines a missing `mfa_method_data` entry as non-fatal ("the method stays in
`mfa_methods` but without an attached method_data entry", `shared/spi/mfa.go`
`MFABeginner` doc) — and record the skip reason in the `mfa_failure` audit.
No new distinguishable error shape; legitimate users are never locked out of
the flow, they just stop receiving pushes for the window.

### Acceptance check

Unit test on `issueMFAChallenge` with a push provider wired: M rapid
`DecisionRequireMFA` logins for one subject produce exactly the budgeted
number of `transport.Send` calls and PENDING approvals; the response bodies
across the budget boundary are identical in shape (challenge id + methods
present); an audit event records each suppressed Begin; the factor-verify
lockout counter is untouched.

---

## 2. MFA self-service enrollment requires no step-up (re-authentication)

### Problem

Committing a new second factor (`/me/mfa/totp/confirm`, `/me/mfa/webauthn/finish`)
is gated only by a live bearer token (`MeSubjectOrChallenge`). The confirm
leg's "proof of possession" verifies a code against a secret minted in the
**same** compromised session — `begin` and `confirm` run under the same stolen
token — so a session-theft attacker can enroll an attacker-controlled factor
and defeat MFA on the next login. The codebase already demands strictly
stronger proof for weaker actions: trusting a device requires `amr` containing
`mfa` this session (`insufficient_user_authentication`, RFC 9470), and
changing the password re-verifies the current password. Enrollment is the
strongest trust decision on the surface and the weakest-gated one.

### Evidence

| File | Symbol | Fact |
|---|---|---|
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleTOTPEnrollBegin` / `HandleTOTPEnrollConfirm` | Only `MeSubjectOrChallenge`; secret + code both live in the same bearer session |
| `protocols/selfservice/selfserviceaccount/security.go` | `HandleWebAuthnRegisterBegin` / `HandleWebAuthnRegisterFinish` | Same — no `AMR` check |
| `protocols/selfservice/selfserviceaccount/trusted_devices.go` | `HandleTrustMyDevice` | `slices.Contains(claims.AMR, "mfa")` else 403 `security.ErrInsufficientUserAuthentication` — the existing step-up gate for a weaker action |
| `protocols/selfservice/selfserviceaccount/security.go` | `HandleChangeMyPassword` | Re-verifies `current_password` via `PasswordCredentialStore().VerifyPassword` |
| `docs/error-codes.md` §Trusted devices | `insufficient_user_authentication` row | Step-up demand documented for `/me/devices/trust` only |

### Proposed behavior

Require step-up for the enrollment **commit** legs: when the bearer token's
`amr` lacks `mfa` this session (same check `HandleTrustMyDevice` uses), return
403 `insufficient_user_authentication` from `/me/mfa/totp/confirm` and
`/me/mfa/webauthn/finish`, reusing `security.ErrInsufficientUserAuthentication`.
`begin` legs stay as-is (they mint no credential). Update `docs/error-codes.md`
(MFA section), `docs/feature-matrix.md`, and `docs/openapi.yaml` in the same
change.

### Acceptance check

Cross-server test in `test/`: a token minted from password-only login gets
403 `insufficient_user_authentication` on both commit endpoints; after
completing `/auth/mfa` step-up, the identical call returns 201. Existing
enrollment e2e tests (`test/me_mfa_totp_enroll_test.go`,
`test/me_mfa_webauthn_register_test.go`) are updated to step up first.

---

## 3. `/me/mfa/*` error-code contract drift (`docs/error-codes.md` vs code)

### Problem

`docs/error-codes.md` documents only three codes for the whole self-service
MFA surface, and the actual responses are internally inconsistent and partly
undocumented:

- Unwired-store responses split three ways: TOTP begin/confirm → **501**
  `totp_enrollment_not_supported` (documented); WebAuthn begin/finish →
  **501** + `not_found` (undocumented); recovery-codes generate/count → **501**
  + `not_found` (endpoints absent from the doc entirely).
- `DELETE /me/mfa/{id}` cross-user/missing → 404 `not_found` (undocumented;
  the doc's `not_found` row names only `/me/devices*`).
- The `webauthn_registration_failed` row claims "malformed body" collapses,
  but a missing `session_id` returns 400 `invalid_request` — a distinguishable
  shape.
- `GET /me/mfa` (factor list) and `POST/GET /me/mfa/recovery-codes` have no
  rows at all, though `docs/openapi.yaml` specifies the endpoints.

### Evidence

| File | Symbol | Fact |
|---|---|---|
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleTOTPEnrollBegin/Confirm` (lines 85, 116) | 501 `totp_enrollment_not_supported` — the documented convention |
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleGenerateRecoveryCodes` / `HandleGetRecoveryCodesCount` (lines 167, 196) | 501 + `not_found` |
| `protocols/selfservice/selfserviceaccount/security.go` | `HandleWebAuthnRegisterBegin/Finish` (lines 125, 157) | 501 + `not_found`; missing `session_id` → 400 `invalid_request` (line 160-162) |
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleDeleteMyMFAFactor` (lines 60-66) | 404 `not_found` for cross-user/missing |
| `docs/error-codes.md` | §MFA orchestration / §TOTP enrollment / §Trusted devices (lines 199-221) | `not_found` row scoped to `/me/devices*`; recovery-codes absent |

### Proposed behavior

Standardize the "operator must wire this" convention: keep 501 for all
unwired-store cases and emit the same documented code shape — either extend
the `not_found` row to cover 501 + `not_found` on `/me/mfa/webauthn/*` and
`/me/mfa/recovery-codes`, or introduce a dedicated not-supported code, then
make the TOTP/WebAuthn/recovery trio consistent. Add error-codes.md rows for
`GET /me/mfa`, `DELETE /me/mfa/{id}`, `POST/GET /me/mfa/recovery-codes`, and
the `invalid_request` malformed-input cases (`totp` empty secret/code,
missing `session_id`); align the `webauthn_registration_failed` row with the
actual collapse boundary (attestation/session failures collapse, malformed
input does not).

### Acceptance check

Table-driven handler tests in `protocols/selfservice/selfserviceaccount`
asserting the exact (status, error-code) pair for every documented branch
(unwired store, cross-user delete, malformed body, wrong code) — matching the
updated `docs/error-codes.md` rows one-to-one; a docscheck-style scan confirms
every `/me/mfa/*` code named in the handlers appears in `docs/error-codes.md`.
