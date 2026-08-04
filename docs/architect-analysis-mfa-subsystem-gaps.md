# MFA subsystem analysis — three evidence-backed improvement points

Reviewed against `docs/feature-matrix.md` (capability `identity.mfa`, row 57;
"MFA orchestration" row, line 130) and `docs/error-codes.md` (§MFA
orchestration / §TOTP enrollment / §Trusted devices, lines 199–221).

Scope note: the requested paths `domains/mfa/` and `interfaces/sso/me_mfa.go`
do not exist. The subsystem is spread across:

- orchestration: `interfaces/sso/server_mfa.go`, `interfaces/sso/server_mfa_trust.go`
- step-up wiring: `interfaces/sso/server_login_client.go`, `interfaces/sso/server_login_gates.go`
- SPI: `shared/spi/mfa.go`
- self-service `/me/mfa/*`: `protocols/selfservice/selfserviceaccount/mfa.go`,
  `security.go`, `trusted_devices.go`
- factors/implementations: `domains/authenticators/totp.go`,
  `infrastructure/defaultimpl/defaultmfa/` (push, multi, recovery, composite)

Prior art: `docs/architect-analysis-mfa-subsystem-review.md` already covers
unbounded challenge issuance / push fatigue, step-up on the TOTP/WebAuthn
enrollment **commit legs**, and `/me/mfa/*` error-code drift. The three points
below are distinct: a broader step-up scope, the lockout-key scope, and the
trusted-device skip split between the two step-up engines.

---

## 1. MFA credential-mutating self-service endpoints lack the step-up gate the same package already enforces for trusted devices

### Problem

`DELETE /me/mfa/:id` (factor removal), `POST /me/mfa/recovery-codes`
(regeneration), `POST /me/mfa/totp/confirm`, and
`POST /me/mfa/webauthn/finish` are all gated only by a live bearer token —
`MeSubjectOrChallenge` returns `claims.Subject` and the handlers never inspect
`claims.AMR`. A stolen, non-stepped-up bearer (a session/access token minted
from a password-only login, or an exfiltrated token that never completed MFA)
can, without any second factor:

- delete every enrolled factor, downgrading the account to password-only
  (`HandleDeleteMyMFAFactor`),
- regenerate the recovery-code batch, revoking the user's existing codes and
  returning a fresh set exactly once to the attacker
  (`HandleGenerateRecoveryCodes`),
- commit an attacker-controlled TOTP secret or passkey
  (`HandleTOTPEnrollConfirm`, `HandleWebAuthnRegisterFinish`).

The codebase already demands strictly stronger proof for a strictly weaker
action: trusting a device to skip *future* MFA requires the token's `amr` to
contain `mfa` this session, else 403 `security.ErrInsufficientUserAuthentication`
(RFC 9470), and `docs/error-codes.md` §Trusted devices documents that gate.
The mutation surface above is the strongest trust decision on the surface and
the weakest-gated one. The gap is not just theoretical: the WebAuthn finish
handler even accepts a bearer from a *different* context than the ceremony
(the registrar binds the credential to the begin session's subject, but the
finish bearer is only checked for validity, not for step-up).

### Evidence

| File | Symbol | Fact |
|---|---|---|
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleDeleteMyMFAFactor` (line 40) | list + remove with only `MeSubjectOrChallenge`; no AMR check |
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleGenerateRecoveryCodes` (line 159) | `RevokeAll` + `Generate` with only `MeSubjectOrChallenge` |
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleTOTPEnrollConfirm` (line 107) | commit leg, only `MeSubjectOrChallenge` |
| `protocols/selfservice/selfserviceaccount/security.go` | `HandleWebAuthnRegisterFinish` (line 149) | commit leg, only `MeSubjectOrChallenge` |
| `protocols/selfservice/selfserviceaccount/trusted_devices.go` | `HandleTrustMyDevice` (line 56; check at 66) | `slices.Contains(claims.AMR, "mfa")` else 403 — the in-repo precedent |
| `interfaces/sso/server_me.go` | `meSubjectOrChallenge` (line 27) / `meClaimsOrChallenge` (line 40) | full claims available; handlers discard `claims.AMR` |
| `docs/error-codes.md` | §Trusted devices, `insufficient_user_authentication` row (line 218) | step-up demand documented only for `/me/devices/trust` |

### Proposed behavior

Require the same RFC 9470 gate on every MFA-credential-mutating endpoint:
`DELETE /me/mfa/:id`, `POST /me/mfa/recovery-codes`,
`POST /me/mfa/totp/confirm`, `POST /me/mfa/webauthn/finish` — 403
`insufficient_user_authentication` when `claims.AMR` lacks `mfa` (same check
`HandleTrustMyDevice` uses, via `MeClaimsOrChallenge`). Exception for
first-factor bootstrap: a subject with **zero** enrolled factors
(`MFAEnrollmentStore.ListFactors` empty) may commit their first factor with a
plain authenticated bearer — otherwise a user who has never completed MFA
could never enroll. `GET` endpoints (factor list, recovery-code count) stay
open. Update `docs/error-codes.md`, `docs/feature-matrix.md`, and
`docs/openapi.yaml` in the same change.

### Acceptance check

Cross-server test in `test/`: a token minted from password-only login gets 403
`insufficient_user_authentication` on all four mutation endpoints; the
identical calls succeed (201/204) after completing `/auth/mfa` step-up; a
subject with no enrolled factors can still enroll the first TOTP factor; a
second factor (and any removal / recovery-code regeneration) requires step-up.
Existing self-service MFA tests are updated to step up first.

---

## 2. MFA brute-force lockout is keyed per-subject, amplifying a single-client compromise into whole-account denial of service

### Problem

`verifyMFAFactor`'s lockout key is `"mfa lockout:" + subjectID` — one bucket
for the subject across **all** clients. The password leg's key is
`clientID + ":" + identity` (`security.LockoutKey`) — scoped per
(client, user). Consequences of the scope mismatch:

- **Cross-client availability amplification.** A caller who knows the victim's
  password for any *one* client can, per `/auth/login`, pass the primary
  credential (successes are not lockout-registered), collect a fresh single-use
  challenge, and submit a wrong factor. Five such failures within the 1-hour
  `FailureWindow` lock the subject's MFA completions on **every** client —
  including unrelated admin/sensitive clients — for the full 15-minute
  `DefaultLockoutDuration`. With per-(client, subject) keying the same attacker
  could only deny the client whose password they already possess (and the
  password leg there already gives them that).
- **Self-inflicted global lockout.** Five TOTP typos on a kiosk/shared client
  lock the legitimate user out of every client.

The namespace separation from the password leg (`mfaLockoutKey`'s comment,
lines 298–305) is sound, but the scope decision is inconsistent with the
password leg's client-scoped key, and the `mfa_locked` audit reason exists
only in code — `docs/error-codes.md` §MFA orchestration documents only the
`mfa_invalid` wire code and never the audit reason that distinguishes a
lockout from a wrong factor.

### Evidence

| File | Symbol | Fact |
|---|---|---|
| `interfaces/sso/server_mfa.go` | `mfaLockoutKey` (line 301) | `"mfa lockout:" + subjectID` — no client component |
| `interfaces/sso/server_mfa.go` | `verifyMFAFactor` (line 252) | `IsLocked`/`RegisterFailure` on that subject-wide key |
| `shared/security/account_lockout.go` | `LockoutKey` (line 199) | password leg: `clientID + ":" + identity` |
| `shared/security/account_lockout.go` | `DefaultLockoutMaxFailures`/`DefaultLockoutFailureWindow`/`DefaultLockoutDuration` (lines 73–75) | 5 failures / 1 h window / 15 min lock |
| `interfaces/sso/server_mfa.go` | `persistMFAChallenge` | the challenge already carries `ClientID` — available at verify time for keying |
| `docs/error-codes.md` | §MFA orchestration (lines 203–204) | `mfa_invalid` row only; no `mfa_locked` audit reason |

### Proposed behavior

Key the MFA lockout per (client, subject): `"mfa lockout:" + clientID + ":" +
subjectID`, using `challenge.ClientID` at verify time (set by
`persistMFAChallenge` from the issuing client). Keep the `mfa lockout:`
namespace prefix so the password leg can never collide. The wire shape stays
byte-identical (`mfa_invalid`); the audit reason `mfa_locked` is documented in
`docs/error-codes.md`. Note the accepted trade-off: a password-holder can now
rotate clients to make more guesses, but each guess still requires a fresh
successful password login, and the password leg is itself per-client locked —
the brute-force bound is preserved while the blast radius shrinks to one
client.

### Acceptance check

Unit test around `verifyMFAFactor` + `security.MemoryAccountLockout`: 5 failed
verifies against a client-A challenge lock the `(clientA, subject)` key and
leave `(clientB, subject)` unlocked — a valid code for client B still
completes; `RegisterSuccess` on client A clears only client A's counter.
Existing lockout tests that reference the bare `"mfa lockout:<user>"` key are
updated to the two-part key. `docs/error-codes.md` gains the `mfa_locked`
audit-reason row.

---

## 3. Trusted-device skip is honored by the risk-scorer step-up path but silently ignored by the enforced conditional-access step-up path — an undocumented split contract

### Problem

`runPostCredentialGates` (line 274) runs `evaluateLoginRisk` first (line 281),
then `enforceConditionalAccessLogin` (line 284); either may own the response.
The risk-scorer path consults `trustedDeviceAllowsSkip` before issuing
(lines 181–183) and records `mfa_skipped_trusted_device` on a hit. The
conditional-access path (`VerdictRequireStepUp`) issues the challenge
unconditionally (line 245) — a live device grant is never consulted. Two
observable consequences:

- A returning user with a valid device grant is silently re-challenged when a
  conditional-access policy demands step-up, while the identical login with the
  identical grant skips when only the RiskScorer fired. The `mfa_required`
  response is byte-identical in both cases, so clients cannot tell a
  policy-enforced step-up from a heuristic one, and the operator has no signal
  that a live grant was overridden.
- `docs/error-codes.md` line 221 documents the skip contract ("A successful
  skip records the `mfa_skipped_trusted_device` audit event instead of a
  wire-visible signal") with no mention of the conditional-access exception;
  `docs/feature-matrix.md`'s "MFA orchestration" row (line 130) is equally
  silent. `trustedDeviceAllowsSkip`'s own doc comment (lines 429–441) names
  only the risk-scorer path.

Security-wise the current behavior is defensible — an operator-enforced
verdict should not be bypassable by a device grant — so the fix is contract +
observability, not a behavior flip.

### Evidence

| File | Symbol | Fact |
|---|---|---|
| `interfaces/sso/server_login_client.go` | `evaluateLoginRisk` (line 144) | lines 181–183: `trustedDeviceAllowsSkip` before `issueMFAChallenge` (line 187) |
| `interfaces/sso/server_login_client.go` | `enforceConditionalAccessLogin` (line 221) | line 245: `issueMFAChallenge` with no skip check |
| `interfaces/sso/server_login_client.go` | `trustedDeviceAllowsSkip` (line 442) | doc comment (429–441) covers only the risk-scorer path |
| `interfaces/sso/server_login_gates.go` | `runPostCredentialGates` (line 274) | risk gate (281) then CA gate (284) — both run, either owns the response |
| `docs/error-codes.md` | line 221 | skip contract documented without the CA exception |
| `docs/feature-matrix.md` | line 130 | "MFA orchestration" row: no device-trust caveat |

### Proposed behavior

Keep the enforced-verdict-wins semantics, and make the split contract
explicit and observable:

1. Extend `docs/error-codes.md` §Trusted devices and `docs/feature-matrix.md`
   "MFA orchestration": a live device grant skips only risk-scorer (heuristic)
   step-up demands, never an enforced conditional-access
   `VerdictRequireStepUp`.
2. In `enforceConditionalAccessLogin`, when a valid grant is present
   (`trustedDeviceAllowsSkip` returns true) but the verdict still demands
   step-up, emit the `mfa_required` audit event with a marker meta key (for
   example `trusted_device_overridden=true`) so operators can distinguish
   policy-forced challenges from ordinary ones. The wire response stays
   byte-identical.

### Acceptance check

Cross-server test in `test/`: (1) RiskScorer-only `RequireMFA` + valid
`device_token` → login proceeds, `mfa_skipped_trusted_device` audit, no
challenge issued; (2) CA `VerdictRequireStepUp` + valid `device_token` →
`mfa_required` issued with the new audit marker; (3) both engines firing →
exactly one challenge issued (the CA path owns it) with the marker present. A
docscheck-style scan confirms the `docs/error-codes.md` /
`docs/feature-matrix.md` rows name the conditional-access exception.
