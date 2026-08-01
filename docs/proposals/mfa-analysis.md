Verified — `Registrar.FinishRegistration` (domains/authenticators/webauthn/registrar.go:50) does check the finish bearer against the begin session's subject, but never for step-up, so the claim in point 1 stands as written.

Analysis complete. Output: **`docs/architect-analysis-mfa-subsystem-gaps.md`** (docs-only change; no Go gates triggered).

**Scope note first:** the paths you named don't exist — there is no `domains/mfa/` and no `interfaces/sso/me_mfa.go`. The subsystem is in `interfaces/sso/server_mfa.go`, `interfaces/sso/server_mfa_trust.go`, `interfaces/sso/server_login_client.go`, `shared/spi/mfa.go`, `protocols/selfservice/selfserviceaccount/{mfa,security,trusted_devices}.go`, and `infrastructure/defaultimpl/defaultmfa/`. The prior `architect-analysis-mfa-subsystem-review.md` already covers push-fatigue, enrollment-commit step-up, and error-code drift, so the three points below are deliberately distinct from it.

## The 3 proposed improvement points

**1. MFA credential-mutating endpoints lack the step-up gate the same package already enforces for trusted devices**
`DELETE /me/mfa/:id`, `POST /me/mfa/recovery-codes`, `/me/mfa/totp/confirm`, `/me/mfa/webauthn/finish` are gated only by a live bearer (`MeSubjectOrChallenge`), so a stolen non-stepped-up token can delete all factors, hijack recovery codes, or bind an attacker factor. Contrast: `HandleTrustMyDevice` (trusted_devices.go:66) requires `amr` contains `mfa` → 403 `insufficient_user_authentication`, documented at error-codes.md:218. Proposal: apply the same RFC 9470 gate, with a zero-enrolled-factors bootstrap exemption; acceptance: cross-server tests asserting 403 before step-up / 201 after.

**2. MFA brute-force lockout is keyed per-subject only, amplifying a one-client password compromise into whole-account DoS**
`mfaLockoutKey` (server_mfa.go:301) = `"mfa lockout:"+subjectID`; the password leg is client-scoped (`LockoutKey`, account_lockout.go:199). 5 failed factors within 1 h locks the subject on *every* client for 15 min. Proposal: key `"mfa lockout:"+clientID+":"+subjectID` using `challenge.ClientID`, keep the wire shape, document the `mfa_locked` audit reason in error-codes.md (currently absent).

**3. Trusted-device skip is honored by the risk-scorer step-up path but silently ignored by the enforced conditional-access path — undocumented split contract**
`runPostCredentialGates` runs both gates (server_login_gates.go:281, 284); `evaluateLoginRisk` checks `trustedDeviceAllowsSkip` (server_login_client.go:181) while `enforceConditionalAccessLogin` issues unconditionally (line 245), with a byte-identical `mfa_required` in both cases and no audit signal. error-codes.md:221 documents the skip contract without the exception. Proposal: keep enforced-verdict-wins, document the exception, and emit an audit marker (e.g. `trusted_device_overridden`) when a live grant is overridden.

Each point in the document includes a file/symbol evidence table, proposed behavior, and an acceptance check, per your template.
