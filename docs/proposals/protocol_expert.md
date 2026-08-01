The review is complete. Here's a summary of what was done:

## Verification results (all three points confirmed against code)

**Checks performed:** evidence scans across 9 files, plus `go test ./protocols/selfservice/selfserviceaccount/ -count=1` (ok) and `go test ./test/ -run 'TestMFA_SecondFactorLockout|TestTOTPEnroll_ConfirmThenListedAndUsable|TestMFA_TrustDevice_MintsGrantAndReturnsToken' -count=1 -v` (3/3 PASS).

- **Point 1 (step-up gate)** — **Verified.** All four mutation handlers (`mfa.go:40/107/159`, `security.go:149`) use only `MeSubjectOrChallenge`; `HandleTrustMyDevice` (trusted_devices.go:56, check at 66) is the in-repo RFC 9470 precedent. The analysis-block note is also confirmed: `Registrar.FinishRegistration` (registrar.go:50) enforces finish-bearer == begin-session subject via `expectedUserID`, but never step-up. Existing e2e tests enroll with a plain password token (verified in `test/me_mfa_totp_enroll_test.go`).
- **Point 2 (lockout key scope)** — **Verified.** `mfaLockoutKey` (server_mfa.go:301) is subject-only; `LockoutKey` (account_lockout.go:199) is `clientID+":"+identity`; defaults 5/1h/15min; `challenge.ClientID` round-trips (`spi.MFAChallenge`); `test/mfa_test.go:803` asserts on the bare `"mfa lockout:alice"` key; `mfa_locked` is code-only.
- **Point 3 (trusted-device split)** — **Verified.** Risk path skips at server_login_client.go:181–183, CA path issues unconditionally at 245, both run from `runPostCredentialGates` (274/281/284); the `mfa_required` audit event is emitted inside shared `issueMFAChallenge` (server_mfa.go:36), so the proposed marker is implementable at one call site; error-codes.md:221 and feature-matrix:130 document no CA exception.

## Deliverable

- `docs/architect-analysis-mfa-subsystem-gaps.md` — the architect output (already present, matches the analysis block; no changes needed).
- **`docs/architect-analysis-mfa-protocol-review-gaps.md`** (new) — this run's protocol-expert output: scope/references (RFC 8176, RFC 9470, NIST 800-63B §5.2.9/§5.2.2, RFC 6749 §5.1), a 10-row compliance matrix with status/deviation/test evidence, findings 1–3 with severities (High / Medium / Medium), requirement levels, and corrective behavior, plus priority conformance tests, the declared bootstrap exemption, and certification posture (none claimed; proposals touch no OIDC/OAuth wire surface).

Key protocol-review judgment: RFC 9470 applies to the self-service APIs only as the codebase's own established adaptation — the authoritative grounding for point 1 is NIST 800-63B §5.2.9; points 2 and 3 have no normative wire basis (availability and contract discipline respectively).

Docs-only change: no Go files touched, so no build/vet/architecture gates were triggered.
