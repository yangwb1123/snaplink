Verified — `newMeMFAHarness.loginAs` is a plain password login with no MFA provider wired, so `TestMyMFA_UnbindOwnFactor` and `TestMyMFA_WebAuthnPasskeyListedAndUnbound` delete factors with un-stepped-up bearers, pinning the vulnerable behavior. All facts in the review are now cross-checked. Deliverable: **`docs/qa-review-mfa-subsystem-gaps.md`** (docs-only; no Go gates triggered).

## QA Lead Summary

**1. Test inventory (run at `6c8fb33c`, dirty worktree noted in doc)**
- `go build ./...` + `go vet ./interfaces/sso/ ./test/` — OK
- `go test ./interfaces/sso/ -run 'TestConditionalAccess_|TestMaintainability_|TestArchitecture_'` — ok
- `go test ./protocols/selfservice/selfserviceaccount/` — ok
- `go test ./test/ -run 'TestMFA_|TestMyMFA_|TestTOTPEnroll_|TestWebAuthnRegister_|TestDeviceTrustE2E|TestRiskScorer_|TestLockout_|TestMemoryAccountLockout_|TestMFA_RecoveryCode_' -count=1` — ok
- Same suite `-race -count=1` — ok
- Measured coverage (`-coverpkg=./interfaces/sso/...`): `verifyMFAFactor` 95.7%, `evaluateLoginRisk` 85.7%, `enforceConditionalAccessLogin` **11.8%**, `handleGenerateRecoveryCodes`/`handleGetRecoveryCodesCount` **0.0%**, `mfaLockoutKey` 66.7%. `make ci` / full `./... -race` not run (docs-only, dirty tree) — remain the handoff gate.

**2. Requirement-to-test matrix (13 rows, in doc):** R1/R1a/R1b step-up gate + bootstrap exemption — **Missing**; R2/R2a lockout key scope + `mfa_locked` — **Missing** (zero test refs to the audit reason); R3 risk-path skip — **Covered** (`TestMFA_TrustDevice_MintsGrantAndReturnsToken`); R3a CA override — **Missing** (no test wires both stores); R6 recovery-code regeneration — **Missing**; R5/R7/R9 recovery login, CA routing/fail-open, route mounting — **Covered**.

**3. Findings (6, sorted):**
- **F1 High** — recovery-code regeneration/count endpoints at 0.0% coverage; the top fix target is untested. Add `TestMyMFA_GenerateRecoveryCodes_RequiresStepUp`: plain bearer → 403, stepped-up → 200, old batch invalidated.
- **F2 High** — point-1 fix flips two green tests that pin today's behavior (`TestTOTPEnroll_ConfirmThenListedAndUsable` must become the explicit zero-factor exemption test; `TestMyMFA_UnbindOwnFactor` must become 403-then-step-up-204).
- **F3 Medium** — `mfa_test.go:803` pins the bare `"mfa lockout:alice"` key; the deliberate canary. Add two-client isolation test + `mfa_locked` audit-sink assertion.
- **F4 Medium** — CA gate at 11.8% from `test/`; both gates share `issueMFAChallenge`, so a naive skip would silently disable enforced CA. Add `TestConditionalAccess_EnforceOverridesTrustedDeviceSkip` with `trusted_device_overridden` marker assertion.
- **F5 Low** — no fixture mints a stepped-up bearer for self-service tests (`loginAs` is plain-password-only in both harnesses); add a shared `loginSteppedUp` helper.
- **F6 Info** — bootstrap-exemption window; pin that the exemption applies only when `ListFactors` is empty.

**4. Scenarios (9, in doc):** happy (delete/regenerate/enroll-second-factor), boundary (zero-factor exemption vs one-factor gate), error (byte-identical 403 + no-store headers), audit (`mfa_locked`), isolation (two-client lockout), race (concurrent single-use consume), recovery (regeneration invalidates old batch), CA override + fail-open, AMR-across-refresh pin (Low).

**5. Gaps / flake / fixtures / exit criteria:**
- **Gaps:** no cross-server recovery-codes test; the only CA e2e test never wires the CA engine; `test/chaos/` has no MFA coverage; `mfa_locked` and both new 403s undocumented (error-codes.md/feature-matrix — part of the fix per AGENTS.md §5.6).
- **Flake risks:** TOTP `time.Now()/30` window-straddle (use RFC 4226 vector secrets, 2-second margin); `countingLockout` unsynchronized (keep single-goroutine); lockout tests need `-count=10+`.
- **Fixtures:** `loginSteppedUp` helper, two-client harness, trusted-device+CA+risk harness, recovery-code store double-wiring.
- **Exit criteria:** F1–F4 green under `-race` (+`-count=10` for lockout), full `./... -race` and `make ci` on a clean tree, byte-identical wire except new 403s/markers, docs rows added, no `interfaces/sso` file-ceiling or exemption-map changes (new tests go in `test/`).

**Independent review note:** all three deliverables' code claims re-verified independently (including the `Registrar.FinishRegistration` subject-bound-never-step-up note and `challenge.ClientID` availability); the QA review's added value is the two High findings (F1's 0.0% recovery-codes coverage and F2's deliberate test churn) that the product reviews did not quantify.
