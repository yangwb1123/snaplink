# QA Review — MFA Subsystem Gaps (architect / security-engineer / protocol-expert inputs)

Role: QA lead, risk-based test review of the three MFA gap analyses
(`docs/architect-analysis-mfa-subsystem-gaps.md`,
`docs/security-review-mfa-subsystem-gaps.md`,
`docs/architect-analysis-mfa-protocol-review-gaps.md`).

Revision reviewed: `6c8fb33c`. The three proposals are **not yet implemented**;
this review assesses test readiness for landing them and independently confirms
the coverage claims with freshly measured numbers.

> Worktree caveat: the checkout carries unrelated in-progress modifications
> (client-secret rotation, config reload, federation registration, regenerated
> proto). All commands below ran on that tree; numbers may shift on a clean
> checkout, but the gaps identified are structural, not measurement noise.

## 1. Test inventory and commands actually run

| Command (this revision) | Result |
|---|---|
| `go build ./...` | OK |
| `go vet ./interfaces/sso/ ./test/` | OK |
| `go test ./interfaces/sso/ -run 'TestConditionalAccess_\|TestMaintainability_\|TestArchitecture_' -count=1` | ok |
| `go test ./protocols/selfservice/selfserviceaccount/ -count=1` | ok |
| `go test ./test/ -run 'TestMFA_\|TestMyMFA_\|TestTOTPEnroll_\|TestWebAuthnRegister_\|TestDeviceTrustE2E\|TestRiskScorer_\|TestLockout_\|TestMemoryAccountLockout_\|TestMFA_RecoveryCode_' -count=1` | ok |
| `go test ./test/ -run 'TestMFA_\|TestDeviceTrustE2E\|TestTOTPEnroll_\|TestMyMFA_' -race -count=1` | ok |
| Coverage: same `test/` set with `-coverpkg=./interfaces/sso/...` | 15.7% total; key functions below |

Key measured coverage (cross-server `test/` package, `-coverpkg=./interfaces/sso/...`):

| Function | Coverage | Reading |
|---|---:|---|
| `verifyMFAFactor` (server_mfa.go:252) | 95.7% | second-factor verify + lockout path well exercised |
| `evaluateLoginRisk` (server_login_client.go:144) | 85.7% | risk path incl. trusted-device skip exercised |
| `issueMFAChallenge` / `recordMFARequiredAudit` | 77.8% / 80.0% | shared challenge issuance covered |
| `enforceConditionalAccessLogin` (server_login_client.go:221) | **11.8%** | live CA gate nearly untested from `test/`; unit coverage exists in `interfaces/sso/server_conditional_access_test.go` |
| `handleGenerateRecoveryCodes` (server_me.go:148) | **0.0%** | regeneration endpoint never tested |
| `handleGetRecoveryCodesCount` (server_me.go:153) | **0.0%** | count endpoint never tested |
| `handleTrustMyDevice` (server_me.go:168) | 0.0% (from `test/`) | covered instead at handler level: `interfaces/sso/rootcov_trusted_devices_test.go:102` asserts the 403 `insufficient_user_authentication` |
| `mfaLockoutKey` (server_mfa.go:301) | 66.7% | key namespace only partially pinned |

Not run (out of scope for a docs-only revision, and the tree is dirty): full
`go test ./... -race`, `make ci`. Those remain the handoff gate for the fix
landing, per AGENTS.md.

## 2. Requirement-to-test matrix

| # | Requirement / invariant | Status | Evidence |
|---|---|---|---|
| R1 | MFA credential-mutating endpoints step-up gated (RFC 9470, as `HandleTrustMyDevice` already is) | **Missing (Verified)** | Handlers gate on `MeSubjectOrChallenge` only (`protocols/selfservice/selfserviceaccount/mfa.go:40,107,159`, `security.go:149`); `meClaimsOrChallenge` already resolves `AMR` (`interfaces/sso/server_me.go:40`) but handlers discard it. Precedent tested: `rootcov_trusted_devices_test.go:102`, `server_session_trust_test.go:64` |
| R1a | Zero-enrolled-factors bootstrap exemption for first-factor commit | **Missing (Verified)** | No test asserts a zero-factor state machine. `TestTOTPEnroll_ConfirmThenListedAndUsable` (test/me_mfa_totp_enroll_test.go:63) enrolls with a plain password bearer and 0 factors — it will exercise the exemption but does not assert it |
| R1b | Deletion and recovery-code regeneration stay gated even at zero factors (security-engineer refinement) | **Missing (Verified)** | `TestMyMFA_UnbindOwnFactor` (test/me_mfa_test.go:104) deletes a factor with a plain bearer and expects success — **pins the vulnerable behavior**; must flip to 403 |
| R2 | MFA brute-force lockout keyed per (client, subject), not subject-only | **Missing (Verified)** | `mfaLockoutKey` = `"mfa lockout:"+subjectID` (server_mfa.go:301); password leg is client-scoped (`LockoutKey`, account_lockout.go:199); `challenge.ClientID` round-trips (used at server_mfa.go:318) |
| R2a | `mfa_locked` audit reason documented and asserted | **Missing (Verified)** | Zero test references to `mfa_locked` in the tree; absent from docs/error-codes.md; emitted only at server_mfa.go:269 |
| R2b | MFA second-factor throttling is oracle-safe | Covered | `TestMFA_SecondFactorLockout` (test/mfa_test.go:777): locked subject + **correct** code still → `400 mfa_invalid`; store-level: `TestMemoryAccountLockout_*` incl. `DistinctKeysIsolated` (test/account_lockout_test.go:120) |
| R3 | Trusted-device skip honored by risk-scorer step-up path | Covered | `TestMFA_TrustDevice_MintsGrantAndReturnsToken` (test/mfa_test.go:352): follow-up `/auth/login` with `device_token` skips the challenge (harness wires `newStubScorer(spi.DecisionRequireMFA)`, mfa_test.go:118) |
| R3a | Enforced conditional-access path overrides the skip, with audit marker | **Missing (Verified)** | `enforceConditionalAccessLogin` issues unconditionally (server_login_client.go:243–245); no test wires `WithTrustedDeviceStore` + `WithConditionalAccess(..., Enforce:true)` together; `TestConditionalAccess_EnforceStepUpRoutesToMFA` (server_conditional_access_test.go:266) passes no `device_token` |
| R4 | Single-use challenge consume; correct-code-after-consume rejected | Covered | `verifyMFAFactor` 95.7%; `TestMFA_RecoveryCode_HappyPathAndSingleUse` (test/mfa_recovery_test.go:94) |
| R5 | Recovery-code login path | Covered | `TestMFA_RecoveryCode_HappyPathAndSingleUse`, `TestMFA_RecoveryCode_WrongCode` (test/mfa_recovery_test.go:129) |
| R6 | Recovery-code regeneration / count endpoints | **Missing (Verified)** | 0.0% measured; no test file references `/me/mfa/recovery-codes` |
| R7 | CA live gate: step-up routing, decay-to-allow without MFA wiring, fail-open on store outage | Covered (unit) | `TestConditionalAccess_EnforceStepUpRoutesToMFA`, `_EnforceStepUpDecaysToAllowWithoutMFA`, `_EnforceFailsOpenOnStoreOutage` |
| R8 | WebAuthn finish bearer bound to begin session subject | Covered (subject only) | `Registrar.FinishRegistration` enforces `expectedUserID` (domains/authenticators/webauthn/registrar.go:50); `TestWebAuthnRegister_FinishBadSession` (test/me_mfa_webauthn_register_test.go:131). Never step-up-bound — confirms the mfa-analysis note |
| R9 | Route mounting gated on wiring (enroller/writer/registrar) | Covered | `TestTOTPEnroll_NotMountedWithoutEnroller`, `_NotMountedWithoutWriter`, `TestWebAuthnRegister_NotMountedWithoutRegistrar` |

## 3. Findings (severity, untested failure, regression risk, test to add)

### F1 — High: recovery-code regeneration lands untested, and it is a top fix target
- **Untested failure:** `POST /me/mfa/recovery-codes` (and the count endpoint) have 0.0% measured coverage. The step-up gate (point 1) cannot be proven at these handlers, and the security-engineer refinement (regeneration gated unconditionally, revoking the victim's batch on a stolen bearer) has no pin either way.
- **Regression risk:** the gate fix could land with the wrong behavior on these two endpoints and `make ci` would still pass.
- **Test to add** (`test/me_mfa_recovery_test.go`): `TestMyMFA_GenerateRecoveryCodes_RequiresStepUp` — plain password bearer → `403 insufficient_user_authentication` (RFC 9470 body, `Cache-Control: no-store`); stepped-up bearer → 200 with a fresh code list; regeneration invalidates the previous batch (old recovery code then fails at `/auth/mfa` with `400 mfa_invalid`).
- **Acceptance:** status 403 vs 200 exactly as above; second-generation codes listed by `GET /me/mfa/recovery-codes` count; old code rejected after regeneration.

### F2 — High: the point-1 fix flips two existing green tests; the churn must be deliberate
- **Untested failure / churn:** `TestTOTPEnroll_ConfirmThenListedAndUsable` (enroll with plain bearer, 201) and `TestMyMFA_UnbindOwnFactor` (delete with plain bearer, 204) pin today's behavior. Under the security-engineer refinement (exemption only for first-factor commit), the enroll test must be **re-asserted as the exemption test** (still 201, now with an explicit zero-factor precondition + a follow-up assertion that a *second* factor enroll with a plain bearer is 403), while the unbind test must become a two-step test: 403 with plain bearer, then step up and assert 204.
- **Regression risk:** if the exemption is scoped wrong (e.g., applied to delete), these tests become false positives.
- **Acceptance:** zero-factor pre-state asserted via `GET /me/mfa` before enroll; 403 before step-up / 204 after for delete; 403 on second-factor enroll with un-stepped-up bearer.

### F3 — Medium: lockout-key fix breaks the one test that pins the namespace (`mfa_test.go:803`)
- **Untested failure:** `TestMFA_SecondFactorLockout` asserts `lock.failures["mfa lockout:alice"] >= 3` — the bare subject key. Under the point-2 fix this becomes `"mfa lockout:mfa-app:alice"`; the pin is the deliberate canary and must be updated in the same change.
- **Regression risk:** without a two-client test, the fix could key on client and *still* share state via a buggy store; `TestMemoryAccountLockout_DistinctKeysIsolated` covers store-level isolation only.
- **Test to add:** `TestMFA_LockoutClientScoped` — seed a second client in `buildMFAHarness`; 3 failures via client A → client B login (correct code) still 200; further A failures still rejected; the `mfa_failure` audit event for the locked attempt carries reason `mfa_locked` (assert via the harness `audit.MemorySink`, which `buildMFAHarness` already returns).
- **Acceptance:** cross-client isolation, same-client persistence, `mfa_locked` reason present in sink, wire response remains byte-identical `400 mfa_invalid`.

### F4 — Medium: the point-3 split contract is untested and the CA gate is at 11.8% from `test/`
- **Untested failure:** live `device_token` + enforced CA `VerdictRequireStepUp` — today unconditionally issues `mfa_required`; after the fix it must still issue `mfa_required` *and* emit the `trusted_device_overridden` marker, with the risk-path skip (R3) unchanged.
- **Regression risk:** both gates share `issueMFAChallenge` → `recordMFARequiredAudit` (server_mfa.go:30/98), so a naive "skip when trusted" implementation would silently disable enforced CA. No existing test distinguishes the two issuers.
- **Test to add:** `TestConditionalAccess_EnforceOverridesTrustedDeviceSkip` (in `interfaces/sso/server_conditional_access_test.go` style but with `WithTrustedDeviceStore` wired and a minted token from `HandleTrustMyDevice`): CA-enforced login presenting the live device_token → `200` with `error: mfa_required` and `mfa_challenge_id`; audit sink contains `trusted_device_overridden` (post-fix) exactly once; control: same token with CA unwired → 200 with `access_token` (skip still works).
- **Acceptance:** enforced verdict wins in both pre- and post-fix states; marker present post-fix; risk-path skip byte-identical.

### F5 — Low: no fixture exists to mint a stepped-up bearer for self-service tests
- `newTOTPEnrollHarness.loginAs` (test/me_mfa_totp_enroll_test.go:62) produces only plain password tokens; `buildMFAHarness` wires an MFA provider but its harness lacks a TOTP *enroller*. Every F1/F2 test needs a stepped-up token. Add a shared helper (e.g. `loginSteppedUp`) that drives `/auth/login` → `/auth/mfa` and returns the amr-mfa bearer; reuse across the new tests rather than duplicating the two-leg dance.
- **Acceptance:** helper used by all new step-up tests; tokens validated to carry `amr: ["mfa"]` in at least one test (decode the JWT), so tests cannot silently regress to un-stepped-up tokens.

### F6 — Info: bootstrap-exemption window (residual risk, per security review)
- A zero-factor enroll via a stolen plain bearer binds an attacker factor by design (exemption). Mitigation is the documented exemption window + the F1/F2 pins; no separate test needed beyond R1a/R1b, but the acceptance for R1a should assert the exemption applies *only* when `ListFactors` is empty.

## 4. Prioritized scenario list

1. **Happy:** stepped-up bearer → delete factor 204, regenerate codes 200, enroll second factor 201 (F1/F2).
2. **Boundary:** zero-factor enroll exemption vs one-factor delete/regenerate (F2); second-factor enroll with plain bearer → 403.
3. **Error:** plain bearer on every mutation endpoint → byte-identical `403 insufficient_user_authentication` + `Cache-Control: no-store` (bearer endpoints, per AGENTS.md); unknown factor id → 404 (unchanged, oracle-safe).
4. **Error/audit:** locked MFA attempt → `400 mfa_invalid` + `mfa_failure` audit with `mfa_locked` reason (F3).
5. **Isolation:** two clients, failures on A don't lock B; same client re-locks and auto-unlocks after TTL (F3, reuse `TestMemoryAccountLockout_AutoUnlocksAfterDuration` shape).
6. **Race/concurrency:** concurrent `verifyMFAFactor` for the same challenge → exactly one success (single-use consume is `DELETE RETURNING`-style; covered for recovery codes, add for the step-up-gated mutations); concurrent lockout `RegisterFailure` calls.
7. **Recovery:** regeneration invalidates old batch; old recovery code → `mfa_invalid`, not `invalid_grant` (F1).
8. **CA override:** live device_token + enforced CA → `mfa_required` + marker; store outage + device_token → fail-open 200 (F4).
9. **Rotation/refresh:** stepped-up bearer minted before refresh keeps `amr` (residual AMR-across-refresh risk from the security review — pin with a refresh-then-mutate test, Low priority).

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**Gaps**
- No cross-server test for `/me/mfa/recovery-codes` (0.0%) or the count endpoint; openapi.yaml coverage for these routes should be checked in the fix change.
- No test combines trusted-device + enforced CA (F4); the only CA e2e test (`conditional_access_e2e_test.go`) never wires the CA engine — it tests device context only.
- `test/chaos/` has no MFA coverage (lockout or challenge single-use); out of scope for this fix but worth a follow-up.
- `mfa_locked` and the two new 403 surfaces are undocumented in `docs/error-codes.md`; feature-matrix:130 documents the skip contract without the CA exception. Docs assertions (error-codes/config/openapi checks inside `make ci`) will catch drift once rows exist — they are part of the fix, per AGENTS.md §5 step 6.

**Flake risks**
- TOTP helpers compute `time.Now()/30` at the client and verify server-side; a code minted in the final second of a window can straddle the boundary. Existing suites pass consistently (`-count=1` and `-race`), but the new step-up tests add more TOTP mints — use the RFC 4226 test-vector secret pattern (`buildMFAHarness`) and keep the verify window ≥1 step tolerant, or compute codes with a 2-second margin before use.
- `countingLockout` is unsynchronized; fine single-goroutine, and the `-race` run passed — keep new lockout tests single-threaded.
- Lockout/rotation-style tests must run `-count=10+` when the fix lands (AGENTS.md race-fix rule).

**Fixtures needed**
1. `loginSteppedUp` shared helper (F5) — two-leg login returning an amr-mfa bearer.
2. Two-client `buildMFAHarness` variant (F3).
3. Combined trusted-device + CA-enforce + RequireMFA-risk harness (F4).
4. A recovery-code store backing both self-service and login-time verify paths (the TOTP store pattern already exists; recovery codes need the same double-wiring).

**Exit criteria**
- F1–F4 tests added and green with `-race -count=1`; lockout tests additionally `-count=10`.
- `go test ./... -race` and `make ci` green on a clean tree.
- Wire responses byte-identical except the new 403s and audit markers; `docs/error-codes.md` gains `mfa_locked` + the step-up rows; feature-matrix documents the CA exception; openapi.yaml covers recovery-codes if absent.
- No exemption-map or budget changes (handlers stay in existing files; `interfaces/sso` is at its 60-file ceiling — new tests go into `test/`, not new `interfaces/sso` files).
