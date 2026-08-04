# MFA subsystem gaps — identity-protocol review

Reviewer role: identity-protocol expert (`ai-dev/prompts/protocol_expert.md`).
Input: the three-point analysis in
`docs/architect-analysis-mfa-subsystem-gaps.md`, re-verified against current
code, error-codes docs, feature matrix, and tests at this revision. This
review maps each point to exact specification sections and requirement
levels, assigns severities, and checks the proposed corrective behavior for
wire-contract impact. It is a companion to
`docs/architect-analysis-mfa-protocol-review.md` (which reviewed the earlier
`architect-analysis-mfa-subsystem-review.md` input); the three points here are
distinct from that review's findings.

Checks that actually ran for this revision (all green):

- Evidence scans: `grep`/`sed` over `interfaces/sso/server_mfa.go`,
  `server_login_client.go`, `server_login_gates.go`, `server_me.go`,
  `protocols/selfservice/selfserviceaccount/{mfa,security,trusted_devices}.go`,
  `shared/security/account_lockout.go`, `shared/spi/mfa.go`,
  `domains/authenticators/webauthn/registrar.go`, `docs/error-codes.md`,
  `docs/feature-matrix.md`
- `go test ./protocols/selfservice/selfserviceaccount/ -count=1` — ok
- `go test ./test/ -run 'TestMFA_SecondFactorLockout|TestTOTPEnroll_ConfirmThenListedAndUsable|TestMFA_TrustDevice_MintsGrantAndReturnsToken' -count=1 -v` — 3/3 PASS

Docs-only change: no Go files touched, so no build/vet/architecture gates
were triggered (AGENTS.md §2 applies the mandatory gates after `.go` edits).

---

## 1. Protocol/profile scope and authoritative references

The three points touch these standards. Everything else (SAML, SCIM,
CAEP/SSF, CIBA) is out of scope.

| Protocol | Relevance to the three points | Authoritative reference |
|---|---|---|
| OAuth 2.0 | no-store discipline on the four mutation endpoints (point 1 context); nothing else affected | RFC 6749 §5.1 |
| RFC 8176 | `amr` values incl. the `mfa` multi-factor marker; the proposed gate reads `claims.AMR` | RFC 8176 §2 |
| RFC 9470 | `insufficient_user_authentication` step-up demand; the in-repo precedent (`HandleTrustMyDevice`) already adapts it to a self-service API | RFC 9470 §2 |
| NIST SP 800-63B | §5.2.9 reauthentication before authenticator-management changes (point 1); §5.2.2 throttling/rate-limit guidance (point 2) | advisory profile guidance, not a wire contract |
| RFC 6238 / RFC 4226 | the TOTP factor these endpoints manage; unchanged by the points | RFC 6238 §4.2, §5.2 |
| W3C WebAuthn L2/L3 | the passkey factor; point 1's WebAuthn-finish leg | WebAuthn §5.1, §7.2 |

Profile notes: MFA is an opt-in stock-binary capability (`identity.mfa`,
feature-matrix row 130). The `/me/mfa/*` and `/me/devices/trust` surfaces are
proprietary self-service APIs — they are **not** OIDC/OAuth wire surfaces, so
RFC 9470 applies to them only as an in-repo adaptation, not as a normative
requirement. Point 1's authoritative grounding is therefore NIST 800-63B
§5.2.9 plus the codebase's own consistency requirement; points 2 and 3 have
no normative wire-contract basis at all (availability discipline and
repository contract discipline respectively). **No OIDF or FIDO certification
is claimed or evidenced anywhere in the tree.**

## 2. Compliance matrix

Status: **Compliant** (implemented per spec), **Stricter** (exceeds the
spec's minimum), **Optional** (spec-permitted choice), **Gap** (missing
behavior this review flags), **Drift** (docs vs. code disagreement).

| # | Section / requirement | Implementation evidence | Status | Deviation / note | Test evidence |
|---|---|---|---|---|---|
| 1 | RFC 9470 §2 step-up demand semantics (403 `insufficient_user_authentication`) | `trusted_devices.go:56` `HandleTrustMyDevice`, check at line 66: `slices.Contains(claims.AMR, "mfa")` else 403 `security.ErrInsufficientUserAuthentication`; `error-codes.md:218` documents it | Compliant (adapted to a self-service API) | established precedent; the four mutation endpoints do **not** follow it (finding 1) | `TestMFA_TrustDevice_MintsGrantAndReturnsToken` (passes; grant minted only from stepped-up token) |
| 2 | RFC 8176 §2 `amr` claim availability on bearer tokens | `server_me.go:40` `meClaimsOrChallenge` returns full `TokenClaims` incl. `AMR`; `meSubjectOrChallenge` (line 27) discards everything but `Subject` | Compliant at claim level | the claim is present and reachable; handlers never consume it for mutation gating (finding 1) | `meClaimsOrChallenge` used by `HandleTrustMyDevice`; AMR folding covered in `test/mfa_test.go` (prior review matrix #9) |
| 3 | NIST 800-63B §5.2.9: reauthenticate before binding/removing authenticators | `mfa.go:40` `HandleDeleteMyMFAFactor`, `mfa.go:107` `HandleTOTPEnrollConfirm`, `mfa.go:159` `HandleGenerateRecoveryCodes`, `security.go:149` `HandleWebAuthnRegisterFinish` — all gate on `MeSubjectOrChallenge` only | **Gap** | a stolen non-stepped-up bearer can delete factors, rotate recovery codes, or bind an attacker factor (finding 1) | existing e2e tests enroll with a plain password token and expect 201 (`TestTOTPEnroll_ConfirmThenListedAndUsable` passes — confirms the current ungated behavior) |
| 4 | NIST 800-63B §5.2.2: rate limiting / throttling of authentication attempts | `server_mfa.go:301` `mfaLockoutKey` = `"mfa lockout:"+subjectID`; `verifyMFAFactor` (line 252) checks/registers on that key; defaults 5 failures / 1 h window / 15 min lock (`account_lockout.go:73-75`) | Partial | throttling exists but is subject-scoped while the password leg is (client, user)-scoped (`LockoutKey`, `account_lockout.go:199`) — cross-client availability amplification (finding 2) | `TestMFA_SecondFactorLockout` (passes; asserts failures registered on the bare `"mfa lockout:alice"` key at `test/mfa_test.go:803`) |
| 5 | Oracle-safe failure collapse at `/auth/mfa`, incl. lockout | locked subject collapses to the same `400 mfa_invalid`; lockout detail only in the `mfa_locked` audit reason (`server_mfa.go:269`) | Compliant (wire) | **Drift**: `error-codes.md` §MFA orchestration (lines 203–204) documents only `mfa_required`/`mfa_invalid`; the `mfa_locked` audit reason is code-only (finding 2) | `TestMFA_SecondFactorLockout`, `TestMFA_WrongCode_Returns_mfa_invalid` |
| 6 | RFC 6749 §5.1 no-store on credential endpoints | `TokenNoStoreHeaders` at the top of all four mutation handlers (`mfa.go`, `security.go`) | Compliant | — | handler-level; `TestTOTPEnroll_*` |
| 7 | Trusted-device skip grant: contract and scope | skip honored only by the risk-scorer path (`server_login_client.go:181-183`, before `issueMFAChallenge` at 187); `enforceConditionalAccessLogin` (line 221) issues unconditionally at line 245; both run from `runPostCredentialGates` (`server_login_gates.go:274`, 281 then 284); `trustedDeviceAllowsSkip` doc (429–441) names only the risk path | Compliant (behavior); **Drift** (documentation) | enforced-verdict-wins is the safe direction, but `error-codes.md:221` and feature-matrix row 130 document the skip contract without the conditional-access exception; no audit marker distinguishes an overridden grant (finding 3) | `TestMFA_TrustDevice_*` suite (risk path); no test covers the CA-override case |
| 8 | Fail-closed on trusted-device store error | `trustedDeviceAllowsSkip` returns false on Verify error (opposite of the risk-scorer's fail-open) | Stricter | documented, deliberate; unchanged by the proposals | `TestMFA_TrustDevice_NoStoreWiredIsSafeNoOp`, `TestMFA_TrustDevice_FailedAttemptNeverTouchesStoreOrChangesResponse` |
| 9 | Audit observability of step-up decisions | `mfa_skipped_trusted_device` event exists (`server_login_client.go:458`); `mfa_required` event emitted inside `issueMFAChallenge` (`server_mfa.go:36`) — shared by both paths, so an override marker is implementable at one call site | **Gap** | no signal when a live grant is overridden by a CA verdict (finding 3) | audit assertions in `TestMFA_TrustDevice_*` |
| 10 | Discovery metadata | `mfa_endpoint` / `mfa_methods_supported` (OIDC discovery extensions) | Unaffected | none of the three proposals changes discovery; the new 403 is on a proprietary self-service surface | `test/mfa_discovery_test.go` |

## 3. Findings

### Finding 1 — High — MFA-credential-mutating self-service endpoints lack the step-up gate the same package already enforces for trusted devices

- **Requirement level**: NIST SP 800-63B §5.2.9 (reauthentication before
  authenticator-management changes) — advisory; RFC 9470 §2 only as the
  codebase's own established adaptation (`error-codes.md:218`); internal
  consistency with `HandleTrustMyDevice` (trusted_devices.go:56–66).
- **Location** (all verified): `protocols/selfservice/selfserviceaccount/mfa.go`
  `HandleDeleteMyMFAFactor` (line 40), `HandleTOTPEnrollConfirm` (line 107),
  `HandleGenerateRecoveryCodes` (line 159); `security.go`
  `HandleWebAuthnRegisterFinish` (line 149). All call only
  `MeSubjectOrChallenge` (`server_me.go:27`) and never inspect `claims.AMR`.
- **Interop/security impact**: a stolen non-stepped-up bearer (password-only
  login token, or an exfiltrated token from a session that never completed
  MFA) can, with no second factor: delete every enrolled factor (account
  downgraded to password-only), regenerate the recovery-code batch and read
  the fresh plaintext exactly once, or bind an attacker-controlled TOTP
  secret / passkey. The WebAuthn finish leg is subject-bound (the finish
  bearer's `userID` is passed as `expectedUserID` to
  `Registrar.FinishRegistration`, registrar.go:50, which go-webauthn enforces
  against the begin session), so cross-user binding is blocked — but step-up
  is not checked, confirming the analysis's claim as written. Wire-contract
  impact of the fix: none for compliant clients; the 403 is new only on
  proprietary self-service routes.
- **Corrective behavior** (adopts the analysis): reuse the exact
  `HandleTrustMyDevice` gate — `MeClaimsOrChallenge` +
  `slices.Contains(claims.AMR, "mfa")` else 403
  `security.ErrInsufficientUserAuthentication` — on all four mutation
  endpoints, with a zero-enrolled-factors bootstrap exemption
  (`MFAEnrollmentStore.ListFactors`, `shared/core/spi.go:367`, returns empty
  for a never-enrolled subject) so first-factor enrollment stays possible
  with a plain bearer. Update `docs/error-codes.md`, `docs/feature-matrix.md`,
  and `docs/openapi.yaml` in the same change; update the existing e2e tests
  (currently password-only, per `test/me_mfa_totp_enroll_test.go:85-108`) to
  step up first. `GET` endpoints stay open.

### Finding 2 — Medium — MFA brute-force lockout is keyed per-subject, amplifying a single-client password compromise into whole-account MFA denial of service

- **Requirement level**: no RFC mandates lockout keying; NIST 800-63B §5.2.2
  (throttling) is advisory. This is an availability-design deviation, not a
  wire-contract violation.
- **Location** (verified): `interfaces/sso/server_mfa.go:301`
  `mfaLockoutKey(subjectID)` returns `"mfa lockout:"+subjectID`; used at line
  266 in `verifyMFAFactor` (line 252) for `IsLocked`/`RegisterFailure`/
  `RegisterSuccess`. The password leg is (client, user)-scoped
  (`shared/security/account_lockout.go:199` `LockoutKey`). Defaults 5/1 h/15
  min (`account_lockout.go:73-75`). `challenge.ClientID` is populated
  (`persistMFAChallenge`, `server_mfa.go:82-83`; `spi.MFAChallenge.ClientID`,
  `shared/spi/mfa.go:93-95`) and round-trips through the store, so
  per-client keying is implementable at the verify site.
- **Interop/security impact**: five wrong factors within 1 h locks the
  subject's MFA completions on **every** client for 15 min, repeatable
  indefinitely by anyone holding the password for a single client (password
  successes are not lockout-registered). Conversely, five TOTP typos on a
  shared/kiosk client lock the legitimate user out of all clients. The wire
  shape is already collapse-safe (`mfa_invalid`), so the blast-radius fix has
  zero wire impact.
- **Corrective behavior** (adopts the analysis): key
  `"mfa lockout:"+clientID+":"+subjectID` from `challenge.ClientID`; keep the
  namespace prefix (the RFC 6749 client_id charset has no space, so
  collision with the password leg remains impossible); document the
  `mfa_locked` audit reason in `docs/error-codes.md` (currently code-only,
  `server_mfa.go:269`). Accepted trade-off (analysis point): a password
  holder can rotate clients for more guesses, but each guess still requires a
  fresh successful password login and the password leg remains per-client
  locked — the brute-force bound holds while the blast radius shrinks to one
  client.

### Finding 3 — Medium — Trusted-device skip is honored by the risk-scorer path but silently ignored by the enforced conditional-access path — undocumented split contract

- **Requirement level**: repository contract discipline (AGENTS.md §1:
  `docs/error-codes.md` and `docs/feature-matrix.md` are public contracts).
  No external specification governs the skip grant; it is a profile feature.
- **Location** (verified): `server_login_client.go:144` `evaluateLoginRisk`
  consults `trustedDeviceAllowsSkip` (lines 181–183) before
  `issueMFAChallenge` (187); `server_login_client.go:221`
  `enforceConditionalAccessLogin` issues unconditionally at line 245;
  `server_login_gates.go:274` `runPostCredentialGates` runs the risk gate
  (281) then the CA gate (284); `trustedDeviceAllowsSkip` (line 442) doc
  comment (429–441) names only the risk-scorer path; `error-codes.md:221`
  documents the skip contract without the CA exception; feature-matrix row
  130 is silent.
- **Interop/security impact**: none on security — enforced-verdict-wins is
  the correct direction (a CA verdict must not be bypassable by a device
  grant). The defects are contract and observability: the `mfa_required`
  response is byte-identical whether the challenge is heuristic or
  policy-enforced, and no audit signal marks an overridden live grant, so
  operators cannot distinguish forced re-challenges from normal ones.
- **Corrective behavior** (adopts the analysis): keep the semantics; document
  the exception in `docs/error-codes.md` §Trusted devices and
  `docs/feature-matrix.md`; in `enforceConditionalAccessLogin`, when
  `trustedDeviceAllowsSkip` returns true but `VerdictRequireStepUp` still
  demands the challenge, emit the `mfa_required` event (`server_mfa.go:36`)
  with a marker meta key (e.g. `trusted_device_overridden=true`) —
  implementable at one call site since both paths share `issueMFAChallenge`.
  Wire response stays byte-identical.

## 4. Priority conformance tests, declared unsupported features, certification evidence

### Priority conformance tests (in priority order)

1. **Mutation-endpoint step-up gate** (cross-server, `test/`): password-only
   token → 403 `insufficient_user_authentication` on all four mutation
   endpoints (`DELETE /me/mfa/:id`, `POST /me/mfa/recovery-codes`,
   `/me/mfa/totp/confirm`, `/me/mfa/webauthn/finish`); the identical calls
   succeed (201/204) after completing `/auth/mfa`; a subject with zero
   enrolled factors can still enroll the first TOTP factor; a second factor,
   any removal, and recovery-code regeneration require step-up. Update
   `TestTOTPEnroll_*`, `TestWebAuthnRegister_*`, `TestMyMFA_*`, and the
   `TestMFA_TrustDevice_*` suite to step up first (acceptance for finding 1).
2. **Lockout-key scoping** (unit, `interfaces/sso` +
   `security.MemoryAccountLockout`): 5 failed verifies against a client-A
   challenge lock the `(clientA, subject)` key while `(clientB, subject)`
   stays unlocked — a valid client-B code still completes;
   `RegisterSuccess` on client A clears only client A's counter. Update the
   bare-key assertion at `test/mfa_test.go:803`. A docscheck-style scan
   confirms the new `mfa_locked` row in `docs/error-codes.md` (acceptance for
   finding 2).
3. **Trusted-device override** (cross-server, `test/`): (1) RiskScorer-only
   `RequireMFA` + valid `device_token` → login proceeds,
   `mfa_skipped_trusted_device` audit, no challenge minted; (2) CA
   `VerdictRequireStepUp` + valid `device_token` → `mfa_required` issued with
   the `trusted_device_overridden` marker; (3) both engines firing → exactly
   one challenge (the CA path owns it) with the marker present. No existing
   test covers the CA-override case (acceptance for finding 3).
4. **Wire-shape regression sweep on `/auth/mfa`**: rerun the oracle-safety
   suite (`TestMFA_WrongCode_Returns_mfa_invalid`,
   `TestMFA_UnknownChallengeID`, `TestMFA_Replay_AlreadyConsumed`,
   `TestMFA_SecondFactorLockout`) after the lockout-key change to prove the
   response body stays byte-identical.

### Declared unsupported features / explicit exceptions

- Zero-enrolled-factors bootstrap exemption (finding 1's proposal): first
  factor enrollment with a plain authenticated bearer remains permitted; the
  step-up gate applies from the second factor onward. This mirrors the
  practical impossibility of stepping up before any factor exists and is the
  analysis's declared exception, not an oversight.
- The trusted-device skip grant remains a profile feature; a CA
  `VerdictRequireStepUp` overrides it by design (no bypass).
- Nothing else in the earlier review's "declared unsupported" list changes
  (HOTP, TOTP SHA-256/512, TOTP resync, strict single-use TOTP without
  opt-in).

### Remaining certification evidence

- **No OIDF or FIDO certification is claimed** (no published current result
  exists in the tree), and this review does not assert one.
- None of the three proposals touches an OIDC/OAuth wire surface: the 403
  step-up demand is new only on proprietary `/me/mfa/*` routes; lockout and
  audit changes keep response bodies byte-identical. Certification posture
  (none claimed) is therefore unaffected.
- Evidence gaps to close before implementing: an explicit test of the
  bootstrap-exemption boundary (zero factors vs. one factor), and the
  CA-override audit marker — both are covered by the acceptance tests above.
