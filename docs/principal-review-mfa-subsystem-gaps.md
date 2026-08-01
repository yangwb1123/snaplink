# Principal review — MFA subsystem gaps (consolidated)

Synthesis of three supplied deliverables for the MFA subsystem gap analysis:
`docs/architect-analysis-mfa-subsystem-gaps.md` (architect, with the
mfa-analysis verification note), `docs/security-review-mfa-subsystem-gaps.md`
(security engineer), and `docs/architect-analysis-mfa-protocol-review-gaps.md`
(protocol expert). Reviewed revision: HEAD `6c8fb33c`.

**Independent verification performed for this review** (direct code reading;
not derived from the deliverables):

- All four mutation handlers gate on `MeSubjectOrChallenge` only —
  `protocols/selfservice/selfserviceaccount/mfa.go:40` (`HandleDeleteMyMFAFactor`),
  `:107` (`HandleTOTPEnrollConfirm`), `:159` (`HandleGenerateRecoveryCodes`),
  `security.go:149` (`HandleWebAuthnRegisterFinish`). `claims.AMR` never read.
- `HandleTrustMyDevice` (`trusted_devices.go:66`) requires
  `slices.Contains(claims.AMR, "mfa")` else 403
  `security.ErrInsufficientUserAuthentication`; `docs/error-codes.md:218`
  documents that gate for `/me/devices/trust` only.
- `mfaLockoutKey` (`interfaces/sso/server_mfa.go:301`) = `"mfa lockout:"+subjectID`;
  password leg `LockoutKey` (`shared/security/account_lockout.go:199`) =
  `clientID+":"+identity`. `test/mfa_test.go:803` pins the bare
  `"mfa lockout:alice"` key. `mfa_locked` absent from `docs/error-codes.md`.
- `runPostCredentialGates` (`server_login_gates.go:274`) runs
  `evaluateLoginRisk` (281) then `enforceConditionalAccessLogin` (284);
  risk path consults `trustedDeviceAllowsSkip` (`server_login_client.go:181`),
  CA path issues `issueMFAChallenge` unconditionally (`:245`). Both-engines
  case yields exactly one challenge (risk gate returns early on issue, falls
  through on skip).
- `spi.MFAChallenge.ClientID` (`shared/spi/mfa.go:93-95`) is set at persist
  (`server_mfa.go:82`) and consumed at resume (`:340`) — per-client lockout
  keying is implementable at the verify site. `mfa_required` audit is emitted
  in the shared `issueMFAChallenge` (`server_mfa.go:36-39`) — the Finding 3
  marker is implementable at one call site.
- The three deliverable docs are untracked files at `6c8fb33c`; the working
  tree additionally carries unrelated in-flight changes (client-secret
  rotation, config reload) that pre-date and are independent of this review.

**Checks that ran for this revision**: the protocol expert ran
`go test ./protocols/selfservice/selfserviceaccount/ -count=1` (ok) and
`go test ./test/ -run 'TestMFA_SecondFactorLockout|TestTOTPEnroll_ConfirmThenListedAndUsable|TestMFA_TrustDevice_MintsGrantAndReturnsToken' -count=1 -v`
(3/3 PASS). No full-suite run occurred at this revision — correct and
sufficient for a docs-only change (AGENTS.md §2 gates trigger on `.go` edits;
none were made).

---

## 1. Advisory recommendation

**Conditionally ready — proceed to implementation of all three findings as
one change set, gated on the acceptance checks in §4.**

- Evidence confidence for the three findings: **high**. Each was verified by
  three independent reviewers (architect, security, protocol) and the
  load-bearing claims were re-verified directly for this review. The three
  reviewers' file/symbol/line evidence is mutually consistent; no contradicting
  evidence was found anywhere.
- This review does **not** bless a release: nothing is implemented yet. The
  reviews are advisory analysis (docs-only), and `make ci` has not been run on
  any implementation.
- No severity or direction conflict blocks the work; the one severity
  disagreement (Finding 3) resolves without a decision fork (§3.3).

---

## 2. Consolidated findings (deduplicated, with source)

### High — F1. MFA credential mutation requires no step-up (Verified)

- **Sources (dedup)**: architect point 1; security Finding 1 (High); protocol
  Finding 1 (High). The mfa-analysis note on `Registrar.FinishRegistration`
  (registrar.go:50 / webauthn.go:376) is folded in: finish-bearer subject is
  bound to the begin session's user, but no step-up is ever checked.
- **Defect**: `DELETE /me/mfa/:id`, `POST /me/mfa/recovery-codes`,
  `POST /me/mfa/totp/confirm`, `POST /me/mfa/webauthn/finish` are gated only
  by bearer liveness. A stolen non-stepped-up bearer can delete all factors
  (permanent MFA downgrade), regenerate recovery codes (revoking the victim's
  batch and reading the fresh plaintext exactly once), and bind an
  attacker-controlled factor — while the same package demands step-up for the
  strictly weaker action `POST /me/devices/trust`.
- **Impact**: complete loss of second-factor control from a credential the
  codebase already refuses to trust for MFA-skip. Violates NIST 800-63B §5.2.9
  and the codebase's own consistency contract (error-codes.md:218).
- **Required fix** (adopts the security engineer's refinement over the
  architect's broader wording): RFC 9470 gate via `MeClaimsOrChallenge` +
  `slices.Contains(claims.AMR, "mfa")` on all four endpoints, reusing the
  already-documented 403 `insufficient_user_authentication`. Bootstrap
  exemption **only** for first-factor commit (`totp/confirm`,
  `webauthn/finish` when `MFAEnrollmentStore.ListFactors` is empty). `DELETE`
  and `recovery-codes` get **no** exemption — there is no legitimate
  zero-factor delete/regenerate case. `GET` endpoints stay open.
- **Validation**: cross-server tests — password-only token → 403 on all four;
  post-step-up → 201/204; zero-factor subject can still enroll first factor;
  with ≥1 factor, delete/regenerate require step-up. Existing tests that
  enroll with plain tokens (`test/me_mfa_totp_enroll_test.go`,
  `selfserviceaccount/mfa_test.go`, `security_test.go`) must step up first —
  they pin the vulnerable behavior and their update is part of the change.

### Medium — F2. MFA brute-force lockout keyed per-subject only (Verified)

- **Sources (dedup)**: architect point 2; security Finding 2 (Medium);
  protocol Finding 2 (Medium). Severity agreed across all three.
- **Defect**: `mfaLockoutKey` = `"mfa lockout:"+subjectID` while the password
  leg is per (client, user). Five wrong factors via any one client lock the
  subject on every client for 15 min, repeatable by anyone holding the
  password for one client (password successes are not lockout-registered);
  five TOTP typos on a kiosk client self-inflict the same.
- **Required fix**: key `"mfa lockout:"+clientID+":"+subjectID` from
  `challenge.ClientID`; preserve the `"mfa lockout:"` namespace prefix (space
  not in the RFC 6749 client_id charset — keep as a unit assertion); wire
  shape byte-identical (`mfa_invalid`); document the `mfa_locked` audit reason
  in error-codes.md (currently code-only).
- **Validation**: unit test with `security.NewMemoryAccountLockout` — 5
  failures on client A lock `(A, subject)` and leave `(B, subject)` unlocked;
  success on A clears only A. Update `test/mfa_test.go:803`. Rerun the
  oracle-safety suite after the change (`TestMFA_WrongCode_Returns_mfa_invalid`,
  `TestMFA_UnknownChallengeID`, `TestMFA_Replay_AlreadyConsumed`,
  `TestMFA_SecondFactorLockout`).

### Medium — F3. Trusted-device skip: honored by risk path, silently ignored by enforced conditional-access path (Verified — contract/observability)

- **Sources (dedup)**: architect point 3; security Finding 3 (**Low**);
  protocol Finding 3 (**Medium**).
- **Severity resolution (no decision fork)**: the disagreement is a lens
  difference, not a factual one. Security impact is Low — enforced-verdict-wins
  is the correct direction and no wire response changes. Contract impact is
  Medium under AGENTS.md §1: `docs/error-codes.md:221` and feature-matrix row
  130 document the skip contract without the conditional-access exception, and
  the doc/behavior disagreement is a drift to be reported and reconciled, not
  silently left. Both lenses prescribe the identical action, so no maintainer
  choice between severities is required — record as **Medium (contract),
  Low (security)**.
- **Required fix**: keep enforced-verdict-wins. Document the exception in
  error-codes.md §Trusted devices and feature-matrix.md; in
  `enforceConditionalAccessLogin`, when `trustedDeviceAllowsSkip` is true but
  the verdict still demands step-up, emit the `mfa_required` event with a
  `trusted_device_overridden=true` meta key via `audit.SetMeta` (the
  AGENTS.md-sanctioned metadata path; event type unchanged so `auditreport`
  classification is unaffected; boolean cardinality bounded). Wire response
  byte-identical.
- **Validation**: 3-scenario cross-server test (risk-only skip; CA override;
  both engines → exactly one challenge with marker).

### Info — accepted residuals and scope exclusions (no action in this change set)

- **Bootstrap-exemption window**: a stolen non-stepped-up token on a
  zero-factor account can still bind a first factor. Accepted: that is the
  pre-existing password-only compromise state; the exemption is required by
  construction (no step-up is possible before any factor exists); deletion and
  regeneration stay gated unconditionally. Owner: security (accepted, noted in
  security review §5).
- **`HandleChangeMyPassword`** (`security.go:22`) also lacks an MFA step-up
  gate, but requires proof of the current password (`VerifyPassword`) — a
  distinct, legitimate reauthentication control. No reviewer covered it; it is
  outside the MFA-factor scope of all three reviews. Flagged so maintainers
  can consciously decide whether NIST 800-63B §5.2.9 should later extend to
  password change; deliberately **not** added to this change set.
- **Prior-review items** remain tracked separately: unbounded challenge
  issuance / push fatigue, `/me/mfa/*` error-code drift
  (`docs/architect-analysis-mfa-subsystem-review.md`).

---

## 3. Trade-off ledger

| # | Conflict | Options | Recommendation | Consequence | Decision owner |
|---|---|---|---|---|---|
| 3.1 | F1 bootstrap exemption scope: architect's broad "zero-enrolled-factors" wording vs security refinement (commit legs only) | (a) exemption on all four endpoints; (b) exemption only on `totp/confirm` + `webauthn/finish` | (b) — strictly safer; there is no legitimate zero-factor delete or recovery-code-regeneration use case | Attacker with a non-stepped-up token on a zero-factor account can still bind a factor (pre-existing compromise state, unchanged); deletion/regeneration become unconditionally gated | Security engineer (proposal) → maintainers to ratify |
| 3.2 | F2 blast radius vs guess budget: per-subject lockout (status quo) vs per-(client, subject) | (a) keep subject-wide key; (b) key by `challenge.ClientID` + subject; (c) stronger (e.g. per-IP) | (b) — matches the password leg's scope; keeps the `"mfa lockout:"` namespace disjointness | Blast radius shrinks to one client; a password-holder can rotate clients for more guesses, but each guess needs a fresh successful password login and the password leg is itself per-client locked — brute-force bound preserved | Security (control keying) + maintainers (availability posture) |
| 3.3 | F3 severity framing: Low (security) vs Medium (protocol) | (a) record as Low; (b) record as Medium-contract | (b) under AGENTS.md §1 (docs are public contracts; drift must be reported and reconciled) — with the security-Low note | No behavioral fork; the fix (docs rows + audit marker) is identical either way; classification matters only for backlog prioritization | Principal (this review) — resolved, no maintainer action |
| 3.4 | F1 dependency: gate reads `claims.AMR`; if any refresh path drops `amr`, legit users get a fail-closed 403 on MFA management after refresh | (a) ship F1 and pin AMR preservation in the same change set (P3 test); (b) ship F1 without the pin | (a) — AGENTS.md already mandates refresh auth-context preservation; the positive assertion makes the gate's foundation executable rather than documented | One extra test in the change set; prevents a silent availability regression for stepped-up users whose tokens refreshed | Security + maintainers |
| 3.5 | Fix breaks existing tests that enroll with plain tokens (they pin the vulnerable behavior) | (a) update them to step up first; (b) gate only new tests | (a) — the tests encode the defect; keeping them would make the fix unmergeable under CI | Expected, bounded test churn; no product-visible behavior loss for legitimate flows (bootstrap exemption covers first-factor) | Implementer (no authority needed) |
| 3.6 | F2 implementation detail: empty `clientID` at verify time | (a) keep the existing empty-key guard, extended to clientID; (b) treat empty client as unkeyable | (a) — preserve the current "empty subject → unkeyable" behavior symmetrically; `mfaLockoutKey` returns `""` today and the call sites already guard on it | No behavior change for the degenerate case; no oracle introduced | Implementer (no authority needed) |

No accepted-risk decision in this set requires CTO or compliance authority:
no OIDC/OAuth wire surface changes (the new 403 is on proprietary `/me/mfa/*`
routes only), no certification posture is claimed or affected, and no
regulated-data handling changes. The security review's abuse-case table (17
rows) and 10 positive controls were checked against the code during this
review's verification pass and found consistent.

---

## 4. Preconditions, acceptance checks, rollback, monitoring

### Preconditions (before or with implementation)

1. Pin `amr`-across-refresh preservation with a positive cross-server test
   (step up → refresh → call `/me/mfa/totp/confirm` → 201). This is the
   foundation of the F1 gate (ledger 3.4).
2. Confirm `challenge.ClientID` is non-empty for every challenge that reaches
   `verifyMFAFactor` (it is set from the issuing client at persist, `server_mfa.go:82`).
3. Budget check before editing: all edits land in existing files; the F1 gate
   adds ~5 lines per handler — no file/function budget crossings anticipated,
   and no new packages (no `layerName()`/`layerExemptions` impact).

### Executable acceptance checks (post-implementation)

| Finding | Check | Command |
|---|---|---|
| F1 | 403 `insufficient_user_authentication` pre-step-up on all four endpoints; 201/204 post-step-up; zero-factor bootstrap works; delete/regenerate never exempt | `go test ./test/ -run 'TestE2E|TestMFA|TestTOTP|TestMyMFA|TestWebAuthn' -v` (new cross-server tests in `test/`) |
| F2 | per-(client, subject) lockout isolation; `test/mfa_test.go:803` updated; namespace-disjointness assertion | unit tests in `interfaces/sso` + `shared/security`; `go test ./... -race` |
| F3 | 3-scenario override test; marker present; docs rows name the CA exception | `test/` cross-server; docscheck-style scan of error-codes.md / feature-matrix.md |
| All | wire shapes byte-identical (`mfa_invalid`, `mfa_required`, 403 reuses documented code) | oracle-safety rerun: `go test ./test/ -run 'TestMFA_WrongCode|TestMFA_UnknownChallengeID|TestMFA_Replay|TestMFA_SecondFactorLockout' -v` |

Mandatory gates per AGENTS.md §2, in order: `go build ./... && go vet ./...`;
`go test -run 'TestMaintainability_|TestArchitecture_' .`; then
`go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`.
Documentation updates (error-codes.md, feature-matrix.md, openapi.yaml) must
land in the same change set (AGENTS.md §5 step 6).

### Rollback triggers

- **F1**: any legitimate first-factor enrollment returns 403 for a zero-factor
  account (bootstrap bug) → roll back the exemption logic only, keep the gate.
- **F2**: lockout stops engaging (brute-force regression) or any wire-body
  drift on `/auth/mfa` → roll back keying to the subject-wide key.
- **F3**: `trusted_device_overridden` marker appears in a wire response (it
  must be audit-only) or `auditreport` classification breaks → drop the
  marker, keep the docs rows.
- **General**: any byte-identical-wire guarantee violated is a rollback trigger.

### Monitoring (post-deploy)

- Rate of `mfa_locked` audit reason per client vs per subject after F2
  (expect per-client skew; sustained per-subject spread indicates keying
  drift).
- Rate of 403 `insufficient_user_authentication` on `/me/mfa*` after F1 — an
  initial spike from legit clients holding non-stepped-up tokens is expected;
  sustained volume indicates a client-integration break worth a migration
  notice (this is a behavioral break for password-only-token MFA management,
  which is the intended security fix — operators should be told).
- Count of `mfa_required` events with `trusted_device_overridden=true` after
  F3 (SIEM correlation: users with live grants who were re-challenged).

### Explicit exclusions (this change set)

- Password-change endpoint step-up (Info item above; separate decision).
- Unbounded challenge issuance / push fatigue and `/me/mfa/*` error-code
  drift (prior review `architect-analysis-mfa-subsystem-review.md`).
- Multi-replica lockout backend (memory-backed lockout forks per replica;
  pre-existing operator requirement, unaffected by F2).
- OIDF/FIDO certification (none claimed anywhere in the tree).

### Residual risks (accepted, from security review §5, cross-checked)

- `device_token` is bearer-equivalent for its (user, client) until TTL —
  by design; minted only from stepped-up sessions, hashed at rest, never
  renewed.
- Bootstrap-exemption window (Info above).
- Memory-backed lockout is per-replica; a shared backend remains an operator
  responsibility.
- AMR-across-refresh is contract-backed but unpinned by a test until
  precondition 1 lands.

---

## 5. Missing evidence and next actions

**Missing/not supplied** (not fabricated here):

- No full-suite run (`go test ./... -race`, `make ci`) at `6c8fb33c` — not
  required for docs-only work, but the implementation must run it.
- No reviewer ran the maintainability/architecture gates at this revision
  (again, docs-only — no `.go` edits).
- No existing test pins AMR-across-refresh preservation; the F1 gate's
  foundation is documented (AGENTS.md invariant) but not executable today.
- No test covers the CA-override case (F3) — confirmed absent before
  implementation.
- `test/mfa_test.go:803` and the enroll-with-plain-token tests are the only
  known test sites pinned to pre-fix behavior; a full `grep` sweep for other
  plain-token MFA-management callers belongs to the implementer.
- No load/performance analysis is needed: F2 is an O(1) key change on a
  cold path; F1/F3 add no hot-path work.

**Narrow next actions to reach a release decision:**

1. Implement F1 + F2 + F3 and the docs rows in one change set, with the
   acceptance tests above (P0–P2; P3 AMR pin included per ledger 3.4).
2. Run the mandatory gates in AGENTS.md order, then `make ci`.
3. Re-review the diff (security + protocol lens) for wire-shape byte-identity
   and oracle-safety, then a release owner makes the release call.

No sign-offs, deadlines, or approval status are asserted in this review; the
accountable owners named in the ledger are the parties the recommendation
routes to.
