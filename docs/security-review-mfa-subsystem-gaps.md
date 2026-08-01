# Security review — MFA subsystem: verification of the three proposed gaps

Principal security engineer review of `docs/architect-analysis-mfa-subsystem-gaps.md`
against executable code at revision `6c8fb33c`. All three proposed points are
**Verified** by direct code reading and confirmed test/key evidence; severity
assessments, exploit walkthroughs, and regression tests below are this review's
own. Docs-only change: no Go gates triggered.

Scope note (agreed with the architect): there is no `domains/mfa/` and no
`interfaces/sso/me_mfa.go`. The subsystem lives in `interfaces/sso/server_mfa.go`,
`interfaces/sso/server_mfa_trust.go`, `interfaces/sso/server_login_client.go`,
`interfaces/sso/server_login_gates.go`, `shared/spi/mfa.go`,
`protocols/selfservice/selfserviceaccount/{mfa,security,trusted_devices}.go`,
`domains/authenticators/webauthn/`, and `infrastructure/defaultimpl/defaultmfa/`.

---

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Location | Sensitivity |
|---|---|---|
| MFA factor enrollments (TOTP secrets, WebAuthn passkeys) | `MFAEnrollmentStore` / WebAuthn credential store | Highest: second-factor proof of identity |
| Recovery-code batches (plaintext shown once, hashed at rest) | `RecoveryCodeStore` | Highest: password-equivalent fallback |
| Single-use MFA challenges (frozen login state) | `MFAChallengeStore` | High: one factor-verify round trip |
| Trusted-device skip grants (`device_token`, hashed at rest) | `TrustedDeviceStore` | High: MFA-skip bearer credential, per (user, client) |
| Sessions / access tokens carrying `amr` | session + token stores | High: the step-up evidence this review keys on |
| MFA failure/lockout counters | `AccountLockout` (memory or shared backend) | Medium: availability + brute-force bound |

### Trust boundaries

1. **Bearer-boundary**: every `/me/mfa*`, `/me/trusted-devices*` request crosses
   from unauthenticated to authenticated at `meClaimsOrChallenge`
   (`interfaces/sso/server_me.go:40`). Everything inside trusts
   `claims.Subject`, `claims.ClientID`, `claims.AMR`. This boundary is the
   subject of Finding 1 — it validates *liveness* of a token but not the
   *strength* of the authentication that minted it.
2. **Login-gate boundary**: `/auth/login` credential validation happens before
   the post-credential gates (`runPostCredentialGates`,
   `server_login_gates.go:274`); risk and conditional-access engines sit on the
   server side of it. The `device_token` input crosses from client to server
   here and is the subject of Finding 3.
3. **Store boundary**: challenge/device-token consumption is atomic
   (`Consume`/`Take`/`Verify`), so a credential never crosses the boundary
   twice. Replay stops at this boundary.
4. **Oracle boundary**: wire responses must not distinguish internal causes.
   Finding 2's fix must not move this boundary.

### Attacker capabilities (model)

- **A1 — stolen non-stepped-up bearer**: exfiltrated access/refresh token from a
  password-only client login (or a client whose MFA step-up was skipped), valid
  and unexpired, `amr` lacking `mfa`. Cannot mint a trusted-device grant today
  (403), but *can* mutate MFA credentials (Finding 1).
- **A2 — password-holder on one client**: knows the victim's password for
  client A; can complete `/auth/login` (primary-leg success is not
  lockout-registered) and receive fresh single-use challenges. Cannot mint
  tokens (needs the factor), but can burn failures (Finding 2).
- **A3 — returning user with a legitimately stolen `device_token`**: can skip
  the risk-scorer step-up for (user, client). By design; the grant is the
  control. Cannot skip an enforced conditional-access verdict (Finding 3's
  correct half).
- **A4 — unauthenticated remote attacker**: no bearer, no password. Reaches
  `/auth/login`, `/auth/mfa`. Bounded by oracle-safe collapses and the
  per-(client, subject) password lockout; MFA lockout is reachable only via A2
  (needs a successful primary leg per attempt).

### Entry points reviewed

`DELETE /me/mfa/:id`, `GET/POST /me/mfa/recovery-codes`,
`POST /me/mfa/totp/{begin,confirm}`, `POST /me/mfa/webauthn/{begin,finish}`,
`GET/POST/DELETE /me/trusted-devices*`, `/auth/login`, `/auth/mfa`,
`POST /me/password`. All mount through the `SelfService`-gated
`core.GatedRouter` (`mountSelfServiceCredentials`, `server_me.go`) — hot-toggle
is uniform and was not found to be a differentiator between the gated and
ungated endpoints.

---

## 2. Findings

### Finding 1 — MFA credential mutation requires no step-up (Verified, High)

**Verdict on the architect's claim: Verified.** All four mutation endpoints are
gated only by bearer validity, and the full-claims plumbing that would enable
the gate already exists and is used for a strictly weaker action one file away.

**Evidence**

| File | Symbol (line) | Fact |
|---|---|---|
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleDeleteMyMFAFactor` (40) | list + `RemoveFactor` under `MeSubjectOrChallenge` only; `claims.AMR` never read |
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleTOTPEnrollConfirm` (107) | verifies code against a caller-supplied secret, persists factor, under bearer only |
| `protocols/selfservice/selfserviceaccount/mfa.go` | `HandleGenerateRecoveryCodes` (159) | `RevokeAll` + `Generate`, returns fresh plaintext batch once, under bearer only |
| `protocols/selfservice/selfserviceaccount/security.go` | `HandleWebAuthnRegisterFinish` (149) | commits passkey under bearer only |
| `interfaces/sso/server_me.go` | `meSubjectOrChallenge` (27) / `meClaimsOrChallenge` (40) | full claims (incl. `AMR`) already resolved; the four handlers call the subject-only wrapper and discard `AMR` |
| `protocols/selfservice/selfserviceaccount/trusted_devices.go` | `HandleTrustMyDevice` (56; check at 66) | `slices.Contains(claims.AMR, "mfa")` else 403 `security.ErrInsufficientUserAuthentication` — the in-repo RFC 9470 precedent |
| `docs/error-codes.md` | line 218 | step-up demand documented only for `/me/devices/trust` |
| `domains/authenticators/webauthn/registrar.go` | `FinishRegistration` (50) → `domains/authenticators/webauthn/webauthn.go` (365–378) | finish bearer's subject is checked against the begin session's user (`user.Name != expectedUserID` → error); nothing checks whether that bearer completed MFA. Confirms the mfa-analysis verification note: subject-bound yes, step-up-bound no |

**Exploit preconditions and steps (A1).** Precondition: possession of a valid,
unexpired bearer whose `amr` lacks `mfa` — e.g. an access token from a
password-only client login, a stolen token before the victim's step-up, or a
token from a login whose risk-scorer step-up was legitimately skipped.

1. `DELETE /me/mfa/<id>` for each enrolled factor id (enumerable from
   `GET /me/mfa`) — each returns 204. Account is now password-only; every
   subsequent login of the victim mints tokens with no second factor.
2. `POST /me/mfa/recovery-codes` — 201 with a fresh plaintext batch; the
   victim's existing codes are revoked in the same call. The attacker now holds
   the account's fallback credential; the victim's copy dies silently.
3. `POST /me/mfa/totp/confirm` with an attacker-generated secret + current code
   (or `POST /me/mfa/webauthn/finish` with a fresh passkey ceremony) — 201. The
   attacker factor is now an enrolled second factor; the account is under
   attacker control even after the stolen token expires.

Steps 1–3 are independent; step 1 alone is a permanent MFA downgrade.

**Impact.** Complete loss of the second-factor control: MFA downgrade,
recovery-code takeover, and attacker factor binding — all from a credential
that the same package already refuses to trust for the weaker "skip future
MFA" action. NIST SP 800-63B §5.2.10 (re-authentication for credential
changes) and RFC 9470 are both violated by the *inconsistency* even where the
endpoint individually passes a naive "authenticated" check.

**Mitigating factors.** The attacker needs a live bearer (not just the
password); recovery codes are returned exactly once and hashed at rest;
`/me/mfa*` sets no-store headers. None of these reduce the step-up gap itself.

**Remediation (as proposed, refined).** Require `amr` containing `mfa` on all
four mutation endpoints, via the existing `MeClaimsOrChallenge` + the exact
`HandleTrustMyDevice` check — 403 `insufficient_user_authentication` (RFC
9470), which is already documented at error-codes.md:218 and therefore not a
new error shape. Bootstrap exemption: only `totp/confirm` and
`webauthn/finish`, and only when `MFAEnrollmentStore.ListFactors` returns zero
factors for the subject (first-factor bootstrap). `DELETE /me/mfa/:id` and
`POST /me/mfa/recovery-codes` must **not** get the exemption — there is no
bootstrap need for deletion, and regeneration with zero factors is a
recovery-code takeover with no legitimate first-time-user counterpart.
`GET` endpoints stay open. Update error-codes.md, feature-matrix.md, and
openapi.yaml in the same change.

**Regression test.** Cross-server (`test/`, `package ssotest`), modeled on the
existing `buildRiskHarness`/`rootcov_trusted_devices_test.go` patterns:
(1) mint a token from a password-only login (no step-up); assert 403
`insufficient_user_authentication` on all four mutation endpoints; (2) run the
same calls after completing `/auth/mfa` step-up; assert the pre-change statuses
(204/201/201/201); (3) a zero-factor subject can still enroll the first TOTP
factor and first passkey with a plain bearer; (4) with one factor enrolled,
deletion and recovery-code regeneration require step-up. Existing unit tests
in `protocols/selfservice/selfserviceaccount/mfa_test.go`,
`security_test.go` (which currently drive these handlers with plain claims)
must step up first or be extended with a stepped-up fixture, mirroring
`trusted_devices_test.go:37` (`AMR: []string{"pwd", "mfa"}`).

### Finding 2 — MFA lockout is keyed per-subject, amplifying one-client password compromise into whole-account MFA DoS (Verified, Medium)

**Verdict on the architect's claim: Verified.**

**Evidence**

| File | Symbol (line) | Fact |
|---|---|---|
| `interfaces/sso/server_mfa.go` | `mfaLockoutKey` (301) | `"mfa lockout:" + subjectID` — no client component |
| `interfaces/sso/server_mfa.go` | `verifyMFAFactor` (252; key use 266, `IsLocked` 268, `RegisterFailure` 282) | both the lock check and failure registration use the subject-wide key |
| `test/mfa_test.go` | line 803 | `lock.failures["mfa lockout:alice"]` — test pins the bare per-subject key |
| `shared/security/account_lockout.go` | `LockoutKey` (199) | password leg: `clientID + ":" + identity` — per (client, user) |
| `shared/security/account_lockout.go` | defaults (73–75) | 5 failures / 1 h window / 15 min lock |
| `interfaces/sso/server_mfa.go` | `persistMFAChallenge` (56) | `challenge.ClientID` is set from the issuing client — available at verify time |
| `docs/error-codes.md` | §MFA orchestration (lines 203–204) | only `mfa_required`/`mfa_invalid` rows; the `mfa_locked` audit reason (server_mfa.go:269) is undocumented |

**Exploit preconditions and steps (A2).** Precondition: the victim's password
for any one client, and the ability to submit wrong factors for the victim.

1. For each of 5 iterations: `POST /auth/login` with correct password for
   client A → 200 `mfa_required` + fresh single-use challenge (the primary-leg
   success is not lockout-registered, and the challenge is minted per login).
2. `POST /auth/mfa` with that challenge id and a wrong factor → 400
   `mfa_invalid`, `RegisterFailure("mfa lockout:<victim>")`.
3. After 5 failures: the victim's MFA completion is locked on **every**
   client — including unrelated admin/sensitive clients — for 15 minutes.
4. Repeat after the lock expires: sustained whole-account MFA denial of
   service for as long as the attacker holds the password.

Self-inflicted variant: 5 TOTP typos on a kiosk/shared client lock the
legitimate user out of all clients. Wire shape stays byte-identical
(`mfa_invalid`), so there is no new oracle; the finding is availability
amplification plus a documentation gap.

**Impact.** One-client credential compromise (or one user's typo burst)
becomes a whole-account MFA availability weapon. The per-client password leg
already scopes the same attacker to client A; the MFA leg's wider scope is
inconsistent with it and is the amplification.

**Remediation (as proposed).** Key `"mfa lockout:" + clientID + ":" +
subjectID` using `challenge.ClientID`. The `"mfa lockout:"` prefix (with the
space, which RFC 6749 client_ids cannot contain) keeps namespace disjointness
from the password leg — this property must be preserved and is worth a unit
assertion. Wire shape unchanged; document the `mfa_locked` audit reason in
error-codes.md. Accepted trade-off (agreed): a password-holder can rotate
clients to attempt more factor guesses per window, but every attempt requires a
fresh successful password login and the password leg is itself per-client
locked, so the brute-force bound per (client, user) is preserved while the
blast radius shrinks to one client. Note that recovery-code attempts ride the
same provider-Verify path and therefore the same key — that property is
retained by this change.

**Regression test.** Unit test around `verifyMFAFactor` with
`security.NewMemoryAccountLockout`: 5 failed verifies against a client-A
challenge lock `(clientA, subject)` and leave `(clientB, subject)` unlocked —
a valid client-B code still completes and its success clears only client B's
counter. Update `test/mfa_test.go:803` to the two-part key, and add a
namespace-disjointness assertion (`"mfa lockout:"` can never equal a
`LockoutKey` output).

### Finding 3 — Trusted-device skip honored by the risk path, silently ignored by the enforced conditional-access path (Verified, Low — contract + observability)

**Verdict on the architect's claim: Verified.** Behavior is defensible; the
gap is documentation and audit observability, not a security inversion.

**Evidence**

| File | Symbol (line) | Fact |
|---|---|---|
| `interfaces/sso/server_login_gates.go` | `runPostCredentialGates` (274) | `evaluateLoginRisk` (281) then `enforceConditionalAccessLogin` (284); either may own the response; in the both-engines case the risk gate's skip returns false and the CA gate still runs → exactly one challenge, issued by the CA path |
| `interfaces/sso/server_login_client.go` | `evaluateLoginRisk` (144) | line 181: `trustedDeviceAllowsSkip` before `issueMFAChallenge`; skip records `mfa_skipped_trusted_device` (`recordMFASkippedTrustedDevice`, 458) |
| `interfaces/sso/server_login_client.go` | `enforceConditionalAccessLogin` (221) | line 243–245: `VerdictRequireStepUp` → `issueMFAChallenge` unconditionally; no `trustedDeviceAllowsSkip` call anywhere in the function |
| `interfaces/sso/server_login_client.go` | `trustedDeviceAllowsSkip` (442) | doc comment (429–441) names only the risk-scorer path |
| `docs/error-codes.md` | line 221 | skip contract documented ("A successful skip records the `mfa_skipped_trusted_device` audit event instead of a wire-visible signal") with no conditional-access exception |
| `docs/feature-matrix.md` | line 130 | "MFA orchestration" row: no device-trust caveat |

**Impact.** An operator who configures an enforced step-up policy gets
correctly enforced step-up (a device grant cannot bypass an operator verdict —
the security-correct half), but: (a) returning users with live grants are
silently re-challenged while the identical login skips under a risk-scorer-only
deployment, with a byte-identical `mfa_required` response so clients and
operators cannot distinguish policy-forced challenges from heuristic ones;
(b) there is no audit signal that a live grant was overridden, so SIEM
correlation between "user has a valid grant" and "user was re-challenged" is
impossible.

**Remediation (as proposed).** Keep enforced-verdict-wins. (1) Document the
exception in error-codes.md §Trusted devices and feature-matrix.md "MFA
orchestration": a live grant skips only risk-scorer (heuristic) step-up, never
an enforced `VerdictRequireStepUp`. (2) In `enforceConditionalAccessLogin`,
when `trustedDeviceAllowsSkip` is true but the verdict still demands step-up,
add an audit meta marker to the `mfa_required` event (e.g.
`audit.SetMeta(evt, "trusted_device_overridden", "true")`) — event type
unchanged, so `auditreport` classification (`platform/audit/auditreport/control_areas.go:62`)
is unaffected, and cardinality stays bounded (boolean value). Wire response
byte-identical.

**Regression test.** Cross-server: (1) RiskScorer-only `RequireMFA` + valid
`device_token` → login proceeds, `mfa_skipped_trusted_device` audit, no
challenge (this already exists in
`interfaces/sso/rootcov_trusted_devices_test.go:221–257`); (2) CA
`VerdictRequireStepUp` + valid `device_token` → `mfa_required` issued with the
new marker; (3) both engines firing → exactly one challenge, marker present.

---

## 3. Abuse-case table

| Abuse case | STRIDE | Reachable? | Result today | Post-fix |
|---|---|---|---|---|
| Identity spoofing: stolen non-stepped-up bearer enrolls attacker TOTP/passkey | Spoofing | **Yes** (Finding 1) | 201, attacker factor bound | 403 `insufficient_user_authentication` unless zero-factor bootstrap |
| Identity spoofing: stolen non-stepped-up bearer deletes all factors, downgrades to password-only | Spoofing/Tampering | **Yes** (Finding 1) | 204 per factor; permanent MFA loss | 403 |
| Identity spoofing: stolen non-stepped-up bearer regenerates recovery codes, revoking the victim's batch | Spoofing | **Yes** (Finding 1) | 201, fresh plaintext batch to attacker exactly once | 403 (no bootstrap exemption) |
| Identity spoofing: non-stepped-up bearer mints trusted-device grant | Spoofing | **No** | 403 — precedent gate holds (trusted_devices.go:66) | unchanged |
| Replay: consumed MFA challenge replayed at `/auth/mfa` | Repudiation/Replay | **No** | atomic `Consume` → 400 `mfa_invalid`, indistinguishable from all other failures | unchanged |
| Replay: WebAuthn finish session replayed | Replay | **No** | `sessions.Take` single-use; session-user binding enforced (webauthn.go:366–378) | unchanged |
| Replay: stolen `device_token` replayed at `/auth/login` | Replay | Yes — by design | skips risk-scorer step-up for its (user, client) only; verify is per-pair and fail-closed on store error | unchanged; documented residual (see §5) |
| Cross-tenant access: delete/read another tenant's factor | Elevation | **No path found** | ownership enforced via user-scoped store lists → uniform 404 (mfa.go:60–69, trusted_devices.go:126–134); bearer subject is the authorization root; token validation is tenant-bound at issuance | unchanged |
| Cross-tenant: device grant from tenant B skips tenant A login | Elevation | **No** | `TrustedDeviceStore.Verify(userID, clientID, token)` — client-scoped; a client belongs to one tenant | unchanged |
| Proxy/header forgery: XFF spoofing on `/me/mfa*` | Spoofing | No new surface | handlers consume IP only for `audit.ClientIP` (trusted-proxies-gated per AGENTS.md); no host/proto trust in these handlers; `resumeLoginAfterMFA` re-checks tenant + SCIM active in the verify window | unchanged |
| Resource exhaustion: cross-client MFA lockout DoS | DoS | **Yes** (Finding 2) | 5 wrong factors via one client lock the subject on all clients for 15 min, repeatable | per-(client, subject) key; blast radius = one client |
| Resource exhaustion: unbounded challenge issuance / push fatigue | DoS | Yes — **already covered** by `docs/architect-analysis-mfa-subsystem-review.md` (prior review) | challenge per successful primary leg, TTL-bounded; no per-subject issuance cap | out of scope here, tracked in prior review |
| Resource exhaustion: metric-label spray via `mfa_method` | DoS | **No** | `recordMFACompletion` bounds labels to `SupportedMethods()` (server_mfa.go) | unchanged |
| Sensitive-data leakage: recovery-code plaintext at rest / in audit | Info disclosure | **No** | hashed at rest; plaintext returned exactly once; audit records count only (`recordRecoveryCodesRegenerated`) | unchanged |
| Sensitive-data leakage: TOTP secret in audit/logs | Info disclosure | **No** | secret never logged/audited (recordTOTPEnroll* carry factor_id/reason only) | unchanged |
| Sensitive-data leakage: `GET /me/mfa` exposes factor secrets | Info disclosure | **No** | metadata only | unchanged |

---

## 4. Positive controls verified, residual risks, validation plan

### Positive controls verified (by direct code reading at 6c8fb33c)

1. **Oracle-safe factor verification** — `verifyMFAFactor` collapses unknown,
   expired, consumed, wrong-method, wrong-factor, and locked cases to the
   verbatim 400 `mfa_invalid`; the cause lives only in the `mfa_failure` /
   `mfa_locked` audit reasons (server_mfa.go:252–292). Finding 2's fix must
   preserve this.
2. **Atomic single-use consumption** — challenge `Consume` happens before any
   factor verification; replay of a consumed challenge is `mfa_invalid`
   (server_mfa.go:262).
3. **Credential endpoints set no-store** — `/auth/mfa` (`tokenNoStoreHeaders`)
   and every `/me/mfa*` / `/me/trusted-devices*` handler.
4. **Lockout namespace disjointness** — `"mfa lockout:"` prefix contains a
   space, which RFC 6749 client_id syntax cannot; password-leg keys can never
   collide (server_mfa.go:296–300). Preserve in the Finding 2 fix.
5. **Fail-open/fail-closed discipline** — risk scorer fails open (logged);
   trusted-device `Verify` fails closed (a store outage costs one MFA prompt,
   never a skipped control); conditional-access engine fails open on policy-
   store outage (server_login_client.go doc comments + code).
6. **Step-up state survives resume** — `resumeLoginAfterMFA` re-checks client
   activity, tenant, SCIM `active`, residency write-gate, email verification,
   and password expiry in the challenge-verify window (server_mfa.go:340+);
   `DeviceToken` is scrubbed from the persisted resume state
   (`persistMFAChallenge`).
7. **Cross-user and cross-client factor isolation** — delete/revoke use
   user-scoped lists with uniform 404; device grants verify per (user, client).
8. **Challenge entropy** — 32-byte `crypto/rand` ids (256 bits, server_mfa.go).
9. **WebAuthn ceremony binding** — finish requires the bearer subject to equal
   the begin session's user (webauthn.go:376), sessions are single-use, and
   the attestation-policy gate runs after go-webauthn verification and before
   persistence (webauthn.go:393–401).
10. **Break-glass attribution** — `stampBreakGlassActor` propagates
    impersonation context to every self-service audit event (server_me.go:62).

### Residual risks (accepted or out of scope)

- **`device_token` is bearer-equivalent.** Exfiltration of a live grant skips
  risk-scorer step-up for its (user, client) until TTL. By design; the grant is
  minted only from a stepped-up session, hashed at rest, never renewed, and
  scoped per (user, client). Consider revocation-on-compromise-signal parity
  with `RevokeTrustedDevicesOnCompromiseSignal` if that set ever grows.
- **Memory-backed lockout is per-replica.** `MemoryAccountLockout` forks per
  replica (documented in account_lockout.go); the MFA key inherits this. A
  shared backend is an operator requirement for multi-replica deployments;
  Finding 2's change does not alter this.
- **Finding 1's bootstrap exemption** (zero enrolled factors may enroll the
  first factor with a plain bearer) is required for first-time users, but note
  it means a stolen non-stepped-up token on a zero-factor account can still
  bind an attacker factor. That is the pre-existing password-only compromise
  state; the exemption does not worsen it, and deletion/regeneration stay gated
  unconditionally.
- **Refresh-rotation AMR preservation** — the step-up gate in Finding 1
  depends on `amr` surviving refresh rotation (AGENTS.md invariant: "Carry
  `FamilyID` through refresh rotation … preserve … refresh auth context").
  Invariant is documented; a positive cross-server assertion (step up, refresh,
  call `/me/mfa/totp/confirm`, expect 201) should pin it in the regression
  suite.

### Prioritized validation plan

| # | Item | Evidence | Gate |
|---|---|---|---|
| P0 | Finding 1 fix + cross-server regression (403 pre-step-up / 201 post; bootstrap exemption; docs) | `test/` + docs diff | `go test ./test/ -run TestE2E -v`, `make ci` |
| P1 | Finding 2 key change + `mfa_locked` doc row; update `test/mfa_test.go:803`; namespace-disjointness unit test | `interfaces/sso` + `shared/security` unit tests | `go test ./... -race`, `make ci` |
| P2 | Finding 3 docs rows + `trusted_device_overridden` audit marker + 3-scenario cross-server test | `test/` + docs diff | `make ci`, docscheck scan |
| P3 | Positive assertion: refresh rotation preserves `amr` (pins the Finding 1 gate's foundation) | `test/` | `go test ./test/ -run TestE2E -v` |

All changes are contract-respecting: wire responses remain byte-identical in
every proposed fix (403 `insufficient_user_authentication` reuses an already
documented error; `mfa_invalid` shape unchanged; `mfa_required` body unchanged
in Finding 3). No new oracle surfaces are introduced, and no secrets appear in
any example or audit payload.
