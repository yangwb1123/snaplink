# Security review: `domains/userlifecycle` production-hardening (durable store, leased sweep, persistent last-active)

Review of `docs/auto/domains-userlifecycle-prod-design.md` from the
security-engineering standpoint: privilege boundaries, oracle safety,
fail-open/fail-closed posture, credential lifecycle, anti-enumeration,
injection, sensitive-data handling, and the availability/identity-lifecycle
consequences of the sweep and the new activity signal. Advisory only; no files
modified. Evidence labels: **Verified** = source-inspected and/or commands run
at this revision, **Partial** = confirmed with a caveat, **Proposed** = design
intent not yet in code.

**Checks actually run at HEAD `0235cc47`:** `go build ./... && go vet ./...`
(clean), `go test ./domains/userlifecycle/... -count=1` (ok, 2 pkgs). Doc-only
revision — no `.go` edits, so the maintainability gates are unaffected.

The headline security conclusion, stated up front: **the design adds no new
request-facing attack surface** — every new seam (`SweepLeaser`,
`StaleEnumerator`, `ActivityRecorder`, the lease/cursor/last-active tables) is
in-process or SQL-parameterized, consumes only server-resolved identities and
server time, and changes no wire code. The security-relevant findings are
about what the *signal and the sweep do with identities* — three
wrong-deprovisioning paths (S1-S3, one of them a live stock path the design
claims covered), one silently-diverging backend selection (S4), and three
control-outage/hygiene gaps (S5-S7). None of these is a credential- or
oracle-safety regression.

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets in scope

| Asset | Store today → proposed | Security role |
|---|---|---|
| Lifecycle state + history (`user_lifecycle`, `user_lifecycle_history`) | `memory.Store` (per-process, lost on restart) → durable SQL | Governance metadata; **not an auth gate today** (`WithUserLifecycle` doc: "it NEVER gates authentication"; Verified: zero `userlifecycle` references in `server_login.go`/`server_mfa.go`/`server_finish_login.go`). Becomes a gate if direction-1 lands — the findings below are written for both regimes. |
| Last-active signal (`user_lifecycle_last_active`, Proposed) | `memory.ActivityTracker` (zero production writers) / `SessionLastActive` (session-derived) → durable SQL | The dormancy evidence base; feeds INACTIVE/ARCHIVED decisions |
| Sweep lease (`sweep_lease`, Proposed) | none → durable SQL | Cross-replica coordination of the sweep |
| User records (`core.User`) | `UserProvider` | Roster for the legacy sweep path; ghost guard on the cursor path |
| Admin lifecycle surface (`GET`/`POST /api/v1/admin/users/:id/lifecycle`) | unchanged (backend-swapped) | `admin:read`/`admin:write`; trusted |

### Trust boundaries

- **Untrusted**: `/auth/login` (all providers), federated `/callback`,
  `/webauthn/login/finish` (+ conditional), `/token`. The design inserts the
  Touch into `authenticateUser` (`server_login_auth.go:97-103`, after
  `rejectDeactivatedUser`) and `finalizeCallbackSession` (`server_oauth.go:212-233`,
  after the SCIM gate). Both anchors consume only **server-resolved**
  `result.UserID` and **server** `time.Now()` — Verified: no client-supplied
  user id, timestamp, header, or query value reaches the new seams. The lease
  holder is server-stamped (hostname+pid+nonce, Proposed); the cursor runs
  server-side.
- **Trusted**: admin API, composition root (`build_stores.go` wiring), the
  database (lease/last-active tables), config (`user_lifecycle.backend`).
- **New trust domain**: the durable store's SQL. All statements are
  parameterized (Proposed; the `(last_active, user_id) > ($1,$2)` row-value
  cursor and the `INSERT ... SELECT ... WHERE $from = 'active'` guard included),
  migrations are static + advisory-locked (`migrate.go` pattern, Verified in
  `infrastructure/postgres/invitation.go`). No string interpolation of any
  variable — no injection surface.

### Attacker capabilities considered

1. **Unauthenticated remote attacker** — can drive the Touch anchors only with
   a valid credential (failed auth never reaches the anchor: it sits after
   `rejectDeactivatedUser`, which is after `auth.Authenticate` succeeds).
   Cannot influence their own or any other user's signal beyond legitimate
   logins; cannot reach the lease, cursor, or tables (no wire surface).
2. **Primary-credential holder without the second factor** — the S1 scenario:
   can refresh the dormancy signal (and reset the account-lockout budget on
   the same path) without ever completing a session.
3. **Authenticated user** — no capability over the new surfaces; `userID` is
   always the server-resolved identity of their own login.
4. **Admin** — trusted; can delete users (creating the S3/S6 orphan and
   id-reuse conditions) and drive transitions.
5. **Database attacker** — out of scope (DB is a trust root).

### Entry points for the new behavior

| # | Site | Touch? | Security note |
|---|---|---|---|
| 1 | `authenticateUser` (`server_login_auth.go:97-103`) — all provider primaries at `/auth/login` | Yes (Proposed) | Fires **before MFA completes** — S1 |
| 2 | `finalizeCallbackSession` (`server_oauth.go:223`) — federated | Yes (Proposed) | Fires only after the SCIM gate passes; deprovisioned users never refresh the signal (positive) |
| 3 | MFA ceremony resume (`server_mfa.go:368` → `finishLoginWithDeviceTrust`) | No (transitively covered) | **Verified**: the primary login already Touched; replay is `finishLogin`, not `authenticateUser` — correct, no double-count |
| 4 | WebAuthn standalone ceremony (`cmd/sso-server/serverwebauthn/webauthn_handlers.go:122-158`, conditional at `:258-273`; mounted unconditionally with WebAuthn at `build_http.go:290`) | **No** | Mints tokens via `issueWebAuthnToken` (`webauthn.go:152`) with **no session created** — invisible to both the fallback and the durable signal — **S2** |
| 5 | Refresh grants (`token_refresh.go`, `TrackActivity` at `spi.go:150`) | No (deliberate) | Refresh-only users age — residual, documented in the design |

## 2. Findings

### S1 — High — The `authenticateUser` anchor counts incomplete MFA logins as activity: a stolen primary credential suppresses the dormancy control

- **Evidence (Verified)**: the anchor sits after `auth.Authenticate` succeeds
  and `rejectDeactivatedUser` returns false — i.e. after primary-factor
  validation, **before any second factor runs** (`server_login_auth.go:92-106`).
  The same point already calls `RegisterSuccess` ("A single legit login resets
  the brute-force budget (before risk evaluation)", `server_login_auth.go:104-106`).
  The session-derived signal the durable source replaces
  (`SessionLastActive` over session `CreatedAt`) only ever reflected
  *completed* logins. The design's reason for not also Touching at
  `finishLogin` — "harmless under monotonicity" (`prod-design.md` §3) — is
  true for the write, but the two anchors have **different semantics**: the
  anchor pair the spec mandates records "someone presented a valid primary
  credential", not "a session was minted".
- **Exploit preconditions**: attacker holds the primary credential of an
  MFA-protected account (password dumper, phishing of the password only) but
  not the second factor; `auto_deprovision` enabled; durable backend wired.
- **Exploit steps**: POST `/auth/login` with the stolen credential once per
  `dormant_after` window; each attempt validates the primary factor → Touch →
  the account's `last_active` stays fresh. Optionally abandon before MFA.
- **Impact**: the dormancy hygiene control — the mechanism that flags
  abandoned accounts for INACTIVE/ARCHIVED — is suppressed indefinitely for
  exactly the accounts with the strongest credential posture (MFA-protected).
  The same successful primary auth resets the per-credential lockout budget,
  so the attacker's probes also erode the account-lockout defense the login
  gate relies on. If direction-1's lifecycle gate ever lands, the attacker is
  additionally preserving the account's ACTIVE state. The signal now *masks*
  the attacker's presence: dormancy-based anomaly review will classify the
  account as healthy.
- **Remediation (recommended)**: keep the spec-mandated primary anchor (it is
  the only evidence for non-MFA primaries) but **add a second Touch at
  `finishLogin`** (the session-completion funnel for every interactive
  login — `server_finish_login.go`); monotonicity makes the primary anchor a
  strict lower bound and the completion anchor the authoritative value. At
  minimum, document in `docs/config-reference.md` the widened definition:
  "last active = successful primary authentication, not completed session"
  (the design already commits to updating that section).
- **Regression test**: conformance-level test with a recording
  `ActivityRecorder` stub: (a) primary auth success without MFA completion
  advances `LastActive` (pins the current semantics if kept), (b) a completed
  `finishLogin` writes a newer value that wins under monotonicity. Assert the
  documented definition matches the observed writes.

### S2 — High — The WebAuthn standalone ceremony is a live stock path invisible to both activity sources; the design's "ceremonies are covered transitively" claim is false

- **Evidence (Verified)**: `webauthnFinishLoginHandler`
  (`cmd/sso-server/serverwebauthn/webauthn_handlers.go:122-158`) and
  `webauthnFinishLoginConditionalHandler` (`:258-273`) authenticate via
  `deps.Helper.FinishLogin`/`FinishLoginConditional` and mint the token bundle
  via `issueWebAuthnToken` (`webauthn.go:152-216`) — access token, optional
  id_token and refresh_token. Neither calls `authenticateUser` nor
  `finalizeCallbackSession`, and **no session is created**, so the ceremony is
  invisible to `SessionLastActive` (today's fallback) and to the proposed
  durable Touch alike. The routes mount on the stock router whenever WebAuthn
  is enabled (`cmd/sso-server/build_http.go:290`). The design's transitive
  claim is **true only for the MFA-factor ceremony** (`server_mfa.go:368`
  replays `finishLogin` after a primary login that already Touched) and for
  `provider=webauthn` at `/auth/login` (funnels through `authenticateUser`).
- **Exploit preconditions**: an account that has *any* prior non-zero signal
  (a past password/federated login — the durable row never self-heals) whose
  user then switches to passkey-only ceremony logins; `auto_deprovision`
  enabled with `archive_after > 0`.
- **Exploit steps**: user logs in via `/webauthn/login/finish` (or the
  conditional autofill path) every day. No Touch fires; the stored
  `last_active` ages; the sweep evaluates the account against the stale value.
- **Impact**: an actively-used account is transitioned INACTIVE and then
  ARCHIVED while the user authenticates daily — the exact
  wrong-deprovisioning class dormancy must avoid. Today the damage is
  governance metadata + audit noise; with direction-1's gate it becomes
  lockout of active passkey users. The failure is silent (no error anywhere:
  the ceremony path simply has no seam).
- **Remediation**: add the ceremony mint as a **third anchor** — a Touch in
  `applyWebAuthnTokenIssuance` (or at the `FinishLogin` completion) inside
  `serverwebauthn`, or explicitly scope the standalone ceremony out of the
  signal's coverage in the design with the consequence stated. The design's
  "must be regression-tested" note covers future routes, not this existing one.
- **Regression test**: a recording-`ActivityRecorder` test (or `test/` E2E
  with WebAuthn enabled): complete a ceremony login, assert
  `LastActive(userID)` equals the assertion time after the fix; pre-fix,
  assert the documented scoping instead.

### S3 — Medium — User-id reuse after deletion: a fresh account inherits stale governance state, stale signal, and the prior account's history; the ghost guard passes

- **Evidence (Verified)**: no delete path touches the lifecycle or last-active
  tables (grep: no cascade, no cleanup — the design declares deletion-time
  cleanup a non-goal); the ghost guard only checks `Users.GetByID` presence
  (`prod-design.md` §2), which a **re-created** user satisfies. User
  re-creation is a designed flow: `finalizeCallbackSession` upserts via
  `CreateOrUpdate` (`server_oauth.go:228`), and SCIM provisioning can reuse an
  id after deletion. With the memory store, restart implicitly cleaned the
  poison; the SQL peer preserves it **permanently** (the DS review's F-DS-3,
  confirmed independently here).
- **Exploit preconditions**: admin or SCIM deletes a user; the same id is
  provisioned again (federated login or SCIM re-import) without an admin
  lifecycle transition.
- **Exploit steps**: the re-created account's `Get` returns the inherited
  record (possibly INACTIVE/ARCHIVED with the old history) and the inherited
  stale `last_active`; the sweep's next tick evaluates the fresh account
  against the old signal and ARCHIVEs it within one tick.
- **Impact**: (a) availability — a freshly provisioned account is
  deprovisioned silently; (b) **governance-information leakage across account
  generations** — the new account's admin lifecycle GET (`HandleAdminGetUserLifecycle`,
  `interfaces/admin/lifecycle.go:26-50`) exposes the previous tenant's
  transition history, including admin `reason` free-text and `actor` ids; (c)
  if direction-1's gate lands, instant lockout of new accounts. The epoch
  guard suggested by the DS review (skip when `user.UpdatedAt >
  record.UpdatedAt`) is O(1), reuses the `GetByID` the ghost guard already
  performs, and closes all three effects.
- **Remediation**: implement the epoch guard in `sweepUser`, or deletion-time
  cleanup of the three tables on the user-deletion path(s); at minimum declare
  id-reuse-after-deletion unsupported in `docs/config-reference.md`.
- **Regression test**: seed INACTIVE + old `last_active` for id X, delete,
  re-create with a fresh `UpdatedAt`, run `SweepOnce` on both backends →
  assert no transition; assert the re-created account's `Get` returns no
  inherited history post-cleanup (or documents the residual).

### S4 — Medium — `haCoherenceIssues` does not cover the lifecycle backend: multi-replica with `memory`/`sqlite` diverges silently, the exact failure the spec §1 says is "worse than a missing feature"

- **Evidence (Verified)**: `haCoherenceIssues` (`cmd/sso-server/build_stores.go:99-125`)
  checks oauth, sessions, JTI-replay, CIBA, identity, MFA, identity-link, and
  pairwise backends — **no lifecycle entry**. The design's durable backend
  eliminates divergence only for `backend: postgres`; `""`/`memory` (the zero
  value) and `sqlite` (single-file, single-node — the DS review's declared
  topology) remain per-pod with no boot-time detection. The design proposes
  `user_lifecycle.backend` as a new config key without adding the
  corresponding coherence check.
- **Exploit preconditions**: `topology.mode: multi` + `user_lifecycle.enabled`
  with backend `""`, `memory`, or `sqlite` — all currently permitted and
  currently booting clean.
- **Exploit steps**: none required — deployment-time misconfiguration; replica
  B's admin API and sweep read a different state than replica A's.
- **Impact**: an admin suspension or the sweep's INACTIVE/ARCHIVED applied on
  replica A is invisible on replica B; sweep fights return (bounded by CAS,
  but nondeterministic winners); with direction-1's gate, the divergence
  becomes a login-gate divergence (suspension enforced on one replica only).
- **Remediation**: add `{multi && cfg.UserLifecycle.Enabled,
  "user_lifecycle.backend", cfg.UserLifecycle.Backend}` to `haCoherenceIssues`
  (`perPodBackend("")`/`("memory")` already return true; extend `perPodBackend`
  or inline `sqlite` as per-pod), refusing or warning on multi-replica +
  non-postgres, mirroring the existing entries.
- **Regression test**: unit on `haCoherenceIssues` — multi + `enabled` +
  backend `""`/`memory`/`sqlite` produces an issue; multi + `postgres` does
  not; wiring test asserting the boot error in the refused case.

### S5 — Medium — The dormancy cutoff is cross-replica clock-sensitive and ARCHIVED does not self-heal; "never wrong-deprovisioning" is an overclaim, and `StateInactive`'s "reversible on next login" doc is false

- **Evidence (Verified)**: the correctness-sensitive comparison is
  `now(sweeper) − last_active(writer) > DormantAfter` (`dormancy.go:34`); with
  the durable store the writer and the decider are different processes for the
  first time. Login performs **no lifecycle writes at all** — zero
  `userlifecycle` references in `server_login.go`, `server_mfa.go`,
  `server_finish_login.go` (grep) — so neither INACTIVE nor ARCHIVED is
  reactivated by activity; `INACTIVE→ACTIVE` exists only as a legal
  admin/transition-table edge (`transitions.go:17-27`), and `nextState`
  (`sweep.go:64-77`) never produces it. `StateInactive`'s doc comment
  ("Reversible back to ACTIVE (e.g. on next login)", `userlifecycle.go:41`)
  describes a behavior no code implements — the durable Touch makes that gap
  observable (the DB review's F-DB-2, confirmed).
- **Exploit preconditions**: NTP failure or VM-snapshot resume on the sweeping
  replica, or writer-replica clock behind the sweeper by δ; thresholds
  configured tight relative to δ.
- **Impact**: premature INACTIVE at `DormantAfter − δ` and premature ARCHIVED
  at `DormantAfter + ArchiveAfter − δ`; ARCHIVED requires manual admin
  restoration. Bounded by the repo's clock convention (skew ≪ threshold), but
  the design's blanket "fail-safe, never wrong-deprovisioning" is not earned.
- **Remediation**: (a) state the operating constraint in
  `docs/config-reference.md` (`dormant_after`/`archive_after` ≫ max expected
  inter-replica skew); (b) qualify the design's claim; (c) fix the
  `StateInactive` doc to say admin-reversible only; (d) consider reactivating
  INACTIVE→ACTIVE on a fresh Touch at `finishLogin` (a fail-safe-direction
  transition, audited like the sweep's) as a follow-up knob — the durable
  signal finally makes it implementable.
- **Regression test**: injectable `Now` on store and sweep; writer clock
  behind sweeper by δ → assert the transition fires at `DormantAfter − δ` and
  the margin requirement is pinned in the test comment.

### S6 — Medium — Cursor no-op prefix: stale non-actionable users starve the actionable set; the deprovisioning control stops silently in the default configuration

- **Evidence (Verified)**: `nextState` acts only on ACTIVE-dormant and
  INACTIVE-past-archive (`sweep.go:64-77`); SUSPENDED, ARCHIVED, PURGED, and
  INVITED users are never acted on, keep their last-active rows forever (no
  cascade), and — because the keyset orders `(last_active, user_id)`
  ascending — occupy every page ahead of more-recently-dormant ACTIVE users.
  INACTIVE with `ArchiveAfter=0` (the default posture) is a permanent no-op
  row of the same kind, and deleted users' orphans (S3) join the prefix. With
  page size = `MaxPerSweep` and no persisted cursor, a page full of no-ops is
  reprocessed every tick and actionable users behind it are never reached —
  a regression the legacy roster walk does not have (QA review F2, confirmed).
- **Exploit preconditions**: any deployment with ≥ `MaxPerSweep` users in
  non-actionable states who do not log in (suspended/archived accounts are
  exactly that population).
- **Impact**: dormant ACTIVE accounts are never INACTIVEd/ARCHIVEd — the
  hygiene control silently stops; the spec's O(k) acceptance fails in the
  default regime. No wrong transitions, but the control the feature exists to
  provide is disabled by ordinary account mix.
- **Remediation**: skip-advance past non-actionable states in the cursor loop
  or add a SQL-side state filter to `ListStaleAfter` (the design's own
  `(last_active, user_id)` index makes a state-join filter cheap); add the
  same shape to the O(k) acceptance fixture.
- **Regression test**: fixed clock; users `s1,s2` SUSPENDED with
  `last_active = now−90d`, `u` ACTIVE with `last_active = now−40d`,
  `DormantAfter=30d`, `MaxPerSweep=2`, `ArchiveAfter=0` → after `SweepOnce`,
  `u` is INACTIVE (no-op rows must not consume the actionable budget).

### S7 — Low — A lost lease is silent: a security-control outage is indistinguishable from "no work"

- **Evidence (Verified)**: the design's `SweepOnce` returns `(0, nil)` on a
  lost lease; `RunUserAutoDeprovision` logs only on error
  (`options_admin.go:331-333`). If lease acquisition keeps losing (e.g. a
  stuck holder, misconfigured TTL), the deprovisioning control stops with no
  log line. (The schema defect behind *why* a lease can be lost — the
  holder-PK table excluding no distinct holder — is F-DS-1 in the DS review;
  this finding is about observability of the control.)
- **Impact**: dormancy deprovisioning (a security-hygiene control) silently
  disabled; operators cannot distinguish "nothing dormant" from "control
  down".
- **Remediation**: log the lost lease via `d.Logger` (already in `SweepDeps`)
  before returning, and document the acquire-error-vs-lost-lease distinction
  in the `SweepLeaser` interface doc.
- **Regression test**: race test asserts the losing holder logged a
  lost-lease line (memory sink).

### S8 — Low — Durable history makes admin free-text reasons and actor ids permanent with no retention knob; the admin `reason` field has no length cap

- **Evidence (Verified)**: `lifecycleTransitionRequest.Reason`
  (`interfaces/admin/lifecycle.go:21-24`) is passed through `strings.TrimSpace`
  only (`:79`), with no length bound; the durable `user_lifecycle_history`
  stores it forever (the design flags unbounded *growth*; the *content*
  retention is the security note). Memory self-healed on restart; the SQL peer
  does not. Reasons are admin-supplied (trusted surface), and history is read
  only by `admin:read` — no wire leak — but retained investigation notes and
  actor ids are exactly the data a compliance/retention policy would bound.
- **Impact**: bounded; long-term storage growth from unbounded reasons, and
  permanent retention of governance free-text.
- **Remediation**: add a reason length cap at the admin handler (cheap,
  mirrors other admin free-text fields) and note a future retention/redaction
  knob next to the design's unbounded-history flag.
- **Regression test**: admin transition with an over-long reason → 400
  `invalid_request` (or documented truncation).

### S9 — Low — `StaleEnumerator`/`LastActive` agreement and the dual `MaxPerSweep` semantics are undocumented invariants

- **Evidence (Verified)**: `StaleEnumerator` is an optional `LastActiveSource`
  extension; a custom SDK source could enumerate a different set than its own
  `LastActive` reports, silently blinding the sweep to genuinely-dormant users
  (the cursor is only a valid candidate set if the two agree). `MaxPerSweep`
  bounds scanned candidates on the cursor path and applied transitions on the
  legacy path — one knob, two semantics, selected by which source is wired
  (DS review F-DS-6, confirmed).
- **Impact**: a custom activity source can silently disable deprovisioning for
  a subset of users; an operator tuning the storm guard gets different
  behavior per backend wiring.
- **Remediation**: state both invariants in the interface docs ("the cursor
  MUST enumerate exactly the users whose `LastActive` returns a value older
  than cutoff"; "`MaxPerSweep` caps scanned candidates on the cursor path,
  applied transitions on the legacy path").
- **Regression test**: conformance case with a deliberately-divergent fake
  source asserting the sweep still evaluates the divergent user (or documents
  the requirement).

### S10 — Info — Lease and cursor are pure in-process coordination: no privilege boundary, no attacker surface

- **Evidence (Verified/Proposed)**: `SweepLeaser` acquire/release take a
  server-stamped holder; release is holder-scoped (post-F-DS-1-fix); no HTTP
  or config surface reaches the lease. `TouchAt`'s `userID` and `at` are
  server-resolved; a zero/empty-ID guard is required on the SQL peer to match
  memory (`memory.go:124-126`) — QA F4 covers the parity, this review only
  notes that no attacker can reach the method to exploit its absence. The
  sweep's transitions are audited via the existing
  `EventAdminUserLifecycleChanged` with `ActorSystem` (`sweep.go`), bounded
  cardinality, no new event type, no `auditreport` classification change.

## 3. Abuse-case table

| Case | Path | Verdict | Notes |
|---|---|---|---|
| Identity spoofing: attacker submits another user's id to Touch/lease/cursor | All new seams consume server-resolved `result.UserID`, server-stamped holders, server time | **Not exploitable (Verified)** | No client-controlled id, timestamp, header, or query reaches any new surface; the admin API's `:id` is unchanged and admin-only |
| Replay: duplicated login POST | `TouchAt` monotone upsert (memory `memory.go:119-126`, Proposed SQL) | **Safe** | Stale writes are no-ops; no read-then-write; no regression |
| Replay: stolen primary credential, MFA never completed | `authenticateUser` anchor fires pre-MFA (`server_login_auth.go:92-106`) | **Reachable** | **S1** — attacker suppresses the dormancy signal and resets the per-credential lockout budget; dormancy sees "healthy account" |
| Replay: passkey-ceremony login by an active user | `/webauthn/login/finish` (+ conditional) mints tokens, no session, no anchor (`webauthn_handlers.go:122,258`; `webauthn.go:152`) | **Reachable — wrong-deprovisioning** | **S2** — account with any prior signal ages into INACTIVE/ARCHIVED while the user authenticates daily; design's transitive-coverage claim false |
| Replay: refresh-token-only usage | Refresh grants never Touch (deliberate, `spi.go:150` is session-scoped) | **Accepted residual** | Refresh-only/machine users age into dormancy; documented in the design; availability note for CLI/API clients |
| Cross-tenant access | No tenant dimension anywhere in the design; users are global subjects; new tables keyed by user_id only | **Not applicable** | Same model as the existing admin surface; no new cross-tenant read/write |
| Proxy/header forgery | No new header, XFF, forwarded, mTLS, or mesh-trust consumer | **Not applicable** | All new behavior is in-process/SQL; no `security.trusted_proxies` interaction |
| Resource exhaustion: sweep work grows with deleted users | Orphan rows re-listed every tick; cursor path = O(k + orphans) with one `GetByID` per candidate | **Reachable, bounded** | **S3/S6** — every tick re-reads the orphan prefix; no page-count growth per tick, but work no longer tracks the live roster; needs the epoch guard / cleanup |
| Resource exhaustion: unbounded history/reason | `reason` uncapped (`lifecycle.go:21-24,79`); history appends forever | **Reachable (admin-trusted)** | **S8** — durable retention + unbounded admin free-text; Low (trusted surface) |
| Resource exhaustion: hot-path latency | One PK upsert per login, synchronous, fail-open, no retry | **Bounded** | Login never blocks on Touch errors; a down DB adds at most one failed round-trip |
| Resource exhaustion: mass sweep in one tick | `MaxPerSweep=0` = unlimited applied transitions (legacy semantics) | **Pre-existing** | Storm guard unchanged on the legacy path; cursor path now also caps scanned |
| Sensitive-data leakage: history across account generations | Re-created id inherits prior history incl. reasons/actors (`Get` at `memory.go`/Proposed SQL) | **Reachable** | **S3b** — governance-information leakage; epoch guard or deletion cleanup required |
| Sensitive-data leakage: wire/logs | New errors reuse `ErrStateConflict`→409 `lifecycle_state_conflict`; store errors → 500 on the trusted admin surface; sweep logs user_ids only | **None found** | No new error codes, no credentials anywhere; oracle-safe shapes unchanged |
| Oracle: unknown vs conflict on the admin transition | `ErrStateConflict` → 409 vs `ErrNotFound` → 404 (unknown user, checked first, `lifecycle.go:59-63`) | **Preserved** | Durable backend maps through the same sentinels; byte-identical wire codes |
| TOCTOU: admin transition vs sweep on the same user | CAS `Append` (memory mutex / SQL conditional upsert) | **Safe (Proposed)** | Loser gets 409 (admin) or skip-and-log (sweep); exactly one applies |
| Availability: sweep control silently off | Lost lease `(0, nil)`; no-op cursor prefix; orphan prefix | **Reachable** | **S6/S7** — three independent ways the control stops with no signal |

## 4. Positive controls verified, residual risks, prioritized validation plan

### Positive controls verified (this revision)

1. **No new request-facing surface** — every new seam is in-process or SQL;
   no headers, query params, body fields, bearer endpoints, or proxy-trust
   consumers; SSRF/mTLS/XFF surfaces untouched (Verified: the design adds no
   HTTP handler; the admin endpoints are backend-swapped only).
2. **Oracle safety preserved** — the durable backend maps through the existing
   sentinels: `ErrStateConflict` → 409 `lifecycle_state_conflict`
   (`docs/error-codes.md`), unknown user → 404 checked before the store read
   (`interfaces/admin/lifecycle.go:59-63`), store outage → 500 on the trusted
   admin surface only. No new wire codes, no new event types, no
   `auditreport` classification change.
3. **Fail-open/fail-closed boundary matches AGENTS.md** — Touch write errors
   are logged and never block login (fail-open, in the documented list);
   state CAS and boot-on-unreachable-backend are fail-closed; sweep per-user
   errors skip-and-log. The design's placement — Touch after the SCIM gates —
   means deprovisioned users never refresh their own signal (Verified at both
   anchors).
4. **The sweep cannot grant privileges** — `nextState` returns only INACTIVE
   and ARCHIVED (`sweep.go:64-77`); no sweep edge targets ACTIVE, SUSPENDED,
   or PURGED; every transition is audited with `ActorSystem`. No escalation
   path exists or is proposed.
5. **No-record = ACTIVE and zero-value-OFF anchors hold** — resolution 3's
   separate last-active table is load-bearing: `Touch` never creates a
   lifecycle row, `Get`/`ListByState` observations are unchanged for
   logging-in users, and `ListByState`-based enumeration (rejected in
   resolution 2) would have silently stopped deprovisioning implicit-ACTIVE
   users — the correction is confirmed against
   `userlifecycle.go:143-147` + `memory.go:57-75` + `sweep.go:44-62`.
6. **Injection resistance** — all proposed SQL is parameterized (conditional
   upserts, row-value cursor, `$from` guard); migrations are static and
   advisory-locked (`infrastructure/postgres/migrate.go` pattern). No string
   interpolation of any variable.
7. **Identity binding** — `TouchAt` user ids are server-resolved
   (`result.UserID`/`AuthResult.UserID`); the lease holder is server-stamped;
   the cursor consumes server-side state. No anti-enumeration surface is
   introduced (the sweep's `GetByID` ghost guard is in-process).

### Residual risks (accepted or requiring a design amendment)

- **S1/S2 wrong-deprovisioning and signal-suppression paths** — S1 is
  spec-mandated (document the widened definition; consider the `finishLogin`
  anchor); S2 contradicts a design claim and needs a third anchor or an
  explicit scope-out.
- **S3 id-reuse poisoning** — requires the epoch guard or deletion cleanup;
  the design's "ghost guard" name overstates its contract (covers deleted,
  not re-created, users).
- **S4 sqlite/memory divergence in multi-replica** — needs the
  `haCoherenceIssues` entry; the durable fix only covers postgres.
- **S5 clock-skew margin** — must be stated as an operating constraint;
  ARCHIVED remains admin-reversible only; `StateInactive` doc needs the
  correction.
- **S6 no-op cursor prefix** — the design's O(k) claim holds only with the
  state filter/skip-advance.
- Refresh-only and ceremony-only users age into dormancy (deliberate, now
  documented); lifecycle state remains metadata-only today (direction-1 gate
  not landed), which bounds the impact of S1-S3 until it lands.

### Prioritized validation plan

1. **Before coding (design amendments)**: S2 third anchor or explicit
   scope-out; S3 epoch guard decision; S4 coherence-check entry; S6 state
   filter; S5 doc corrections (`StateInactive`, skew margin); S7 lost-lease
   log; S8 reason cap. The F-DS-1 singleton-key lease fix from the DS review
   is a prerequisite for decision 2's own acceptance test.
2. **Per-change gates**: `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .` after every edit
   (per AGENTS.md §2).
3. **Unit/conformance**: `userlifecycletest` lease case (two holders, exactly
   one acquire — memory + SQLite, per F-DS-1); `TouchAt` empty-ID/zero-time
   parity (QA F4); `haCoherenceIssues` lifecycle entry (S4); cursor no-op
   prefix + O(k) with unrecorded dormant users (S6); epoch-guard delete/
   re-create (S3); reason-length cap (S8).
4. **Integration (`package ssotest`)**: recording-`ActivityRecorder` stub on
   `authenticateUser`, `finalizeCallbackSession`, **and the WebAuthn ceremony
   mint** (S2); MFA-incomplete login → Touch semantics pinned (S1);
   failure-injection (Touch error → login succeeds); refresh-only user ages
   (documented residual).
5. **Full handoff**: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
   `make ci`, plus the DSN-gated Postgres/Cockroach conformance arms in a
   manual run (per the QA review's CI-gap note).
6. **Contract updates in the same change** (AGENTS.md §5.6):
   `docs/config-reference.md` backend naming, activity-source definition
   (primary-auth vs completed-session), skew margin, and removal of the "no
   other activity backend exists" caveat; `StateInactive` doc fix;
   `docs/error-codes.md` untouched (no new codes).

**Bottom line**: the design is sound on the surfaces that matter most to a
security review — no new request input, oracle-safe errors, a clean
fail-open/fail-closed boundary, injection-resistant SQL, and a sweep that can
never grant privileges. The security-critical gaps are the three identity/
availability paths — the pre-MFA Touch semantics (S1), the live WebAuthn
ceremony the design wrongly claims is covered (S2, High), and user-id-reuse
poisoning (S3) — plus the unguarded sqlite/memory divergence (S4) and the
silent control-outage modes (S6/S7). None blocks the durable-store decision
(1) or the last-active table (3) as designed; decision 2 needs the singleton
lease fix (DS F-DS-1), the S6 state filter, and the S2 anchor decision before
it can claim its stated guarantees.
