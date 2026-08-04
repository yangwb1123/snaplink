# domains/userlifecycle — 方向 1 设计 QA 评审（risk-based test review）

Review of `docs/auto/domains-userlifecycle-direction1-design.md` at stage
"design". The implementation has **not** landed (Verified: no
`AllowsAuthentication`, no `rejectLifecycleBlockedUser`, no
`LifecycleState` on `RefreshGrantDeps`, no `RevokeAccessOnSuspend`, no bus
wiring in `wireUserLifecycle` anywhere in non-test Go). This review therefore
validates the design's evidence against the working tree, maps every spec
acceptance to an existing or required test, measures the baseline the change
will build on, and pressures the proposed test plan (Decision 7) for gaps.
All commands below ran for this revision; no result is inherited from
documentation.

## 1. Test inventory and commands actually run

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | full module |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | budget/architecture gates (0.142s) |
| `go test ./domains/userlifecycle/... ./protocols/lifecyclereactions/... ./internal/handler/tokengrant/... -cover -count=1` | PASS | coverage below |
| `go test -race` on the same 4 packages | PASS | — |
| `go test ./cmd/sso-server/ -run 'UserLifecycle|Lifecycle' -cover -count=1` | PASS | wiring tests, 21.7% |
| `go test ./interfaces/sso/ -run 'TestRcovAdmin_UserLifecycle' -count=1` | PASS | 2 tests (0.08s each) |
| `go test ./test/ -run 'TestRefreshFamily_\|TestRefreshGrace_\|TestRefreshToken_\|TestPerClientRefreshTTL_\|TestRefreshAbsoluteMaxLifetime_\|TestRotationVelocity_' -count=1 -v` | PASS | 19 E2E tests, 0.152s |

Coverage (line coverage only; behavioral adequacy argued in §3):

| Package | Coverage | Comment |
|---|---|---|
| `domains/userlifecycle` | 82.3% | state machine + bus + sweep |
| `domains/userlifecycle/memory` | 95.8% | — |
| `protocols/lifecyclereactions` | 74.2% | archive reaction; suspend twin is new code |
| `internal/handler/tokengrant` | **9.1%** | refresh logic is exercised almost entirely from `test/` E2E; the new unit test (F4) is the only unit-level protection for the gate |

`make ci`, `make config-validate-all`, chaos/load/bench/conformance suites:
**not run** — design stage, no `.go` edits; exit criteria (§5) require them at
implementation.

### Design-claim verification (independent re-check)

Every anchor the design's Decisions 1–7 rest on was re-verified:

- **Five enforcement points**: 4 `rejectDeactivatedUser` call sites
  (`server_login_auth.go:98`, `server_mfa.go:359`, `server_mfa_trust.go:256`)
  plus the inline SCIM check at `server_oauth.go:221` inside
  `finalizeCallbackSession` (401 `ErrCallbackFailed`, logs only, no audit
  event). Verified.
- **Line budgets**: `server_login_auth.go` 493, `server_mfa.go` 471,
  `server_mfa_trust.go` 491, `server_oauth.go` 495, `server_login_resolve.go`
  413, `options_admin.go` 474, `token_refresh.go` 431; `interfaces/sso`
  has exactly **60 non-test files** (frozen ceiling). Verified — the
  device-context move is mandatory, not cosmetic.
- **Refresh flow order**: `Consume` (first statement) → `refreshBindGuard` →
  `refreshEnforceAbsoluteMaxLifetime` → `refreshCheckSessionLiveness`
  (fail-closed on store error, per its doc) → `refreshResolveGrant` →
  `EnforceRefreshDepthPolicy` → `refreshVelocityGate` (side effect:
  `RecordRotation`) → `refreshIssueAndRotate`. The proposed gate slot
  (after liveness, before resolve) is after Consume and before every side
  effect. Verified.
- **Store contract**: `memory.Store.Get` returns `{State: DefaultState}`
  for no record, never an error; `Store` interface is 3 methods
  (Get/Append/ListByState) — a failing-store test double is small. Verified.
- **Bus**: `LifecycleEventBus.On/OnAsync`, `OnUserSuspended`,
  `OnUserArchived`, `Record` filters on `EventAdminUserLifecycleChanged`;
  `audit.Recorder.AddSink` exists (wiring-time-only per its doc,
  `recorder.go:100,131`); `RecordTransition` emits the event with
  `MetaTargetUser/MetaFromState/MetaToState` (`sweep.go:171-173`). Verified.
- **Audit events**: `audit.RecordLoginFailure`/`RecordCallbackFailure` take
  no meta today (variadic extension is backward-compatible);
  `recordLoginFailure` bumps `LoginAttemptsTotal`, dispatches anomaly, and
  records tenant attempt (`server_helpers.go:282-294`). Verified.
- **`account_locked` drift**: `docs/error-codes.md:139` documents 423; all
  code sites write 403. Verified — the design must pin 403.
- **Stale "NEVER gates authentication" docs**: `options_admin.go:277`,
  `docs/config-reference.md:695` ("GOVERNANCE metadata only — it NEVER gates
  authentication"), `domains/userlifecycle` package doc. All three verified
  present.
- **No `ChainStore` in the composition root**: only
  `interfaces/admin/lifecycle.go:109` takes one; nothing wires it. The
  dropped chain leg is justified. Verified.
- **`OnUserSuspended` zero production callers**: only `bus_test.go`. Verified.
- **Test doubles for `RefreshGrantDeps`**: none exist in `*_test.go` — the
  interface addition breaks nothing today, but the design's grep-before-commit
  advice is correct (any future double is compile-enforced).
- **Existing SCIM byte-compare fixture**: `TestCallback_DeprovisionedUserBlocked`
  (`test/handle_callback_test.go:181`) drives a deactivated SCIM user through
  the federated callback — the 401 `callback_failed` comparison target exists.
- **Grace cache**: `WithRefreshRotationGrace(window)` is opt-in
  (`options_security.go:341`), off by default — relevant to F1.

## 2. Requirement-to-test matrix

| # | Requirement (from spec/design) | Existing test | Planned (D7) | Status |
|---|---|---|---|---|
| R1 | Login gate denies non-ACTIVE at all five sites; ACTIVE/no-record/nil-store allowed | none (lifecycle store never on login path today) | D1 table + per-site variants | **Missing → planned**; harnesses verified extendable |
| R2 | Denials oracle-safe, byte-identical to each site's SCIM denial (403 `account_locked` / 401 `callback_failed`); state only in audit | `TestCallback_DeprovisionedUserBlocked` (SCIM side only) | D1 byte-compare vs SCIM path | **Partial** — comparison target exists; lifecycle side to be added |
| R3 | Login gate fail-closed on store read error, audit meta present-but-empty, indistinguishable on wire | none; `memory.Store.Get` never errors | D1 store-error injection | **Missing → planned**; needs a failing `Store` double (F2) |
| R4 | Refresh gate denies non-ACTIVE with byte-identical `invalid_grant`, after Consume, before any side effect | `TestRefreshToken_ExchangeUnknownToken` is the byte anchor; 19 refresh E2E tests green | D2 E2E + unit placement test | **Partial** — anchor and regression net exist |
| R5 | Refresh gate fail-closed on error; no-record/nil-store = byte-identical no-op | `TestRefreshToken_LoginOmitsRefreshTokenWhenStoreUnwired` (unwired baseline) | D2 nil-store + ACTIVE-user byte-identical | **Partial** — nil-store variant must be explicit (F8) |
| R6 | SUSPENDED/ARCHIVED transitions revoke sessions + refresh tokens synchronously, idempotently, best-effort | `revoke_on_archive_test.go` (6 tests: legs, bus E2E, non-matching state, nil legs, empty userID); `bus_test.go` (9 tests: sync/async, error handler, panic containment) | D3 E2E + `RevokeAccessOnSuspend` unit tests | **Partial** — archive twin covered; suspend twin is new |
| R7 | Wiring: no new `sso.Option`; opts-count tests stay green; bus via `recorder.AddSink`; audit-disabled warning | `userlifecycle_wiring_test.go` asserts `len(b.opts) ∈ {0,1,2}`; `TestRcovAdmin_UserLifecycle{,_DefaultOff}` | extend wiring test for bus + warning path | **Partial** — assertions exist and pin the no-new-option constraint |
| R8 | Docs reconciled in same change: 3× "NEVER gates", `account_locked` 423→403, fail-closed outage note in config-reference | doc/code drift checkers in `make ci` (not run this revision) | contract update in change | **Missing** — pre-existing drift verified real |
| R9 | Budgets: no `interfaces/sso` file > 500 lines, no new files, device-context move lands | `TestMaintainability_*` (PASS this revision) | re-run after move | **Gate** — the move's size is the risk (Decision 6.1) |
| R10 | Existing refresh semantics unchanged for healthy users (byte-identical regression) | 19 refresh E2E tests (family, grace, velocity, max-lifetime, TTL) | re-run + gate-wired ACTIVE user | **Partial** — the net exists; the gate-wired variant is the new pin |
| R11 | Denial consumes the token; retry kills the family (grace interaction) | `TestRefreshFamily_ReusedTokenKillsFamily`, `TestRefreshGrace_DoubleSubmitReturnsSameSuccessor` | D2 single-vs-double attempt choreography | **Partial** — interaction with the gate unwired today (F7) |
| R12 | INVITED denied; invitation flow must advance INVITED→ACTIVE before first login | none (no production INVITED writer) | predicate table test; seed store directly | **Missing → planned**; fixture note: seed via `Append(StateNone→StateInvited)` |
| R13 | Residual auth-code-exchange gap documented (no per-subject `AuthCodeStore` SPI) | n/a (no behavior change) | documentation | **Documentation** — no test possible without new SPI; design accepts |
| R14 | Multi-replica divergence documented; refresh gate narrows blast radius | n/a | documentation | **Documentation** |

## 3. Findings

### F1 — Medium: "reactivation restores rotation for a surviving family" (D2 acceptance) is not directly constructible E2E

**Evidence**: The gate runs after `Consume` (verified order, §1), so a denied
presentation destroys the presented token. The family model is one login =
one family, one live token at a time — rotation consumes the parent
(`TestRefreshFamily_RotationKeepsSameFamilyID`, `TestRefreshToken_SingleUseRotationEnforced`
both green). After one denial, the family has **zero live tokens**, so
"reactivate → rotate again" has nothing to present. The grace cache only
replays successors of *rotated* tokens (`refresh_grace.go`); a denied token
was never rotated, so re-presentation hits the reuse path and kills the
family. An E2E re-presentation of the pre-rotation token within a grace
window (the only E2E variant that works) short-circuits **before** the gate
(via `refreshHandleConsumeError`), so it proves family survival, not that the
gate re-allows rotation.

**Exact test to add** (unit level): new `internal/handler/tokengrant/token_refresh_test.go`
with a `RefreshGrantDeps` double (compile-enforced to add `LifecycleState`)
over a fake `RefreshTokenStore` seeded with **two live tokens sharing one
FamilyID** for user U.

1. `LifecycleState` returns SUSPENDED → `HandleRefreshGrant` with token A →
   assert 400 `invalid_grant`, body byte-equal to `core.ErrorBody(core.ErrInvalidGrant)`,
   token A consumed, token B untouched, family not deleted.
2. `LifecycleState` flips to ACTIVE → `HandleRefreshGrant` with token B →
   assert 200 + rotation issued (family preserved).

**Acceptance assertion**: a gate denial never deletes a family by itself
(no bus wired), and the same gate allows rotation once the state is ACTIVE —
proving the gate is a per-request predicate, not a family destructor.

### F2 — Medium: fail-closed store-error tests need a fixture the plan doesn't name

**Evidence**: `memory.Store.Get` can never error (`memory/memory.go:34`), so
the D1/D2 "store-error injection → deny" acceptances require a test double.
The `userlifecycle.Store` interface is 3 methods (Get/Append/ListByState) —
small, but it must exist in both `test/` (E2E) and `tokengrant` (unit)
fixture sets.

**Exact test to add**: a `failingLifecycleStore` returning a sentinel error
from `Get`. Login variant: valid credentials + failing store → 403
`account_locked`, body byte-identical to the SCIM denial, audit
`login_failure` with `Reason=account_locked` and **`Metadata["lifecycle.state"]`
present-but-empty** (pins oracle-indistinguishability of outage vs
suspension). Refresh variant: failing store → 400 `invalid_grant`,
byte-identical to unknown-token.

**Acceptance assertion**: wire bytes of the outage denial equal the
suspension denial byte-for-byte; the only differentiator is the fail-closed
log line (assert it is emitted) — the design's Decision 5 promise made
testable.

### F3 — Low: the federated-site audit delta is a design intent that needs pinning

**Evidence**: `finalizeCallbackSession`'s SCIM leg logs and returns 401
without an audit event; the lifecycle leg adds `recordCallbackFailure`
(design §1.2 site 4). Wire-identical, audit-divergent — intentional, but
untested intent.

**Exact test to add**: extend `handle_callback_test.go`'s harness
(already wires `WithUserProvider`, `TestCallback_DeprovisionedUserBlocked`):
same user, lifecycle SUSPENDED → assert 401 body byte-equal to the SCIM
denial body, and exactly one `callback_failure` event with
`Metadata["lifecycle.state"]="suspended"`. SCIM variant asserts **no**
`callback_failure` event.

**Acceptance assertion**: byte-equal bodies across the two denial paths;
`callback_failure` present iff the denial was lifecycle-driven.

### F4 — Low: gate-ordering pins belong in the new tokengrant unit test

**Evidence**: `internal/handler/tokengrant` unit coverage is 9.1% — the
refresh handler's behavior is only exercised through `test/` E2E. The design
claims three ordering properties (after Consume, before `RecordRotation`,
before issue) that only a unit test can assert directly.

**Exact test to add** (same `token_refresh_test.go` as F1, using a
call-recording double): SUSPENDED user, valid token → assert
(a) `Consume` called and the token is gone from the fake store;
(b) the velocity store's `RecordRotation` **not** invoked;
(c) no successor token issued; (d) response is 400 `invalid_grant`.
Then the ACTIVE-user control: same double, same token → full rotation path.

**Acceptance assertion**: call-order log equals
`[Consume, LifecycleState, deny]` for SUSPENDED and
`[Consume, LifecycleState, Resolve, Velocity, Issue]` for ACTIVE — the
"no side effects before the gate" contract pinned mechanically.

### F5 — Low: D3 tests must cover the suspend-twin leg matrix explicitly

**Evidence**: `RevokeAccessOnSuspend` shares the already-extracted legs
(verified `revoke_on_archive.go` `revokeRefreshTokens`/`destroySessions`),
so the archive suite's 6 tests transfer, but the new reaction needs its own
matrix (state-match, idempotency, leg isolation) plus the E2E "admin 200
implies revocation done" (synchronous dispatch is verified: `bus.Record` →
`invoke` inside `RecordTransition`, before the 200).

**Exact tests to add**: mirror `revoke_on_archive_test.go` for SUSPENDED
(revokes both legs, non-suspending transition no-op, nil-store leg skip,
empty-userID no-op, one-store-error isolation via `errors.Join`); in `test/`:
live session + family → POST lifecycle suspend → 200 → session cookie 401,
`RefreshTokenSubjectIndex` empty, refresh → `invalid_grant`; run the
idempotency variant with `-count=10` (AGENTS race discipline).

**Acceptance assertion**: second suspension run is a no-op with no errors;
a failing session leg still revokes the token leg (never-less-locked-out).

### F6 — Info: no explicit concurrency scenario in the plan

**Evidence**: the login gate reads the store concurrently with admin
transitions; `memory.Store` is RW-locked, so no race is expected, but the
plan lists no concurrent test, and the TOCTOU window (Decision 6.5) is
exactly a concurrency property.

**Exact test to add**: `-race` E2E — N goroutines log in while a goroutine
flips ACTIVE→SUSPENDED→ACTIVE; assert every response ∈ {200, 403
`account_locked`}, zero 500s, zero races, and the final store state matches
the last transition. Assert the outcome *set*, not per-request results
(non-deterministic by design — accepted TOCTOU).

### F7 — Info: D2 family-survival test needs an explicit two-attempt choreography

**Evidence**: Decision 6.11 flags the retry interaction. The plan's "family
unchanged when no bus wired" must pin both halves: one denied attempt leaves
the family intact (token consumed); a second presentation kills it via the
existing reuse path.

**Exact test to add**: `test/` — login → suspend → refresh (400
`invalid_grant`, family alive in `RefreshTokenSubjectIndex` with token
consumed) → refresh again with the same token → 400 `invalid_grant` and
family deleted. Must not wire the bus (the reaction would delete the family
first — the plan's own caveat).

**Acceptance assertion**: first denial: family survives; second: family
deleted — byte-identical to the pre-change reuse behavior for healthy users.

### F8 — Info: the D2 nil-store/ACTIVE byte-identical regression is under-specified

**Evidence**: D1's plan pins nil-store → byte-identical; D2's does not, but
R5/R10 are the backward-compatibility anchors.

**Exact test to add**: `test/` — server with `WithUserLifecycle(memory)`,
ACTIVE user: login → refresh → rotate, compare response body and family ID
against the unwired harness (`TestRefreshToken_FullRoundTripRotates`); and
a no-record user refresh. Nil-store variant: server without
`WithUserLifecycle`, refresh flow byte-identical to today.

**Acceptance assertion**: `refresh_token` present, family ID preserved,
body equal to the unwired run — the gate is invisible for allowed states.

### F9 — Info: site-2/site-3 fixtures are the least-supported part of D1

**Evidence**: site 2 (MFA second leg, `server_mfa.go:359`) has a harness
(`test/mfa_test.go` builds a TOTP server — additive `WithUserLifecycle`
fits); site 3 (trusted-device transaction, `server_mfa_trust.go:256`) has
**no dedicated harness** in `test/` (grep: no trusted-device/mfa-trust test
file). The site-3 test needs a login-transaction fixture that does not
exist yet.

**Exact test to add**: site 2 — password login (MFA required) → suspend
before the second leg → complete TOTP → 403 `account_locked`, no session, no
tokens, `login_failure` with `lifecycle.state=suspended`. Site 3 — drive the
trusted-device continuation to a suspended user → 403 `account_locked`.

**Acceptance assertion**: the challenge-TTL window is closed by the gate —
a code minted pre-suspension cannot complete the login post-suspension.

## 4. Prioritized scenario list

Happy path (P1): ACTIVE/no-record login allowed at all five sites with the
gate wired — byte-identical to unwired; ACTIVE-user refresh rotates with
family preserved; suspend→reactivate restores login and rotation.

Boundary (P1): the six-state denial table {SUSPENDED, INACTIVE, ARCHIVED,
PURGED, INVITED denied; ACTIVE, no-record, nil-store allowed} at the
password site; INVITED seeded via direct `Append` (no production writer);
MFA-second-leg and trusted-device re-checks close the challenge window.

Error (P1): store-read failure at login → 403 `account_locked` + empty-state
audit meta + fail-closed log (byte-equal to suspension); at refresh → 400
`invalid_grant` byte-equal to unknown-token; reaction one-store failure →
`errors.Join`, other leg still revokes, admin 200.

Race (P2): concurrent logins × transition flips under `-race` (outcome-set
assertion); concurrent double-submit of a denied refresh token (family-kill
path unchanged); `AddSink` at build time only (no runtime registration —
asserted in wiring test).

Recovery (P2): reactivation of a suspended account restores login + rotation
(surviving-family unit choreography per F1); sweep-driven ARCHIVED fires the
reaction (existing `TestRcovAdmin_UserLifecycle` + archive bus test pattern);
audit-disabled config boots with the warning and read gates still enforce.

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

**Gaps in the plan**: no unit test file exists for the refresh gate today
(`token_refresh_test.go` must be created — tokengrant unit coverage 9.1%);
no failing-`Store` double exists anywhere; no trusted-device harness exists;
no concurrent login×transition test; D1's MFA-leg tests are listed but not
broken into site-2/site-3 choreographies.

**Flake risks**: the E2E reactivation choreography (F1) is timing-sensitive
(grace window is opt-in, default off) — avoid it; prefer the unit test. D3
idempotency tests should use `-count=10`. D1 audit-meta assertions must not
depend on anomaly-runner timing (the dispatch is separate from the audit
record; assert on `MemorySink` contents, the established pattern in
`audit_facets_test.go`).

**Fixtures needed**: (1) 3-method failing `userlifecycle.Store` double
(shared by `test/` and `tokengrant`); (2) `RefreshGrantDeps` recording double
in a new `token_refresh_test.go`; (3) trusted-device login-transaction
harness for site 3; (4) bus-aware server builder in `test/`
(`WithUserLifecycle` + `rec.AddSink(bus)` + `OnUserSuspended/OnUserArchived`)
derived from the `account_lockout_test.go` pattern; (5) two-token
same-family fake refresh store.

**Exit criteria** (implementation stage):
1. All Decision-7 tests plus F1–F9 additions green, including byte-compare
   pairs at both denial shapes and the fail-closed/byte-identical pins.
2. `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`
   — with `interfaces/sso` still at 60 files and every file ≤ 500 lines after
   the device-context move.
3. `go test ./... -race` and `go test ./test/ -run TestE2E -v` green;
   `make ci` green.
4. Docs updated in the same change: 3× "NEVER gates authentication"
   (`options_admin.go`, `docs/config-reference.md`, package doc),
   `account_locked` 423→403 row in `docs/error-codes.md`, fail-closed outage
   consequence + monitoring guidance in `docs/config-reference.md`, known
   residuals (auth-code exchange, multi-replica divergence) recorded.
5. No new `sso.Option`; `userlifecycle_wiring_test.go` opts-count assertions
   unmodified; audit-disabled warning path covered by a wiring test.

**Review verdict**: the design's evidence is accurate (all ten verification
rows re-confirmed), the oracle-safe collapse shapes are correctly derived
per site, and the test plan covers the acceptances — but three fixtures
(failing store, refresh-gate unit double, trusted-device harness) and two
choreographies (reactivation, denial-then-retry) are under-specified, and
the reactivation acceptance as written is not E2E-constructible (F1). None
of the findings block the design; all are implementable within the planned
test surface.
