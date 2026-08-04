# domains/userlifecycle — Direction 2 design QA review (risk-based test review)

Review of `docs/auto/domains-userlifecycle-direction2-design.md` at stage
"design". The implementation has **not** landed (Verified: no
`AllowsAuthentication`, no `rejectLifecycleBlockedUser`, no production
`NewLifecycleEventBus` — see §1). This review therefore (a) re-verifies every
claim in the design's verification record and Decisions 1–8 against the
working tree, (b) maps each spec acceptance to an existing or required test,
(c) measures the baseline the change will build on, and (d) pressures
Decision 7's test plan for gaps — with two High findings: the default
reaction-mode partial-erasure path has no planned test, and the two admin
lifecycle handlers' error matrix sits at **measured 0.0% coverage** with no
planned test for it. All commands below ran for this revision; no result is
inherited from documentation.

## 1. Test inventory and commands actually run

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | full module |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | budget/architecture gates (0.132s) |
| `go test -cover ./domains/userlifecycle/... ./protocols/lifecyclereactions/...` | PASS | coverage below |
| `go test ./protocols/compliance/... ./interfaces/admin/` | PASS | 1.2s + 0.014s |
| `go test -race -count=3 ./domains/userlifecycle/...` | PASS | store/bus/sweep under race, 3 iterations |
| `go test -run 'TestWireUserLifecycle|TestUserLifecycle' -v ./cmd/sso-server/` | PASS | 7/7 wiring tests |
| `go test -coverprofile=/tmp/admin_cover.out ./interfaces/admin/` | PASS | per-function coverage below |
| `go test ./test/ -run 'TestE2E' -count=1` | PASS | 0.014s — the default-CI E2E subset is small |

Coverage (line coverage only; behavioral adequacy argued in §2–§3):

| Package / function | Coverage | Comment |
|---|---|---|
| `domains/userlifecycle` | 82.3% | state machine + bus + sweep |
| `domains/userlifecycle/memory` | 95.8% | — |
| `protocols/lifecyclereactions` | 74.2% | archive reaction only; `EraseOnPurge` is new code |
| `interfaces/admin/lifecycle.go` `HandleAdminGetUserLifecycle` | **0.0%** | see Finding F2 |
| `interfaces/admin/lifecycle.go` `HandleAdminTransitionUserLifecycle` | **0.0%** | see Finding F2 |
| `interfaces/admin/lifecycle.go` `applyLifecycleTransition` / `writeLifecycleValidationError` | **0.0%** | exercised only via cmd E2E happy path |

Suite taxonomy (for §5): default CI = `go test ./...`, `go test ./test/
-run TestE2E`, `make ci`. Tagged/manual = `test/chaos` (`//go:build chaos`:
clock-jump, jti-replay, panic-recovery, refresh-rotation), `test/dr`
(DR failover). Benchmarks exist (`interfaces/ratelimit`,
`infrastructure/defaultimpl/sqlite`, `infrastructure/defaultimpl/issuer`,
`shared/core/auth_pipeline`) but there is no load/soak suite. `make ci` and
the chaos/DR tags were **not run** — design stage, no `.go` edits; §5 exit
criteria require them at implementation.

### Design-claim verification (independent re-check)

Every anchor in the design's verification record and Decisions 1–8 was
re-verified. All **Verified** except where noted.

- **The three spec corrections are accurate.**
  - `memory/memory_test.go:88-89` is `TestGet_ReturnsCopy` (a returned copy
    is mutated with a `StatePurged` transition to prove copy isolation), not
    a PURGED persistence fixture. Verified. Consequence the design draws is
    right: the "PURGED persists forever" behavior is structural (the `Store`
    interface has no `Delete`; `memory.Store` never removes records;
    `transitions.go` `StatePurged: {}` is terminal) — and there is **no
    existing test pinning PURGED persistence**, so improvement 3's
    `Delete` changes no test fixture. Lower regression risk than the spec
    implied.
  - Admin 404 checks are at `interfaces/admin/lifecycle.go:28-31`
    (`HandleAdminGetUserLifecycle`) and `:47-49` (transition handler) —
    `UserProvider().GetByID` before any store access in both. Verified.
  - Direction 1 has **not** landed: repo-wide grep for
    `rejectLifecycleBlockedUser` / `AllowsAuthentication` (including tests)
    returns nothing. Verified. The design's both-orderings composition
    contract (Decision 2.4) is therefore mandatory, and its fallback
    placement (`server_pairwise.go` at 394 lines, 106 headroom) is real.
- **`applyLifecycleTransition` does exactly Append + audit** (`lifecycle.go:77-95`;
  `Append` at :80, `RecordTransition` at :89). Verified.
- **`OnUserPurged` / `NewLifecycleEventBus` have zero production callers.**
  Verified: only `bus_test.go`, `revoke_on_archive_test.go`,
  `protocols/lifecyclereactions/doc.go`, and the `bus.go` doc comment.
- **Eraser wiring**: `newSelfServiceEraser` at `compliance_routes.go:32`,
  `lateBindComplianceStores` at `:223`, `mountComplianceAndSCIM` at
  `build_http.go:329`, `wireUserLifecycle` at `build_stores.go:328`
  (file = 444 lines, as cited). `wireUserLifecycle` runs inside
  `wireGovernance` (`build_app_security.go:240`), before
  `lateBindComplianceStores` (`build_app.go:257`) and before route mounting —
  the ordering the design's Decision 1.4 depends on. Verified.
- **`eraseResponse`** (`compliance_routes.go:117-155`) JSON tags match the
  proposed `ReportView` field-for-field (`user_id`, `dry_run`,
  `refresh_tokens_deleted`, `sessions_destroyed`, `consent_revoked`,
  `mfa_factors_removed`, `reset_tokens_revoked`, `user_deleted`,
  `skipped,omitempty`, `errors,omitempty`). The compliance wire bytes would
  not change. **But** reusing the struct verbatim injects
  `"dry_run":false` into the lifecycle POST's erasure block — the design's
  sample response (§1.3) omits it. See Finding F7.
- **Budgets**: `interfaces/admin` = exactly 10 non-test files (every one
  460-492 lines; `lifecycle.go` 481); `interfaces/sso` = exactly 60
  non-test files (`options_admin.go` 474, `server_login_auth.go` 493,
  `server_admin_handlers.go` 498, `sso_selfservice.go` 469,
  `server_login_resolve.go` 413, `server_oauth.go` 495);
  `config/config_admin.go` = 333; `protocols/scim/handler.go` = 349;
  `protocols/compliance/erasure.go` = 308. All Verified — the Decision 6.1/6.3
  shuffles are mandatory, not cosmetic. `build_stores.go` 444 → ~488 fits.
- **Sweep never reaches PURGED**: `nextState` (`sweep.go:142-154`) emits only
  ACTIVE → INACTIVE → ARCHIVED. Verified — the bus's `OnUserPurged` hook has
  no other production trigger to lose under the handler-owned model.
- **`ListByState` has no production callers** (grep: only the interface
  declaration and the memory implementation). Verified — the "no production
  consumer of PURGED listings" claim in Decision 3.2 holds.
- **`userlifecycle_wiring_test.go` opts assertions**: `len(b.opts) == 0`
  (disabled) and `== 1` (enabled alone) exist as asserted; the design's
  Decision 6.2 count-change analysis is correct (enabled-alone with nil
  stores still wires 1 option — that test stays green; new eraser-store
  cases need new tests).
- **Config surface**: `UserLifecycleConfig` at `config/config_admin.go:264`;
  openapi.yaml already lists `invited` in the lifecycle state enums
  (lines 8538/8556/8600) — the spec's "enum value no request can produce"
  claim verified; `docs/error-codes.md:678-680` has
  `illegal_lifecycle_transition` / `unknown_lifecycle_state` /
  `lifecycle_state_conflict`; `docs/feature-matrix.md` row 157 exists.
- **Login-path anchors**: `authenticateUser` at `server_login_auth.go:57`,
  `rejectDeactivatedUser` called at :98 (design said ~96 — trivial drift,
  immaterial); `finalizeCallbackSession` at `server_oauth.go:212` with the
  inline SCIM deprovision check at :219-226. The two `maybeAcceptInvitation`
  call sites are real. The "no MFA second leg needed" claim is sound
  (first leg accepts).
- **New edges are legal**: `protocols/lifecyclereactions` → `protocols/compliance`
  is a same-rank sibling (the forbidden pair is `oauth ↔ oidc` only);
  `protocols/scim` → `domains/userlifecycle` is downward. No cycle risk:
  `compliance` imports `protocols/oauth` + `shared/core` only. Verified by
  import inspection; the architecture gate passes today.

## 2. Requirement-to-test matrix

Status: **Verified** = existing test measured in this revision; **Planned** =
named in design Decision 7 but not yet written; **Gap** = required by the
spec/design but absent from Decision 7.

| Requirement (spec §) | Test(s) | Status / Evidence |
|---|---|---|
| Invariant: no record = ACTIVE | `memory_test.go` `TestGet_MissingRecordIsDefaultActive`, `TestListByState` (implicit-active never listed); `TestUserLifecycle_EndToEnd` initial `state: active` | **Verified** — measured 95.8% memory pkg |
| Invariant: PURGED terminal | `transitions_test.go` `TestAllowedTransitions_SortedAndTerminal` | **Verified** |
| Invariant: unwired = byte-identical | `TestWireUserLifecycle_DisabledIsNoOp` (0 opts), `TestUserLifecycle_DefaultOff_RouteNotMounted` (404), `TestWireUserLifecycle_EnabledAppendsStoreOptionOnly` (1 opt) | **Verified** — 7/7 cmd wiring tests pass |
| Invariant: import direction | `TestArchitecture_` gate | **Verified** (passes; new edges inspected, see §1) |
| Imp.1: `EraseOnPurge` reference reaction | Design 7: nil eraser / empty userID no-op, no dry-run, idempotent second call, joined error, panic containment | **Planned** — no `EraseOnPurge` exists yet |
| Imp.1: purge integration (sessions/tokens erased, report in response, audit meta, GET 404, re-provision fresh) | Design 7 "Purge" integration | **Planned** |
| Imp.1: fail-closed refusal (500, ARCHIVED read-back, no PURGED history, failure audit) | Design 7 "Fail-closed" integration | **Planned** |
| Imp.1: **partial erasure in reaction mode** (200 + `erasure.errors`, record retained, never claimed complete) | — | **Gap — Finding F1** |
| Imp.1: wiring proof (bus constructed in cmd, `AddSink`, opts counts, late-bind, boot warning) | Design 7 wiring bullet | **Planned** (extend `userlifecycle_wiring_test.go`; current assertions measured) |
| Imp.1: **cmd never registers `OnUserPurged`** (single-execution rule) | — | **Gap — Finding F8** |
| Imp.2: seed `StateNone → INVITED` atomicity | `memory_test.go` `TestAppend_SeedRequiresNoRecord` (:50-63) | **Verified** (existing); new call path **Planned** |
| Imp.2: admin seed form branch table (no record / PURGED / other / knob off) | Design 7 adminlifecycle unit | **Planned** |
| Imp.2: duplicate seed → 409; INVITED→SUSPENDED → 400; seed response shape (`previous_state` omitted, `allowed_transitions: [active, archived]`) | Design 7 "Invite" integration | **Planned** |
| Imp.2: first login auto-accept (ACTIVE + ActorSystem audit); admin accept | Design 7 "Invite" integration | **Planned** |
| Imp.2: `accept_on_first_login: false` (stays INVITED; admin-accept only) | — | **Gap — Finding F6** |
| Imp.2: SCIM create seeds INVITED; **seeder failure → 201, account ACTIVE**; replace/patch never seed | Design 7 mentions seeder plumbed through wiring only | **Partial — Gap on failure path (Finding F5)** |
| Imp.3: `Store.Delete` unit semantics (removes, Get → DefaultState, absent = nil, ListByState drops) | Design 7 memory unit | **Planned** — compile-enforced interface growth (memory + any fakes) |
| Imp.3: crash-window repair (PURGED record, user absent → re-seed without `ErrStateConflict`) | Design 7 "Crash window" | **Planned** |
| Imp.3: post-purge GET 404 via existing user-existence check | Design 7 "Purge" integration | **Planned** |
| Imp.3: **`Delete` failure path** (logged, PURGED persists, repaired on provisioning) | — | **Gap — Finding F4** |
| Imp.1/3 residual: **erase-then-Append conflict in fail-closed mode** (409, erasure audited) | — | **Gap — Finding F3** |
| Existing handler error matrix (400/404/409/500) | — | **Gap — Finding F2, measured 0.0%** |

## 3. Findings

### F1 — High — Reaction-mode partial erasure (the default mode) has no planned test

The spec's preserved invariant is "a partially-erased purge is visible, not
claimed complete" (`direction2-spec.md`), and Decision 1.3's default
(reaction) mode promises: partial erasure still returns 200, the response
carries `erasure.errors`, the audit meta carries the report, and the record
is **not** deleted (Decision 3.2's `rep.Err() == nil && rep.UserDeleted`
rule). Decision 7's plan only tests full-success purge and fail-closed
refusal — the partial-erasure branch is the untested middle.

- **Exact test to add** (integration, `test/` `package ssotest`, or
  adminlifecycle unit): wire an eraser whose `Sessions` leg fails (fake
  `core.SessionManager` returning an error on `ListByUser`); drive
  ARCHIVED → PURGED in reaction mode.
- **Acceptance assertion**: status 200; body `erasure.errors` non-empty;
  `erasure.user_deleted == false`; `Store.Get` still reads PURGED (record
  retained — the honest tombstone); audit `EventAdminUserLifecycleChanged`
  carries the erasure-report meta; a second purge attempt after the store
  recovers completes the erasure and deletes the record (recovery path).

### F2 — High — The moved handlers' error matrix is at measured 0.0% coverage and no test is planned for it

Measured this revision: `HandleAdminGetUserLifecycle`,
`HandleAdminTransitionUserLifecycle`, `applyLifecycleTransition`,
`writeLifecycleValidationError` are all **0.0%** in `interfaces/admin`
package tests; the only exercise is the cmd wiring E2E happy path
(`TestUserLifecycle_EndToEnd` — suspend only). The wire contract these
functions own — 400 `invalid_request` (missing id / missing state / bad
body), 404 unknown user, 400 `unknown_lifecycle_state`, 400
`illegal_lifecycle_transition`, 409 `lifecycle_state_conflict`, 500
store-error — is asserted nowhere at handler level. Decision 6.1 moves these
functions into a new `interfaces/admin/lifecycle` subpackage and threads new
branches (seed form, erasure orchestration) through them; that is precisely
when the pre-existing table needs pinning, before the move makes
regression attribution ambiguous. The design's Decision 7 unit bullet covers
only the *new* seed/erasure branches.

- **Exact test to add** (adminlifecycle unit, table-driven; needs a `Deps`
  harness — extend the `gcTestDeps` pattern at
  `interfaces/admin/governance_test.go:60`): cases = unknown user → 404;
  missing `id` / missing `state` / unparsable JSON → 400
  `invalid_request`; `state: "none"` → 400 `unknown_lifecycle_state`;
  ACTIVE → PURGED (no record) → 400 `illegal_lifecycle_transition`;
  stale-from injection (store whose `Append` returns `ErrStateConflict`) →
  409 `lifecycle_state_conflict`; store `Get`/`Append` error → 500
  `internal_error`.
- **Acceptance assertion**: every case asserts both the status code and the
  exact `errorBody` code string; the 409 case asserts the conflict code is
  `lifecycle_state_conflict`, not a generic 409.

### F3 — Medium — Fail-closed erase-then-Append residual: repair claim overreaches for non-PURGED concurrent winners

Decision 1.3's residual is scoped as "two concurrent PURGED transitions",
but in fail-closed mode the loser can also lose to a **non-PURGED**
transition (the other writer commits ARCHIVED → ACTIVE first; our pre-Append
erasure already ran; our Append conflicts → 409). The record then reads
ACTIVE for an erased user — not PURGED — and Decision 3's repair path
("SeedInvited treats a found **terminal** record as provision over it")
does **not** apply: a non-terminal record makes `SeedInvited` return
`ErrStateConflict`, the admin seed form falls through to 400, and the SCIM
path logs and returns 201 with the account left ACTIVE. The "repaired on
next provisioning" wording in the failure table overclaims for this
interleaving. No security hole (the user record is gone; re-provisioning is
an operator action), and no PURGED-inheritance poison — but the design
should state the non-terminal branch explicitly rather than implying full
repair.

- **Exact test to add** (adminlifecycle unit with a store that lets a
  concurrent writer commit ARCHIVED → ACTIVE between erasure and our
  Append): assert 409, erasure audited, record = ACTIVE; then assert the
  documented degradation: admin seed on that record → 400, SCIM-style
  re-provision → proceeds with existing state (no `ErrStateConflict` leak).
- **Acceptance assertion**: 409 body is `lifecycle_state_conflict`;
  follow-up seed behavior matches the Decision 2.2/2.3 table, and the
  handler comment (required by Decision 1.3) documents this branch.
- **Required design fix**: amend the failure-table row and the Decision 1.3
  residual to cover non-PURGED winners before implementation.

### F4 — Medium — `Store.Delete` failure path untested

Failure-table row "Clean erasure, `Store.Delete` fails → logged; PURGED
record persists (orphaned); repaired on next provisioning" has no planned
test, and the delete rule (`rep.Err() == nil && rep.UserDeleted`) is a new
three-way conditional (erase ok / user deleted / delete ok) that deserves
its own matrix: (a) all-true → record gone; (b) `UserDeleted=false`
(no Users leg) → record kept PURGED; (c) delete error → record kept PURGED.
Case (b) is the "purge without Users leg" anchor the design calls out in
Decision 3.2 and is untested too.

- **Exact test to add** (adminlifecycle unit + memory unit): fault-injecting
  `userlifecycle.Store` wrapper with a `Delete` error switch; eraser with
  and without a `Users` leg.
- **Acceptance assertion**: (b) `Get` still returns PURGED with
  `UserDeleted=false`; (c) `Get` still returns PURGED and the subsequent
  `SeedInvited` (crash-window repair) re-seeds fresh.

### F5 — Medium — SCIM seeder failure path untested

Decision 2.3's "a seed failure logs and still returns 201 — user
provisioning must not fail over governance metadata" is a deliberate
fail-open-with-audit choice on a public provisioning surface (SCIM) and has
no planned test. Also unpinned: `replaceUser`/`patchUser` never seed.

- **Exact test to add** (`protocols/scim` handler test): create with a
  failing seeder → 201, user visible, `GET /lifecycle` (or store read)
  shows ACTIVE; create with working seeder → 201, INVITED; replace/patch →
  state unchanged.
- **Acceptance assertion**: 201 in all cases; only the create path mutates
  the lifecycle record, and a seeder error never surfaces as a 4xx/5xx.

### F6 — Medium — `accept_on_first_login: false` semantics untested

Design Decision 2.4 documents the knob-off branch (account stays INVITED;
admin INVITED → ACTIVE is the only exit; direction 1 then denies at login)
as a deliberate supported configuration, and Decision 10 of the risk list
documents the knob-interaction. Decision 7 only plans the auto-accept
on-path. The flip side is one assertion away.

- **Exact test to add**: extend the invite integration test — with
  `accept_on_first_login: false`, first login does **not** flip the state
  (record still INVITED, no `ActorSystem` transition in history), and the
  admin INVITED → ACTIVE transition works.
- **Acceptance assertion**: after a successful login, `GET /lifecycle`
  still reads `state: invited` and history contains no acceptance
  transition; after admin accept, `state: active` with the admin actor.

### F7 — Low — `dry_run` wire drift between the design sample and `ReportView` reuse

Reusing `compliance.ReportView` verbatim in the lifecycle response (the
`eraseResponse` field-for-field match verified in §1) means the erasure
block serializes `"dry_run": false` (the tag has no `omitempty`), which the
design's sample JSON (§1.3) omits. Decide before implementation: keep and
document the field, or drop `DryRun` from the lifecycle projection. Either
way the sample and the OpenAPI update (Decision 8) must agree.

### F8 — Low — The single-execution rule (no `OnUserPurged` in cmd) is comment-only

Decision 1.1/6.5 pins "the composition root does NOT register `OnUserPurged`"
in comments. Risk 6.5 correctly warns a reviewer might "helpfully" add it,
double-erasing every purge. A wiring assertion makes the rule mechanical.

- **Exact test to add** (cmd wiring test): after `wireUserLifecycle` +
  `AddSink`, assert the bus holds exactly the ARCHIVED reaction and no
  PURGED reaction (export a test accessor or assert via a reaction-count
  hook on the bus).
- **Acceptance assertion**: registering `OnUserPurged` on the production
  bus fails the test — the single-execution invariant is compile-visible.

### F9 — Info — `erasure.errors` renders raw store error strings on an admin surface

`eraseResponse` renders `Report.Errors` as `err.Error()` strings; the
lifecycle block inherits this. Consistent with the existing admin GDPR
surface and admin-scoped (`admin:write`), so acceptable — but note in the
handler comment (as Decision 1.3 already requires documentation) that these
strings are store error text, not wire codes.

### F10 — Info — Direction-1 ordering acceptance is comment-pinned and untestable until direction 1 lands

The "call after `maybeAcceptInvitation`" contract lives in a doc comment;
the cross-direction acceptance (INVITED first login → ACTIVE → session
minted) cannot be written until direction 1's gate exists. Record it as a
deferred acceptance in the direction-1 spec (its own test plan should
include the composed ordering) so it is not lost. The interim ordering
(direction 1 absent: seeded INVITED authenticates and flips) IS testable now
and is in the plan.

### F11 — Info — Spec-vs-design deviation should be amended in the spec file

The spec's improvement-1 behavior bullet says "register
`OnUserPurged(EraseOnPurge(eraser))`"; the design's handler-owned model is a
documented deviation. The spec's *acceptance* bullets are all satisfiable
(bus constructed in cmd; `OnUserArchived` registered; unit tests for
`EraseOnPurge`), so no acceptance fails — but a literal spec-vs-tree
comparison later will show drift. Recommend appending the deviation note to
the spec (same change as the implementation) so the spec and design agree on
"the bus seam is the reference; the stock handler owns execution".

**QA verdict on the deviation itself**: sound. The bus is an `audit.Sink`
whose `invoke` discards reaction errors and fires after `Append`, so it
cannot refuse a transition or return a report to the handler; handler-owned
synchronous erasure is the only model satisfying the spec's (a) report, (b)
refuse-before-Append, and (c) single-execution requirements coherently. It
also survives `audit.enabled: false` — strictly stronger than the bus
dependency. `EraseOnPurge` remaining a reference reaction mirrors
`RevokeAccessOnArchive`'s own unwired-in-production status, so precedent
holds.

## 4. Prioritized scenario list

P0 — required in the same change as the feature (spec acceptances + F1/F2):

1. Purge happy path, reaction mode: seed account with live sessions +
   refresh family; ARCHIVED → PURGED with eraser wired → sessions destroyed,
   tokens revoked across clients, `user_deleted: true`, response erasure
   view, audit transition + report meta, `GET /lifecycle` → 404, same id
   re-provisioned seeds fresh and logs in, purge audit intact.
2. Partial erasure, reaction mode (**F1**): failing Sessions leg → 200 +
   `erasure.errors`, record retained PURGED; recovery run completes.
3. Fail-closed refusal: `purge_requires_erasure=true`, eraser whose
   `Users.Delete` fails → 500 `internal_error`, `Store.Get` still ARCHIVED,
   no PURGED history, `RecordTransitionFailure` audit present.
4. Handler error matrix table (**F2**): 400/404/409/500 cases above.
5. `Store.Delete` unit semantics + delete-rule matrix (**F4**): record gone /
   kept-without-Users-leg / kept-on-delete-error.
6. Crash-window repair: PURGED record + absent user → re-provision re-seeds,
   no `ErrStateConflict`; login succeeds.
7. Seed form: no record → INVITED (`previous_state` omitted,
   `allowed_transitions: [active, archived]`); duplicate → 409; PURGED →
   re-seed; non-terminal → 400; knob off → 400 byte-identical.
8. `EraseOnPurge` unit suite: `EraseSubject(userID, {})` (no dry-run), nil
   eraser / empty userID no-op, idempotent second call, joined error, panic
   containment through the bus.
9. Invite integration: first login → ACTIVE + `ActorSystem` audit; admin
   accept → ACTIVE; INVITED → SUSPENDED → 400.

P1 — bounded weaknesses; add in the same change or immediately after:

10. Fail-closed erase-then-Append conflict, both winner kinds (**F3**):
    409 + audited erasure; non-PURGED winner degrades per the amended
    failure table.
11. SCIM create with seeder: success → INVITED; failure → 201/ACTIVE;
    replace/patch never seed (**F5**).
12. `accept_on_first_login: false`: stays INVITED after first login; admin
    accept exits (**F6**).
13. Wiring: opts counts (0/1/2 with eraser stores), bus as audit sink,
    late-bind populates the lifecycle eraser, boot warning when
    `purge_requires_erasure` without an eraser, no-`OnUserPurged` guard
    (**F8**).
14. Seed response wire shape: no `previous_state` key; `dry_run` decision
    pinned (**F7**).

P2 — hardening / deferred:

15. Race: concurrent Get/Append/Delete under `-race` (extend memory tests;
    `Delete` must sit under the existing lock — design says ~6 lines, the
    lock is already there).
16. Idempotent double-purge across "replicas" (two `EraseSubject` runs over
    the same stores — already the idempotence unit test; state it as the
    multi-replica story).
17. TOCTOU login-concurrent-with-purge: accepted class per the failure
    table; document in the integration test comment, no timing-based test.
18. Direction-1 composed ordering: deferred acceptance once direction 1
    lands (**F10**).

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

### CI/manual-suite gaps

- **No handler-level lifecycle tests exist today** (F2 is the baseline gap
  the design inherits; the subpackage move must not replicate it).
- `test/` has **zero user-lifecycle E2E coverage** today (repo-wide grep:
  `userlifecycle` appears in no `test/` file; the 8 case-insensitive
  "lifecycle" hits are incidental — session/token lifecycle and DR harness
  comments); all proposed integration tests are net-new `package ssotest`
  work following the deterministic `account_lockout_test.go` pattern
  (buildApp + httptest, no sleeps; that file's 12 tests pass in the suite).
- Tagged/manual suites (`test/chaos`, `test/dr`) are untouched by this
  design and need no additions — the memory store is per-process, so
  chaos-clock tests cannot observe lifecycle state divergence (worth a
  one-line note in the design's multi-replica row).
- No benchmark needed for the per-login cost (one `Store.Get` behind a
  config gate); if a reviewer wants one, `BenchmarkAcceptInvitation` on the
  memory store is trivial — but the real invariant is "config gate precedes
  the read", which is a code-review check, not a benchmark.

### Flake risks

- The planned tests are all deterministic (injected conflicts and store
  faults, never timing). The concurrent-purge tests must use fault-injecting
  stores, not goroutine sleeps — otherwise they flake under `-race -count=10+`.
- The erase-then-Append residual test (F3) needs the store wrapper to
  sequence the interleaving deterministically; do not attempt it with real
  concurrency.
- `AddSink` wiring is build-time only (verified pattern at
  `interfaces/sso/sso.go:150-162`); the wiring test must assert the sink
  list after `buildApp`, never event timing.
- Multi-replica divergence is inherited and must **not** be tested as
  convergence — that would be a guaranteed flake.

### Fixtures needed

1. **Fault-injecting `userlifecycle.Store` wrapper** — Get/Append/Delete
   error switches + forced `ErrStateConflict` (F2/F3/F4; also exercises the
   compile-enforced interface growth).
2. **Real `compliance.Eraser` over fake SPIs** — pattern already exists in
   `protocols/compliance/erasure_test.go`; reuse for `EraseOnPurge` and the
   adminlifecycle erasure branches (including a `Users.Delete` failure leg).
3. **`Deps` harness for `adminlifecycle`** — extend `gcTestDeps`
   (`interfaces/admin/governance_test.go:60`); the three new `Deps` methods
   (`LifecycleEraser`, `PurgeRequiresErasure`, `InviteProvisioning`) must be
   nil/false in the default harness so unwired cases are tested too.
4. **SCIM handler harness with seeder option** — extend
   `protocols/scim/handler_test.go`; seeder both nil (byte-identical) and
   failing.

### Exit criteria

Design stage (this review):
1. F1 and F2 folded into Decision 7 (partial-erasure test + handler error
   matrix table) — required before implementation starts.
2. F3's failure-table wording amended to cover non-PURGED concurrent winners.
3. F7's `dry_run` decision made and reflected in the Decision 1.3 sample and
   Decision 8's OpenAPI bullet.
4. F10 recorded as a deferred acceptance in the direction-1 spec.
5. Budget pre-flight re-run immediately before the first commit: `interfaces/sso`
   non-test file count (must stay 60) and per-file lines after the Decision 6.3
   shuffle — direction 1 may land first and consume `server_login_resolve.go`
   headroom (design's own fallback to `server_pairwise.go` is verified real).

Implementation stage (design Decision 7/8):
6. After every `.go` edit: `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .`.
7. Before handoff: `go test ./... -race`; `go test ./test/ -run TestE2E -v`;
   `make ci` (including nested modules and module validation). Chaos/DR
   suites only if a change touches shared stores or the bus.
8. Wire-contract diff review: OpenAPI lifecycle POST (seed form, erasure
   block, `previous_state` omission, post-purge GET 404), `docs/error-codes.md`
   (no new codes claim), `docs/config-reference.md` (three knobs + knob
   interaction note), `docs/feature-matrix.md` row 157.
