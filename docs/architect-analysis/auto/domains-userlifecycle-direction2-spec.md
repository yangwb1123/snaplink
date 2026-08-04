# domains/userlifecycle — Direction 2 requirements spec: PURGED actually erases, INVITED becomes reachable

Scope: expansion direction 2 from `docs/auto/domains-userlifecycle-analysis.md` —
「PURGED 声称"数据已擦除"却无任何擦除动作；INVITED 状态没有任何生产入口（邀请流程缺失）」.

The seven-state machine (`INVITED → ACTIVE → {SUSPENDED, INACTIVE} → ARCHIVED → PURGED`)
has two states whose documented semantics no production path implements:

- `StatePurged` is documented as "the account's data has been erased"
  (`domains/userlifecycle/userlifecycle.go`), yet the admin transition handler
  only persists the transition and emits an audit event — the account's
  sessions, refresh tokens, consent, MFA enrollments, and user record all
  survive. The cross-store erasure engine that would do the work
  (`protocols/compliance.Eraser`) exists and is wired for self-service and
  admin GDPR endpoints, but nothing connects it to the lifecycle terminal
  state.
- `StateInvited` is documented as "entered by the provisioning/invitation
  flow", and the transition table seeds it via `StateNone → INVITED`, but no
  production code ever writes that seed. The only production `Append` callers
  start from a live `rec.State` (which reads ACTIVE for a record-less user),
  so INVITED is unreachable: one state is a lie, one is dead code.

This spec contains exactly three evidence-backed improvements:

1. Erase on purge — the PURGED transition runs the `compliance.Eraser` (with an
   optional fail-closed mode in which the transition is refused unless erasure
   completes), wired through the `LifecycleEventBus` reference-reaction seam.
2. INVITED provisioning entry — a production writer for the `StateNone →
   StateInvited` seed plus a production `INVITED → ACTIVE` acceptance path, so
   the documented provisioning flow actually exists.
3. PURGED tombstone semantics — the lifecycle record must not outlive the
   erased account: after erasure the record is removed (audit preserved), and
   a re-provisioned account seeds fresh instead of inheriting a terminal,
   inescapable PURGED record.

## Preserved invariants (non-negotiable)

- **No record = ACTIVE.** `Store.Get` returns `{State: DefaultState}` for an
  unknown user (`domains/userlifecycle/userlifecycle.go`; `memory.Store.Get`),
  and improvement 3 keeps that anchor by *removing* the record at purge rather
  than inventing a new "erased" read-back state. Every account predating the
  feature reads exactly as today.
- **Unwired = byte-identical.** Nil lifecycle store, nil bus, or nil eraser
  (all defaults) make each new seam a no-op. A build that never calls
  `WithUserLifecycle` / never registers reactions behaves exactly as today;
  PURGED-without-erasure remains possible only when the operator has not wired
  the erasure (the current, documented behavior), never silently by default.
- **"PURGED means erased" is enforced when armed, never assumed.** In
  fail-closed mode the transition is refused if the erasure fails; in the
  default reaction mode the erasure Report is surfaced in the admin response
  and audit so a partially-erased purge is visible, not claimed complete.
- **Import direction preserved.** `protocols/lifecyclereactions` already
  imports `domains/userlifecycle` (rank 3 → rank 2, legal) and may import
  `protocols/compliance` (same rank, sibling — allowed; the forbidden pair is
  `protocols/oauth ↔ protocols/oidc`). The admin handler receives the eraser
  through the existing `Deps` accessor pattern; no upward imports, no
  `interfaces/sso` imports from either protocols package.
- **Direction-1 interplay.** The separate direction-1 spec (auth-gate
  enforcement) denies INVITED at the login gate; improvement 2 below provides
  the INVITED → ACTIVE acceptance trigger that gate depends on, so the two
  directions compose without deadlocking invited accounts.

---

## 1. Erase on purge: PURGED transition runs the compliance.Eraser

**Name**: `EraseOnPurge` — terminal-state erasure reaction wired at the composition root

**Problem**: The state machine claims the terminal state erases data, but no
code path does it. `HandleAdminTransitionUserLifecycle` →
`applyLifecycleTransition` (`interfaces/admin/lifecycle.go`) does exactly two
things: `LifecycleStore().Append` and `RecordTransition` (audit). An operator
who drives an ARCHIVED account to PURGED gets a state that says "the account's
data has been erased" while the sessions, refresh-token families, consent
grants, MFA enrollments, and the `core.User` record all remain intact and
usable. The mechanism that should do the work is dead in production:
`LifecycleEventBus.OnUserPurged` (`domains/userlifecycle/bus.go`) has zero
production callers — repo-wide grep finds `NewLifecycleEventBus` only in
`bus_test.go`, `revoke_on_archive_test.go`, and the `doc.go` example, never in
`cmd/` or `interfaces/` — and the only reference reaction
(`protocols/lifecyclereactions/revoke_on_archive.go`) covers ARCHIVED with
credential revocation only, not erasure. The `compliance.Eraser` that would
erase is already built in production — for `POST /me/account/erase`
(`cmd/sso-server/compliance_routes.go:32-47`, `newSelfServiceEraser`) and the
admin `POST /api/v1/compliance/users/:id/erase` (`compliance_routes.go:142`) —
but those are standalone GDPR surfaces with no lifecycle coupling. Result:
the GDPR/compliance story the state machine documents is unenforceable, and
worse, it is *dishonest* — the wire state asserts an erasure that did not
happen.

**Evidence**:
- `domains/userlifecycle/userlifecycle.go` (`StatePurged` doc): "the account's
  data has been erased. No transition leaves it."
- `interfaces/admin/lifecycle.go` (`applyLifecycleTransition`, lines 73-91):
  only `Append` + `RecordTransition` — no side effect, no erasure dependency.
- `domains/userlifecycle/bus.go` (`OnUserPurged`): the terminal-state hook
  exists; repo-wide grep shows no production constructor of
  `NewLifecycleEventBus` and no caller of `OnUserPurged`.
- `protocols/lifecyclereactions/revoke_on_archive.go` (`RevokeAccessOnArchive`):
  the only reference reaction; it revokes credentials at ARCHIVED, never
  erases, and is itself unwired in production.
- `protocols/compliance/erasure.go` (`Eraser.EraseSubject`, `EraseOptions`,
  `Report`): a complete, idempotent, dry-run-capable, per-store best-effort
  eraser — already production-wired at `cmd/sso-server/compliance_routes.go`
  (self-service and admin GDPR endpoints) but with zero reference from
  `domains/userlifecycle`.

**Proposed behavior**:
- Add `lifecyclereactions.EraseOnPurge(eraser *compliance.Eraser)
  userlifecycle.ReactionFunc` — the reference PURGED reaction, mirroring
  `RevokeAccessOnArchive`'s shape: it calls `eraser.EraseSubject(ctx, userID,
  compliance.EraseOptions{})` and returns `Report.Err()` (best-effort aggregate;
  a nil eraser or empty userID is a no-op). Idempotent by construction (the
  Eraser is). Dry-run is not part of the reaction — a purge is a commit; dry-run
  stays available on the standalone compliance endpoints.
- Wire the composition root in `cmd/sso-server`: build a
  `userlifecycle.NewLifecycleEventBus` alongside `BuildUserLifecycle`, register
  `OnUserPurged(EraseOnPurge(eraser))` (and, for completeness,
  `OnUserArchived(RevokeAccessOnArchive(...))`), add the bus as an
  `audit.Sink` (it already observes `EventAdminUserLifecycleChanged` emitted by
  `RecordTransition` — no new instrumentation in the admin handler or sweep).
  The eraser is the already-built `compliance.Eraser` from
  `compliance_routes.go`, finalized with consent/MFA/notification stores the
  same way `finalize` late-binds them today.
- Fail-closed option, config-gated: `user_lifecycle.purge_requires_erasure`
  (default `false` — current behavior preserved). When `true`, the admin
  handler runs `EraseSubject` BEFORE `Append`: any erasure error → the
  transition is refused (`500 internal_error`, state unchanged, error in
  audit); success → Append proceeds. This makes "PURGED means erased" an
  enforced invariant instead of a documentation claim. The reaction mode
  (`On`, synchronous) covers the non-fail-closed wiring and makes the report
  available in the admin response.
- Surface the outcome: the `POST /api/v1/admin/users/:id/lifecycle` response
  for a PURGED transition includes the erasure summary
  (`refresh_tokens_deleted`, `sessions_destroyed`, `user_deleted`,
  `skipped`, `errors` — from `compliance.Report`), and `RecordTransition`'s
  audit metadata gains an erasure-report summary for the terminal transition.

**Acceptance check**:
- Unit (`protocols/lifecyclereactions`): `EraseOnPurge` calls `EraseSubject`
  with the given userID and no dry-run; a second invocation on an already-erased
  subject returns nil (idempotent); a failing store yields the joined error,
  and a panicking eraser cannot crash the bus (`invoke` containment, already
  exercised by `bus_test.go`).
- Integration (`test/`, `package ssotest`): seed an account with live sessions
  and a refresh family; admin-transition ARCHIVED → PURGED; assert sessions
  destroyed, refresh tokens revoked across clients, user record deleted (when
  `Users` wired), response carries the erasure summary, and the audit trail
  contains both the transition and the report.
- Fail-closed test: with `purge_requires_erasure=true` and an eraser whose
  `Users.Delete` fails, the transition returns 500, `Store.Get` still reads
  ARCHIVED, and no PURGED history entry exists.
- Wiring proof: `NewLifecycleEventBus` is constructed in `cmd/sso-server`
  production code (not only tests); `make ci` passes with the bus registered
  as an audit sink (MultiSink ordering preserved).

---

## 2. INVITED provisioning entry: a production writer for the seed and its acceptance path

**Name**: Invitation provisioning — seed `StateNone → StateInvited` + `INVITED → ACTIVE` acceptance

**Problem**: `StateInvited` is unreachable in production. Its own doc says it
is "entered by the provisioning/invitation flow"
(`domains/userlifecycle/userlifecycle.go`), and the legal table seeds it via
`StateNone → INVITED` (`domains/userlifecycle/transitions.go:26`), but no
production code ever writes that seed. The only production `Append` callers
are `interfaces/admin/lifecycle.go:80` — where `From` is always `rec.State`,
and a record-less user reads as `DefaultState` (ACTIVE), so the `StateNone`
seed path never fires, while `ACTIVE → INVITED` is illegal per the transition
table — and `domains/userlifecycle/sweep.go:144`, which only advances
ACTIVE → INACTIVE → ARCHIVED. The memory store implements the seed atomically
(`memory/memory.go:52-55`) but the only exerciser is a test
(`memory/memory_test.go:50`). A repo-wide grep for `StateInvited` finds it in
production only inside `domains/userlifecycle` itself. The existing
org-invitation surface (`POST /me/invitations/accept`,
`protocols/selfservice/selfserviceaccount/organizations.go`) is tenant
collaboration, not the user-lifecycle state. Result: the documented model
"INVITED → ACTIVE (accept invite / rescind)" is fiction — of the seven states
the docs promise, one cannot ever be entered, and with direction 1's gate
denying INVITED at login, an invited account would also be dead on arrival
without the acceptance trigger this improvement provides.

**Evidence**:
- `domains/userlifecycle/userlifecycle.go` (`StateInvited` doc): "Entered by
  the provisioning/invitation flow, not by transition from an active account."
- `domains/userlifecycle/transitions.go:26-27`: `StateNone → {StateInvited,
  StateActive}` seed edges exist; `INVITED → {ACTIVE, ARCHIVED}` at line 27.
- `interfaces/admin/lifecycle.go:79-80` (`applyLifecycleTransition`): the sole
  admin `Append`; `From` is always `rec.State` (never `StateNone`), so the
  seed is unreachable through the admin surface and `ACTIVE → INVITED` is
  `illegal_lifecycle_transition` (validated at `lifecycle.go:73-76`).
- `domains/userlifecycle/sweep.go:142-150` (`apply`): the other production
  `Append`; only ACTIVE/INACTIVE sources.
- `domains/userlifecycle/memory/memory.go:52-55`: the seed branch exists
  ("a seed (t.From == StateNone) requires no existing record") with no
  production caller; `memory_test.go:50` is the only exerciser.
- `docs/openapi.yaml` (`/api/v1/admin/users/:id/lifecycle` schema): `invited`
  is a documented enum value no request can ever produce.

**Proposed behavior**:
- Add a production seed writer. Two complementary, small surfaces (pick at
  least one; both share the same `Append(From: StateNone)` call):
  - SCIM provisioning: `protocols/scimprovision` user creation accepts an
    opt-in "invited" mode (config flag or a SCIM attribute mapped at the
    `deliver`/create step), seeding `StateNone → StateInvited` with
    actor = `ActorSystem` instead of leaving the account implicitly ACTIVE.
  - Admin seed: `POST /api/v1/admin/users/:id/lifecycle` with
    `state: "invited"` is accepted only as an explicit seed — `From:
    StateNone` — for a user with no lifecycle record (currently impossible:
    the handler always validates from `rec.State`). A user with an existing
    record gets `illegal_lifecycle_transition`; a concurrent duplicate seed
    gets the existing `409 lifecycle_state_conflict` from the atomic seed
    branch.
- Add a production acceptance trigger for `INVITED → ACTIVE` (the edge already
  exists at `transitions.go:27`): either (a) first successful authentication
  auto-accepts — a login-hot-path hook that advances the record
  `INVITED → ACTIVE` (actor `ActorSystem`, reason `invitation accepted`)
  before/at the same point direction 1's gate would deny the account — or
  (b) an explicit admin accept (INVITED → ACTIVE is already a legal admin
  transition). Wire whichever is chosen in `interfaces/sso` alongside the
  existing `IsActive` checks; the documented choice is (a) auto-accept on
  first login, with (b) available unchanged.
- Update contracts in the same change: `docs/openapi.yaml` (lifecycle POST
  documents the seed form and the new response path), `docs/config-reference.md`
  (new `user_lifecycle.invite` provisioning knob and acceptance semantics),
  `docs/feature-matrix.md` (INVITED is now reachable), and `docs/error-codes.md`
  (no new codes — `illegal_lifecycle_transition` and `lifecycle_state_conflict`
  already cover the negative cases).

**Acceptance check**:
- Unit (`domains/userlifecycle/memory`): `Append(StateNone → StateInvited)` on
  a fresh user succeeds; on an existing record returns `ErrStateConflict`
  (already covered at `memory_test.go:50-63`, extended to the new call path).
- Integration (`package ssotest`): create a user through the invited
  provisioning path → `GET /lifecycle` returns `state: invited` with
  `allowed_transitions: [active, archived]`; a second invited seed → 409;
  INVITED → SUSPENDED → 400 `illegal_lifecycle_transition`.
- Acceptance trigger test: an INVITED user completes first login → lifecycle
  reads ACTIVE and the audit trail shows the `INVITED → ACTIVE` transition
  with `ActorSystem`; an admin accept produces the same state via the admin
  actor.
- Mandatory gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`, `make ci`.

---

## 3. PURGED tombstone semantics: the record must not outlive the erased account

**Name**: Purge tombstone — remove the lifecycle record after erasure; re-provisioning seeds fresh

**Problem**: After improvement 1 erases the account, the lifecycle record
stays in the store at `StatePurged` forever: the `Store` interface offers only
`Get`/`Append`/`ListByState` (`domains/userlifecycle/userlifecycle.go`), and
`memory.Store` keeps the record (a persisted PURGED record is even an explicit
test fixture at `memory/memory_test.go:88-89`). The codebase explicitly
anticipates re-registration of the same subject id — `compliance.Eraser`'s
`Consent` field doc says "a re-registered account under the same id does NOT
silently inherit prior consent" (`protocols/compliance/erasure.go:32-35`) —
yet nothing resets the lifecycle record on re-provisioning. A re-created
account therefore reads as PURGED, which is terminal (`transitions.go:33`:
`StatePurged: {}` — no exit edge), so the account is stuck: no legal
transition can ever restore it, and under direction 1's gate every
authentication is denied. Meanwhile the admin handlers 404 when the user does
not exist (`interfaces/admin/lifecycle.go`), so a PURGED record whose user was
deleted by the eraser is orphaned — invisible to admins, unreachable by any
transition, and a permanent poison for `ListByState(StatePurged)` consumers.
The state machine asserts "data erased" while the metadata itself survives to
contradict the next provisioning of that id.

**Evidence**:
- `domains/userlifecycle/userlifecycle.go` (`Store` interface): `Get`,
  `Append`, `ListByState` only — no `Delete`/`Reset`; nothing can clear a
  PURGED record.
- `domains/userlifecycle/memory/memory.go` (`Append`): a seed requires "no
  existing record" (`memory.go:52-55`) — so re-provisioning cannot even
  re-seed over a PURGED record without a new store capability or a reset path.
- `domains/userlifecycle/memory/memory_test.go:88-89`: a PURGED record is
  persisted and read back — the current intended behavior, which improvement 3
  changes.
- `domains/userlifecycle/transitions.go:33`: `StatePurged: {}` — terminal, no
  legal exit.
- `interfaces/admin/lifecycle.go:22-25, 46-49`: both handlers 404 when the
  `UserProvider` has no such user — an erased account's record is orphaned and
  unreachable.
- `protocols/compliance/erasure.go:32-35`: re-registration of the same subject
  id is an anticipated scenario (consent/MFA must not be inherited) — but the
  lifecycle record, the one store with no re-registration story, is not
  handled.

**Proposed behavior**:
- Extend the `Store` contract with `Delete(ctx context.Context, userID string)
  error` (idempotent: deleting an absent record is a no-op), implemented in
  `memory.Store` and required of any future SQL peer. Keep `Get`'s
  "no record = ACTIVE" semantics unchanged.
- Define the terminal sequence as: transition ARCHIVED → PURGED (Append) →
  run erasure (improvement 1) → audit the erasure report → `Store.Delete`.
  The purge history and the erasure report live on in the audit trail
  (`EventAdminUserLifecycleChanged` + report metadata); the lifecycle record
  itself is a tombstone that is removed once the erasure is done — "PURGED"
  is a terminal *event*, not a resting record state that blocks the future.
- Make re-provisioning resilient: the invited/SCIM create path (improvement 2)
  treats a found terminal record as "provision over it" — if the user was
  re-created after a purge, the seed `Append(StateNone → ...)` is preceded by
  `Delete` (crash-window repair: a record orphaned by a crash between erase
  and delete never blocks re-provisioning with `ErrStateConflict`).
- Update the docs in the same change: `docs/error-codes.md` and
  `docs/config-reference.md` state-machine sections say PURGED is terminal and
  the record is removed after erasure; re-provisioning starts a fresh account;
  `docs/openapi.yaml` documents the post-purge `GET /lifecycle` behavior
  (404 via the existing user-existence check).

**Acceptance check**:
- Unit (`domains/userlifecycle/memory`): `Delete` removes the record;
  `Get` afterwards returns `{State: DefaultState}`; deleting an absent record
  returns nil; `ListByState` no longer returns purged ids after delete.
- Integration (`package ssotest`): ARCHIVED → PURGED with erasure wired →
  `GET /api/v1/admin/users/:id/lifecycle` → 404 (user gone); re-create the
  same id through the provisioning path → `GET /lifecycle` returns `active`
  (or `invited` when the invited mode from improvement 2 is used), and a
  fresh login succeeds; the audit trail still contains the purge transition
  and the erasure report.
- Crash-window test: a PURGED record exists while the user does not →
  re-provisioning re-seeds without `ErrStateConflict` (the Delete-then-seed
  repair path).
- Mandatory gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`, `make ci`.

---

## Contract and gate updates (same change as the improvements)

| Surface | Update |
|---|---|
| `docs/error-codes.md` | PURGED semantics ("terminal; record removed after erasure"); fail-closed refusal reuses `internal_error`; no new lifecycle codes required (revisit only if a dedicated `purge_erasure_failed` is preferred — then register it here) |
| `docs/openapi.yaml` | Lifecycle POST: seed form for `state: invited`, erasure-summary fields in the PURGED response; state-model description reflects tombstone removal and re-provisioning |
| `docs/config-reference.md` | New knobs: `user_lifecycle.purge_requires_erasure`, invited-provisioning flag; state-machine section rewritten for erase-on-purge and reachable INVITED |
| `docs/feature-matrix.md` | Row 157: note PURGED erasure wiring and INVITED provisioning |

Ordering: improvement 1 first (it defines the PURGED semantics improvement 3
removes the record for), then improvement 2 (independent seed writer; the
acceptance trigger is required by direction 1's gate), then improvement 3
(record lifecycle). All three preserve the "unwired = byte-identical" anchor:
with no bus, no eraser, and no invite knob wired, the seven-state admin
surface behaves exactly as it does today. Mandatory verification after every
`.go` edit: `go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .`; full gate before
handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.
