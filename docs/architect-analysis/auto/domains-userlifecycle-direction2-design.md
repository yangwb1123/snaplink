# Design: `domains/userlifecycle` — direction 2, PURGED erases, INVITED becomes reachable, tombstones die

Source: `docs/auto/domains-userlifecycle-direction2-spec.md` (direction 2 of
`docs/auto/domains-userlifecycle-analysis.md`). This doc fixes the three
improvements — erase-on-purge via the `compliance.Eraser`, a production
INVITED provisioning entry plus acceptance trigger, and PURGED-tombstone
removal with re-provisioning repair — down to API surface, storage model,
failure modes, and the risks that could break the design.

## Verification record (spec claims vs. verified working tree)

Every claim was re-verified by source inspection before writing. Corrections
to the spec:

| Spec claim | Verified reality |
|---|---|
| "`applyLifecycleTransition` (lifecycle.go:73-91) only Appends + audits" | Confirmed: `Append` at `interfaces/admin/lifecycle.go:80`, `RecordTransition` at `:89`, nothing else. |
| "`OnUserPurged` has zero production callers; `NewLifecycleEventBus` only in tests/doc.go" | Confirmed: repo-wide grep hits only `bus_test.go`, `revoke_on_archive_test.go`, and `protocols/lifecyclereactions/doc.go`. `cmd/` never constructs the bus. |
| "`compliance.Eraser` built at `compliance_routes.go:32-47`, wired only to `/me/account/erase` + admin GDPR erase" | Confirmed: `newSelfServiceEraser` (line 32) + `complianceEraseHandler`; `mountComplianceRoutes` at `build_http.go:337`. `lateBindComplianceStores` (`compliance_routes.go:223`) binds consent/MFA/reset late because the eraser pointer is captured before those stores exist — the SAME pattern direction 2 reuses for the lifecycle eraser. |
| "INVITED seed edge exists (`transitions.go:26`) but no production `Append` reaches it" | Confirmed. Admin `Append` always passes `From=rec.State`; a record-less user reads `DefaultState` (ACTIVE), and `ACTIVE → INVITED` is illegal. The sweep (`sweep.go:142`) only emits ACTIVE/INACTIVE sources. |
| "`memory_test.go:88-89`: a PURGED record is persisted and read back" | **Citation wrong, behavior right.** Lines 88-89 are `TestGet_ReturnsCopy`, which appends a `StatePurged` transition to a *returned copy* to prove copies don't leak — not a PURGED persistence fixture. The real proof of "PURGED persists forever" is structural: the `Store` interface has no `Delete`, `memory.Store` never removes records, and `transitions.go:33` makes PURGED terminal. The spec's behavioral claim stands; the evidence lines don't. |
| "admin handlers 404 when the user does not exist (`lifecycle.go:22-25`)" | Confirmed, lines 28-31 (`UserProvider().GetByID` before any store access in both handlers). |
| "`erasure.go:32-35`: re-registration under the same id is anticipated" | Confirmed (`eraseConsent` doc: "a re-registered account under the same id does NOT silently inherit prior consent"). The lifecycle record is the one store with no re-registration story. |
| Direction-1 interplay | **Direction 1 has NOT landed**: no `AllowsAuthentication` / `rejectLifecycleBlockedUser` in the tree. Direction 2 must therefore specify its acceptance trigger against both orderings (landed / not landed) — see Decision 2.4. It also means direction 1's planned `interfaces/sso` budget shuffle (device-context block → `server_login_resolve.go`) may or may not have happened when direction 2 lands. |
| Budgets (new findings) | `interfaces/admin` is at its 10-file ceiling and every non-test file is 460-492 lines (`lifecycle.go` 481). `interfaces/sso` is at its frozen 60-file ceiling with nearly every file 488-500 (`options_admin.go` 474, `server_login_auth.go` 493, `server_admin_handlers.go` 498, `sso_selfservice.go` 469, `server_login_resolve.go` 413). `protocols/compliance` is at its 10-file ceiling. `cmd/sso-server/build_stores.go` 444, `build_app.go` 498. These force the mandatory moves in Decision 6. |
| Wiring order for the bus/eraser | Confirmed usable: `wireUserLifecycle` runs inside `wireGovernance` (`build_app_security.go:240`), `lateBindComplianceStores` runs after it (`build_app.go:257`) before `NewServer`, and SCIM/compliance routes mount later in `buildHTTPHandler` (`build_http.go:28` → `mountComplianceAndSCIM` at `:329`) — so a lifecycle eraser and an invite seeder built in `wireUserLifecycle` are fully populated before any request can arrive. |
| `userlifecycle_wiring_test.go` | Asserts `len(b.opts) == 0` (disabled) and `== 1` (enabled alone). Direction 2's new options change these counts — the assertions are updated in the same change (Decision 6.2). |

---

## Decision 1: Erase on purge — handler-owned synchronous erasure, `EraseOnPurge` as the reference reaction

### 1.1 Why the admin handler owns the erasure (spec deviation, with rationale)

The spec asks for three things that only one execution model satisfies
coherently: (a) the erasure report in the admin response, (b) a fail-closed
mode that refuses the transition *before* `Append`, and (c) a
`bus.OnUserPurged(EraseOnPurge(eraser))` registration in the composition root.

(a) and (b) require the erasure to run inside the admin handler with its
return value in hand: the bus is an `audit.Sink` — `invoke` discards the
reaction's error and there is no channel back to the handler, and the bus
fires inside `RecordTransition`, which the handler calls *after* `Append` (so
the bus can never refuse a transition). Running the erasure both in the
handler and in a registered `EraseOnPurge` reaction would execute every purge
twice (idempotent but wasteful, and the two executions would race each other
through the same stores).

**Decision: the admin handler executes the erasure; the composition root does
NOT register `OnUserPurged`.** `EraseOnPurge` still exists in
`protocols/lifecyclereactions` as the reference reaction for SDK embedders who
drive transitions without the admin handler (their own `RecordTransition`
calls, custom surfaces) — it is the documented, unit-tested implementation of
"purge = erase" on the bus seam. The spec's wiring-proof acceptance
("`NewLifecycleEventBus` is constructed in production code; `make ci` passes
with the bus registered as an audit sink") is met by constructing the bus and
registering `OnUserArchived(RevokeAccessOnArchive(...))` in `cmd/sso-server`
(Decision 1.4). "PURGED means erased is enforced when armed, never assumed"
holds: erasure runs exactly once, synchronously, in the request that commits
the PURGED state.

The sweep never reaches PURGED (`sweep.go` `nextState` only emits
ACTIVE → INACTIVE → ARCHIVED), so the bus's `OnUserPurged` hook has no other
production trigger to lose. The fail-closed guarantee is independent of the
audit recorder (the handler calls `EraseSubject` directly), which is
deliberately stronger than direction 1's reaction wiring (Decision 5).

### 1.2 API surface

**`protocols/lifecyclereactions/erase_on_purge.go` (new file; dir goes 2 → 3
non-test files, under the 10-file ceiling):**

```go
// EraseOnPurge returns a userlifecycle.ReactionFunc that runs the
// compliance.Eraser against userID the moment a user transitions into PURGED
// — the terminal-state twin of RevokeAccessOnArchive. A nil eraser or empty
// userID is a no-op; the Eraser is idempotent, so a second invocation on an
// already-erased subject returns a clean Report. The returned error is
// Report.Err() (best-effort aggregate). Dry-run is NOT part of the reaction —
// a purge is a commit; dry-run stays on the standalone compliance endpoints.
func EraseOnPurge(eraser *compliance.Eraser) userlifecycle.ReactionFunc
```

Import check: `protocols/lifecyclereactions` already imports
`domains/userlifecycle`; adding `protocols/compliance` is a same-rank sibling
edge — the forbidden pair is `protocols/oauth ↔ protocols/oidc` only. No
cycle: `compliance` imports `protocols/oauth` + `shared/core`, neither of
which imports `lifecyclereactions`.

**`interfaces/admin/deps.go` (177 lines, room) — three new Deps methods, all
nil/zero when unwired (byte-identical):**

```go
// LifecycleEraser returns the erasure engine wired for PURGED transitions,
// or nil when erase-on-purge is not armed (purges then behave exactly as
// today: state recorded, data untouched).
LifecycleEraser() *compliance.Eraser
// PurgeRequiresErasure reports whether a PURGED transition is REFUSED
// unless erasure completes first (user_lifecycle.purge_requires_erasure).
// Meaningful only when LifecycleEraser() != nil.
PurgeRequiresErasure() bool
// InviteProvisioning reports whether the INVITED provisioning surfaces are
// armed (user_lifecycle.invite.enabled) — see Decision 2.
InviteProvisioning() bool
```

**`interfaces/sso` — one new Option + three accessors (placement in the
mandatory shuffle, Decision 6.3):**

```go
// WithLifecycleErasure arms erase-on-purge: eraser is the finalized
// compliance.Eraser (Consent/MFA stores late-bound before serving, same
// pattern as WithSelfServiceAccountErasure); purgeRequiresErasure switches
// the admin handler into fail-closed mode. Unwired = purges record the
// terminal state with no erasure, exactly as today.
func WithLifecycleErasure(eraser *compliance.Eraser, purgeRequiresErasure bool) Option

func (s *Server) LifecycleEraser() *compliance.Eraser   // nil default
func (s *Server) PurgeRequiresErasure() bool            // false default
func (s *Server) InviteProvisioning() bool              // false default; Decision 2
```

`interfaces/sso` importing `protocols/compliance` is a downward edge
(interfaces → protocols), legal.

### 1.3 Handler flow (`interfaces/admin/lifecycle` subpackage — see Decision 6.1)

`applyLifecycleTransition` gains a PURGED branch, run only when
`d.LifecycleEraser() != nil`; every other state flows through the existing
Append → audit → 200 path byte-identically.

**Reaction mode (default; `PurgeRequiresErasure() == false`):**

1. `Append(ARCHIVED → PURGED)` — the transition commits first (existing
   conflict/500 handling unchanged).
2. `rep, err := eraser.EraseSubject(ctx, userID, compliance.EraseOptions{})`
   — credentials first, best-effort across stores, idempotent.
3. `RecordTransition(...)` with new variadic meta (below) carrying the
   erasure summary; the response carries the `compliance.ReportView`
   (below).
4. If `err == nil && rep.UserDeleted` → `LifecycleStore().Delete(userID)`
   (Decision 3). Delete failure is logged; the PURGED record then serves as
   its own tombstone and the Decision-3 repair path covers re-provisioning.

A partial erasure (`err != nil`) still returns 200 with
`erasure.errors` populated — the transition happened; the response and audit
make the partial state visible rather than claiming completion. This mirrors
the compliance erase endpoint's 207-with-report philosophy, but the lifecycle
POST's primary subject is the *transition*, so the code stays 200 and the
truth lives in the `erasure` block.

**Fail-closed mode (`PurgeRequiresErasure() == true`):**

1. `EraseSubject` runs BEFORE `Append`. Any error → no Append, response
   `500 internal_error` (state unchanged — `Store.Get` still reads ARCHIVED,
   no PURGED history entry), audit via new `RecordTransitionFailure`
   (OutcomeFailure, reason = erasure error, erasure summary meta). The 500
   matches the handler's existing store-error mapping (`core.ErrInternal`).
2. Clean erasure → `Append` → audits → conditional `Delete` → 200 with the
   report, as in reaction mode.
3. Residual: if `Append` conflicts *after* a clean erasure (two concurrent
   PURGED transitions), the user is already erased but the record shows the
   other writer's transition. The erasure is audited and the conflict
   returns 409; the orphaned record is repaired on next provisioning
   (Decision 3). Accepted residual, documented in the handler comment.

**Audit surface** (no new event types — `auditreport` classification
untouched):

- `RecordTransition` (`sweep.go:162`) becomes variadic:
  `RecordTransition(ctx, rec, userID, t, meta ...map[string]string)` —
  existing callers unchanged (direction-1 precedent: variadic meta on
  `recordLoginFailure`). New meta key `MetaErasureReport = "erasure_report"`
  (const beside `MetaTargetUser`): compact JSON of the summary
  (countable fields + `skipped` + `errors` as strings) — fixed key set,
  bounded cardinality.
- New `RecordTransitionFailure(ctx, rec, userID, t, reason string, meta
  ...map[string]string)`: same `EventAdminUserLifecycleChanged` with
  `OutcomeFailure` + reason. Used for fail-closed refusals.
- A second `EventAdminSubjectErased` emission is deliberately NOT added: the
  lifecycle event + report meta is the single truthful record of the purge;
  emitting the GDPR event from the operational surface would double-count
  erasures in compliance queries. Documented in the handler comment.

**Response shape** (`POST /api/v1/admin/users/:id/lifecycle`, PURGED only,
additive field):

```json
{ "user_id": "u1", "state": "purged", "previous_state": "archived",
  "allowed_transitions": [],
  "erasure": { "user_id": "u1", "refresh_tokens_deleted": 2, "sessions_destroyed": 3,
               "consent_revoked": 0, "mfa_factors_removed": 1, "reset_tokens_revoked": 0,
               "user_deleted": true, "skipped": [], "errors": [] } }
```

`compliance.ReportView` is the shared JSON view: exported struct +
`NewReportView(*Report) ReportView` added to `protocols/compliance/erasure.go`
(the package is at its 10-file ceiling — the type extends the existing file,
308 → ~350 lines, room). `cmd/sso-server/compliance_routes.go`'s private
`eraseResponse` is deleted and the handler switches to the shared view with
IDENTICAL JSON tags — the compliance wire bytes do not change (verified
field-by-field against `eraseResponse`).

### 1.4 Composition-root wiring (`cmd/sso-server/build_stores.go` `wireUserLifecycle`, 444 → ~488 lines)

```go
eraser := newLifecycleEraser(b.userProvider, b.sessionMgr, refreshIdx, b.clientStore)
// newLifecycleEraser mirrors newSelfServiceEraser; Consent/MFAEnrollments/
// PasswordReset are nil here and late-bound by lateBindComplianceStores
// (extended to also bind the lifecycle eraser — one extra block, same pattern).
if eraser != nil {
    b.opts = append(b.opts, sso.WithLifecycleErasure(eraser, cfg.PurgeRequiresErasure))
    if cfg.PurgeRequiresErasure && eraser == nil { /* unreachable; kept for the warning below */ }
}
bus := userlifecycle.NewLifecycleEventBus(
    userlifecycle.WithBusLogger(b.logger),
    userlifecycle.WithReactionErrorHandler(func(state userlifecycle.State, userID string, err error) {
        b.logger.Error("userlifecycle: reaction failed", "state", string(state), "user_id", userID, "error", err)
    }),
)
bus.OnUserArchived(lifecyclereactions.RevokeAccessOnArchive(b.sessionMgr, b.refreshTokenStore, b.clientStore))
if b.recorder != nil {
    b.recorder.AddSink(bus) // wiring-time call; AddSink is not concurrent-safe with Record
} else {
    b.logger.Warn("user_lifecycle: transition reactions INERT — audit.enabled is false (the bus is an audit sink)")
}
```

Rules pinned:

- **Eraser nil-ness is store-driven, not config-driven**: construct the
  lifecycle eraser only when at least one leg is usable (`Users`, `Sessions`,
  or `Refresh+Clients`). A nil eraser means `WithLifecycleErasure` is not
  emitted, the PURGED branch never arms, and the build is byte-identical to
  today — even with `purge_requires_erasure: true`.
- `purge_requires_erasure: true` + nil eraser → **loud boot warning** (same
  class as the audit-disabled bus warning), then the knob is inert: purges
  proceed un-erased. Rationale: enforcement requires something to enforce
  with; refusing every purge because an eraser wasn't wired would break the
  "nil eraser = no-op" anchor. The warning is the operator's signal.
- `lateBindComplianceStores` (`compliance_routes.go:223`) additionally binds
  `Consent`/`MFAEnrollments`/`PasswordReset` on the lifecycle eraser pointer
  (read at request time, same late-bind pattern as `accountEraser`).
- The bus is NOT registered with `OnUserPurged` in this root (Decision 1.1).
- Shutdown: only synchronous `On` reactions are registered; no `Close`
  wiring needed (direction-1 precedent).

---

## Decision 2: INVITED provisioning — seed writers and an acceptance trigger

### 2.1 Domain API (`domains/userlifecycle/provisioning.go`, new file; dir goes 5 → 6 non-test files)

```go
// Exists reports whether rec is a persisted record. Store.Get's contract
// pins "no stored record" to {State: DefaultState} with EMPTY history, so
// len(History) == 0 ⇔ no record — the admin seed form relies on this.
func (r Record) Exists() bool { return len(r.History) > 0 }

// SeedInvited seeds a brand-new account as INVITED (the StateNone seed edge
// of transitions.go). s is the lifecycle store; auditor may be nil. If a
// TERMINAL record (PURGED) already exists — a crash-window orphan from
// Decision 3 — the record is deleted first so re-provisioning starts fresh.
// Any other existing record returns ErrStateConflict (the caller decides
// whether that is a 400 or a 409). Audit: RecordTransition with
// From=StateNone, actor stamped by the caller.
func SeedInvited(ctx context.Context, s Store, auditor *audit.Recorder, userID, actor, reason string) error

// AcceptInvitation advances an INVITED account to ACTIVE — the
// invitation-acceptance trigger. No-op (nil) when the account is not
// INVITED (callers invoke it unconditionally on successful auth). A lost
// Append race re-reads: if the winner left the account ACTIVE, the loser
// proceeds; otherwise the conflict is returned and the caller's lifecycle
// gate (direction 1) remains the authority. Audit: RecordTransition with
// ActorSystem, reason "invitation accepted".
func AcceptInvitation(ctx context.Context, s Store, auditor *audit.Recorder, userID string) error

// Seeder is the optional provisioning hook inbound provisioning surfaces
// (protocols/scim) call after creating a user, so the account seeds INVITED
// instead of implicitly ACTIVE. Nil (unwired) = today's behavior.
type Seeder interface {
    SeedInvited(ctx context.Context, userID string) error
}
```

`userlifecycle.Seeder` is imported by `protocols/scim` — a downward edge
(protocols → domains), legal. `SeedInvited`/`AcceptInvitation` are domain
free functions owning their audit, mirroring `RecordTransition`; they are
pure w.r.t. the store (no logging).

### 2.2 Seed writer 1: admin seed form (`POST /api/v1/admin/users/:id/lifecycle`)

When `d.InviteProvisioning()` is true and `to == StateInvited`, the handler
branches BEFORE the `ValidateTransition(rec.State, to)` call (which would
reject ACTIVE → INVITED):

| `rec` at request time | Behavior |
|---|---|
| No record (`!rec.Exists()`) | Seed: `SeedInvited(... actor=admin, reason from body)`. A concurrent duplicate seed hits `Append`'s atomic no-record branch → `409 lifecycle_state_conflict` (existing code path). Response: 200, `state: invited`, `allowed_transitions: [active, archived]`, `previous_state` omitted (its wire value would be the empty `StateNone` string). |
| Existing record, `State == PURGED` | Decision-3 repair: `SeedInvited` deletes the terminal record and re-seeds. |
| Existing record, any other state | Falls through to normal validation → `400 illegal_lifecycle_transition` (spec: "a user with an existing record gets `illegal_lifecycle_transition`"). |
| Knob OFF | No branch; no-record reads ACTIVE → `400 illegal_lifecycle_transition` — byte-identical to today. |

The user-existence 404 check is unchanged: the seed targets an existing
`core.User` (the admin surface cannot repair an orphan whose user is gone —
that is the SCIM path's job, Decision 2.3).

### 2.3 Seed writer 2: SCIM create (`protocols/scim`)

- `scim.WithInviteSeeder(seeder userlifecycle.Seeder) Option` — new option
  added to `protocols/scim/handler.go` (349 → ~364 lines; NO new file — the
  package is on a frozen fan-out ceiling and adding to it is not worth the
  gate risk). Nil default → byte-identical.
- `createUser` (`handler_users.go:58`, after `CreateOrUpdate`, before the
  201): `if h.seeder != nil { if err := h.seeder.SeedInvited(r.Context(), id); err != nil { h.log... } }`.
  A seed failure logs and still returns 201 — user provisioning must not
  fail over governance metadata; the account then reads ACTIVE (visible via
  `GET /lifecycle`, auditable). `replaceUser`/`patchUser` do NOT seed:
  invites are a create-time property.
- The seeder is the config-gated adapter built at the composition root
  (spec's "config flag" option chosen over a SCIM attribute mapping — a
  per-resource attribute would invent SCIM semantics; the flag is
  unambiguous). `serverbuildplatform.NewInviteSeeder(store
  userlifecycle.Store, auditor *audit.Recorder) userlifecycle.Seeder`
  returns nil when the store is nil; stamps actor `ActorSystem`, reason
  "scim: invited provisioning". Carried on `*app` (set in
  `wireUserLifecycle`, consumed by `mountSCIMRoutes` via
  `mountComplianceAndSCIM` — ordering verified in the verification record).

### 2.4 Acceptance trigger: auto-accept on first login

`interfaces/sso` helper (placement in Decision 6.3):

```go
// maybeAcceptInvitation advances an INVITED account to ACTIVE on its first
// successful authentication — the invitation-acceptance trigger direction
// 1's login gate depends on. No-op when the lifecycle store is unwired, the
// invite surface is disabled, or accept_on_first_login is false. Best-effort:
// a store error is logged and the caller continues into the lifecycle gate,
// which then denies INVITED (fail-closed via the gate, never fail-open).
func (s *Server) maybeAcceptInvitation(ctx context.Context, userID string)
```

Call sites — exactly the two hot paths direction 1 gates:

1. `authenticateUser` (`server_login_auth.go`), immediately after
   `rejectDeactivatedUser` (line ~96), before lockout success registration.
   One added guard line.
2. `finalizeCallbackSession` (`server_oauth.go:221-227`), beside the inline
   SCIM check — the federated leg, so invited federated users are accepted
   before direction 1's `callback_failed` denial could fire.

MFA second legs need no call: the first leg already accepted.

**Ordering contract with direction 1 (both orderings must compose):** the
accept MUST run before the lifecycle gate's denial, so when both directions
land, first login = accept → gate sees ACTIVE → allow. The contract is
enforced structurally: direction 1's gate helper and `maybeAcceptInvitation`
land in the same file and the gate's doc comment pins "call after
maybeAcceptInvitation". If direction 1 lands first with its gate, an INVITED
account is denied until this trigger lands — acceptable interim (INVITED is
unreachable until direction 2's seed writers land anyway).

**Interim behavior note (direction 1 NOT landed):** with no gate in the tree,
a seeded INVITED account can authenticate today; `accept_on_first_login:
true` (default when the invite knob is on) flips it to ACTIVE on that first
login, so no account is left INVITED-usable-but-stale. With
`accept_on_first_login: false`, the account stays INVITED (admin accept —
the legal `INVITED → ACTIVE` transition, available unchanged — is the only
way out, and direction 1 then denies it at login until accepted). Both
semantics are documented in `docs/config-reference.md`.

Per-login cost: `AcceptInvitation` issues one `Store.Get` per successful
login, only when `invite.enabled && accept_on_first_login` (config gate first
— zero reads when the feature is off). When direction 1 lands, its gate reads
the same record; merging accept+gate into one read is a noted follow-up, not
a requirement.

### 2.5 Config (`config/config_admin.go`, 333 → ~365 lines, room)

```yaml
user_lifecycle:
  enabled: true
  purge_requires_erasure: false   # NEW — fail-closed purge (Decision 1)
  invite:
    enabled: false                # NEW — admin seed form + SCIM invited seeding
    accept_on_first_login: true   # NEW — INVITED -> ACTIVE on first successful auth
```

`UserLifecycleConfig` gains `PurgeRequiresErasure bool` and
`Invite UserLifecycleInviteConfig{Enabled, AcceptOnFirstLogin bool}` — both
default false/true as shown; config/ is at its frozen file ceiling, so the
fields fold into the existing struct (the file's own stated convention).

---

## Decision 3: PURGED tombstone — `Store.Delete`, the terminal sequence, and repair

### 3.1 Store contract

```go
// Delete removes userID's lifecycle record entirely. IDEMPOTENT: deleting an
// absent record is a no-op (nil). Callers: the PURGED terminal sequence
// (Decision 1.3) and the provisioning repair path (Decision 2.1). After
// Delete, Get returns {State: DefaultState} with empty history — the "no
// record = ACTIVE" anchor is unchanged, never a new "erased" read-back state.
Delete(ctx context.Context, userID string) error
```

Added to `domains/userlifecycle/userlifecycle.go` (164 → ~178 lines);
implemented in `memory.Store` (map delete under the existing lock, ~6 lines);
required of any future SQL peer. Compile-enforced: the only implementor
today is `memory.Store` plus test fakes — all must add the method (loud,
mechanical breakage, Decision 6.2).

### 3.2 The terminal sequence and the delete rule

`ARCHIVED → PURGED` (Append) → erasure (Decision 1) → audits (transition +
report meta) → **`Delete` iff `rep.Err() == nil && rep.UserDeleted`**.

The second condition is deliberate: "the record must not outlive the erased
account" — and the erased account is one whose `core.User` record was
deleted. When the eraser has no `Users` leg wired (`skipped: ["user(not
wired)"]`), the account survives; deleting the record then would make it
read ACTIVE while the operator's intent was purge — instead the PURGED
record persists as the honest terminal marker (direction 1 denies login),
and re-provisioning uses the repair path. When the user IS deleted, the
record is removed exactly when the orphan problem would otherwise begin
(admin handlers 404 on the gone user, leaving the record unreachable).
Purge history and the erasure report live on in the audit trail; the
lifecycle store itself is reset for the next provisioning of that id.

`Delete` failure after a clean erasure is logged; the record stays PURGED
(now orphaned) — the repair path below is the recovery, and
`ListByState(StatePurged)` consumers see the orphan until then (documented;
no production consumer exists today).

### 3.3 Crash-window repair

A crash between erase and delete (or a delete failure) leaves a PURGED
record for a deleted user. `SeedInvited` (Decision 2.1) treats a found
terminal record as "provision over it": `Delete` then seed. This is the
guarantee that re-provisioning the same subject id never inherits an
inescapable PURGED record — the `ErrStateConflict` the atomic seed branch
would otherwise raise. Covered by the crash-window test (Decision 7).

Post-purge `GET /api/v1/admin/users/:id/lifecycle` returns 404 via the
EXISTING user-existence check (unchanged handler, no new code path).

---

## Decision 4: Storage model

No new storage. The design extends one interface and consumes existing
stores read/write through existing SPIs:

| Store | Change | Access pattern |
|---|---|---|
| `userlifecycle.Store` (`memory.Store`) | + `Delete` (idempotent) | Write: terminal sequence, seed repair. Read: `Get` in the seed/accept paths |
| `compliance.Eraser` composition (`Users`/`Sessions`/`Refresh`+`Clients`/`Consent`/`MFAEnrollments`/`PasswordReset`) | none (reused; finalized pointer late-bound) | Write on PURGED transition only |
| `core.SessionManager`, `oauth.RefreshTokenSubjectIndex`, `core.ConsentStore`, `core.MFAEnrollmentStore`, `core.UserProvider`, ... | none | Written by the eraser during purge |
| `platform/audit.Recorder` | none | Lifecycle event + report meta; bus as additional sink |

Anchors preserved:

- **No record = ACTIVE**: `Store.Get` unchanged; `Delete` only ever removes
  records, and the delete rule (3.2) never removes a record that would
  misrepresent a surviving account.
- **Unwired = byte-identical**: nil store (no `WithUserLifecycle`), nil
  eraser (no `WithLifecycleErasure`), invite knob off, nil seeder, nil bus —
  every new seam is a no-op by construction; PURGED-without-erasure remains
  possible only when the operator has not armed an eraser, never silently by
  default.
- Memory store remains per-process; in a multi-replica deployment the
  lifecycle view diverges per replica (inherited from the state machine
  itself) while the erasure operates on the shared stores — idempotent
  across replicas, so a purge applied twice is safe.

---

## Decision 5: Failure modes and outage policy

| Surface | Failure | Behavior |
|---|---|---|
| PURGED transition, no eraser wired | — | Record + audit only, exactly today. Fail-closed knob inert, boot warning if set. |
| Reaction mode, erasure partial failure | per-store errors | Transition stands (PURGED); 200 with `erasure.errors`; audit meta carries the report; record NOT deleted (rule 3.2). Partially-erased purge is visible, never claimed complete. |
| Fail-closed mode, erasure failure | any store error | No Append; `500 internal_error`; state reads ARCHIVED; `RecordTransitionFailure` audit; no PURGED history. Oracle-safe: response body is the standard `internal_error`. |
| Clean erasure, `Store.Delete` fails | store error | Logged; PURGED record persists (orphaned if user deleted); repaired on next provisioning (3.3). |
| Crash between erase and delete | — | Orphaned PURGED record; `ListByState(PURGED)` lists it; re-provisioning repairs (3.3). |
| Fail-closed, `Append` conflicts after clean erasure | concurrent transition | Erasure audited, 409; orphaned record repaired on provisioning. Accepted residual (1.3). |
| Duplicate INVITED seed (admin) | race | 409 `lifecycle_state_conflict` (atomic seed branch). |
| Seed over existing non-terminal record | — | Admin: 400 `illegal_lifecycle_transition` (2.2). SCIM: logged, 201 (account keeps its state). |
| `AcceptInvitation` store error | — | Logged; control falls to the lifecycle gate, which denies INVITED — fail closed via the gate, never fail-open. |
| `audit.enabled: false` | — | Handler-owned erasure and fail-closed still enforce (direct call, nil-safe audit helpers). The bus reactions are inert with a boot warning (direction-1 coupling, inherited). **This is a deliberate strength of the handler-owns model**: erase-on-purge does not depend on the audit backbone. |
| Login concurrent with purge | TOCTOU | A login that read ACTIVE pre-Append can mint a session post-erasure; the refresh gate (direction 1) cuts the token path. Same accepted class as direction 1's TOCTOU; MFA/transaction re-checks shrink, not eliminate. |
| Multi-replica | — | Per-replica erasure over shared stores: idempotent, safe. Lifecycle record divergence inherited from the memory store. |

Fail-closed posture is consistent with the direction-1 precedent (a
lifecycle-store outage denies; a suspension invariant is not an oracle).
Erase-on-purge's refusal is `internal_error`, not a new code — the spec's
"no new lifecycle codes" holds; a dedicated `purge_erasure_failed` is
deliberately NOT added (the refusal is a server-side operation failure, not
a request-shape problem, and 500 + audit reason is the codebase's existing
shape for that class).

---

## Decision 6: What could break the design

1. **`interfaces/admin` is at its 10-file ceiling AND every file is 460-492
   lines (highest mechanical risk).** The new handler logic (seed branch,
   erasure orchestration, report/audit helpers ≈ 90 lines) cannot fit
   `lifecycle.go` (481). Mandatory pre-step: create subpackage
   `interfaces/admin/lifecycle` (package `adminlifecycle`), moving
   `HandleAdminGetUserLifecycle`, `HandleAdminTransitionUserLifecycle`,
   `applyLifecycleTransition`, `writeLifecycleValidationError` (~100 lines)
   there together with the new logic (~190 lines total; split into
   `handlers.go` + `erasure.go` under the subdir's own 10-file budget).
   Root `lifecycle.go` keeps the device/token-exchange/login-history
   handlers and is renamed `devices.go` (root stays at 10 files — within
   the ceiling; the new subdirectory counts against its own budget). The
   subpackage imports the parent for `Deps` (same-layer edge, legal; the
   parent never imports the child, so no cycle). `layerName` classifies it
   "interfaces" by prefix — no `layerExemptions` entry. `server_admin_handlers.go`
   (498) renames two call sites and adds one import line → 499, fits.
   Rejecting the subpackage is not an option: the root has no headroom and
   no file slot.
2. **`Store` interface growth breaks fakes; wiring-test assertions change.**
   `Delete` on the interface is compile-enforced (memory + any test fakes).
   `userlifecycle_wiring_test.go`'s `len(b.opts) == 0/1` assertions change:
   enabled-alone with no eraser stores still wires 1 option; with eraser
   stores, 2 (store + erasure). Updated in the same change.
3. **`interfaces/sso` is saturated (60-file ceiling, files 488-500).**
   Mandatory shuffle: relocate the userlifecycle option cluster
   (`WithUserLifecycle`, `WithUserAutoDeprovision`, `LifecycleStore`,
   `RunUserAutoDeprovision`, `userDeprovisionDeps`, ~81 lines,
   `options_admin.go:270-350`) to `server_routes_admin.go` (332 → 413),
   which already hosts the lifecycle route registration; add the new options
   + accessors there (→ ~464) and the 4 Server fields beside the existing
   lifecycle fields in `sso_selfservice.go` (469 → ~479). `maybeAcceptInvitation`
   goes to `server_login_resolve.go` (413 → ~428). `options_admin.go` sheds
   the cluster (474 → ~393). **Direction-1 interplay**: if direction 1 has
   already moved its device-context block into `server_login_resolve.go`
   (413 → 486), `maybeAcceptInvitation` instead lands in `server_pairwise.go`
   (394, 106 headroom). The shuffle is mandatory, not cosmetic; reviewers
   rejecting it leave no legal home for the surface.
4. **`protocols/compliance` at its 10-file ceiling**: `ReportView` extends
   `erasure.go` (308 → ~350), no new file. `protocols/scim` on a frozen
   fan-out ceiling: the seeder option extends `handler.go`, no new file.
5. **Double-erasure risk** if a reviewer "helpfully" adds
   `bus.OnUserPurged(EraseOnPurge(...))` alongside the handler erasure in
   `cmd` — both would run per purge (idempotent but wasteful and racy).
   The composition-root comment pins the single-execution rule (1.1/1.4).
6. **Direction-1 gate ordering** (deadlock risk): if direction 1 lands and
   its gate denies INVITED before `maybeAcceptInvitation` runs, invited
   accounts are dead on arrival. Pinned by the call-site ordering contract
   (2.4) and the shared-file placement.
7. **Fail-closed erase-then-Append orphan window** (1.3): a concurrent
   transition after a successful pre-Append erasure orphans the record.
   Rare, audited, repaired on provisioning. Accepted.
8. **`purge_requires_erasure` without an eraser** looks like a config
   mistake to operators: knob inert + loud boot warning (1.4). The
   invariant "enforced when armed, never assumed" holds because the knob
   arms nothing by itself.
9. **`previous_state` wire value for seeds** is the empty string (StateNone);
   the seed response omits it. `docs/openapi.yaml` must document the
   omission or clients will read `"previous_state": ""`.
10. **Seed-form semantics are knob-gated**: an operator who seeds INVITED
    then disables `user_lifecycle.invite.enabled` still has the INVITED
    records (states persist) but loses the seed form and auto-accept —
    accounts remain INVITED and (with direction 1) denied at login until
    admin-accepted via the always-legal INVITED → ACTIVE transition. All
    three surfaces (seed, accept, admin-accept) are documented in
    `docs/config-reference.md` so the interaction is not a surprise.
11. **Multi-replica lifecycle divergence** and **AddSink concurrency**: both
    inherited (memory store; AddSink is wired during build, before serving —
    the established pattern). No new exposure.
12. **Audit bounded cardinality**: the erasure meta is a single fixed-key
    JSON summary; no unbounded per-request metadata. `auditreport` needs no
    classification (no new event types).

## Decision 7: Test plan (mapping the spec's acceptances)

- **Unit — `domains/userlifecycle/memory`**: `Delete` removes; `Get`
  afterwards returns `{State: DefaultState}`; deleting an absent record is
  nil; `ListByState` drops purged ids after delete. `SeedInvited`: fresh →
  INVITED (history length 1, audit event); PURGED record → deleted + re-seed;
  non-terminal record → `ErrStateConflict`. `AcceptInvitation`: INVITED →
  ACTIVE (ActorSystem, reason "invitation accepted", audit event); ACTIVE/
  other states → nil no-op; conflict re-read → nil when winner left ACTIVE.
- **Unit — `protocols/lifecyclereactions`**: `EraseOnPurge` calls
  `EraseSubject(userID, EraseOptions{})` (no dry-run); nil eraser / empty
  userID → nil no-op; second invocation on an erased subject → nil
  (idempotent); failing store → joined error; a panicking reaction cannot
  crash the bus (`invoke` containment, existing `bus_test.go` machinery).
- **Unit — `interfaces/admin/lifecycle` (adminlifecycle)**: seed-form branch
  table (no record / PURGED / other / knob off); fail-closed refusal shape.
- **Integration — `test/` (`package ssotest`)**, harness per
  `account_lockout_test.go` pattern:
  - Purge: seed account with live sessions + refresh family; ARCHIVED →
    PURGED with eraser wired → sessions destroyed, tokens revoked across
    clients, `user_deleted: true`, response carries the erasure view, audit
    trail has the transition + report meta; `GET /lifecycle` → 404; same id
    re-provisioned → seeds fresh, login succeeds, purge audit intact.
  - Fail-closed: `purge_requires_erasure=true` + eraser whose `Users.Delete`
    fails → 500 `internal_error`, `Store.Get` still ARCHIVED, no PURGED
    history, failure audit present.
  - Invite: invited provisioning → `GET /lifecycle` → `state: invited`,
    `allowed_transitions: [active, archived]`; duplicate seed → 409; admin
    INVITED → SUSPENDED → 400 `illegal_lifecycle_transition`; first login →
    ACTIVE + `ActorSystem` audit; admin accept → ACTIVE.
  - Crash window: PURGED record present, user absent → re-provision re-seeds
    without `ErrStateConflict`.
  - Unwired anchors: no eraser → purge byte-identical to today (no erasure
    block in the response); no invite knob → seed form returns 400.
- **Wiring — `cmd/sso-server`**: bus constructed + `AddSink` observed
  (extend `userlifecycle_wiring_test.go`; opts counts per 6.2);
  `lateBindComplianceStores` binds the lifecycle eraser; SCIM seeder
  plumbed through `mountComplianceAndSCIM`; `purge_requires_erasure` without
  eraser → boot warning path.
- **Gates**: after every edit `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`; before handoff
  `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.

## Decision 8: Contract and gate updates (same change)

| Surface | Update |
|---|---|
| `docs/error-codes.md` | State-machine section: PURGED = terminal event; record removed after clean erasure; re-provisioning seeds fresh; fail-closed refusal reuses `internal_error`. No new codes. |
| `docs/openapi.yaml` | Lifecycle POST: `state: invited` seed form (knob-gated), `erasure` block in the PURGED response, `previous_state` omitted for seeds, post-purge GET 404 note. |
| `docs/config-reference.md` | `user_lifecycle.purge_requires_erasure`; `user_lifecycle.invite.{enabled,accept_on_first_login}`; state-machine section rewritten for erase-on-purge, reachable INVITED, tombstone removal, and the knob-interaction note (Decision 6.10). |
| `docs/feature-matrix.md` | Row 157: PURGED erasure wiring + INVITED provisioning + acceptance. |
| `platform/audit` | No change: no new event types; `RecordTransition` variadic meta and `RecordTransitionFailure` reuse `EventAdminUserLifecycleChanged` (OutcomeSuccess/Failure). |

Ordering: Decision 1 first (it defines the PURGED semantics Decision 3
removes the record for), then Decision 2 (independent seed writers; the
acceptance trigger is direction 1's dependency), then Decision 3 (record
lifecycle). All three preserve the "unwired = byte-identical" anchor; the
mandatory budget shuffles (Decision 6.1, 6.3) are the first commits of the
change, before any feature logic.
