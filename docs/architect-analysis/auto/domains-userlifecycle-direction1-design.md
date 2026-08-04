# Design: `domains/userlifecycle` — direction 1, lifecycle state becomes an enforced auth gate

Source: `docs/auto/domains-userlifecycle-direction1-spec.md` (direction 1 of
`docs/auto/domains-userlifecycle-analysis.md`). This doc fixes the three
improvements — a login-path lifecycle gate, a refresh-grant lifecycle gate,
and transition-time revocation — down to API surface, storage model, failure
modes, and the risks that could break the design.

## Verification record (spec claims vs. verified working tree)

Every claim was re-verified by source inspection before writing. Corrections
to the spec:

| Spec claim | Verified reality |
|---|---|
| "Three existing `rejectDeactivatedUser` sites" | There are **four** call sites (`grep -rn rejectDeactivatedUser interfaces/sso`): `server_login_auth.go:98` (password/LDAP `authenticateUser`), `server_mfa.go:359` (`resumeLoginAfterMFA`), `server_mfa_trust.go:256` (`resumeLoginTransaction` — **missed by the spec**), plus the inline SCIM check at `server_oauth.go:221–227` (`finalizeCallbackSession`). Five post-credential enforcement points total. The design covers all five. |
| "add `rejectLifecycleBlockedUser` ... in `interfaces/sso/server_login_auth.go`" | `server_login_auth.go` is 493 lines against a hard 500-line physical-line budget (`maintainability_budget_test.go` `countFileLines` counts `\n` bytes; exemptions frozen at zero). Every `interfaces/sso` file is 488–500 lines and the directory sits at exactly the frozen 60-file ceiling. The helper **cannot** be added without an extractive move (see Decision 1). |
| Federated callback "invoked immediately after `rejectDeactivatedUser`" at `server_oauth.go:223` | That site is the inline SCIM check, not a `rejectDeactivatedUser` call, and its denial shape is **401 `callback_failed`**, not 403 `account_locked`. Per-site collapse must mirror the site's existing SCIM denial (Decision 1.4). |
| `OnUserSuspended` "zero production callers" | Confirmed: repo-wide grep hits only `bus_test.go`; `wireUserLifecycle` (`cmd/sso-server/build_stores.go:328`) wires store + sweep only. |
| Refresh gate sits "after session-liveness, before any rotation side effect" | Confirmed in `internal/handler/tokengrant/token_refresh.go`: `refreshCheckSessionLiveness` ends ~line 93, then `refreshResolveGrant` (~96), depth policy, `refreshVelocityGate` (which calls `RecordRotation` — a side effect). The gate inserts between liveness and resolve. |
| `userlifecycle.Store.Get` no-record contract | Confirmed (`domains/userlifecycle/userlifecycle.go` + `memory/memory.go:34`): unknown user → `{State: DefaultState}`, never an error. |
| Bus is an `audit.Sink` keyed on `EventAdminUserLifecycleChanged` | Confirmed (`domains/userlifecycle/bus.go` `Record`; `RecordTransition` at `sweep.go:162` emits it for admin- and sweep-driven moves alike, setting `MetaTargetUser`/`MetaFromState`/`MetaToState`). |
| Composition-root wiring order supports the bus | Confirmed: `wireFoundation` (sets `b.recorder` via `wireAudit`, `build_app_core.go:221`) → `wireDomains` (sets `b.refreshTokenStore` at `build_app_oauth.go:300`) → `wireEdge` → `wireGovernance` (`build_app.go:251`) → `wireUserLifecycle` (`build_app_security.go:240`). `b.sessionMgr`/`b.clientStore`/`b.refreshTokenStore`/`b.recorder` are all populated beforehand. |
| `audit.Recorder.AddSink` | Confirmed at `platform/audit/recorder.go:131`; documented "not safe for concurrent use with Record — call it during wiring". Wired during build: compliant. |
| Pre-existing doc drift (unrelated, flagged not fixed) | `docs/error-codes.md:139` documents `account_locked` as **423**, but the code writes **403** (`http.StatusForbidden`) at every site (`server_login_auth.go:101`, `:156`). The gates below pin the code's 403; the contract update must reconcile the doc row. |
| No token-exchange chain store in the composition root | Confirmed: no `ChainStore` in `cmd/sso-server` or `interfaces/admin.Deps`. The spec's optional chain-store reaction leg is dropped (Decision 3.3). |

Other anchors: `recordLoginFailure` at `server_helpers.go:282` (also bumps
`LoginAttemptsTotal` + dispatches anomaly); `audit.RecordLoginFailure`
(`recorder_events_session.go:134`) and `audit.RecordCallbackFailure` (:170)
take no meta today; `audit.SetMeta` at `handler_helpers.go:110`;
`LifecycleStore()` accessor at `options_admin.go:305` (file at 474 lines, 26
headroom); `authzErrorBodyWithState` at `server_discovery.go:290`;
`var _ tokengrant.RefreshGrantDeps = (*Server)(nil)` guard at
`accessors_handlers.go:363`; `userlifecycle_wiring_test.go` asserts
`len(b.opts) == 1` / `== 2` — so the design adds **no new `sso.Option`**.

---

## Decision 1: Login-path lifecycle gate — one domain predicate, one thin server helper, five call sites

### 1.1 API surface

**Domain (rank 2, `domains/userlifecycle/userlifecycle.go` — file is 164 lines, room):**

```go
// AllowsAuthentication reports whether lifecycle state s may complete an
// authentication. Only ACTIVE (and the implicit no-record zero value, which
// Store.Get already maps to DefaultState) is allowed; INVITED is denied
// because an invitation must be provisioned to ACTIVE before first login.
// Enforcement seams (interfaces/sso login gate, tokengrant refresh gate)
// call this so the state set cannot drift from the policy.
func AllowsAuthentication(s State) bool { return s == StateActive || s == StateNone }
```

This is the "domain free function" per AGENTS.md §5's domain-extraction
pattern: the decision is pure, testable, and shared by both gates. No new
file in `domains/userlifecycle` (6 non-test files today; the 10-file
per-directory ceiling is respected either way).

**Interfaces (rank 5, `interfaces/sso/server_login_auth.go`):**

```go
// lifecycleAuthBlocked resolves the wired lifecycle store for userID.
// Returns (blocked, state). Nil store → not blocked (byte-identical unwired
// builds). No record → not blocked (Store.Get returns DefaultState). Read
// error → blocked (FAIL CLOSED — a suspension is a security invariant;
// deliberately NOT the fail-open posture of rejectDeactivatedUser's SCIM
// read nor of tenant-suspension lookups, see Decision 5).
func (s *Server) lifecycleAuthBlocked(ctx context.Context, userID string) (bool, userlifecycle.State)

// rejectLifecycleBlockedUser denies non-ACTIVE lifecycle states AFTER
// credential verification and AFTER the SCIM check, BEFORE any
// session/token side effect — the same ordering contract as
// rejectDeactivatedUser. Collapses to the existing 403 account_locked
// (an unavailable account, not a credential oracle); state lands only in
// audit (meta "lifecycle.state") + server log. Returns true when the
// response was written.
func (s *Server) rejectLifecycleBlockedUser(ctx HandlerContext, req *login.Request, userID string) bool
```

The helper writes the response itself (mirroring `rejectDeactivatedUser`'s
shape), so each call site stays a one-line guard. The write is:
`recordLoginFailure(...) + ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))`.

**Budget-preserving pre-step (mandatory):** `server_login_auth.go` is 493
lines; the two functions above (~30 lines with doc comments) push it over.
Move the self-contained device-context summary block — `deviceContext`
struct (line 268) through `deviceTypeFromCtx` (ends ~line 340), 73 lines —
to `server_login_resolve.go` (413 lines, 87 headroom; it already hosts
`WithDeviceStore`/`WithDevicePolicy`/`WithLoginHistoryStore`, so the device
helpers are thematically at home). Result: 420 + 30 ≈ 450 and 413 + 73 =
486, both ≤ 500. This is the "split before feature work if the change would
cross a budget" discipline AGENTS.md §2 requires. No new file in
`interfaces/sso` (60-file ceiling — the helper **must** extend an existing
file).

### 1.2 Call sites (five, not three)

| # | Site | Existing SCIM denial | Lifecycle denial (byte-identical at that site) |
|---|---|---|---|
| 1 | `server_login_auth.go:98` (`authenticateUser`) | 403 `account_locked` | 403 `account_locked` |
| 2 | `server_mfa.go:359` (`resumeLoginAfterMFA` — second leg, closes the challenge-TTL window) | 403 `account_locked` | 403 `account_locked` |
| 3 | `server_mfa_trust.go:256` (`resumeLoginTransaction`) | 403 `account_locked` | 403 `account_locked` |
| 4 | `server_oauth.go:221–227` (`finalizeCallbackSession`) | 401 `callback_failed` | 401 `callback_failed` + `recordCallbackFailure` (the SCIM leg there today only logs; the lifecycle leg additionally records the block so the state reaches audit) |

Each site adds one guard after the existing SCIM check; sites 2–4 files have
4–29 lines of headroom (471 / 491 / 495) — a one-line guard each fits.

### 1.3 Audit metadata

Extend `recordLoginFailure` (`server_helpers.go:282`) and
`audit.RecordLoginFailure` (`recorder_events_session.go:134`) with a variadic
`meta ...map[string]string` (applied via `audit.SetMeta`); existing callers
are untouched (variadic). The gate passes
`map[string]string{userlifecycle.MetaLifecycleState: string(state)}` with
`MetaLifecycleState = "lifecycle.state"` (new const in `sweep.go` next to
`MetaTargetUser`). Cardinality is bounded by the six-state enum — compliant
with the audit bounded-cardinality rule. The existing `account_locked`
reason, metric bump, and anomaly dispatch all flow unchanged through
`recordLoginFailure`. `audit.RecordCallbackFailure` gets the same variadic
meta for the federated leg.

### 1.4 Semantics pinned

- Denied: SUSPENDED, INACTIVE, ARCHIVED, PURGED, INVITED.
- Allowed: ACTIVE, no-record (Store.Get contract), nil store (no-op).
- Read error: denied (fail closed), logged, audited with `lifecycle.state`
  empty and reason `account_locked` — indistinguishable from a real
  suspension on the wire, by design.
- Ordering: after credential verification + SCIM check, before lockout
  success-registration, before session/code/token side effects.

---

## Decision 2: Refresh-grant lifecycle gate — optional accessor on `RefreshGrantDeps`, oracle-safe `invalid_grant`

### 2.1 API surface

**`internal/handler/tokengrant/token_refresh.go` — add to `RefreshGrantDeps`:**

```go
// LifecycleState returns the user's lifecycle state (userlifecycle.State).
// Satisfied by *sso.Server via accessors_token_grant.go's guard pattern.
// Nil lifecycle store → (DefaultState, nil): the unwired build is a
// byte-identical no-op. No record → DefaultState (Store.Get contract).
// Any error is a fail-closed denial per the gate's contract.
LifecycleState(ctx context.Context, userID string) (userlifecycle.State, error)
```

`internal/handler/tokengrant` is classified `interfaces` (rank 5) by
`architecture_layer_test.go` (`internal/handler` prefix); importing
`domains/userlifecycle` (rank 2) is a downward edge — no `layerExemptions`
entry needed. Direct interface addition (not a runtime-asserted optional
interface): `RefreshGrantDeps` is internal with exactly one production
implementor, and the compile-time guard at `accessors_handlers.go:363`
enforces the method's existence. Test doubles implementing
`RefreshGrantDeps` must add the method (mechanical; the interface change is
compile-enforced so no double can silently miss it).

**`interfaces/sso/options_admin.go` (next to `LifecycleStore()`, line 305; 26 lines headroom):**

```go
func (s *Server) LifecycleState(ctx context.Context, userID string) (userlifecycle.State, error) {
    if s.userLifecycleStore == nil {
        return userlifecycle.DefaultState, nil // unwired → no-op
    }
    rec, err := s.userLifecycleStore.Get(ctx, userID)
    return rec.State, err // no-record already reads DefaultState
}
```

### 2.2 Gate placement and shape in `HandleRefreshGrant`

Insert immediately after `refreshCheckSessionLiveness` (line ~93) and before
`refreshResolveGrant`:

```go
if state, err := d.LifecycleState(ctx.Request().Context(), info.UserID); err != nil {
    d.LogErrorCtx(ctx, "lifecycle gate lookup failed (fail-closed)", "user_id", info.UserID, "error", err)
    ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
    return
} else if !userlifecycle.AllowsAuthentication(state) {
    d.LogErrorCtx(ctx, "refresh denied: user lifecycle state blocks rotation",
        "user_id", info.UserID, "state", string(state), "family", info.FamilyID)
    ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
    return
}
```

Pinned properties:

- **Byte-identical oracle collapse**: `core.ErrorBody(core.ErrInvalidGrant)` —
  the exact body of the unknown/expired/consumed path. No new error code, no
  distinguishing detail; state goes only to the server log (the refresh path
  has no audit event for denials today — matching the absolute-max-lifetime
  and liveness precedents, no new event type is invented, and
  `auditreport` classification is avoided).
- **Runs after `Consume`**: the presented token is consumed before denial —
  no token leak. A second presentation of the same token hits the existing
  reuse path and kills the family (unchanged semantics; for a suspended user
  this is desirable — the family is already slated for deletion).
- **No side effects before the gate**: it precedes `refreshVelocityGate`'s
  `RecordRotation`, so a denied suspended user's family is not even counted.
- **Fail-closed on read error**, matching the documented
  `refreshCheckSessionLiveness` contract ("A store error is treated as
  'session not found'"). Called out in the gate's doc comment as
  deliberately different from tenant-suspension fail-open.
- **No-record = ACTIVE** (`Store.Get` → `DefaultState`) and **nil store =
  ACTIVE** (accessor) — both byte-identical to today.
- Doc comment on `HandleRefreshGrant` and `docs/config-reference.md`
  ("User Lifecycle") updated in the same change.

---

## Decision 3: Transition-time revocation — `RevokeAccessOnSuspend` + composition-root bus wiring

### 3.1 API surface

**`protocols/lifecyclereactions/revoke_on_suspend.go` (new sibling file; dir
goes 2 → 3 non-test files, under the 10-file ceiling):**

```go
// RevokeAccessOnSuspend returns a userlifecycle.ReactionFunc that revokes
// every refresh token (across every registered client) and destroys every
// active session the moment a user transitions into SUSPENDED — the
// SUSPENDED twin of RevokeAccessOnArchive, sharing its extracted legs
// (revokeRefreshTokens / destroySessions). Same credentials-first ordering,
// best-effort-across-stores, idempotent, never-less-locked-out contract.
func RevokeAccessOnSuspend(sessions core.SessionManager,
    refresh oauth.RefreshTokenSubjectIndex, clients core.ClientStore) userlifecycle.ReactionFunc
```

Implementation shares the existing package-private `revokeRefreshTokens` /
`destroySessions` from `revoke_on_archive.go` (already extracted; no
refactor needed). `RevokeAccessOnArchive` is unchanged.

### 3.2 Composition-root wiring (`cmd/sso-server/build_stores.go` `wireUserLifecycle`)

When `user_lifecycle.enabled` (store != nil), after the existing
`WithUserLifecycle` option:

```go
bus := userlifecycle.NewLifecycleEventBus(
    userlifecycle.WithBusLogger(b.logger),
    userlifecycle.WithReactionErrorHandler(func(state userlifecycle.State, userID string, err error) {
        b.logger.Error("userlifecycle: revocation reaction failed",
            "state", string(state), "user_id", userID, "error", err)
    }),
)
bus.OnUserSuspended(lifecyclereactions.RevokeAccessOnSuspend(b.sessionMgr, b.refreshTokenStore, b.clientStore))
bus.OnUserArchived(lifecyclereactions.RevokeAccessOnArchive(b.sessionMgr, b.refreshTokenStore, b.clientStore))
if b.recorder != nil {
    b.recorder.AddSink(bus) // wiring-time call; AddSink is not concurrent-safe with Record
} else {
    b.logger.Warn("user_lifecycle: transition-revocation reactions INERT — audit.enabled is false (the bus is an audit sink)")
}
```

- **No new `sso.Option`**: the bus stays composition-local; the
  `WithUserLifecycle` signature is unchanged and `userlifecycle_wiring_test.go`'s
  `len(b.opts)` assertions keep passing. SDK embedders get reactions by
  constructing a bus + `recorder.AddSink(bus)` themselves (the pattern
  already documented in `lifecyclereactions/doc.go`).
- **Synchronous `On`** (not `OnAsync`): the bus dispatches inside
  `RecordTransition`, which `applyLifecycleTransition` calls after `Append`
  and before writing the 200 — so the admin response implies revocation
  completed. Reaction failure is logged via the error handler and never
  fails the transition (the bus's documented best-effort contract).
- **Both admin- and sweep-driven transitions fire the bus**: the audit-sink
  seam observes `EventAdminUserLifecycleChanged` from `RecordTransition`
  (admin handler `interfaces/admin/lifecycle.go` and sweep `sweep.go:148`)
  with zero new instrumentation. Sweep-driven `INACTIVE → ARCHIVED`
  triggers `RevokeAccessOnArchive` too — a behavior improvement, not a
  regression (archive semantics already promise revoked access).
- **Shutdown**: only `On` (synchronous) reactions are registered, so
  `bus.Close` has nothing to drain; no shutdown wiring is added. A future
  switch to `OnAsync` must pair with `bus.Close` in the shutdown sequence.
- **`audit.enabled: false` + `user_lifecycle.enabled: true`**: recorder is
  nil (`wireAudit` returns early), so the bus can never observe transitions.
  Loud boot warning (above), not a boot failure — this config is valid
  today for the store alone and must keep building. Read gates (1, 2) still
  enforce; only the pre-transition credential window stays open.

### 3.3 Scope cuts

- **Token-exchange chain store**: no `ChainStore` is wired in
  `cmd/sso-server` or `interfaces/admin.Deps` — the spec's optional chain
  leg is dropped. The reaction signature stays the 3-SPI shape of
  `RevokeAccessOnArchive`; an embedder wiring a chain store can compose its
  own reaction.
- **PURGED**: out of scope (analysis direction 2 — Eraser wiring); the
  ARCHIVED reaction already covers the revocable states reachable today.

---

## Decision 4: Storage model

No new storage. The design consumes three existing stores read-only on the
hot paths and writes nothing new on them:

| Store | Use | Access pattern |
|---|---|---|
| `userlifecycle.Store` (`memory.Store`) | `Get` — one read per login leg and per refresh grant | Read-only; no-record → `{State: DefaultState}`; `ListByState`/`Append` untouched |
| `core.SessionManager` | `ListByUser` + `Destroy` in the reactions | Write on transition only |
| `oauth.RefreshTokenSubjectIndex` (`DeleteAllForSubject`) + `core.ClientStore.List` | refresh-leg of the reactions | Write on transition only |

Semantics that make this safe without a new store:

- **No-record = ACTIVE** is enforced by `Store.Get` itself — the gates
  never special-case "missing", so every account predating the feature is
  unaffected (the backward-compatibility anchor).
- **Nil store = feature absent**: both gates no-op; the reactions cannot be
  wired (bus constructed only behind `user_lifecycle.enabled`).
- The lifecycle store remains memory-only per-process. In a multi-replica
  deployment the gates read a per-replica view and the reactions revoke
  per-replica credentials — the same divergence the analysis already
  documents for the state machine itself (analysis direction 3: SQL peer +
  cross-replica invalidation). The gates inherit, not worsen, this.

---

## Decision 5: Failure modes and outage policy

| Surface | Nil store | No record | Read error | Write error (reaction) |
|---|---|---|---|---|
| Login gate (Decision 1) | allow (byte-identical) | allow (ACTIVE) | **deny 403 `account_locked`** + audit meta + log (fail closed) | n/a |
| Refresh gate (Decision 2) | allow (byte-identical) | allow (ACTIVE) | **deny 400 `invalid_grant`** + log (fail closed) | n/a |
| SUSPENDED/ARCHIVED reaction (Decision 3) | reaction not wired | n/a | n/a | best-effort: `errors.Join` across legs/clients; logged via `ReactionErrorFunc`; never fails the transition nor the admin 200; never less locked out |

The fail-closed posture is a deliberate, documented divergence from two
neighbors:

- `rejectDeactivatedUser` (SCIM) **fails open** on `UserProvider.GetByID`
  error (`uerr != nil || u.IsActive() → allow`) — a SCIM-store outage must
  not lock everyone out. The lifecycle gate fails closed because a
  suspension is a security invariant and the spec pins it; the asymmetry is
  documented in both doc comments.
- Tenant-suspension lookup **fails open with audit** — same reasoning as
  SCIM. The lifecycle gate's fail-closed stance is the refresh-path
  precedent (`refreshCheckSessionLiveness`) extended to login.

Operational consequence (must be in `docs/config-reference.md`): a
lifecycle-store outage under `user_lifecycle.enabled` denies **all**
logins/rotations for users with records, byte-indistinguishably from real
suspension. That is the point (no oracle), and it is observable via the
fail-closed log line + `login_failure` audit stream. This is the cost of
the invariant and is accepted by the spec.

---

## Decision 6: What could break the design

1. **Line-budget collision (highest mechanical risk).** Every
   `interfaces/sso` file is 488–500 lines against a hard 500-line gate with
   a frozen-empty exemption map, and the directory is at its 60-file
   ceiling. The device-context move (73 lines → `server_login_resolve.go`)
   is mandatory, not cosmetic; if reviewers reject the move, the only
   alternative is folding the lifecycle leg into `rejectDeactivatedUser`
   and still extracting ≥15 lines elsewhere — strictly worse. The
   `RefreshGrantDeps` addition must also fit `token_refresh.go` (431 lines,
   69 headroom — fine).
2. **`RefreshGrantDeps` interface growth breaks test doubles.** Compile-time
   enforced (the `var _` guard), so the breakage is loud and mechanical —
   but any test file constructing a bare `RefreshGrantDeps` mock must add
   `LifecycleState`. Grep `RefreshGrantDeps` in tests before committing.
3. **Stale "governance-only" documentation.** Three places assert the
   feature "NEVER gates authentication": `options_admin.go:277` doc,
   `docs/config-reference.md` §User Lifecycle, and the
   `domains/userlifecycle` package doc. All must be revised in the same
   change (AGENTS.md §5.6) or the doc/code drift checkers flag it; leaving
   them is an operational lie after this lands.
4. **Pre-existing `account_locked` doc drift (423 vs code 403).** The gates
   pin the code's 403; the `docs/error-codes.md` row must be reconciled in
   the contract update (or at least the new gate text must not copy the
   wrong status).
5. **TOCTOU between the login gate and the transition reaction.** A login
   that reads ACTIVE just before `Append` commits can create its session
   just after the revocation reaction ran — that session survives until
   TTL (the refresh gate still blocks rotation, so the token path is cut).
   Same class as the existing SCIM race and the MFA challenge window; the
   MFA-second-leg and login-transaction re-checks shrink it but cannot
   eliminate it. Accepted and documented; the only hard fix would be
   blocking logins during transitions (out of scope).
6. **Residual auth-code-exchange gap.** `HandleAuthCodeGrant` performs no
   lifecycle check (the spec deliberately covers login + refresh only), and
   `oauth.AuthCodeStore` has no per-subject delete SPI (`auth_code.go:114`),
   so a pre-suspension, unexchanged auth code can still be exchanged after
   SUSPENDED, minting a fresh family. Narrow (short TTL, single-use,
   requires a captured code) but real; the fresh family dies at first
   rotation. Document as a known residual; a per-subject auth-code index +
   a reaction leg is a follow-up.
7. **Reaction requires `audit.enabled`.** With `user_lifecycle.enabled:
   true` + `audit.enabled: false`, transitions emit no event and the bus
   never fires (boot warning). The read gates still hold. Same coupling the
   webhook engine and CAEP transmitter already have — the audit Recorder is
   the event backbone.
8. **Fail-closed self-lockout on store outage** (Decision 5) — an operator
   who watches only HTTP status will see mass 403s during a lifecycle-store
   outage and may "fix" it by suspending more accounts. The log line and
   audit stream are the only differentiators, by oracle-safe design.
   Documented, metric/monitoring guidance in `docs/config-reference.md`.
9. **INVITED denial vs. the future invitation flow.** Denying INVITED
   login is safe today (no production INVITED writer exists; the admin API
   cannot reach it). When analysis direction 2 lands an invitation flow,
   "accept invite = first login" must advance INVITED → ACTIVE **before**
   the user authenticates, or the gate silently blocks the flow. The
   `AllowsAuthentication` predicate is the single place to revisit.
10. **Multi-replica divergence.** Memory-only store + per-process bus mean
    replica B can keep honoring a suspension applied on replica A until
    convergence (none exists). Inherited from the state machine itself;
    direction 3's SQL peer is the fix. The refresh gate narrows the blast
    radius (families die on every replica's next rotation attempt).
11. **Grace-window interaction.** A refresh denial consumes the presented
    token; a client retrying the same token triggers the reuse path, which
    kills the whole family. For suspended users this is the desired
    outcome, but the acceptance test for "family unchanged" (spec §2) only
    holds when the reaction did not already delete the family — the test
    must wire the gate without the bus, or assert on a surviving family.
12. **`AddSink` is not concurrency-safe with `Record`.** The bus must be
    registered during build, before `NewServer` serves traffic (it is);
    registering at runtime would race the audit hot path.

---

## Decision 7: Test plan (mapping the spec's acceptances)

- `test/` (`package ssotest`): build `sso.NewServer` with
  `WithUserLifecycle(memory store)` + password authenticator + audit
  recorder + bus, per the `account_lockout_test.go` harness pattern.
  - D1: SUSPENDED → password login 403 `account_locked`, no session, no
    tokens, audit meta `lifecycle.state=suspended`; byte-compare body
    against the SCIM-deprovisioned path. Table over {SUSPENDED, INACTIVE,
    ARCHIVED, PURGED, INVITED → denied; ACTIVE, no-record → allowed}.
    Federated-callback (401 `callback_failed`) and MFA-second-leg and
    login-transaction (403) variants. Store-error injection → deny;
    nil-store → byte-identical.
  - D2: login → SUSPENDED → refresh → 400 `invalid_grant`, body
    byte-identical to unknown-token; family unchanged when no bus wired;
    reactivation restores rotation for a surviving family; store-error
    injection → fail closed.
  - D3: live session + family → SUSPENDED → 200 → session cookie 401,
    `RefreshTokenSubjectIndex` empty, refresh → `invalid_grant`; idempotent
    second run; one-store-error isolation (`errors.Join`); disabled config
    byte-identical.
- Unit: `AllowsAuthentication` table; `RevokeAccessOnSuspend` idempotency +
    leg isolation in `protocols/lifecyclereactions`; refresh-gate placement
    in `internal/handler/tokengrant`.
- Wiring: `cmd/sso-server/userlifecycle_wiring_test.go` extended for the
  bus (opts count unchanged; `b.recorder.AddSink` observed; audit-disabled
  warning path).
- Gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./... -race`, `make ci`.
