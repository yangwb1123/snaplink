# domains/userlifecycle — Direction 1 requirements spec: lifecycle state becomes an enforced auth gate

Scope: expansion direction 1 from `docs/auto/domains-userlifecycle-analysis.md` —
「生命周期状态只是"管理元数据"，从未真正执行——SUSPENDED 用户依然可以登录并换取新令牌」.

Today the seven-state machine (`INVITED → ACTIVE → {SUSPENDED, INACTIVE} → ARCHIVED → PURGED`)
is pure governance metadata. The login gate consults only `core.User.IsActive()`
(`shared/core/types_auth.go`), which reflects the SCIM `scim:active` attribute and
nothing about the lifecycle store; the refresh grant consults nothing user-level
at all. An operator who suspends an account via
`POST /api/v1/admin/users/:id/lifecycle` has not cut off access: the user can
still complete a fresh login with correct credentials and can still rotate an
existing refresh family into new access tokens. The package documentation states
this explicitly ("governance/administration metadata, not an auth decision on the
request path").

This spec contains exactly three evidence-backed improvements:

1. Login-path lifecycle gate — non-ACTIVE states refuse new sessions/tokens on
   every authentication leg.
2. Refresh-grant lifecycle gate — non-ACTIVE states refuse token rotation with
   the existing oracle-safe `invalid_grant` collapse.
3. Transition-time revocation reaction — SUSPENDED/ARCHIVED transitions revoke
   already-issued sessions and refresh families at the composition root, so
   pre-transition credentials stop working immediately, not at TTL.

## Preserved invariants (non-negotiable)

- **No record = ACTIVE.** `Store.Get` already returns `{State: DefaultState}` for
  an unknown user (`domains/userlifecycle/userlifecycle.go`, `memory.Store.Get`);
  the enforcement seams below treat a missing record exactly like `active`, so
  every account predating the feature is unaffected.
- **Unwired = byte-identical.** Nil lifecycle store (the default) makes every new
  gate a no-op. A build that never calls `WithUserLifecycle` behaves exactly as
  today; the enforcement is an optional wiring, never a default behavior change
  (the backward-compatibility anchor AGENTS.md §1 requires).
- **Oracle-safe collapses.** The login gate reuses the existing `account_locked`
  403 (credential already verified; block cause lands only in audit, mirroring
  `rejectDeactivatedUser`). The refresh gate collapses to the byte-identical 400
  `invalid_grant` used for unknown/expired/consumed tokens. No new distinguishable
  failure surface is introduced.
- **Outage policy is documented, not accidental.** Lifecycle-lookup read errors
  fail CLOSED (deny), matching the documented fail-closed contract of
  `refreshCheckSessionLiveness` ("A store error is treated as 'session not found'
  (fail-closed)") — a suspension is a security invariant, and the same
  fail-closed posture is already the refresh-path precedent. This differs from
  tenant-suspension lookup (fail open with audit) and must be called out in the
  docs and code comments.
- **Import direction preserved.** `protocols/oauth` and `internal/handler/tokengrant`
  must not import `interfaces/sso`; the lifecycle gate is expressed as a narrow
  read seam (`userlifecycle.Store.Get` or a `LifecycleState(ctx, userID)` accessor
  on the existing `RefreshGrantDeps`), satisfied by `*sso.Server` via the existing
  accessor pattern (`accessors_token_grant.go`).

---

## 1. Login-path lifecycle gate: non-ACTIVE states refuse new authentication

**Name**: Login-path lifecycle gate (read-side enforcement on all authentication legs)

**Problem**: A SUSPENDED (or INACTIVE/ARCHIVED/PURGED) user can complete a brand-new
login with correct credentials and receive a fresh session and fresh tokens. The
only post-credential gate is `rejectDeactivatedUser`, which consults
`core.User.IsActive()` — a pure SCIM `scim:active` read — so the lifecycle store
is never consulted anywhere on the authentication path. The admin transition
handler writes the store and an audit event and stops; nothing downstream ever
reads the state back. This is "security theater": the operator's suspend action
has no effect on access.

**Evidence**:
- `domains/userlifecycle/userlifecycle.go` (package doc): "this package is
  governance/administration metadata, not an auth decision on the request path".
- `shared/core/types_auth.go` (`User.IsActive`, ~lines 417-425): returns false
  ONLY when `Attributes["scim:active"] == "false"` — lifecycle state is invisible
  to it.
- `interfaces/sso/server_login_auth.go:98` (call) and `:144`
  (`rejectDeactivatedUser`): the sole post-credential gate; no lifecycle read.
- `interfaces/sso/options_admin.go:277` (`WithUserLifecycle` doc): "it NEVER
  gates authentication (core.User.IsActive still owns the login decision)".
- `interfaces/admin/lifecycle.go` (`applyLifecycleTransition`): only
  `LifecycleStore().Append` + `RecordTransition` — no enforcement side effect.
- The same SCIM-only gate is re-checked on the federated callback
  (`interfaces/sso/server_oauth.go:221-223`) and the MFA second leg
  (`interfaces/sso/server_mfa.go:359`, `interfaces/sso/server_mfa_trust.go:256`),
  so the gap is uniform across every authentication leg.

**Proposed behavior**:
- Add a `userlifecycle.Gate` read seam (thin wrapper over `Store.Get`) and a
  shared helper `rejectLifecycleBlockedUser(ctx, req, userID) bool` in
  `interfaces/sso/server_login_auth.go`, invoked immediately after
  `rejectDeactivatedUser` at the same three existing call sites
  (password/LDAP login `server_login_auth.go:98`, federated callback
  `server_oauth.go:223`, MFA second leg `server_mfa.go:359`), so all legs are
  covered by one helper — no new instrumentation points.
- Semantics: state ∈ {SUSPENDED, INACTIVE, ARCHIVED, PURGED, INVITED} → deny.
  Deny happens AFTER credential verification and BEFORE any session/token
  side effect (same ordering contract as `rejectDeactivatedUser`). Response
  collapses to the existing 403 `account_locked` (an unavailable account, not a
  credential oracle); the actual state and reason land only in the audit event
  and server log. INVITED is denied by default because an invitation must be
  accepted (advanced to ACTIVE by the provisioning flow) before first login.
- Nil store → no-op (return false), preserving byte-identical behavior for
  unwired builds. Store read error → deny (fail closed) with audit.
- `docs/error-codes.md` and `docs/config-reference.md` ("User Lifecycle"
  section, which currently asserts the feature "NEVER gates authentication")
  are updated in the same change to document the new gate and its outage policy.

**Acceptance check**:
- Integration test in `test/` (`package ssotest`): admin transitions a user to
  SUSPENDED via `POST /api/v1/admin/users/:id/lifecycle`; a subsequent password
  login with the correct credential returns 403 `account_locked`, no session is
  created, no tokens are issued, and the audit record carries the lifecycle
  state while the response body is byte-identical to the SCIM-deprovisioned
  path.
- Parameterized test over {SUSPENDED, INACTIVE, ARCHIVED, PURGED, INVITED} →
  denied; {ACTIVE, no-record} → allowed.
- Federated-callback and MFA-second-leg tests prove the same denial.
- Store-error injection test proves fail-closed (deny + audit), and a nil-store
  test proves the no-op (byte-identical) default.
- Mandatory gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`, `make ci`.

---

## 2. Refresh-grant lifecycle gate: non-ACTIVE states refuse token rotation

**Name**: Refresh/rotation lifecycle gate (oracle-safe `invalid_grant`)

**Problem**: Even after improvement 1 blocks new logins, an existing refresh
family keeps rotating: `HandleRefreshGrant` checks single-use consumption, DPoP
binding, absolute max lifetime, parent-session liveness (SID), token-policy
depth, and rotation velocity — but never the user's lifecycle state. The
session-liveness check only catches revoked/expired sessions, and nothing
revokes sessions on suspension (see improvement 3), so a suspended user's client
continues minting fresh access tokens for the family's entire TTL. This is the
"换取新令牌" half of the direction: the token path, not just the login path,
must enforce the state.

**Evidence**:
- `internal/handler/tokengrant/token_refresh.go` (`HandleRefreshGrant`, and its
  dependency interface `RefreshGrantDeps` at the top of the file): the full
  grant flow contains no user-state consultation and the deps interface has no
  lifecycle accessor.
- `interfaces/sso/server_token.go:441`: the server delegates the whole grant to
  `tokengrant.HandleRefreshGrant`, so there is no server-side hook today either.
- `interfaces/sso/server_oauth.go:221-223`: the only user-state check anywhere
  near the token path is again `IsActive()` (SCIM-only).
- `domains/userlifecycle/bus.go:141-142` (`OnUserSuspended`): the only
  suspension-side mechanism is a reactive bus event with zero production
  callers (repo-wide grep finds only `bus_test.go`) — it can revoke, but nothing
  prevents the next rotation.

**Proposed behavior**:
- Add an optional `LifecycleState(ctx context.Context, userID string)
  (userlifecycle.State, error)` accessor to `RefreshGrantDeps`, satisfied by
  `*sso.Server` through the existing `accessors_token_grant.go` guard pattern;
  nil (unwired) → the check is a byte-identical no-op.
- In `HandleRefreshGrant`, immediately after the existing
  `refreshCheckSessionLiveness` check and BEFORE any rotation/issue side effect
  (`refreshResolveGrant` / `refreshRotateFamily`): state ∉ {ACTIVE, no-record} →
  write the SAME 400 `invalid_grant` as unknown/expired/consumed (no new error
  code, no distinguishing body), log the state, and return. Read error → fail
  closed (deny), matching the documented `refreshCheckSessionLiveness` contract.
- The check runs after `Consume`, so a denied suspended user still consumes the
  presented token (no token leak), and the family-reuse kill semantics for a
  second presentation are unchanged.
- Document the new gate in the `HandleRefreshGrant` doc comment and in
  `docs/config-reference.md` under "User Lifecycle".

**Acceptance check**:
- Test: user completes login (refresh token issued), admin transitions the user
  to SUSPENDED, client presents the refresh token → 400 `invalid_grant`;
  byte-identical response body to a presentation of an unknown token (oracle
  test), no rotated token is issued (`RefreshTokenSubjectIndex` shows the family
  unchanged), and the server log/audit carries the state.
- Parameterized test over {SUSPENDED, INACTIVE, ARCHIVED, PURGED, INVITED} →
  denied; {ACTIVE, no-record, nil deps accessor} → rotation succeeds
  byte-identically to today.
- Test: SUSPENDED → reactivated (SUSPENDED→ACTIVE transition) restores rotation
  for a surviving family (when improvement 3 did not revoke it — both behaviors
  are exercised).
- Store-error injection test proves fail-closed on read error.
- Mandatory gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./... -race`, `make ci`.

---

## 3. Transition-time revocation reaction: SUSPENDED/ARCHIVED destroy pre-existing credentials at the composition root

**Name**: Transition-time credential revocation (production wiring of the lifecycle bus)

**Problem**: Improvements 1 and 2 close the read side (nothing new is issued),
but every token and session issued BEFORE the transition keeps working until its
own TTL — the admin handler (`applyLifecycleTransition`) does `Append` + audit
and nothing else. The mechanism to close this window already exists:
`LifecycleEventBus` runs in-process reactions on transition, and
`protocols/lifecyclereactions.RevokeAccessOnArchive` is a reference
"revoke all sessions + refresh tokens" reaction — but it covers ARCHIVED only,
and the composition root wires NO bus at all: `OnUserSuspended` has zero
production callers, and `wireUserLifecycle` mounts store + sweep only. A
suspended user's existing session cookie and refresh family therefore survive
until expiry.

**Evidence**:
- `protocols/lifecyclereactions/revoke_on_archive.go`
  (`RevokeAccessOnArchive`): exists, ARCHIVED-only; `protocols/lifecyclereactions/doc.go`
  shows the intended-but-unwired usage `bus.OnUserArchived(...)`.
- `domains/userlifecycle/bus.go:141-142` (`OnUserSuspended` sugar) and `:164`
  (`Record` as `audit.Sink`): zero production callers for the SUSPENDED hook
  (repo-wide grep hits only `bus_test.go`).
- `interfaces/admin/lifecycle.go` (`applyLifecycleTransition`): only
  `LifecycleStore().Append` + `RecordTransition` — no revocation side effect.
- `cmd/sso-server/build_stores.go` (`wireUserLifecycle`, ~line 319): wires
  `WithUserLifecycle` + `WithUserAutoDeprovision` only; no `LifecycleEventBus`
  is constructed or registered as an audit sink.

**Proposed behavior**:
- Add `lifecyclereactions.RevokeAccessOnSuspend(sessions core.SessionManager,
  refresh oauth.RefreshTokenSubjectIndex, clients core.ClientStore)
  userlifecycle.ReactionFunc` in `protocols/lifecyclereactions/revoke_on_archive.go`
  (or a new sibling file), sharing the extracted `revokeRefreshTokens` /
  `destroySessions` legs with the archive variant. Same semantics as
  `RevokeAccessOnArchive`: credentials-first ordering (refresh tokens before
  sessions), best-effort-across-stores, idempotent (a second run finds nothing
  to revoke), and never less locked-out after a partial failure.
- In `cmd/sso-server/build_stores.go` `wireUserLifecycle`, when
  `user_lifecycle.enabled`: construct `userlifecycle.NewLifecycleEventBus()`,
  register `OnUserSuspended(RevokeAccessOnSuspend(...))` and
  `OnUserArchived(RevokeAccessOnArchive(...))` with the wired
  `SessionManager`/`RefreshTokenSubjectIndex`/`ClientStore`, and add the bus to
  the audit `Recorder` via `AddSink` (the bus is already an `audit.Sink` keyed on
  `EventAdminUserLifecycleChanged`, so transitions emit for admin- and
  sweep-driven moves alike with zero new instrumentation).
- Ordering contract: reactions run after `Append` (the transition is committed);
  a reaction failure is logged/reported but never rolls back the transition nor
  fails the admin response (the bus's documented best-effort `ReactionErrorFunc`
  contract). `On` (synchronous) is used so the admin response can rely on
  revocation having completed.
- Optionally extend the SUSPENDED reaction with a token-exchange chain-store leg
  where one is wired (best-effort, nil-safe).
- SDK embedding stays opt-in: the bus is wired only by the composition root
  behind `user_lifecycle.enabled`; `sso.WithUserLifecycle` keeps its current
  signature and a server without the option is byte-identical.

**Acceptance check**:
- Test: user with a live session and a live refresh family; admin transitions to
  SUSPENDED; immediately after the 200 response — session is destroyed (a
  request carrying the session cookie → 401), every refresh token for the
  subject is deleted (`RefreshTokenSubjectIndex` empty), and a subsequent
  refresh presentation → 400 `invalid_grant` (not a rotation).
- Idempotency test: a second transition attempt or a re-run of the reaction
  finds nothing to revoke and returns nil error.
- Failure-isolation test: one store (e.g. sessions) erroring does not abort the
  refresh leg and vice versa (collected-error semantics of
  `RevokeAccessOnArchive`).
- Wiring test: with `user_lifecycle.enabled: true` both reactions fire on
  SUSPENDED and ARCHIVED; with the feature disabled (no bus), transitions behave
  byte-identically to today (no revocation).
- Mandatory gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./... -race`, `make ci`.
