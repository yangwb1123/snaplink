Spec written to `docs/auto/domains-userlifecycle-direction1-spec.md`, following the repo's `domains-<module>-direction<N>-spec.md` convention. All evidence was verified against the actual code before writing.

## Requirements spec — Direction 1: lifecycle state becomes an enforced auth gate

**Verified core gap**: `rejectDeactivatedUser` (`interfaces/sso/server_login_auth.go:144`) is the only post-credential gate and reads only SCIM `scim:active` (`shared/core/types_auth.go` `User.IsActive`); `HandleRefreshGrant` (`internal/handler/tokengrant/token_refresh.go`) checks consume/DPoP/lifetime/session-liveness/depth/velocity but never user state; `applyLifecycleTransition` (`interfaces/admin/lifecycle.go`) does `Append` + audit only. The package doc admits "not an auth decision on the request path" and `options_admin.go:277` says it "NEVER gates authentication".

The three improvements:

**## 1. Login-path lifecycle gate** — a shared `rejectLifecycleBlockedUser` helper invoked at all three existing `rejectDeactivatedUser` sites (password login :98, federated callback `server_oauth.go:223`, MFA second leg `server_mfa.go:359`). Non-ACTIVE (incl. INVITED) → deny after credential verification, collapse to existing 403 `account_locked` (oracle-safe; state only in audit). No-record=ACTIVE, nil-store=no-op, store-error=fail closed. *Acceptance*: `test/` integration — SUSPENDED user's correct password → 403, no session/tokens.

**## 2. Refresh-grant lifecycle gate** — optional `LifecycleState(ctx, userID)` accessor on `RefreshGrantDeps` (satisfied via the existing `accessors_token_grant.go` pattern); checked after session-liveness, before any rotation side effect; non-ACTIVE → the byte-identical 400 `invalid_grant` of unknown/expired/consumed. *Acceptance*: oracle test proving suspended user's family stops rotating with indistinguishable body.

**## 3. Transition-time revocation reaction** — `RevokeAccessOnSuspend` sharing the extracted legs of `revoke_on_archive.go` (credentials-first, best-effort, idempotent), registered via `OnUserSuspended`/`OnUserArchived` on a `LifecycleEventBus` added as an audit sink in `cmd/sso-server/build_stores.go` `wireUserLifecycle` — closing the pre-transition credential window (`OnUserSuspended` currently has zero production callers; repo grep confirms). *Acceptance*: after SUSPENDED, live session → 401 and refresh family deleted; disabled config stays byte-identical.

The spec also pins the preserved invariants: no-record=ACTIVE, unwired=byte-identical, oracle-safe collapses, fail-closed outage policy (matching the documented `refreshCheckSessionLiveness` contract, with the difference from tenant-suspension fail-open explicitly called out), and import-direction constraints per AGENTS.md.
