Design doc written to `docs/auto/domains-userlifecycle-direction1-design.md` (no `.go` edits, so no gates were required; all claims re-verified against the tree before writing).

## Summary of the design

**Corrections found while verifying the spec** (recorded in the doc's verification table):

1. **Five enforcement points, not three**: there are four `rejectDeactivatedUser` call sites (`server_login_auth.go:98`, `server_mfa.go:359`, `server_mfa_trust.go:256` — missed by the spec — plus the *inline* SCIM check at `server_oauth.go:221`). The federated callback's denial shape is 401 `callback_failed`, not 403 `account_locked`, so per-site collapse must mirror each site's existing SCIM denial.
2. **The helper cannot go into `server_login_auth.go` as specced**: that file is 493/500 physical lines, every `interfaces/sso` file is 488–500, and the dir is at its frozen 60-file ceiling. Decision 1 makes a ~73-line extractive move of the device-context block to `server_login_resolve.go` (413→486) mandatory before adding the ~30-line gate helper.
3. **`account_locked` doc drift**: `docs/error-codes.md` says 423; the code writes 403. The gates pin the code's 403 and the contract update must reconcile the doc.

**The three decisions**:

- **D1 — Login gate**: a pure `userlifecycle.AllowsAuthentication(state)` predicate (deny all non-ACTIVE incl. INVITED, allow no-record) + a thin `rejectLifecycleBlockedUser` helper, invoked at all five sites after the SCIM check, before any side effect. Fail-closed on read error; state goes to audit via variadic meta on the existing `login_failure`/`callback_failure` events (no new event types).
- **D2 — Refresh gate**: `RefreshGrantDeps.LifecycleState(ctx, userID)` (satisfied by `*sso.Server` in `options_admin.go`; nil store → `DefaultState` so unwired = byte-identical), checked after session-liveness and before `refreshResolveGrant`/`RecordRotation`, collapsing to the byte-identical `invalid_grant` of the unknown-token path. Import edge `internal/handler/tokengrant → domains/userlifecycle` is downward — no layer exemption needed.
- **D3 — Revocation**: `lifecyclereactions.RevokeAccessOnSuspend` sharing the already-extracted legs of `RevokeAccessOnArchive`, wired in `wireUserLifecycle` via `b.recorder.AddSink(bus)` with `OnUserSuspended` + `OnUserArchived` (synchronous, so the admin 200 implies revocation done). No new `sso.Option` — `userlifecycle_wiring_test.go`'s opt-count assertions stay green. Loud boot warning when `audit.enabled: false` (recorder nil → reactions inert). Chain-store leg dropped (nothing wired in the composition root).

**Storage model**: no new storage — read-only `Store.Get` on the hot paths, write-once `SessionManager.Destroy`/`DeleteAllForSubject` in reactions; "no-record = ACTIVE" is enforced by the store itself.

**Highest-risk failure modes** (Decision 6): the line-budget collision (D1's move is mandatory, not cosmetic), the `RefreshGrantDeps` break of test doubles (compile-enforced, mechanical), stale "NEVER gates authentication" docs in three places that must be updated in the same change, the login-gate↔reaction TOCTOU (session created just after revocation survives to TTL — accepted), the residual auth-code-exchange gap (`AuthCodeStore` has no per-subject delete SPI), and the fail-closed self-lockout on store outage (deliberate, must be documented in `config-reference.md`).
