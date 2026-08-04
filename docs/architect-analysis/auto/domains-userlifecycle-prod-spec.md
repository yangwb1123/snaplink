# Requirements Spec: domains/userlifecycle — 生产化短板（expansion direction 3）

Scope: the four production-readiness gaps named in
`docs/auto/domains-userlifecycle-analysis.md` direction 3 — memory-only store,
cross-replica state divergence, full-roster sweep, and an activity signal with
no production writer. Exactly three improvements below; each is independently
shippable and honors the module's backward-compatibility anchors: no lifecycle
record reads as ACTIVE, zero-value config is OFF, and unwired surfaces stay
byte-identical to a build without the feature. "无记录=ACTIVE" is preserved in
every new read path; no existing wire contract changes.

## 1. Durable SQL `Store` peer (eliminates memory-only persistence and cross-replica divergence)

**Name**: SQL-backed `userlifecycle.Store` implementation with atomic optimistic-concurrency `Append`, selected by config.

**Problem**: The lifecycle state machine has exactly one store implementation, a process-local map, so in any multi-replica deployment (the OpenResty/Envoy multi-instance architecture this repo targets) each replica's admin `POST /api/v1/admin/users/:id/lifecycle` writes and sweep transitions diverge silently — a suspension applied on replica A is invisible to replica B, and there is no reconciliation. The divergence is worse than a missing feature because the admin API reports success while the state is not cluster-wide truth. Restart also loses every recorded transition and history, which the store's own comment concedes.

**Evidence**:
- `cmd/sso-server/serverbuildplatform/build_userlifecycle.go` — `BuildUserLifecycle` returns `userlifecyclememory.New()` unconditionally when enabled; comment: "Only a memory backend exists today (`domains/userlifecycle/memory`); a durable peer implementing the same Store contract can be swapped in later without touching this seam."
- `domains/userlifecycle/memory/memory.go` — package doc: "State is lost on restart — fine for tests and small embedded deployments; a multi-replica production deploy should swap in a SQL-backed peer implementing the same `userlifecycle.Store` contract."
- `domains/userlifecycle/userlifecycle.go` — `Store` interface (Get/Append/ListByState): "Implementations live in `userlifecycle/<backend>/` (memory today; a SQL peer can follow the same contract)." `Append` already specifies the atomic, optimistic-concurrency semantics a SQL peer must honor: "Append atomically applies t ... Returns ErrStateConflict when t.From does not match the live state."
- `docs/config-reference.md` (User Lifecycle): "Only a memory backend exists today (`domains/userlifecycle/memory`)."
- Repository grep: zero `userlifecycle` references under `infrastructure/` — no durable backend exists.
- `AGENTS.md` §3: cross-replica invalidation covers token revocation, signing-key rotation, client/authz-policy changes, and tenant suspension — user lifecycle is absent from the list, so divergence is not even detected, let alone invalidated.

**Proposed behavior**:
- Add a durable backend implementing the same `userlifecycle.Store` contract, placed in `infrastructure/postgres` (root-module package per AGENTS.md §4; SQLite test peer alongside under `infrastructure/sqlite` if the existing pattern requires it for gate runs). Tables: `user_lifecycle` (user_id PK, state, updated_at) + `user_lifecycle_history` (user_id, seq, from_state, to_state, reason, actor, at), with an index on `state` for `ListByState`.
- `Append` maps the existing contract onto a single conditional statement: `INSERT ... ON CONFLICT (user_id) DO NOTHING` for seed transitions and `UPDATE ... SET state=$to ... WHERE user_id=$id AND state=$from` for transitions, mapping zero affected rows to `ErrStateConflict` — one atomic statement per transition, preserving the single-use/optimistic-concurrency invariant, no read-then-write.
- `Get` returns `{State: DefaultState}` for a missing row (never an error — the "no record = ACTIVE" anchor is enforced at the SQL boundary, not by callers).
- Config selection: a `user_lifecycle.backend`-style knob (`memory` default, `sql` when a DSN is configured) resolved in `cmd/sso-server/serverbuildplatform/build_userlifecycle.go`; the zero value and memory default keep existing deployments byte-identical. Migration SQL ships with the change; boot fails loud when `sql` is selected without a reachable store.
- Extract the memory store's behavior assertions into a shared conformance suite (mirroring `permissionstest.ConformanceSuite`) so both backends prove identical semantics; extend, never relax, memory coverage.

**Acceptance check**:
- The shared conformance suite passes against both the memory store and the SQL store: seed/conflict/Get-default/ListByState/history-append semantics identical.
- A two-process test sharing one database (or one process plus a second store handle) shows: an `Append` on handle A is observed by `Get` on handle B; a concurrent `Append` from both handles with the same `From` yields exactly one success and one `ErrStateConflict` — divergence eliminated, conflict semantics preserved.
- `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .` pass; `make ci` passes.
- Config reference updated (`docs/config-reference.md`); `user_lifecycle.enabled` with no backend selection still builds the memory store — wire contract and admin API responses byte-identical.

## 2. Lease-serialized, cursor-based incremental sweep (ends full-roster scans and multi-replica sweep fights)

**Name**: Sweep lease plus candidate-cursor iteration; `SweepOnce` stops enumerating the full roster.

**Problem**: Every sweep tick walks `core.UserProvider.List` — the entire roster, unpaginated, per replica. At ten-thousand-plus users each interval is a full-table read whose cost grows with the whole roster rather than with the dormant subset; `MaxPerSweep` caps only *applied transitions*, not rows scanned. The store already exposes `ListByState` (a by-state incremental read) and it is never used — the interface doc explicitly says the sweep "enumerates the full roster via core.UserProvider for the active set". Meanwhile every replica runs its own `RunUserAutoDeprovision` ticker against its own (now shared, post-improvement 1) store, and the resulting lost-update races are silently logged and skipped (`ErrStateConflict` in `apply`) — concurrent sweeps waste work and produce non-deterministic transition winners instead of a single authoritative run.

**Evidence**:
- `domains/userlifecycle/sweep.go` — `SweepOnce`: `users, err := d.Users.List(ctx)` then a linear loop over all users (no pagination, no cursor); `apply`: "A conflict (a concurrent admin transition) or store error is logged and skipped" — races are swallowed, never coordinated.
- `domains/userlifecycle/userlifecycle.go:143-147` — `Store.ListByState` doc: "the sweep enumerates the full roster via core.UserProvider for the active set." Repository grep confirms `ListByState` has zero callers outside its definition and memory implementation.
- `shared/core/spi.go:42` — `UserProvider.List`: "List returns every known user. Order unspecified; pagination is the caller's responsibility."
- `interfaces/sso/options_admin.go` — `RunUserAutoDeprovision` per-process ticker + `userDeprovisionDeps` (no lease or coordination seam); `cmd/sso-server/build_stores.go:368` starts one goroutine per process.
- `DeprovisionConfig.MaxPerSweep` (`sweep.go`) — documented as "a deprovisioning-storm guard", but bounds transitions, not enumeration cost.

**Proposed behavior**:
- Add a lease seam to the store contract (or a narrow companion interface, e.g. `SweepLeaser`): `TryAcquireSweepLease(ctx, holder, ttl)` / `ReleaseSweepLease(ctx, holder)` with TTL-expiry, implemented by the SQL store as a conditional upsert with expiry timestamp and by the memory store as a single-flight in-process mutex (keeping single-replica behavior unchanged). `RunUserAutoDeprovision` acquires the lease before each `SweepOnce` and releases after; a lost lease is logged and the run skipped — exactly one replica sweeps at a time.
- Replace the roster walk with cursor-based candidate enumeration: iterate `ListByState(StateActive)` and `ListByState(StateInactive)` (the only two sweep-eligible states per `nextState`) using a stable, orderable cursor (user_id keyset pagination, e.g. `ListByStateAfter(state, afterID, limit)`), so each tick's work is proportional to the candidate set, not the roster.
- Keep `MaxPerSweep` as the per-run cap over applied transitions and add the same cap over scanned candidates (the existing storm guard, extended to read cost). `ErrStateConflict` during `apply` remains skip-and-log (an admin transition legitimately wins), but the lease removes the duplicate-sweep source of conflicts.
- Semantics of `SweepOnce` (eligible states, thresholds, fail-safe zero-signal handling) are unchanged; the lease and cursor are pure mechanics.

**Acceptance check**:
- New race test: two concurrent `SweepOnce` runs over one store (two holders) — exactly one applies transitions; the other acquires no lease and applies zero (asserted with a counter on the store).
- New test: a roster of N users with only k dormant candidates — the sweep touches O(k) rows, not N (assert via a `ListByStateAfter` call counter or a store probe); `MaxPerSweep` bounds both applied transitions and scanned candidates.
- All existing `sweep_test.go` cases (`TestSweepOnce_*`, including `MaxPerSweepCap`) pass unchanged.
- `go test ./... -race`, `make ci` pass; `docs/config-reference.md` updated (lease TTL knob optional, zero = no lease behavior for memory single-replica deployments).

## 3. Persistent last-active signal written from the login hot path (gives dormancy a production writer)

**Name**: Durable `LastActiveSource` fed by `Touch` calls on successful authentication; replaces session-derived blindness by default when a durable store is wired.

**Problem**: The dormancy signal has no production producer. `memory.ActivityTracker.Touch/TouchAt` — the precise, session-lifetime-independent recorder — has zero callers in production code, so the only wired source is `SessionLastActive`, which reads live-session `CreatedAt` and is documented as blind: activity is visible only inside the session-retention window, and a user with no live session reads as "unknown", which `IsDormant` treats as "do not deprovision". In the default wiring, dormancy either never fires (no evidence) or goes blind exactly when the evidence should outlive sessions. The config reference concedes "no other activity backend exists in this wiring today". The only `Touch` in the whole tree is the admin token store's, an unrelated type.

**Evidence**:
- Repository grep `\.Touch\(` — the sole production call site is `interfaces/admin/middleware.go:405` (`a.adminTokenStore.Touch(r.Context(), claims.JTI)`, backed by `infrastructure/defaultimpl/memorystorecredential/admin_token.go:79` `MemoryAdminTokenStore.Touch`): admin JTI liveness, not user activity.
- `domains/userlifecycle/memory/memory.go` — `ActivityTracker` doc: "Wire it into the login path (call Touch on a successful authentication) so dormancy detection sees real activity even after every session has expired."
- `domains/userlifecycle/dormancy.go` — `SessionLastActive` doc: "because expired sessions are pruned, this reflects activity only within the session-retention window; a user with no live session reads as zero (unknown), which IsDormant treats as 'do not deprovision'."
- `docs/config-reference.md` (User Lifecycle, auto_deprovision): "Activity is derived from the wired `SessionManager` (`userlifecycle.SessionLastActive`) — a user with no live session reads as 'unknown' and is never touched (fail-safe by design; no other activity backend exists in this wiring today)."
- Wiring seam: `cmd/sso-server/build_stores.go:347` passes the single activity source into `sso.WithUserAutoDeprovision`; login success anchors are `interfaces/sso/server_login_auth.go:98` (after `rejectDeactivatedUser` clears the SCIM gate) and `interfaces/sso/server_oauth.go:223` (`finalizeCallbackSession`). `shared/core/spi.go:150` `SessionActivityTracker.TrackActivity` (`internal/handler/tokengrant/token_refresh.go:422`) is session-scoped — same retention-window blindness, not a user-level signal.

**Proposed behavior**:
- Persist last-active with the durable store from improvement 1: extend that backend (e.g. a `last_active` column/table with `TouchLastActive(ctx, userID, at)` on the store contract, or a `PersistentActivityTracker` implementing `userlifecycle.LastActiveSource` over the same table). The memory backend keeps its existing `ActivityTracker` (in-process, tests/small deploys).
- Write the signal on every successful authentication in the hot path: after `rejectDeactivatedUser` returns false in `server_login_auth.go` (`authenticateUser`), and in `finalizeCallbackSession` (`server_oauth.go:223`) after the SCIM gate — covering password/LDAP, federated, and ceremony logins. Fail-open by design: a write error is logged (and counted if a metric seam exists) and never blocks login or session creation, mirroring the module's existing fail-open convention; `TouchAt` advances only on newer timestamps (no regression).
- Wire it as the default activity source in `build_stores.go` when the durable store is enabled; `SessionLastActive` remains the source for memory-only builds. Zero-value config stays OFF; no config key changes meaning.
- Update `docs/config-reference.md` to name the durable backend and remove the "no other activity backend exists" caveat; dormancy now sees activity that outlives session expiry.

**Acceptance check**:
- Integration-style test: successful login writes a last-active timestamp; after every session for that user is expired/destroyed, `LastActive` still returns the recorded instant (persistence independent of session lifetime) and the sweep still evaluates the account against `DormantAfter`.
- Failure-injection test: activity-write error (failing store stub) — login still succeeds and returns tokens (fail-open), error is logged.
- `TouchAt` monotonicity test: out-of-order/late writes never regress the stored instant (existing memory semantics carried to the durable backend).
- Hot-path regression: `TestSweepOnce_*` and login tests pass; `go test ./... -race` and `make ci` pass; `docs/config-reference.md` updated.
