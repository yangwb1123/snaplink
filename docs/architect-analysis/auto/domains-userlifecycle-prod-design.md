# Design: domains/userlifecycle production-hardening (spec: domains-userlifecycle-prod-spec.md)

Three independently shippable decisions. Every anchor from the spec is preserved:
no lifecycle record reads as ACTIVE (`DefaultState`), zero-value config is OFF,
and unwired surfaces stay byte-identical to a build without the feature. The
`Store`, `LastActiveSource`, `DeprovisionConfig`, `SweepDeps`, `SweepOnce`, and
`WithUserAutoDeprovision` public shapes that exist today are NOT modified — all
new behavior is additive (new fields, new narrow companion interfaces resolved
by type assertion, new config keys whose zero value reproduces today's wiring).

Three cross-cutting resolutions, each grounded in the code:

1. **Companion interfaces, never `Store`-method additions.** `userlifecycle.Store`
   is part of the SDK surface (`interfaces/sso`); an SDK consumer that implements
   it today must keep compiling. The lease, the cursor, and the activity writer
   therefore live in narrow optional interfaces (`SweepLeaser`,
   `StaleEnumerator`, `ActivityRecorder`) that `SweepOnce` / the login path /
   the builder resolve with type assertions. A store that does not implement one
   falls back to exactly today's behavior.
2. **The sweep's candidate set must come from the activity signal, not from
   `ListByState`.** The spec's proposal ("iterate `ListByState(StateActive)` and
   `ListByState(StateInactive)`") cannot see implicit-ACTIVE users: the `Store`
   contract says `ListByState` never returns users with no record
   (`userlifecycle.go`), while `SweepOnce` today walks the full roster
   (`sweep.go`) and deprovisions exactly those unrecorded users (their `Get`
   returns `DefaultState`, and `Append` from `StateActive` on a missing row
   succeeds in the memory store). A `ListByState`-driven sweep would silently
   stop deprovisioning every user who never had a transition — a behavior
   regression that contradicts "SweepOnce semantics unchanged". The dormancy
   predicate is `last_active < now - DormantAfter` (`dormancy.go` `IsDormant`:
   zero signal is never dormant), so the correct candidate set is a keyset
   cursor over stale last-active values, which provably covers recorded and
   unrecorded users alike and is O(k) for k dormant candidates.
3. **Last-active is a separate table, not a column on `user_lifecycle`.**
   `Touch` fires for every successful login, including users who never had a
   lifecycle transition. A column would force `Touch` to create a lifecycle row
   for every logging-in user, silently converting "no record = ACTIVE" into a
   recorded row — changing what `Get`/`ListByState` observe and making the
   sweep's candidate set grow to the whole roster. The `user_lifecycle_last_active`
   table keeps the no-record invariant intact.

## 1. Durable SQL `Store` peer

### API surface

New packages (all root-module; placement follows the two existing precedents —
`infrastructure/postgres/permissions*.go` for the shared-pool backend and
`domains/permissions/sqlite/` for the durable embedded/test peer):

- `infrastructure/postgres/user_lifecycle.go` — `user_lifecycle` +
  `user_lifecycle_history` store. Constructors mirror `invitation.go`:
  `NewUserLifecycleStore(cfg Config)` and `NewUserLifecycleStoreWithDB(db *sql.DB,
  dialect Dialect)`, the latter running migrations
  `Run(ctx, db, "user_lifecycle", userLifecycleMigrations, dialect)` (unique
  advisory-lock namespace, `migrate.go` pattern).
- `domains/userlifecycle/sqlite/` — SQLite peer with byte-parity schema and
  `?` placeholders (pattern: `infrastructure/defaultimpl/sqlite/sessions.go`),
  used both as a real embedded backend and as the in-gate conformance target
  (spec's guess of `infrastructure/sqlite` is corrected: the repo's peers live
  in `domains/<domain>/sqlite/` and `infrastructure/defaultimpl/sqlite/`).
- `domains/userlifecycle/userlifecycletest/conformance.go` — shared suite
  mirroring `permissionstest.ConformanceSuite` (`ConformanceSuite{Factory}` +
  `Run(t)`); both backends and `memory.Store` register. Covers Get-default,
  seed/conflict Appends, history append, ListByState ordering, and (per
  decisions 2-3) lease and activity semantics. Memory coverage is extended,
  never relaxed.

Config: `UserLifecycleConfig` gains `Backend string` (`yaml:"backend"`; `""` and
`"memory"` build the memory store — zero value unchanged; `"sqlite"` needs
`UserLifecycleConfig.SQLite.DSN`; `"postgres"` uses the shared pool). Builder
signature changes from `BuildUserLifecycle(cfg)` to
`BuildUserLifecycle(cfg, pg *sql.DB, dialect postgresbackend.Dialect)`, modeled
exactly on `BuildIdentityLinkDurable(cfg, b.pgDB, b.pgDialect)`
(`build_identitylink.go:37`); `wireUserLifecycle` passes `b.pgDB, b.pgDialect`,
both populated before `wireDomains()` runs. `user_lifecycle.enabled` with no
backend still yields the memory store: admin API responses byte-identical.

### Storage model

```sql
CREATE TABLE user_lifecycle (
    user_id    TEXT   PRIMARY KEY,
    state      TEXT   NOT NULL,      -- one of the six wire states
    updated_at BIGINT NOT NULL       -- Unix-nano UTC, sessions convention
);
CREATE INDEX idx_user_lifecycle_state ON user_lifecycle(state);

CREATE TABLE user_lifecycle_history (
    user_id    TEXT   NOT NULL,
    seq        BIGINT NOT NULL,      -- per-user monotonic order
    from_state TEXT   NOT NULL,
    to_state   TEXT   NOT NULL,
    reason     TEXT   NOT NULL DEFAULT '',
    actor      TEXT   NOT NULL DEFAULT '',
    at         BIGINT NOT NULL,
    PRIMARY KEY (user_id, seq)
);
```

Migration versions: v1 = the two tables above; v2 (shipped with decision 3) =
`user_lifecycle_last_active`. Independent versions let the two improvements ship
in either order.

`Append` maps the memory semantics (`memory.go` — the reference for every case)
onto one short transaction (BEGIN; conditional upsert; history insert; COMMIT):

- Seed (`From == StateNone`): `INSERT ... ON CONFLICT (user_id) DO NOTHING`;
  0 rows affected = `ErrStateConflict`.
- Non-seed: a single upsert whose two branches exactly reproduce the memory
  store's missing-row rule:
  `INSERT INTO user_lifecycle (user_id, state, updated_at) SELECT $1,$2,$3 WHERE $from = 'active' ON CONFLICT (user_id) DO UPDATE SET state=EXCLUDED.state, updated_at=EXCLUDED.updated_at WHERE user_lifecycle.state = $from`.
  The `INSERT ... SELECT ... WHERE $from = 'active'` branch covers "no row yet,
  From == DefaultState" (the memory store treats a missing row as ACTIVE); the
  `DO UPDATE ... WHERE` branch re-checks the live state under the row lock.
  0 rows affected = `ErrStateConflict`. In READ COMMITTED, a concurrent loser's
  `WHERE` re-evaluates against the winner's committed row (EvalPlanQual), so
  exactly one concurrent Append with the same `From` succeeds — matching the
  memory mutex.
- History insert: `INSERT INTO user_lifecycle_history ... SELECT $user_id, COALESCE(MAX(seq),0)+1, ...` inside the same transaction; per-user serialization is guaranteed because every non-seed Append for a user takes that user's `user_lifecycle` row lock, and concurrent seeds serialize on the unique index.
- `Get`: `SELECT state, updated_at` + ordered history select; missing row →
  `{State: DefaultState}` with empty history, nil error (the no-record anchor is
  enforced at the SQL boundary, not by callers).
- `ListByState`: `SELECT user_id ... WHERE state=$1 ORDER BY user_id` (memory
  returns sorted ids — keep parity).
- Timestamps are application-supplied Unix-nano (`now` injectable on the store
  for deterministic conformance tests, mirroring memory's `now func()`).

### Failure modes

- Boot with `backend: sqlite|postgres` unreachable: migration/connect error
  propagates — loud boot failure (identity_link precedent).
- Runtime store outage: `Get`/`Append`/`ListByState` return wrapped errors. The
  admin handler maps `ErrStateConflict` to the existing 409
  `lifecycle_state_conflict` wire code; store errors surface as 500. The sweep
  already logs-and-skips per-user errors (`sweep.go` `apply`).
- Partial failure between state-upsert and history-insert: impossible — one
  transaction.
- CockroachDB serializable retries: bounded retry loop (≤5, `migrate.go`
  convention) re-running the conditional statement is safe because the `WHERE`
  re-checks the live state.
- Concurrent seed races: loser gets 0 rows → `ErrStateConflict`, never a
  duplicate row (unique index).

### What could break the design

- **The missing-row-as-ACTIVE case.** A naive `UPDATE ... WHERE state=$from`
  rejects `Append(From=StateActive)` on a never-recorded user, where the memory
  store succeeds — conformance divergence that would change sweep behavior for
  every first-transition user. The `INSERT ... SELECT ... WHERE $from='active'`
  branch exists solely for this; the conformance suite must include "append to
  a never-recorded user from ACTIVE" on both backends.
- **`ON CONFLICT DO UPDATE ... WHERE` + `RowsAffected` semantics.** `DO NOTHING`
  conflicts and `DO UPDATE` with a false `WHERE` both report 0 rows — exactly
  the conflict signal we need, but it must be asserted per backend (Postgres,
  SQLite, and CockroachDB's dialect) in the conformance suite's concurrent-append
  test.
- **History growth is unbounded** (every transition appends forever, as in
  memory). Contract parity says keep it; flagged as a future retention knob,
  not part of this change.
- **SDK breakage** if `ListByStateAfter`/lease/Touch were added to `Store` —
  avoided by companion interfaces (resolution 1).
- **`infrastructure/postgres` gate status**: the maintainability gates treat
  `infrastructure/postgres` as a skipped nested-module dir
  (`maintainability_budget_test.go` `skipDirs`), but the 500-line file budget is
  still the working discipline — split into `user_lifecycle.go` (state+history)
  and, once decision 3 lands, `user_lifecycle_activity.go` (+ `sweep_lease.go`
  for decision 2), each well under 500 lines.

## 2. Lease-serialized, cursor-based incremental sweep

### API surface

Two narrow companion interfaces in `domains/userlifecycle`, resolved by type
assertion (resolution 1):

```go
// SweepLeaser is an optional Store extension: one holder at a time, TTL-expiring.
type SweepLeaser interface {
    TryAcquireSweepLease(ctx context.Context, holder string, ttl time.Duration) (bool, error)
    ReleaseSweepLease(ctx context.Context, holder string) error
}

// StaleEnumerator is an optional LastActiveSource extension: keyset cursor over
// users whose last-active is older than cutoff, ordered by (last_active, user_id).
type StaleEnumerator interface {
    ListStaleAfter(ctx context.Context, cutoff time.Time, afterLastActive time.Time, afterID string, limit int) ([]string, error)
}
```

`DeprovisionConfig` gains `LeaseTTL time.Duration`; `SweepDeps` gains
`Holder string`. Both zero values reproduce today's behavior exactly.

- **Lease placement resolves a contradiction in the spec**: the spec asks for
  the lease at `RunUserAutoDeprovision` yet accepts "two concurrent `SweepOnce`
  runs — exactly one applies". These are only both true if `SweepOnce` itself
  acquires the lease. `SweepOnce` type-asserts `d.Lifecycle.(SweepLeaser)`; when
  `Holder != ""` and `LeaseTTL > 0`, it acquires (defer-release) and returns
  `(0, nil)` on a lost lease. All existing sweep tests pass unchanged: their
  fixtures set no `Holder`, so no lease is attempted (and `memory.Store`
  implements `SweepLeaser` anyway).
- `RunUserAutoDeprovision` (`options_admin.go:319`) stamps a per-process holder
  identity (hostname + pid + start nonce) into `userDeprovisionDeps`; the loop
  shape and error logging are unchanged.
- **Candidate enumeration replaces the roster walk**: when
  `d.LastActive.(StaleEnumerator)` is present, `SweepOnce` pages
  `ListStaleAfter(now-DormantAfter, ...)` with page size = `MaxPerSweep` (or a
  sane default when 0), processes each candidate through the unchanged
  `sweepUser`/`nextState`/`apply`, and advances the keyset with the last row's
  `(lastActive, userID)`. Rationale (resolution 2): the dormancy predicate is
  exactly `last_active < cutoff`, so users outside the cursor are provably
  ineligible (`IsDormant` never fires on a fresh or zero signal); the cursor
  covers recorded, unrecorded, ACTIVE, and INACTIVE candidates in one pass.
- **Ghost guard**: the cursor may surface a last-active row for a deleted user
  (no cascade exists). Each candidate is checked with `d.Users.GetByID`; a
  missing user is skipped (log), so the sweep never creates a lifecycle record
  for a deleted account (today's roster walk cannot do this).
- **Fallback**: a `LastActiveSource` without `StaleEnumerator` (e.g. a custom
  SDK source, or `SessionLastActive` in memory-only builds) keeps today's full
  roster walk verbatim — byte-identical legacy path.
- `MaxPerSweep` now bounds scanned candidates on the cursor path (applied
  transitions remain ≤ scanned); the legacy path keeps its applied-only cap.
- `memory.Store` implements `SweepLeaser` (single-flight mutex + holder/expiry,
  same app-clock TTL semantics as SQL) and `memory.ActivityTracker` implements
  `StaleEnumerator` (in-process filter over its map) so the race test and the
  O(k) test run in-gate without a database.

### Storage model

`sweep_lease` table (migration v3, or shipped with this decision's own version):

```sql
CREATE TABLE sweep_lease (
    holder     TEXT   PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
```

Acquire is one conditional upsert:
`INSERT INTO sweep_lease (holder, expires_at) VALUES ($1, $now+ttl) ON CONFLICT (holder) DO UPDATE SET expires_at = EXCLUDED.expires_at WHERE sweep_lease.expires_at < $now` — 1 row = acquired, 0 rows = another holder is live. Release is `DELETE WHERE holder = $1` (holder-scoped; a TTL-expired lease is taken over by the next acquirer). The stale-cursor query is a keyset page: `SELECT user_id FROM user_lifecycle_last_active WHERE last_active < $cutoff AND (last_active, user_id) > ($afterLA, $afterID) ORDER BY last_active, user_id LIMIT $n` (row-value comparison works on Postgres and SQLite; index `(last_active, user_id)`).

### Failure modes

- **Crash mid-sweep**: the lease dies with the process; the TTL expiry lets the
  next replica acquire. No stale-holder deadlock.
- **TTL expiry during a long run**: a second replica acquires and both run;
  the resulting `ErrStateConflict`s are absorbed by the existing skip-and-log in
  `apply` — the pre-existing failure mode, now rare instead of every tick.
  Default `lease_ttl` on the SQL path is 2x `sweep_interval` (documented);
  zero = no lease (memory single-replica, byte-identical).
- **Clock skew between replicas**: lease expiry and the dormancy cutoff use the
  application clock (repo convention). A skewed acquirer may over-lease or
  under-lease; both outcomes are benign (duplicate work absorbed by conflicts,
  or one replica idles). Fail-safe, never wrong-deprovisioning.
- **Cursor page boundary races**: a `Touch` that lands between pages moves the
  user out of the remaining range — that user is skipped this run and
  re-evaluated next tick; a user read as stale who logs in mid-run may still be
  transitioned this run (identical to today's roster-snapshot race, not a
  regression; the next tick sees the fresh `last_active`).
- **Store errors mid-page**: page errors propagate as `SweepOnce` errors (like
  today's `Users.List` error); per-user errors log-and-skip (unchanged).

### What could break the design

- **The `ListByState` candidate trap** (spec's original proposal): would stop
  sweeping every user without a lifecycle record (resolution 2). The stale
  cursor fixes it; the O(k) acceptance test must include unrecorded dormant
  users to prove it.
- **Ghost lifecycle records** for deleted users if the `GetByID` filter is
  dropped. The filter costs one PK lookup per candidate — O(k), within the
  accepted bound. Deletion-time cleanup of `user_lifecycle*` rows is out of
  scope but noted.
- **Lease inside `SweepOnce` changing existing callers**: strictly opt-in via
  the new `Holder`/`LeaseTTL` zero values; `sweep_test.go` fixtures and direct
  SDK callers are untouched.
- **`MaxPerSweep` redefinition**: capping scanned candidates changes the storm
  guard's meaning on the cursor path only; the legacy path keeps its semantics,
  and `TestSweepOnce_MaxPerSweepCap` passes unchanged.
- **Row-value comparison portability**: `(a,b) > (x,y)` differs across SQL
  dialects; the SQLite and Postgres statements are separate consts (peer-store
  convention) and both are covered by the conformance/race tests.
- **Holder identity collisions** (two processes with identical hostname+pid
  after a PID wrap): the start nonce makes collisions negligible; a collision
  merely causes a skipped tick.

## 3. Persistent last-active signal written from the login hot path

### API surface

One new narrow interface in the domain package:

```go
// ActivityRecorder is the optional write seam of the last-active signal.
// TouchAt is monotone: an at older than the stored value is a no-op.
type ActivityRecorder interface {
    TouchAt(ctx context.Context, userID string, at time.Time) error
}
```

- The durable stores (postgres + sqlite peers) implement `LastActiveSource`
  (`LastActive` over the new table; missing row = zero time, nil error —
  the "unknown" signal `IsDormant` treats as do-not-deprovision) and
  `ActivityRecorder`. They also implement `SweepLeaser`/`StaleEnumerator`
  (decision 2), so one store object serves admin state, activity, and sweep.
- `memory.ActivityTracker` deliberately does NOT implement `ActivityRecorder`
  (its `Touch`/`TouchAt` take no ctx and return nothing): memory builds keep
  today's exact behavior — zero production writers — byte-identically. The
  durable backend is the production writer; this is what the spec means by
  "durable source becomes the default when SQL is wired".
- **No `With*` signature change**: `WithUserAutoDeprovision(cfg, LastActiveSource)`
  keeps its type — SDK callers passing `SessionLastActive` keep compiling.
  `build_stores.go:347` passes the durable store itself (it is a
  `LastActiveSource`) when a durable backend is selected, and
  `userlifecycle.SessionLastActive{Sessions: b.sessionMgr}` otherwise — the
  fallback, unchanged.
- Login hot path: a single Server helper
  `touchUserActivity(ctx, userID)` that type-asserts
  `s.userLifecycleActivity.(userlifecycle.ActivityRecorder)` and calls
  `TouchAt` with `time.Now().UTC()`. Called in the spec's two anchors:
  `authenticateUser` after `rejectDeactivatedUser` returns false
  (`server_login_auth.go:98`, covers password/LDAP/OTP primaries) and
  `finalizeCallbackSession` after the SCIM gate (`server_oauth.go:223`,
  covers federated). Ceremonies are covered transitively: WebAuthn is an MFA
  factor whose completion replays `finishLogin`/`authenticateUser` with a
  frozen `AuthResult` (`server_mfa.go`), and the primary login before any
  ceremony has already Touched. A `Touch` in `finishLogin` instead would also
  re-touch MFA resumes — harmless under monotonicity but redundant; the spec's
  anchors are kept.
- Fail-open: the helper ignores errors, logs them, and never blocks login or
  session creation (the module's existing fail-open convention). Synchronous,
  not async: one conditional upsert per login is bounded work, and the
  failure-injection acceptance test is only deterministic with an inline call.

### Storage model

`user_lifecycle_last_active` table (migration v2):

```sql
CREATE TABLE user_lifecycle_last_active (
    user_id     TEXT   PRIMARY KEY,
    last_active BIGINT NOT NULL      -- Unix-nano UTC
);
CREATE INDEX idx_user_lifecycle_last_active ON user_lifecycle_last_active(last_active);
```

- `TouchAt` is one atomic monotone upsert:
  `INSERT ... VALUES ($1,$2) ON CONFLICT (user_id) DO UPDATE SET last_active = EXCLUDED.last_active WHERE user_lifecycle_last_active.last_active < EXCLUDED.last_active` — 0 rows on a stale write is a no-op, not an error. No read-then-write; the memory `TouchAt`'s monotonicity is carried to SQL exactly.
- Separate table (resolution 3): `Touch` never creates a lifecycle record, so
  "no record = ACTIVE", `Get` shape, and `ListByState` membership are unchanged
  for every user who merely logs in.
- `LastActive`: `SELECT last_active WHERE user_id=$1`; missing → zero time.
- The `(last_active)` index serves both `LastActive` and decision 2's keyset
  cursor (`(last_active, user_id)` scan).

### Failure modes

- **Activity-write failure**: logged, login proceeds and tokens issue — the
  acceptance test injects a failing store stub and asserts success. The signal
  simply ages; dormancy then evaluates against the last good value (or "unknown",
  do-not-deprovision, if never written) — fail-safe.
- **Slow activity write on the hot path**: one PK upsert per login, bounded;
  no new retry or circuit logic (fail-open means a down DB adds at most one
  failed round-trip's latency — call it before session creation but after all
  auth decisions, so no error path exists).
- **Out-of-order/late writes**: the monotone guard prevents regression; the
  conformance suite asserts `TouchAt(t1)` then `TouchAt(t0 < t1)` keeps `t1` on
  both backends.
- **Orphan rows**: deleted users' last-active rows persist (no cascade); the
  sweep's ghost guard (decision 2) makes them inert. Deletion-time cleanup is a
  documented non-goal.

### What could break the design

- **Column-on-lifecycle-table trap** (resolution 3): would silently convert
  every logging-in user from "no record" to a recorded ACTIVE row, changing
  `Get`/`ListByState` observations and making the decision-2 candidate cursor
  (over `last_active`, which would then equal the whole roster) useless. The
  separate table is load-bearing for both decisions.
- **`WithUserAutoDeprovision` signature change**: rejected — it would break SDK
  callers passing `SessionLastActive`. The type-assertion seam keeps the option
  API frozen; a store that is a `LastActiveSource` is wireable as-is.
- **Missed login paths**: any future login route that neither calls
  `authenticateUser` nor `finalizeCallbackSession` would silently skip the
  signal. The acceptance test must cover password, federated, and ceremony
  flows; the two anchors' coverage of ceremonies is transitive (verified
  against `server_mfa.go`) but must be regression-tested, since a new
  authenticator wired without the funnel would be blind.
- **Refresh-only users**: refresh-token grants and per-request
  `TrackActivity` (`spi.go:150`) do not Touch; a user who only refreshes
  sessions can still age into dormancy. This is a deliberate boundary
  (user-level signal = authentication events only) and matches today's
  session-derived behavior; extending the signal to refresh activity is a
  future knob, not this change.
- **Config drift**: `docs/config-reference.md` must name the durable backend
  and drop the "no other activity backend exists" caveat in the same change
  that lands the wiring, per the contract-update rule.
