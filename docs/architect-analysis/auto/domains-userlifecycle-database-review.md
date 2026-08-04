# Database-Architect Review: domains/userlifecycle production-hardening (design: domains-userlifecycle-prod-design.md)

Review basis: `ai-dev/prompts/README.md`, `docs/auto/domains-userlifecycle-prod-design.md`,
its spec (`docs/auto/domains-userlifecycle-prod-spec.md`), current executable
code, and the durable-store precedents the design cites. The feature is
**Proposed** (design only — no implementation landed; HEAD `0235cc47` is the
"Stage: design" commit).

**Checks that ran at this revision:**
- `go build ./... && go vet ./...` — **PASSED**.
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — **PASSED**
  (the maintainability gate's `skipDirs` does contain `"postgres": true`
  (`maintainability_budget_test.go:53`), so `infrastructure/postgres` is out of
  the file-size gate; it is NOT a nested module — AGENTS.md §4 keeps Postgres a
  root-module package — the skip is by directory *name*).
- `go test -race -count=1 ./domains/userlifecycle/...` — **PASSED**.
- Source reads/greps of every cited path; no postgres integration tests ran
  (they self-skip without `SSO_TEST_POSTGRES_DSN`, `infrastructure/postgres/postgres_test.go:18`).

Every claim about current code is **Verified** (code read or gate run) unless
labeled; design claims are **Proposed**; gaps are **Missing**. This is advisory
analysis; no files were modified.

The two architect-level corrections the design makes to the spec are **both
confirmed correct against the code** (validated, not findings):

- **Rejection of `ListByState`-based enumeration.** Verified: `Store.ListByState`
  "never returns" unrecorded users (`domains/userlifecycle/userlifecycle.go:143-147`),
  `ListByState` has zero callers in production code, and `SweepOnce` today walks
  the full roster (`sweep.go:30-50`) and deprovisions exactly the unrecorded
  users — their `Get` returns `DefaultState` and memory `Append` from
  `StateActive` on a missing row succeeds (`memory/memory.go:47-66`). A
  `ListByState`-driven sweep would silently stop deprovisioning every
  first-transition user. The stale-`last_active` cursor is provably the exact
  eligible set: `IsDormant` fires only on a non-zero signal older than the
  threshold (`dormancy.go:29-34`), and every user with a stale signal has a
  `user_lifecycle_last_active` row.
- **Lease inside `SweepOnce`.** Verified contradiction: the spec's acceptance
  test drives two concurrent `SweepOnce` calls directly, so a lease acquired in
  `RunUserAutoDeprovision` (`interfaces/sso/options_admin.go:306`) could never
  serialize them. Opt-in via new zero-value `Holder`/`LeaseTTL` fields keeps
  every existing `sweep_test.go` fixture (no `Holder` set) byte-identical.

---

## 1. Store inventory: purpose, durability, implementation, stock wiring, consistency

| # | Store / table | Purpose | Durability | Implementation | Stock binary wiring | Consistency requirement |
|---|---|---|---|---|---|---|
| S1 | `userlifecycle.Store` (memory) | lifecycle state + history state machine | **Volatile** (process map) | `domains/userlifecycle/memory/memory.go` (RWMutex; Get-default, optimistic Append, sorted ListByState) | **Yes** — `serverbuildplatform.BuildUserLifecycle` returns `userlifecyclememory.New()` unconditionally when `user_lifecycle.enabled` (`build_userlifecycle.go:18-24`); wired via `wireUserLifecycle` (`cmd/sso-server/build_stores.go:328-356`) | Per-user optimistic concurrency: exactly one concurrent Append with the same `From` wins; missing row == `DefaultState` |
| S2 | `memory.ActivityTracker` | in-process last-active signal | **Volatile** | `memory/memory.go:94-139` (monotone `TouchAt`, map) | **None** — zero production callers of `Touch`/`TouchAt` (grep-verified); the only `Touch` in the tree is the admin token store's | Monotone write (older `at` never regresses); zero signal = unknown |
| S3 | `SessionLastActive` | session-derived activity signal | Derived (live sessions only; blind outside retention window) | `dormancy.go:38-66` | **Yes** — `wireUserLifecycle` passes it as the activity source for every current build (`cmd/sso-server/build_stores.go:346`) | Newest `Session.CreatedAt` per user; zero = unknown |
| S4 | postgres shared pool (`pgDB`/`pgDialect`) | durable substrate for every `backend: postgres` store | **Durable** | `infrastructure/postgres/pool.go` (`Open`, pgx stdlib; Dialect postgres/cockroach) | **Yes** — `wirePostgres` (`build_bootstrap.go:308`) runs before `wireDomains`/`finalize`; ready check registered | One pool per DSN; caller owns Close |
| S5 | postgres durable precedents | invitations, sessions, device secrets, permissions, users | **Durable** | `invitation.go` (`NewInvitationStoreWithDB`, `Run(ctx, db, ns, migrations, dialect)` + `DELETE…RETURNING` consume), `session.go` (`UPDATE…RETURNING` refresh), `device_secrets.go`, `permissions*.go` (shared-pool + `permissionstest.ConformanceSuite`), `users.go` (`List` = `SELECT … FROM users ORDER BY id ASC`, no pagination) | **Yes** — `backend: postgres` stores | Single-use atomic consume; schema migrated under per-namespace advisory lock |
| S6 | identitylink durable peers | identity-link store | Durable | `infrastructure/identitylinkpostgres/` (`NewWithDB(pg, dialect)`) + `domains/identitylink/sqlite/` (own `go.mod`-free root package; `New(dsn)`, `migrate.Run`, `MaxVersion()`) | **Yes** — `BuildIdentityLinkDurable(cfg, b.pgDB, b.pgDialect)` (`build_identitylink.go:37`), with boot `CheckSchema` for both backends (`cmd/sso-server/build_stores.go:380-411`) | Same contract across memory/sqlite/postgres; version-table parity across backends |
| S7 | sqlite peers | durable embedded/test peers for domain stores | **Durable** (file DSN) | `domains/permissions/sqlite/` (+ `sqlite_conformance_test.go`), `infrastructure/defaultimpl/sqlite/` (sessions, auth_codes, refresh_tokens — `DELETE…RETURNING` atomic consumes; `busy_timeout.go`) | **Yes** — `backend: sqlite` for permissions/identity_link/sessions etc. | Byte-parity schema + `?` placeholders; same migration namespaces as postgres |
| S8 | **Proposed** `user_lifecycle`, `user_lifecycle_history`, `user_lifecycle_last_active`, `sweep_lease` | durable lifecycle + history, durable activity signal, sweep coordination | **Durable** | design decisions 1-3 (postgres in `infrastructure/postgres/`, sqlite peer in `domains/userlifecycle/sqlite/`, conformance in `userlifecycletest`) | **None yet** — `BuildUserLifecycle` signature change + `wireUserLifecycle` backend selection must land together or the durable backend is unreachable in `sso-server` | Memory-contract parity via conformance suite; atomic Append; monotone TouchAt; single-holder lease |

**Bottom line on "hot vs durable, and does the stock binary wire it":**

- Every currently shipped lifecycle store is **volatile or derived** (S1-S3);
  the durable backend is **Proposed** and, like the identity-link durable
  backend before it, becomes reachable only when the builder + wire function
  land in the same change.
- The login hot path today performs **zero** lifecycle writes. Decision 3 adds
  exactly one PK upsert per successful login — but only on the durable path;
  memory builds keep zero writers (byte-identical), which the design states
  correctly (`memory.ActivityTracker` cannot satisfy `ActivityRecorder` — its
  `TouchAt` takes no `ctx` and returns nothing, `memory/memory.go:121`).
- The sweep hot path today is a **full-roster scan** (`Users.List`, unbounded;
  `shared/core/spi.go:42` "List returns every known user"; postgres
  implementation `ORDER BY id ASC` with no pagination). Decision 2's cursor
  replaces it only when the activity source implements `StaleEnumerator` —
  i.e. only durable builds; `SessionLastActive` (S3) keeps the roster walk.
- The design's placement claims are accurate: shared-pool backend precedent is
  `infrastructure/postgres/permissions*.go`; embedded/test peer precedent is
  `domains/<domain>/sqlite/` and `infrastructure/defaultimpl/sqlite/` (the
  spec's guess of `infrastructure/sqlite` does not exist). Postgres integration
  tests self-skip without `SSO_TEST_POSTGRES_DSN`, so the SQLite peer as the
  in-gate conformance target is the right call.

---

## 2. Findings (sorted by severity)

### F-DB-1 (High — verified coverage defect in decision 3): the WebAuthn primary login ceremony issues tokens without passing through either Touch anchor; the design's "ceremony coverage is transitive" claim is incomplete

- **Evidence (Verified):** `MountWebAuthnRoutes` is stock-wired
  (`cmd/sso-server/build_http.go:290`) and mounts `/webauthn/login/finish` +
  `/webauthn/login/conditional/finish` (`webauthn.go:38-51`). Both handlers
  (`webauthn_handlers.go:122`, `:258`) authenticate the subject via
  `deps.Helper.FinishLogin`/`FinishLoginConditional` and — with a `client_id`
  and wired token issuers — mint a full token bundle (access/refresh/ID token)
  via `applyWebAuthnTokenIssuance`. **Neither handler calls
  `s.authenticateUser` nor `s.finalizeCallbackSession`** — they are standalone
  HTTP handlers on `WebAuthnDeps`, so a WebAuthn first-factor (passwordless)
  login never reaches either of the design's two anchors. The design's
  transitive-coverage claim is verified only against `server_mfa.go` — which is
  the MFA-*completion* ceremony replaying a frozen `AuthResult` whose primary
  leg already Touched (`server_mfa.go:158-162`, `:368`) — not against the
  WebAuthn primary ceremony.
- **Impact:** (a) A user whose only login path is WebAuthn and who previously
  logged in any other way has a stale `last_active` row → the durable cursor
  lists them → the sweep transitions an **actively-logging-in user** to
  INACTIVE and later ARCHIVED. (b) A WebAuthn-only user with no prior row is
  invisible to the cursor forever — the feature's dormancy coverage silently
  misses a whole first-factor family. Both contradict the design's own
  "missed login paths" risk note, which anticipated this class but asserted the
  coverage was verified. Lifecycle never gates auth, so this is state-truth
  corruption, not a lockout — hence High, not Critical.
- **Recommendation:** add a third anchor: a small exported Server helper
  (e.g. `srv.TouchUserActivity(userID)`) that does the same type-assert +
  fail-open `TouchAt`, called from both WebAuthn finish handlers immediately
  after `FinishLogin` success (before token issuance). Add a regression test
  driving `/webauthn/login/finish` and asserting the signal was written (the
  design's acceptance test must cover this route, not just password/federated/
  MFA-replay).

### F-DB-2 (Medium — state-truth gap the design leaves open): nothing reactivates INACTIVE (or ARCHIVED) on login; the durable Touch makes the gap observable

- **Evidence (Verified):** `StateInactive` is documented "Reversible back to
  ACTIVE (e.g. on next login)" (`userlifecycle.go:44-46`); `INACTIVE -> ACTIVE`
  is legal (`transitions.go` table). Grep-verified: **no production code path
  performs the reactivation** — the only INACTIVE→ACTIVE writer is the admin
  POST endpoint. The design's decision 2 even acknowledges the race that makes
  this visible: "a user read as stale who logs in mid-run may still be
  transitioned this run" — with no reactivation seam, that user stays INACTIVE
  indefinitely (fresh `last_active` stops the archive clock, so the account is
  usable but administratively mislabeled until an admin acts).
- **Impact:** after the durable sweep ships, every returning dormant user who
  logs in again carries a stale INACTIVE/ARCHIVED marker; admin dashboards and
  any future auth-gating built on lifecycle state read wrong state for active
  accounts.
- **Recommendation:** decide explicitly in the design. If reactivation is
  intended (the doc comment suggests it), extend the Touch seam with one
  conditional `Append(INACTIVE -> ACTIVE)` (same atomic upsert; no-record
  invariant unaffected because INACTIVE implies a record exists) and add a
  conformance case. If not intended, amend the `StateInactive` doc comment and
  note it in `docs/config-reference.md`. Either way the design must state it.

### F-DB-3 (Medium — schema defect): decision 2 and decision 3 contradict each other on the cursor index; the single-column `(last_active)` index cannot serve the keyset page

- **Evidence (Verified, Proposed):** decision 2's storage model specifies the
  cursor query `WHERE last_active < $cutoff AND (last_active, user_id) > ($1,$2)
  ORDER BY last_active, user_id LIMIT $n` and says "index `(last_active,
  user_id)`". Decision 3's storage model specifies
  `CREATE INDEX idx_user_lifecycle_last_active ON user_lifecycle_last_active(last_active)`
  and claims it "serves both `LastActive` and decision 2's keyset cursor
  ((last_active, user_id) scan)". A single-column index cannot satisfy the
  row-value predicate without sorting the entire stale set per page — the O(k)
  acceptance bound degrades to O(stale) per page.
- **Impact:** at scale (the spec's own "ten-thousand-plus users" framing),
  per-tick sweep cost grows with the stale set rather than the page.
- **Recommendation:** create one composite index `(last_active, user_id)` (it
  also serves the plain `< cutoff` range; `LastActive` reads go through the PK
  anyway) and drop the single-column one. Assert in the acceptance test with
  `EXPLAIN` (both backends) that the page query is an index-range scan.

### F-DB-4 (Medium — unbounded cost leak): deleted users' lifecycle + last-active rows persist forever and are re-scanned every tick

- **Evidence (Verified):** `UserProvider.Delete` exists and is admin-only
  (`shared/core/spi.go:52`); nothing cascades into `user_lifecycle`,
  `user_lifecycle_history`, or `user_lifecycle_last_active` (no such tables
  exist yet, and the design declares deletion-time cleanup a non-goal). The
  design's ghost guard (`GetByID` filter before `sweepUser`) fixes correctness
  — the sweep never creates a record for a deleted user — but every orphan row
  has `last_active < cutoff` forever, so **each tick re-lists all orphans**:
  the O(k) claim silently becomes O(k + orphans) with monotone growth.
- **Recommendation:** keep the ghost guard, but (a) add an acceptance case that
  pages the cursor over a large orphan set and asserts bounded cost, and (b)
  schedule deletion-time cleanup of the three tables (one DELETE per table
  inside the user-deletion transaction) as a follow-up; at minimum record the
  orphan count on the sweep log so growth is observable.

### F-DB-5 (Medium — rollback-safety gap): the wiring omits the `CheckSchema`/`MaxVersion` boot gate both durable precedents use

- **Evidence (Verified):** `wireIdentityLink` fails loud at boot when the live
  schema is ahead of the binary: `postgresbackend.CheckSchema` for postgres and
  `serverbuildsign.CheckSQLiteSchema` for sqlite, backed by `MaxVersion()` on
  each store (`cmd/sso-server/build_stores.go:380-411`,
  `domains/identitylink/sqlite/store.go:91-92`). The design's wiring section
  (decision 1) names only the constructors and the builder, not the schema
  check. Without it, a binary that understands `user_lifecycle` up to v2 will
  silently run against a v3 database — `Run` skips versions ≤ current and
  applies nothing (`infrastructure/postgres/migrate.go:applyPending`).
- **Impact:** mixed-version fleet during a rolling upgrade is the exact window
  this guard exists for; without it, a v2-max binary reads v3 tables it may not
  fully understand.
- **Recommendation:** mirror `wireIdentityLink`: call
  `postgresbackend.CheckSchema(b.schemaCtx, b.pgDB, "user_lifecycle", MaxVersion())`
  for postgres and `CheckSQLiteSchema` for sqlite in `wireUserLifecycle`, and
  ship `MaxVersion()` on both peers.

### F-DB-6 (Low): lease loss and holder collisions are silent

- **Evidence (Proposed):** decision 2 returns `(0, nil)` on a lost lease —
  indistinguishable from a disabled sweep; `RunUserAutoDeprovision` logs only
  `SweepOnce` errors (`options_admin.go:319-327`).
- **Recommendation:** log (info) a skipped-tick reason when `Holder` is set and
  the lease was lost, so a misconfigured multi-replica deployment is
  observable. Optionally surface a `lease_holder`/`lease_expires_at` admin or
  metrics readout.

### F-DB-7 (Info): `ListStaleAfter` returns IDs only; the sweep re-reads the signal per candidate

- **Evidence (Proposed):** each candidate costs `Lifecycle.Get` (PK) +
  `LastActive.LastActive` (PK) — two extra PK reads per candidate, even though
  the cursor already holds `last_active` in the row it scanned.
- **Recommendation:** return `(userID, lastActive)` tuples from
  `ListStaleAfter`; keep the per-user re-read inside `sweepUser` only when the
  signal is stale by more than a page duration (the Touch race the design
  documents). Optional; the O(k) bound is unaffected.

### F-DB-8 (Info): the conformance suite's determinism seam does not exist on the memory peer today

- **Evidence (Verified):** the design says the SQL store's `now` is injectable
  "mirroring memory's `now func()`" — but `memory.Store.now` and
  `ActivityTracker.now` are unexported fields with no setter (`memory/memory.go:24-31`,
  `:104-113`), and the suite lives in a separate package
  (`userlifecycletest`), so it cannot freeze the memory peer's clock.
- **Recommendation:** have the suite use relative offsets from
  `time.Now()` (or add an exported test seam); note that the suite must not
  rely on injectable `now` for the memory peer.

### F-DB-9 (Info): no readiness/health surface for the lifecycle store

- **Evidence (Verified):** the identity-link wiring registers a ready check and
  a health append for both backends (`build_stores.go` `appendIdentityLinkHealth`,
  `serverbuildsign.AppendReadyCheck`); the design mentions none for
  `user_lifecycle`. Postgres reachability is partially covered by the shared
  "postgres" ready check when a postgres block exists, but the sqlite backend
  has no equivalent.
- **Recommendation:** mirror the identity-link pattern (Ping-based ready check)
  for parity; optional.

**Validation note (not a finding):** the design's decision-1 Append mapping was
checked against the memory store for all six row-presence × From combinations;
it is exactly equivalent (see section 3). The design's identification of
`RowsAffected` ambiguity (`DO NOTHING` conflict and false `WHERE` both report 0)
matches PostgreSQL, SQLite, and CockroachDB semantics and is correctly slated
for per-backend conformance assertions.

---

## 3. Query/index and transaction analysis

### 3.1 Proposed `Append` (decision 1) — atomicity and parity

The single-statement design is:

```sql
INSERT INTO user_lifecycle (user_id, state, updated_at)
SELECT $1,$2,$3 WHERE $from = 'active'
ON CONFLICT (user_id) DO UPDATE
   SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at
   WHERE user_lifecycle.state = $from
```

Truth-table against `memory.Store.Append` (`memory/memory.go:47-66`):

| Row exists | From | Memory result | SQL result |
|---|---|---|---|
| no | `StateNone` (seed) | insert (conflict if raced) | `INSERT … ON CONFLICT DO NOTHING` → 1 row / 0 = `ErrStateConflict` |
| yes | `StateNone` | `ErrStateConflict` | 0 rows = `ErrStateConflict` |
| no | `active` | success (missing == DefaultState) | `SELECT … WHERE $from='active'` → 1 row |
| yes | `active` (state=active) | success | `DO UPDATE … WHERE state='active'` → 1 row |
| yes | `active` (state≠active) | `ErrStateConflict` | `WHERE` false → 0 rows |
| no / yes | anything else | `ErrStateConflict` | 0 rows |

The mapping is exactly correct, including the load-bearing missing-row-as-ACTIVE
case. Concurrency semantics per backend:

- **PostgreSQL (READ COMMITTED):** the design's EvalPlanQual claim is correct —
  a concurrent loser's `WHERE` re-evaluates against the winner's committed row
  version, so exactly one concurrent Append with the same `From` succeeds. The
  seed-vs-non-seed race is serialized by the unique index plus the same
  re-check.
- **SQLite:** no EvalPlanQual; the single-writer lock serializes whole
  statements. This is *not* a problem, but the conformance suite's
  concurrent-append test must use the repo's busy-timeout pattern
  (`infrastructure/defaultimpl/sqlite/busy_timeout.go` precedent), or
  concurrent writers surface `SQLITE_BUSY` instead of `ErrStateConflict`.
- **CockroachDB:** serializable isolation; a concurrent loser gets 40001, not a
  deterministic 0-row result. The design's bounded retry (≤5, the
  `serializableMaxRetries` convention in `infrastructure/postgres/migrate.go`)
  re-running the conditional statement is safe because the `WHERE` re-checks
  live state. The conformance suite must run the concurrent-append case under
  the CRDB dialect too (env-gated, like every postgres test today).

History sequencing: `INSERT … SELECT $user_id, COALESCE(MAX(seq),0)+1, …` in the
same transaction is sound — every non-seed Append holds the user's
`user_lifecycle` row lock until commit (so the MAX sees all committed siblings),
and concurrent seeds serialize on the unique index. `MAX(seq)` per user is an
index-backward scan on the `(user_id, seq)` PK — O(history) in the worst case,
but practically a constant. One step the design must pin explicitly: **when the
conditional upsert returns 0 rows, the history insert must be skipped** and
`ErrStateConflict` returned (the design's "0 rows affected = ErrStateConflict"
implies it; make it a conformance assertion so no implementation drifts).

### 3.2 Proposed `TouchAt` (decision 3) — hot-path write

One PK upsert per successful login:

```sql
INSERT INTO user_lifecycle_last_active (user_id, last_active) VALUES ($1,$2)
ON CONFLICT (user_id) DO UPDATE SET last_active = EXCLUDED.last_active
   WHERE user_lifecycle_last_active.last_active < EXCLUDED.last_active
```

0 rows on a stale write = no-op (matches memory `TouchAt` monotonicity
exactly). The statement is bounded work (PK index hit; no read-then-write), so
the fail-open synchronous placement is defensible. Placement notes:

- Anchors verified: `authenticateUser` after the SCIM gate
  (`server_login_auth.go:98`, covers password/LDAP/OTP primaries) and
  `finalizeCallbackSession` after the federated SCIM gate (`server_oauth.go:221-232`).
- **F-DB-1 applies: the WebAuthn primary ceremony is a third, uncovered anchor.**
- Refresh grants and per-request `TrackActivity` (`shared/core/spi.go:150`,
  invoked at `server_oauth.go:494`) deliberately do not Touch — a defensible
  boundary (authentication events only), correctly documented by the design.

### 3.3 Proposed lease (decision 2)

```sql
INSERT INTO sweep_lease (holder, expires_at) VALUES ($1,$2)
ON CONFLICT (holder) DO UPDATE SET expires_at = EXCLUDED.expires_at
   WHERE sweep_lease.expires_at < $now          -- 1 row = acquired, 0 = live holder
DELETE FROM sweep_lease WHERE holder = $1       -- release, holder-scoped
```

Sound: crash leaves a TTL-expiring row (no stale-holder deadlock); a restore
from backup with a future `expires_at` self-heals within one TTL (bounded
sweep idling, never wrong-deprovisioning — the sweep simply doesn't run).
Because `sweep_lease` is a single row keyed by holder, the design should state
that the lease is fleet-global per database (there is exactly one
`DeprovisionConfig` per deployment — true today; if per-tenant deprovision
configs ever arrive, the lease needs a namespace column).

### 3.4 Proposed cursor (decision 2) — cost model

`WHERE last_active < $cutoff AND (last_active, user_id) > ($afterLA, $afterID)
ORDER BY last_active, user_id LIMIT $n` requires the composite index
(F-DB-3). With page size = `MaxPerSweep`, per-tick cost is
O(min(stale, MaxPerSweep)) + O(orphans re-listed) — bounded by the storm guard,
except for the orphan leak (F-DB-4). Row-value comparison is supported on
Postgres and SQLite (and CockroachDB); separate statement constants per backend
with conformance coverage is the right call given SQLite's stricter upsert
grammar.

### 3.5 Evidence from existing atomic/hot paths (repo conventions the design matches)

- Single-use atomic consume via `DELETE … RETURNING`: invitations
  (`infrastructure/postgres/invitation.go:117`), device secrets
  (`device_secrets.go:116`), auth codes (`infrastructure/defaultimpl/sqlite/auth_codes.go:303-320`),
  refresh-token rotation with family mirror (`defaultimpl/sqlite/refresh_tokens.go:137-165`).
- Conditional refresh via `UPDATE … RETURNING` with a `WHERE` re-check:
  `infrastructure/postgres/session.go:181-199`.
- The design's conditional-upsert approach is a different *shape* (single
  statement + RowsAffected) but the same discipline: no read-then-write, atomic
  claim, zero-rows-as-conflict. The `RowsAffected`-ambiguity risk it flags
  (both `DO NOTHING` and false-`WHERE` report 0) is real and correctly assigned
  to per-backend conformance assertions.

---

## 4. Safe migration sequence

All three versions are **additive `CREATE TABLE`s** — no `ALTER` on shared
tables, no backfill, no lock window. The namespace `user_lifecycle` must be
identical across the postgres and sqlite peers (permissions precedent: "the
namespace string 'permissions' is kept identical to the SQLite peer",
`infrastructure/postgres/permissions.go:14-16`) so either backend reports the
same version table.

| Step | Migration | Content | Compatibility |
|---|---|---|---|
| v1 | `user_lifecycle` + `user_lifecycle_history` | state/history (decision 1) | additive; old binaries ignore unknown tables |
| v2 | `user_lifecycle_last_active` | durable activity signal (decision 3) | additive |
| v3 | `sweep_lease` | sweep coordination (decision 2) | additive |

Independent versions correctly let the three improvements ship in any order.

- **Compatibility window:** none required. Every migration is a new table; the
  only cross-version contract is the `user_lifecycle` version table itself,
  which the old binary does not know about (so no `ErrSchemaTooNew` risk on
  rollback). One operator-visible caveat the design should document: switching
  `backend: memory → postgres|sqlite` starts from an **empty** store — every
  account reads ACTIVE again (the no-record anchor). Volatile memory data was
  lost on restart anyway, but the admin-visible state regression at switchover
  should be stated.
- **Roll-forward:** `Run` applies pending versions on boot under the
  per-namespace advisory lock (postgres) / SERIALIZABLE + 40001 retry
  (CockroachDB) — `infrastructure/postgres/migrate.go`; sqlite peer uses
  `platform/migrate` (`domains/identitylink/sqlite/store.go:64-70` precedent).
- **Rollback:** binary rollback is safe while the older binary predates the
  namespace. Once F-DB-5's `CheckSchema` lands, rolling a v2-max binary back
  onto a v3 database fails loud at boot — the intended guard (identity-link
  precedent).
- **Validation queries after each migration (run on both backends):**
  ```sql
  -- version bookkeeping (namespace shared across backends)
  SELECT MAX(version) FROM schema_migrations_user_lifecycle;   -- expected: applied max

  -- table + index existence and shape
  SELECT table_name FROM information_schema.tables
    WHERE table_schema = current_schema() AND table_name IN
      ('user_lifecycle','user_lifecycle_history','user_lifecycle_last_active','sweep_lease');
  SELECT indexname FROM pg_indexes WHERE tablename = 'user_lifecycle_last_active';
  -- sqlite peer: sqlite_master (type='table'/'index')

  -- state domain + PK integrity
  SELECT state, count(*) FROM user_lifecycle GROUP BY state;          -- only the six wire states
  SELECT count(*) FROM user_lifecycle WHERE user_id = '';             -- 0
  SELECT count(*) FROM (SELECT user_id, seq FROM user_lifecycle_history
                        GROUP BY user_id, seq HAVING count(*) > 1);   -- 0 (PK would reject anyway)

  -- per-user history monotonicity + continuity
  SELECT user_id, min(seq), max(seq), count(*) - (max(seq)-min(seq)+1) AS gaps
    FROM user_lifecycle_history GROUP BY user_id HAVING gaps <> 0;    -- 0 rows

  -- sweep/activity sanity
  SELECT count(*) FROM user_lifecycle_last_active;                    -- ≤ distinct logins since v2
  SELECT count(*) FROM sweep_lease;                                   -- 0 or 1
  ```
- **Data-integrity checks:** the conformance suite (both backends + memory)
  covers Get-default, seed/conflict, missing-row-as-ACTIVE append, history
  order, ListByState parity, TouchAt monotonicity, lease acquire/release, and
  concurrent-append (exactly one winner). Add F-DB-1's route-level login test,
  an orphan-page cost test (F-DB-4), and an `EXPLAIN` assertion for the cursor
  index (F-DB-3). Postgres/CRDB cases remain env-gated (`SSO_TEST_POSTGRES_DSN`)
  — the suite must therefore also run in-gate on the SQLite peer.

---

## 5. Unknown volume, retention, and recovery assumptions

No workload evidence exists anywhere in the repo for this domain; the following
must be measured or explicitly assumed before production:

1. **Roster size and per-tick sweep cost.** `Users.List` is a full-table scan
   with no pagination (postgres `ORDER BY id ASC`); the spec's "ten-thousand
   plus" figure is not sourced. Measure roster size, sweep duration, and
   `MaxPerSweep` drain rate; the cursor's benefit is only real when the stale
   set ≪ roster.
2. **Login rate → hot-path write cost.** One PK upsert per login (durable
   builds only); no benchmark exists of the added round-trip at peak login rate,
   nor of `SessionLastActive.LastActive`'s `ListByUser` cost on the fallback
   path (a per-candidate scan of the user's live sessions).
3. **History growth and retention.** `user_lifecycle_history` is unbounded
   append-only by design (parity with memory); no retention/compliance
   requirement is stated. Measure per-account transition rates and agree a
   retention knob before multi-year operation.
4. **Orphan accumulation.** Admin `UserProvider.Delete` frequency is unknown;
   orphan rows are re-scanned every tick (F-DB-4). Needs a measurement and a
   cleanup follow-up.
5. **Multi-replica count and clock skew.** Lease TTL default (2× sweep_interval)
   assumes bounded skew; the repo convention is application-clock time, so skew
   beyond TTL/2 can cause duplicate sweeps (benign, conflict-absorbed) — state
   the assumption.
6. **DormantAfter/ArchiveAfter distributions** determine stale-set size per
   tick; no deployment data exists.
7. **Backup/PITR and restore.** Lifecycle tables ride the main DB backup; no
   restore drill exists (postgres tests are env-gated). Restore-time lease skew
   self-heals within one TTL; history is the audit/compliance record — confirm
   PITR coverage with the operator.
8. **Switchover semantics** (memory → durable) reset observed state to ACTIVE
   for all accounts; document this as an operator-facing consequence.

---

## Summary

The design is architecturally sound and its two corrections of the spec are
verified against the code; the Append/TouchAt/lease/cursor SQL is consistent
with the repo's atomicity conventions and the memory contract. Before
implementation: fix the WebAuthn anchor gap (F-DB-1), state the reactivation
decision (F-DB-2), unify the cursor index (F-DB-3), add the orphan-cost
measurement (F-DB-4), and ship the `CheckSchema` boot gate (F-DB-5). The
remaining items are operational hardening. Required-fix vs optional: F-DB-1
through F-DB-5 are required before the design is implementation-ready; F-DB-6
through F-DB-9 are optional improvements.
