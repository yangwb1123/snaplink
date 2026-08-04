# Distributed-Systems Engineering Review: `domains/userlifecycle` production-hardening (durable store, leased sweep, persistent last-active)

Review of `docs/auto/domains-userlifecycle-prod-design.md` from the
distributed-systems standpoint: consistency, ordering, atomicity, idempotency,
ownership, conflict resolution, replication, partition/crash/retry/clock
behavior, and the documented fail-open/fail-closed boundary. Advisory only; no
files changed.

## 0. Method and verification

All claims below were verified by source inspection at this revision; a
`go build ./...` and `go test ./domains/userlifecycle/...` run green as a
baseline sanity check (this review changes no code, so the mandatory `.go`
gates are unaffected). Evidence labels: **Verified** = read in the tree at
this revision; **Partial** = confirmed with a caveat; **Proposed** = design
intent not yet in code; **Unknown** = no evidence found.

| Claim | Status | Evidence |
|---|---|---|
| `Store` = Get/Append/ListByState; `ListByState` never returns unrecorded users; `Append` is an atomic optimistic CAS (`ErrStateConflict` on mismatch) | **Verified** | `domains/userlifecycle/userlifecycle.go:83-155` (interface + `ErrStateConflict`); `ListByState` doc: "Users with no record (implicitly DefaultState) are NOT returned" |
| Memory `Append`: missing row = `DefaultState`; seed requires no record; monotone `TouchAt` | **Verified** | `domains/userlifecycle/memory/memory.go:38-66` (Append), `:108-126` (TouchAt) |
| `SweepOnce` walks the full roster via `Users.List`; `MaxPerSweep` caps APPLIED transitions only; per-user errors log-and-skip | **Verified** | `domains/userlifecycle/sweep.go:46-62` (`SweepOnce`), `:139-157` (`apply`); `TestSweepOnce_MaxPerSweepCap` exists (`sweep_test.go:153`) |
| Dormancy predicate is `last_active < now - threshold`, zero signal never dormant | **Verified** | `domains/userlifecycle/dormancy.go:27-36` (`IsDormant`) |
| `RunUserAutoDeprovision` is a per-process ticker, no coordination seam; starts one goroutine per process | **Verified** | `interfaces/sso/options_admin.go:319-341`; `cmd/sso-server/build_stores.go:358-374` (`startUserAutoDeprovisionSweep`) |
| Wiring: `build_stores.go:347` passes `SessionLastActive`; `BuildUserLifecycle` is unconditional memory | **Verified** | `build_stores.go:346-347`; `cmd/sso-server/serverbuildplatform/build_userlifecycle.go:18-23` |
| `BuildIdentityLinkDurable(cfg, pg, dialect)` precedent for the builder signature change | **Verified** | `serverbuildplatform/build_identitylink.go:36-38`; `b.pgDB`/`b.pgDialect` populated by `wirePostgres` before `wireEdge`/`wireUserLifecycle` (`build_app.go`) |
| Login anchors: `authenticateUser` after `rejectDeactivatedUser` (`server_login_auth.go:98`); `finalizeCallbackSession` after the SCIM gate (`server_oauth.go:223`) | **Verified** | `interfaces/sso/server_login_auth.go:97-103`; `interfaces/sso/server_oauth.go:223-233` |
| Ceremony coverage is transitive via `finishLogin` replay | **Verified** | `interfaces/sso/server_mfa.go:158,368` (`finishLoginWithDeviceTrust` replay) |
| `WithUserAutoDeprovision(cfg, LastActiveSource)` — no signature change needed | **Verified** | `interfaces/sso/options_admin.go:296` |
| Gate context: `maintainability_budget_test.go` `skipDirs` skips `infrastructure/postgres`; complexity gate shares the set | **Verified** | `maintainability_budget_test.go:42-58`; `maintainability_complexity_test.go:137` |
| Conformance precedents: `permissionstest.ConformanceSuite`; sqlite peers in `domains/<domain>/sqlite/` and `infrastructure/defaultimpl/sqlite/` | **Verified** | `domains/permissions/permissionstest/conformance.go`; `domains/permissions/sqlite/`, `domains/identitylink/sqlite/`, `infrastructure/defaultimpl/sqlite/sessions.go`; postgres peer runs the suite (`infrastructure/postgres/permissions_conformance_test.go`) |
| Migration pattern: `Run(ctx, db, namespace, migrations, dialect)` + advisory lock; `NewInvitationStore`/`NewInvitationStoreWithDB` constructors | **Verified** | `infrastructure/postgres/migrate.go:75-110`; `infrastructure/postgres/invitation.go:47-70` |
| `TrackActivity` is session-scoped, called from refresh grant | **Verified** | `shared/core/spi.go:148-151`; `internal/handler/tokengrant/token_refresh.go:423` |
| Config reference carries the "no other activity backend exists" caveat | **Verified** | `docs/config-reference.md:697` |
| Lifecycle state is NOT a login gate (no `userlifecycle` reference in the login path; direction-1 gate not landed); login never reactivates INACTIVE/ARCHIVED automatically | **Verified** | `interfaces/sso/server_login_auth.go`, `server_login.go` (grep); `domains/userlifecycle/transitions.go:17-27` (INACTIVE→ACTIVE legal but admin/sweep-only) |
| `infrastructure/postgres` is a root-module package (no `go.mod`), imported by `cmd` | **Verified** | `find . -name go.mod` (no `infrastructure/postgres/go.mod`); import in `build_stores.go`; skipDirs' "nested modules" comment is stale for `postgres`/`redis` (AGENTS.md: "Redis and Postgres remain root-module packages") |
| The three spec-correction claims (companion interfaces; `ListByState` cannot see implicit-ACTIVE users; last-active column would break no-record=ACTIVE) | **Verified** | correction 1: `Store` is SDK surface (`options_admin.go:281`); correction 2: `ListByState` doc + `SweepOnce` roster walk; correction 3: `memory.go` `Touch` semantics + `userlifecycle.go:143-147` |

The design's three resolutions are sound as far as they go — the review below
is where the distributed analysis diverges from the design's own failure
analysis. One finding (F-DS-1) invalidates the core mechanism of decision 2 as
specified; it is a design error, not a missing test.

---

## 1. State map: owner, store, durability, consistency, replication, failover

| State / data | Owner | Store (today → proposed) | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Lifecycle record (state + ordered history) | `domains/userlifecycle` | per-process map (`memory.Store`) → `infrastructure/postgres/user_lifecycle.go` + `domains/userlifecycle/sqlite/` peer | **None today (lost on restart)** → durable via SQL | Strong in-process CAS today; proposed SQL CAS via conditional upsert (one statement + history in one tx) | **None today (per-replica divergence)** → shared pool (postgres) / single file (sqlite) | Store-level (DB HA); boot fails loud if backend unreachable |
| Last-active signal | `domains/userlifecycle` | `memory.ActivityTracker` (zero production writers) → `user_lifecycle_last_active` table | None today → durable | Monotone atomic upsert (`TouchAt`); no read-then-write | Shared DB (proposed) | Store-level; **fail-open write** (login never blocked) |
| Sweep lease | sweep loop (`SweepOnce`) | none → `sweep_lease` table (proposed) | n/a (ephemeral by design) | TTL-expiring single-holder intent — **not achieved as specified** (F-DS-1) | Shared DB (proposed) | TTL expiry frees crashed holders |
| Sweep run | `RunUserAutoDeprovision` ticker | one per process, uncoordinated | n/a | Lost-update races absorbed by `Append` CAS | **None today; proposed exactly-one via lease (intent)** | Lease + CAS make duplicate runs benign, not coordinated |
| User records (`core.User`) | `core.UserProvider` | memory/sqlite/postgres | Backend-dependent | Store-level | Shared | Store-level — read by the sweep's ghost guard and the admin 404 check |
| Sessions (fallback signal) | `core.SessionManager` | memory/sqlite/redis/postgres | Backend-dependent | Store-level | Shared | Store-level — `SessionLastActive` keeps its retention-window blindness |
| Audit (`admin_user_lifecycle_changed`) | `platform/audit` | memory (default)/sqlite/postgres | Default memory = lost on crash | — | — | — |

Two structural facts dominate the review:

1. **Decision 2's headline guarantee — "exactly one replica sweeps at a
   time" — is not delivered by the lease as specified** (F-DS-1). Everything
   else in the design degrades gracefully (CAS absorption, fail-open writes);
   this one silently fails its own acceptance criterion on the only backend
   where it matters (shared SQL).
2. **The SQL peer turns two previously self-healing or invisible hazards into
   durable, permanent ones**: stale lifecycle/last-active rows that survive
   user deletion and poison re-created user ids (F-DS-3), and cross-replica
   clock skew that now decides the dormancy cutoff (F-DS-2). The memory store's
   restart used to erase both; the durable store preserves them.

---

## 2. Findings

### F-DS-1 — High: The lease table as specified cannot exclude a second holder; the acceptance criterion "two concurrent `SweepOnce` runs — exactly one applies" fails on the SQL backend

**Evidence (Verified):** the design's acquire is
`INSERT INTO sweep_lease (holder, expires_at) VALUES ($1, $now+ttl) ON CONFLICT (holder) DO UPDATE ... WHERE sweep_lease.expires_at < $now`,
with `holder TEXT PRIMARY KEY` and holder identity defined as "hostname + pid +
start nonce" — i.e. **distinct per process**. `ON CONFLICT (holder)` only fires
when the *same* holder id is re-inserted. Two replicas with different holder
ids never conflict on the PK: both inserts succeed, both sweeps run. The
"0 rows = another holder is live" reading is only correct if `holder` is a
*single fixed key* (the lock identity) with the holder name as a column — the
design conflates the two. The spec's own acceptance test ("two concurrent
`SweepOnce` runs over one store (two holders) — exactly one applies
transitions; the other acquires no lease and applies zero") therefore fails on
the SQL store as specified: both acquire, both apply, and `apply`'s
skip-and-log absorbs the conflicts — the exact "every tick, every replica"
storm decision 2 exists to end.

**Triggering failure:** any two-replica deployment with `backend: postgres`.
Every tick, both replicas acquire (distinct holder rows), both sweep. The
`ErrStateConflict` absorption the design calls "now rare instead of every
tick" remains every-tick, and transition winners stay nondeterministic.

**User impact:** no data loss or security exposure (CAS absorbs), but the
decision's stated purpose — one authoritative sweep, O(k) work, deterministic
winners — is not delivered; the "exactly one applies" acceptance criterion
fails.

**Recovery:** none needed (fail-safe degradation), but the guarantee is
void.

**Corrective pattern (required):** singleton lease row. Either
`sweep_lease (key TEXT PRIMARY KEY, holder TEXT NOT NULL, expires_at BIGINT NOT NULL)`
with `CHECK (key = 'sweep')` and `ON CONFLICT (key) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at WHERE sweep_lease.expires_at < $now`
(1 row = acquired, 0 rows = another holder is live — now literally true), or a
Postgres advisory lock (`pg_try_advisory_lock`) — but the table form keeps the
SQLite peer byte-parity the design depends on for in-gate tests. Two
companion requirements: (a) release must be holder-scoped
(`DELETE ... WHERE key = 'sweep' AND holder = $1`) so a holder whose lease
expired mid-run cannot delete the successor's lease; (b) the memory peer's
single-flight mutex must be keyed on the *lock*, not on the holder id, or the
two-holder race test fails there too. The holder-PK design additionally leaks
one row per process start (crashed runs never clean up) — the singleton row
eliminates that too.

**Validation:** the spec's own race test, run against the **sqlite peer**
(in-gate) and the postgres backend: two `SweepOnce` runs, two holders, one
store; assert exactly one `TryAcquireSweepLease` returns true. Today (as
designed) both return true. After the fix, add a lease-expiry test asserting a
third holder can acquire after TTL and that the first holder's late release
does not revoke it.

### F-DS-2 — Medium: Cross-replica clock skew decides the dormancy cutoff, not just the lease; "never wrong-deprovisioning" is an overclaim

**Evidence (Verified):** the design's skew analysis covers only the lease ("A
skewed acquirer may over-lease or under-lease; both outcomes are benign"). But
the correctness-sensitive comparison is the dormancy cutoff:
`now(sweeper) - last_active(writer) > DormantAfter` (`dormancy.go:34`). With
the durable store, the writer (login replica) and the decider (sweeping
replica) are different processes for the first time. A writer clock behind
the sweeper clock overestimates idle time by the skew; a forward-jumped
sweeper (NTP failure, VM snapshot resume) does the same. INACTIVE is
reachable at `DormantAfter - skew` and ARCHIVED at
`DormantAfter + ArchiveAfter - skew`. Under the repo convention ("production
clocks slew; they do not step backward", AGENTS.md) the skew is bounded and
small against hour/day thresholds — but the design's blanket "fail-safe,
never wrong-deprovisioning" is not earned, and ARCHIVED is **not
self-healing**: login performs no lifecycle reactivation (Verified: no
`userlifecycle` reference in `server_login_auth.go`/`server_login.go`;
`INACTIVE→ACTIVE` is a legal but admin-only transition, `transitions.go:17-27`).
Today the impact is governance metadata + audit noise; if direction 1's login
gate lands, premature ARCHIVED becomes an availability incident.

**Triggering failure:** bounded replica clock skew (tens of seconds to
minutes) plus a dormancy threshold configured tight relative to the skew;
or an NTP failure on the sweeping replica.

**User impact:** accounts flagged INACTIVE/ARCHIVED without genuine
dormancy; admin must manually restore; audit trail records transitions that
should never have happened.

**Recovery:** admin transition back to ACTIVE (legal per `transitions.go`).

**Corrective pattern (recommended):** (1) state the operating constraint in
`docs/config-reference.md`: `dormant_after` (and `archive_after`) must be ≫
the maximum expected inter-replica clock skew; (2) qualify the design's
"never wrong-deprovisioning" claim to "bounded by skew ≪ threshold"; (3)
optionally log `now - last_active` at the cutoff boundary for observability.
No code change required beyond documentation if the constraint is accepted —
but it must be stated, because the design currently asserts the opposite
property.

**Validation:** fault-injection test with an injectable `Now` on the store
and the sweep: writer clock behind sweeper by δ → assert the transition fires
at `DormantAfter - δ`; pin the margin requirement in the test comment.

### F-DS-3 — Medium: Stale lifecycle + last-active rows survive user deletion and poison re-created user ids; the SQL peer makes the poison permanent

**Evidence (Verified):** no cascade or deletion hook exists for
`user_lifecycle*` rows (the design says deletion-time cleanup is out of
scope; grep confirms no delete path touches the store); the ghost guard only
checks `Users.GetByID` — a **re-created** user exists, so the guard passes;
user-id reuse is a designed flow (`finalizeCallbackSession` and the login
path upsert users via `CreateOrUpdate`, `server_oauth.go:228`; direction-2
review already established login recreates deleted users). Today with the
memory store, a restart implicitly cleans the poison; the SQL peer preserves
it indefinitely. A re-created user inherits a lifecycle record (possibly
INACTIVE, or ARCHIVED/PURGED history), its history, and a stale `last_active`
row → the next sweep ARCHIVEs a **fresh** account.

**Triggering failure:** SCIM deletes a user (or an admin deletes, then a
federated login or SCIM re-provisions the same id) without a lifecycle
transition; the sweep's next tick evaluates the inherited state + stale
signal against the now-existing user.

**User impact:** a freshly provisioned account silently lands in
INACTIVE/ARCHIVED governance state within one tick; admin lifecycle GET shows
stale history; reactivation requires manual admin action.

**Recovery:** admin reactivation (INACTIVE→ACTIVE / ARCHIVED→ACTIVE).

**Corrective pattern (recommended):** the cheapest robust guard is an epoch
check in `sweepUser`: skip (or log) when the user record's `UpdatedAt` is
newer than the lifecycle record's `UpdatedAt` — a re-created user has
`user.UpdatedAt > record.UpdatedAt`, while a legitimately swept user has the
reverse ordering (sweep transition is the newest write). This is O(1) per
candidate and reuses the existing `GetByID` read the ghost guard already
performs (now with a `User` in hand, not a presence check). Alternatively,
deletion-time cleanup of the three tables on the user-deletion path(s); at
minimum, declare id-reuse-after-deletion an unsupported topology in the
config reference. The design's "ghost guard" name covers only deleted users,
not re-created ones — the gap is in the guard's contract.

**Validation:** test on both backends: seed INACTIVE + old `last_active` for
user X, delete X, re-create X with a fresh `UpdatedAt`, run `SweepOnce` →
assert X is not transitioned (post-fix) and that the pre-fix behavior is
documented as the residual.

### F-DS-4 — Low: The `authenticateUser` anchor records primary-auth success, so the durable signal counts logins that never complete MFA

**Evidence (Verified):** the anchor is after `rejectDeactivatedUser` returns
false (`server_login_auth.go:97-103`) — before MFA verification. An
MFA-protected account whose primary factor succeeds but whose factor never
completes still Touches. The session-derived signal it replaces
(`SessionLastActive` over session `CreatedAt`) only ever reflected *completed*
logins. The design's argument for rejecting a `finishLogin` anchor
("redundant under monotonicity") is weak: for password/LDAP/OTP-only users
`finishLogin` is the completion funnel and would be the *single* anchor; for
MFA users it fires only on completion. This is the spec's mandated anchor, so
the design is compliant — the semantic widening is the point of the finding.

**Triggering failure:** none — this is a definitional property. Effect: a
compromised password alone (attacker never completes MFA) refreshes the
dormancy signal; dormancy fires *less* for MFA-protected accounts than the
session-derived semantics did.

**User impact:** deprovisioning hygiene is weakened for exactly the accounts
with the strongest credential posture; fail-safe direction (availability over
hygiene), bounded.

**Corrective pattern (optional):** document the widened "active" definition
in `docs/config-reference.md` ("last active = successful primary
authentication, not completed session"); revisit a second `Touch` at
`finishLogin` when the MFA funnel next changes. No change required for
shipment.

### F-DS-5 — Low: No readiness/health surface for the durable lifecycle store; store outage is visible only as admin 500s and per-tick sweep log noise

**Evidence (Verified):** the identity-link precedent exists
(`appendIdentityLinkHealth`, `build_stores.go`; `serverbuildsign.AppendStorageHealthSource`)
and the postgres store would trivially join `b.storageHealthSources` (it will
have a `Ping`-able pool handle). The design adds no health source and no
readiness check for `user_lifecycle`, `user_lifecycle_last_active`, or the
sweep lease. A down lifecycle DB degrades the admin surface to 500s and the
sweep to logged skips while readiness stays green. Also make explicit that a
lease *acquire error* propagates as a `SweepOnce` error (the design says a
lost lease returns `(0, nil)`; an error return must not be conflated with a
lost lease).

**Corrective pattern (optional):** append a storage-health source for the
durable store following `appendIdentityLinkHealth`; document the
acquire-error-vs-lost-lease distinction in the `SweepLeaser` interface doc.

### F-DS-6 — Low: `MaxPerSweep` gains a second meaning, and the `StaleEnumerator`/`LastActive` agreement invariant is undocumented

**Evidence (Verified):** the design makes `MaxPerSweep` bound *scanned*
candidates on the cursor path and *applied* transitions on the legacy path —
one knob, two semantics, selected by which `LastActiveSource` is wired
(byte-identical legacy path for non-`StaleEnumerator` sources). An operator
tuning the storm guard gets different behavior per backend wiring. Separately,
`StaleEnumerator` is defined as an optional `LastActiveSource` extension, but
a custom SDK source could implement it over a different data set than its own
`LastActive` (e.g. sessions vs. a table), making the cursor miss users that
`LastActive` would report — the cursor is only a valid candidate set if the
two agree.

**Corrective pattern (optional):** document both in the interface docs:
"the cursor MUST enumerate exactly the users whose `LastActive` returns a
value older than cutoff" and "`MaxPerSweep` caps scanned candidates on the
cursor path, applied transitions on the legacy path".

### F-DS-7 — Info: The new postgres files land outside the maintainability gates, and the `skipDirs` "nested modules" comment is stale for `postgres`

**Evidence (Verified):** `maintainability_budget_test.go:42-58` and
`maintainability_complexity_test.go:137` skip any directory *named*
`postgres`, with the comment "nested modules (own go.mod)". But
`infrastructure/postgres` has **no** `go.mod` (verified) and is a root-module
package imported by `cmd` (AGENTS.md: "Redis and Postgres remain root-module
packages"). The new `user_lifecycle.go`/`user_lifecycle_activity.go`/
`sweep_lease.go` files will therefore be invisible to the file-size,
complexity, and fan-out gates. The design already treats the 500-line budget
as self-discipline — good — but the mislabeling should be corrected
(either remove `postgres`/`redis` from `skipDirs` — which would then gate the
~40 existing files — or fix the comment and keep the skip as a deliberate,
documented exception). Pre-existing; not introduced by this design.

Also Info: the sqlite backend is a single file — it must be documented as
single-node only (multi-replica requires postgres); the conformance/race
suite running in-gate on sqlite does not exercise cross-replica behavior
(that is what the postgres conformance + two-handle test is for). Unbounded
history growth is acknowledged in the design; the lease stale-row leak is
eliminated by the F-DS-1 fix.

---

## 3. Scenario table (partition, crash, retry, clock, stale cache, outage, recovery)

| # | Scenario | Trace | Outcome | Design row | Verdict |
|---|---|---|---|---|---|
| S1 | Two replicas sweep concurrently (normal operation, `backend: postgres`) | Both `TryAcquireSweepLease` insert distinct holder rows → both succeed → both sweep; `apply` conflicts absorbed | Every-tick duplicate sweeps; nondeterministic winners; acceptance test fails | "exactly one replica sweeps at a time" | **F-DS-1** — lease provides no exclusion as specified |
| S2 | Same as S1 but one holder's lease expired mid-run | Third replica acquires (new row); expired holder's deferred release deletes only its own row | No revocation of the successor (holder-scoped release is sound under the buggy PK design); still three concurrent sweepers | TTL-expiry row | F-DS-1 family |
| S3 | Lease holder crashes mid-sweep | Row persists; TTL expiry lets the next acquirer in | No stale-holder deadlock; with the singleton fix, one stale row is overwritten | crash row | Sound (post-fix); row leak pre-fix (F-DS-1) |
| S4 | Replica crash between cursor page and `apply` | Lease dies with the process; partial sweep; next tick resumes from the last committed page | At-least-once semantics; transitions already applied are CAS-conflict-skipped | crash row | Sound |
| S5 | Admin transition races a sweep on the same user | Both read stale state; one `Append` wins the CAS; loser gets `ErrStateConflict` → 409 (admin) / skip-and-log (sweep) | Exactly-once application; admin wins or retries | conflict row | Sound — verified semantics (`memory.go`, proposed SQL CAS) |
| S6 | Two concurrent `Append`s with the same `From` on a missing row (SQL) | `INSERT ... SELECT ... WHERE from='active'` + `ON CONFLICT DO UPDATE ... WHERE state=$from`; loser's WHERE re-checks under EvalPlanQual | Exactly one succeeds; 0 rows → `ErrStateConflict` | concurrency row | Sound on Postgres; **must** be asserted per backend (SQLite/Cockroach `RowsAffected` semantics) — the design already hedges this |
| S7 | Seed races non-seed on the same user (SQL) | Seed `DO NOTHING` and non-seed `DO UPDATE` serialize on the unique index; the loser's re-check fails | Converges to memory semantics in all interleavings (checked by hand) | concurrency row | Sound — add to the conformance matrix |
| S8 | Clock rollback on the sweeping replica | `now` steps back → users look less dormant; lease expiry delayed | Dormancy delayed (fail-open); sweep delayed | skew row | Sound — direction is safe |
| S9 | Clock forward jump / writer clock behind sweeper | `now - last_active` overestimates by the skew | Premature INACTIVE at `DormantAfter - δ`, premature ARCHIVED at `DormantAfter+ArchiveAfter - δ`; ARCHIVED not self-healing | "never wrong-deprovisioning" | **F-DS-2** — overclaim; must document `threshold ≫ skew` |
| S10 | Partition: replica cannot reach the DB | Sweep errors per tick (logged); admin 500s; lease unacquirable; login Touch fails open | Degraded but no wrong state transitions; readiness unaffected | outage row | Sound; F-DS-5 for visibility |
| S11 | Dependency outage: DB down during login | `TouchAt` fails → logged; login and session creation proceed | Dormancy signal ages; fail-open preserved | fail-open row | Sound — acceptance test covers it |
| S12 | Retry: duplicate login POST | Two `TouchAt`s — monotone guard keeps the newest | Idempotent | idempotency | Sound — verified (`memory.go:119-126`, proposed upsert) |
| S13 | Retry: admin transition after a lost CAS | Re-read → `ErrStateConflict` → 409; no partial history row (single tx) | Converges; retryable | conflict row | Sound — requires the history insert to be gated on the upsert's 1-row result inside the tx |
| S14 | Stale cache: lifecycle + last-active rows for a deleted user | No cascade; ghost guard skips (user missing) | Inert rows persist; bounded | ghost-guard row | Sound for deleted users |
| S15 | Stale cache: user id re-created after deletion | Ghost guard passes (user exists); inherited INACTIVE + stale `last_active` → ARCHIVED next tick | Fresh account deprovisioned; memory store used to self-heal on restart — SQL peer makes it permanent | "deletion-time cleanup out of scope" | **F-DS-3** |
| S16 | Cursor page boundary: `Touch` lands between pages | Row moves past the cursor → skipped this run → re-evaluated next tick | At-least-once with one-tick delay; no regression vs. roster snapshot | boundary row | Sound |
| S17 | Cursor page boundary: user read as stale logs in mid-run | `sweepUser` re-reads `LastActive` → fresh → `IsDormant` false → skip | No transition on fresh evidence | boundary row | Sound — the per-user re-read is the guard |
| S18 | User deleted between ghost-guard `GetByID` and `apply` | `Append` creates a lifecycle row for a deleted user | Single inert orphan row per race (bounded; next tick's guard skips it) | ghost-guard row | Residual — check-then-act, not atomic; Low |
| S19 | Recovery: DB back after outage | Sweep resumes; lease re-acquired; state consistent (CAS) | Converges within one tick | recovery | Sound |
| S20 | Recovery: replica restart with durable backend | State survives; no implicit cleanup (unlike memory) | Correct persistence; F-DS-3's poison also survives | restart row | Sound for the design's purpose; F-DS-3 consequence |
| S21 | Split-brain: both replicas admin-transition the same user | Both read ACTIVE; one CAS wins; loser 409 | Correct | conflict row | Sound |
| S22 | Migration race at boot | Advisory-lock namespace serializes concurrent boots | Exactly-once schema | boot row | Sound — verified pattern (`migrate.go:105-110`) |
| S23 | Readiness: lifecycle DB down at boot | `backend: postgres` unreachable → loud boot failure | No silent memory fallback | boot row | Sound — identity-link precedent |
| S24 | Readiness: lifecycle DB down after boot | Admin 500s, sweep logs, readiness stays green | No signal to the LB | — (not in design) | **F-DS-5** |

---

## 4. Stated guarantees vs. reality, unsupported topologies, validation tests, residual risks

### Stated guarantees

| Guarantee | Verdict |
|---|---|
| `Store` semantics (Get-default, seed/conflict Append, history, ListByState) identical across memory/sqlite/postgres | **Holds by construction** — conditional upsert reproduces the memory CAS in every interleaving checked (S6/S7), with the per-backend `RowsAffected` caveat the design already asserts; conformance suite is the enforcement |
| No-record = ACTIVE preserved on every new read path | **Holds** — separate last-active table (resolution 3) is load-bearing and correct; `Get` at the SQL boundary |
| Unwired surfaces byte-identical; zero-value config OFF | **Holds** — `Backend ""`/`memory` → memory store; `Holder`/`LeaseTTL` zero values skip the lease; `WithUserAutoDeprovision` signature frozen (companion interfaces) |
| Companion interfaces keep SDK implementers compiling | **Holds** — type-assertion seams with fallback to today's behavior |
| Lease: "exactly one holder at a time" | **FALSE as specified** — holder-PK upsert excludes no distinct holder (F-DS-1); the acceptance test fails on SQL |
| Cursor: O(k) candidates covering recorded and unrecorded dormant users | **Holds** — the dormancy predicate and the cutoff predicate are the same inequality; unrecorded dormant users have a stale last-active row and are in the cursor; zero-signal users are provably never dormant |
| `TouchAt` monotone, atomic, no read-then-write | **Holds** — conditional upsert matches `memory.go` semantics |
| Fail-open: activity write, sweep errors, admin conflicts | **Holds** — login proceeds on Touch failure; sweep skips per-user; 409 on conflict |
| Fail-closed: state CAS, boot on unreachable backend | **Holds** — `ErrStateConflict` → 409 `lifecycle_state_conflict`; loud boot |
| "Never wrong-deprovisioning" under clock skew | **Overclaim** — the dormancy cutoff is cross-replica clock-sensitive (F-DS-2); bounded only by the skew ≪ threshold convention |
| Sweep never creates lifecycle records for deleted accounts | **Partial** — true for deleted users (ghost guard), false for re-created ids (F-DS-3), and the guard itself is check-then-act (S18) |

### Unsupported topologies (must be declared)

1. **Multi-replica sweep serialization with the lease as specified** (F-DS-1) — distinct holder ids cannot exclude each other; the singleton-key lease is a prerequisite for the decision's headline guarantee.
2. **Multi-replica dormancy with clock skew approaching the thresholds** (F-DS-2) — `dormant_after`/`archive_after` must be ≫ max expected skew; ARCHIVED is admin-reversible only.
3. **User-id reuse after deletion with a durable backend** (F-DS-3) — inherited lifecycle state and last-active poison the re-created account; needs the epoch guard, deletion-time cleanup, or an explicit declaration.
4. **`backend: sqlite` across replicas** — single file, single node; multi-replica requires postgres (the sqlite peer's role is in-gate conformance/race testing, not fleet deployment).
5. **Memory backend across replicas** — pre-existing divergence; unchanged by this design (the durable peer is the remedy).

### Validation tests (distributed-systems additions, in priority order; all deterministic fault-injection, never timing-based)

1. **Two-holder lease race (F-DS-1, the spec's own criterion):** two `SweepOnce` runs, two holders, one store — sqlite peer in-gate plus the postgres conformance test; assert exactly one `TryAcquireSweepLease` returns true; post-fix, assert holder-scoped release cannot revoke a successor and TTL takeover works.
2. **Concurrent-Append matrix (S6/S7):** seed×seed, seed×non-seed, non-seed×non-seed (same and different `From`), missing-row-from-ACTIVE — on both backends with `-race -count=10`; assert exactly one success per user and identical history sequences.
3. **Cursor coverage (decision-2 acceptance):** roster of N users with k dormant (mixed recorded/unrecorded lifecycle state, mixed ACTIVE/INACTIVE); assert the sweep touches O(k) candidates (store probe counter) and deprovisions exactly the dormant set, including unrecorded users.
4. **Clock-skew injection (F-DS-2):** injectable `Now` on store and sweep; writer clock behind sweeper by δ; assert transition timing shifts by δ and the margin requirement is documented.
5. **Delete/re-create poisoning (F-DS-3):** seed INACTIVE + old last-active, delete user, re-create with fresh `UpdatedAt`, sweep → assert no transition (post-epoch-guard) or the documented residual (pre-fix).
6. **Ghost-guard TOCTOU (S18):** block `GetByID`-to-`Append` window via a store fake; assert the orphan row is inert on the next tick.
7. **TouchAt monotonicity + failure-injection (decision-3 acceptance):** out-of-order writes on both backends; failing store stub → login succeeds, tokens issued, error logged.
8. **Restart matrix:** durable store retains state across restart; memory store loses it (pin the divergence as a tested contract, per F-DS-3's consequence).

### Residual risks (accepted or bounded)

- History growth is unbounded (parity with memory; retention knob explicitly deferred).
- Orphan `user_lifecycle*` rows for deleted users persist until deletion-time cleanup lands (F-DS-3 makes this durable; the epoch guard bounds the *effect*, not the rows).
- Lease TTL expiry mid-run still permits a brief duplicate sweep (absorbed by CAS) — now rare instead of every tick, once F-DS-1 is fixed.
- Refresh-only users never Touch; the signal stays authentication-event-only (deliberate boundary, spec-mandated).
- Lifecycle state remains metadata-only today (direction-1 gate not landed); the sweep's deprovisioning has no login-time effect until that lands — which is also what keeps F-DS-2's impact bounded today.
- Custom SDK `LastActiveSource` implementations must keep `StaleEnumerator` in agreement with `LastActive` (F-DS-6, undocumented).

**Bottom line:** the design's core distributed mechanics — the SQL CAS `Append`
(reproducing the memory store's optimistic concurrency in every interleaving
checked), the keyset cursor (provably equivalent to the dormancy predicate,
covering unrecorded users), the monotone atomic `TouchAt`, and the
fail-open/fail-closed boundary — are sound and verified against the code. The
spec's three corrections are each accurate and load-bearing, and the
lease-inside-`SweepOnce` resolution of the spec's internal contradiction is
the right call. One required fix before decision 2 can claim its headline
guarantee: the lease table as specified provides no cross-replica exclusion —
the `holder` primary key must become a singleton fixed key with the holder as
a column (F-DS-1, High; fails the spec's own acceptance test on SQL). Two
recommended fixes: state the clock-skew margin requirement instead of
claiming "never wrong-deprovisioning" (F-DS-2, Medium), and guard against
user-id-reuse poisoning that the SQL peer makes permanent (F-DS-3, Medium).
F-DS-4 through F-DS-7 are documentation/optional items; none block the design.
