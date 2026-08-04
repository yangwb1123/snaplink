# Performance review: domains/userlifecycle production-hardening design

Reviewer: performance engineer. Input: `docs/auto/domains-userlifecycle-prod-design.md`
(revision staged at `0235cc47`, doc-only). Every cost-bearing claim below was
re-verified against the working tree at that revision before writing; labels
follow the ai-dev evidence standard. No `.go` edits made.

**Checks actually run at this revision:** `go build ./... && go vet ./...` clean;
`go test -run 'TestMaintainability_|TestArchitecture_' .` ok 0.143s. Source-level
verification of every cited symbol/path (anchors, wiring, store semantics, DDL,
lease SQL, cursor SQL, test fixtures).

## 1. Workload assumptions and evidence quality

The change touches four request/background classes. No latency/throughput SLOs
exist anywhere in the repo (grep for SLO-style budgets in `docs/` finds none for
login, admin, or sweep); per the prompt rule, no targets are invented — the plan
in §4 establishes baselines at this revision instead.

| Path | Workload assumption | Cost today (verified) | Cost after design (durable builds) |
|---|---|---|---|
| Password/LDAP/federated login | High rate, latency-sensitive | 0 lifecycle DB ops; bcrypt (DefaultCost, ~50–100 ms) + session/token writes | **+1 synchronous PK upsert** per successful auth (`touchUserActivity` → `TouchAt`), unbounded context |
| Ceremony (MFA-replay) login | High rate | 0 lifecycle ops (replays `finishLogin`, `server_mfa.go:368`) | +0 (already Touched at primary; design anchors `server_login_auth.go:98`, `server_oauth.go:212–226`) |
| Auto-deprovision sweep tick | Background, operator cadence (`sweep_interval`); must finish within interval | 1 roster `List` + 3N queries (per user: `Lifecycle.Get` = 2 queries incl. full history, `SessionLastActive.ListByUser` = 1) | cursor: pages + 4k queries (per candidate: `GetByID` ghost guard + `Get` = 2 incl. history + redundant `LastActive`) |
| Multi-replica sweep coordination | N replicas share one store | N replicas × full walk, conflicts swallowed (`sweep.go` `apply`) | lease: 1 conditional upsert/replica/tick — **but the specified schema excludes nothing** (F-P5) |
| Admin lifecycle GET/POST | Cold, operator-driven | memory map ops | 1 tx (Append) / 2 queries (Get) |

**Evidence quality.** All cost-bearing claims are source-verified. **Missing:**
no benchmarks exist for `domains/userlifecycle` or the login path (grep of
`func Benchmark` — only `interfaces/ratelimit` in the reviewed scope), and no
measurements exist for `SweepOnce` tick duration, roster size, or login
latency distribution at any deployment. The design's "O(k)" claim is therefore
unverified arithmetic; §4 turns it into an executable assertion. Predicted
deltas are order-of-magnitude estimates from code shape, not measurements.

**Hot-path verdict up front.** Decision 3's per-login Touch is the only new
work on a request path: one PK upsert (~0.5–2 ms Postgres RTT) against a
bcrypt-dominated login (~50–100 ms) — a single-digit-percent median delta, but
with an unbounded tail under store degradation (F-P2). The material performance
surface is the sweep: the design replaces an O(N) walk with an O(stale-prefix)
cursor whose stated O(k) bound does not hold as specified (F-P1, F-P3), and
whose per-candidate cost is 4 queries with one provably redundant read (F-P4).
The lease's exclusion property — the mechanism that removes N× duplicate sweep
work — is broken by the schema as written (F-P5, also QA F1 / DS F-DS-1).

## 2. Findings

### F-P1 — High — The O(k) claim fails: non-actionable stale rows own the cursor prefix, so either actionable users starve or each tick is O(stale)

- **Path/symbol**: decision 2 `ListStaleAfter` cursor
  (`WHERE last_active < $cutoff ... ORDER BY last_active, user_id LIMIT $n`),
  page size = `MaxPerSweep`, keyset restarts from zero each tick (no persisted
  cursor in the design); `nextState` (`sweep.go:64–77`) acts only on
  ACTIVE-dormant and INACTIVE-past-archive.
- **Mechanism (Verified)**: SUSPENDED/ARCHIVED/PURGED/INVITED users and INACTIVE
  users with `ArchiveAfter=0` (the default posture) keep their last-active rows
  forever (no cascade; deletion cleanup is a documented non-goal) and carry the
  **oldest** `last_active` values. The cursor is ascending in `last_active`, so
  every page ahead of newly-dormant ACTIVE users is a no-op prefix. The design
  gives `MaxPerSweep` a second meaning — cap on *scanned candidates* — so with
  `MaxPerSweep > 0` one page per tick is fully consumed by no-ops every tick:
  actionable ACTIVE users are **never reached** (starvation), and each tick
  still pays the page query + per-candidate reads for zero progress. If
  `SweepOnce` instead loops all pages in one tick, per-tick cost is O(stale
  set), which in a large fleet with a long `DormantAfter` is O(N) — the exact
  cost the decision exists to remove. The design never states the loop
  termination rule; both readings fail the spec's O(k) acceptance
  ("touches O(k) rows, not N"). The design's own O(k) fixture (all-dormant
  ACTIVE users) cannot detect either failure.
- **Impact (predicted)**: ACTIVE→INACTIVE transitions silently stop in any
  deployment with ≥ `MaxPerSweep` stale non-actionable rows; the sweep's
  read cost per tick is bounded by the stale set, not the dormant set — the
  headline efficiency win of decision 2 is not delivered as specified.
- **Recommendation**: make the cursor skip non-actionable rows without
  consuming the scanned budget — a SQL-side state filter is **unsafe** (it must
  not exclude the unrecorded/implicit-ACTIVE users the cursor exists to cover;
  a `LEFT JOIN user_lifecycle` with `state IN ('active','inactive') OR state IS
  NULL` is the only correct filter shape, or a Go-side skip-advance past
  non-actionable states). Specify the loop rule explicitly: e.g., one tick =
  pages until (a) cursor exhausted, or (b) scanned-candidate cap reached,
  where skip-advanced rows do not count toward the cap.
- **Experiment**: fixed-clock fixture — `s1,s2` SUSPENDED with `last_active =
  now-90d`, `u` ACTIVE with `last_active = now-40d`, `DormantAfter=30d`,
  `ArchiveAfter=0`, `MaxPerSweep=2`; assert `u` becomes INACTIVE after one
  `SweepOnce` and that no-op rows did not consume the budget (counting wrapper
  over the enumerator).

### F-P2 — High — One synchronous, unbounded DB write lands on the login critical path on durable builds

- **Path/symbol**: decision 3 `touchUserActivity` at
  `server_login_auth.go:98` (after `rejectDeactivatedUser`) and
  `finalizeCallbackSession` (`server_oauth.go:212–226`, after the SCIM gate);
  `TouchAt` = one `INSERT ... ON CONFLICT ... DO UPDATE` per successful login.
- **Mechanism (Verified)**: today's login performs **zero** lifecycle writes —
  the durable backend is the first writer. The design mandates synchronous
  (explicitly rejecting async) with no context timeout specified; `database/sql`
  has no default statement timeout, and `infrastructure/postgres/pool.go:61–65`
  bounds only pool size, not wait time. Fail-open means the login goroutine
  waits out the store's full failure latency (pool saturation, unresponsive
  DB) before proceeding. The exposure is real even where the session/token
  stores are healthy: lifecycle lives in Postgres, sessions may live in Redis,
  so "Postgres degraded" is a live scenario where today's login succeeds and
  decision 3's login blocks on every request.
- **Impact (predicted)**: median login +~1 ms (≤ ~2% vs bcrypt at DefaultCost);
  tail latency and login-throughput coupling to lifecycle-store health are the
  material risks — a slow lifecycle store consumes one pool slot per in-flight
  login, feeding pool exhaustion fleet-wide. Availability coupling introduced
  by a decision whose purpose is background dormancy.
- **Recommendation**: keep the synchronous call (the failure-injection
  acceptance is only deterministic inline — the design's reasoning is sound)
  but wrap it in a short derived context timeout (e.g. 250 ms) and a latency
  metric; a failed/expired Touch is already fail-open by contract. Document the
  bound; add a `login_lifecycle_touch` counter (success/timeout/error).
- **Experiment**: login-handler micro-benchmark (sqlite in-gate, PG manual)
  with and without the Touch call at concurrency 64; and a failing-store
  injection asserting login p99 grows by ≤ the chosen timeout bound, not by the
  store's failure time.

### F-P3 — Medium — Index contradiction: decision 3 ships `(last_active)`, decision 2's keyset needs `(last_active, user_id)`

- **Path/symbol**: decision 3 DDL `CREATE INDEX idx_user_lifecycle_last_active
  ON user_lifecycle_last_active(last_active)` vs decision 2's cursor SQL
  requiring `(last_active, user_id)` ordering ("index `(last_active, user_id)`").
- **Mechanism (Verified)**: with only the single-column index, both Postgres
  and SQLite must scan every `last_active < cutoff` entry and sort by
  `(last_active, user_id)` to serve each keyset page; the row-value predicate
  `(last_active, user_id) > ($1,$2)` cannot be pushed into the single-column
  index. Per-page cost becomes O(stale) instead of O(page) — F-P1's cost
  problem resurfaces even with the skip fixed. With Unix-nano timestamps
  production tie-groups are rare, but bulk imports and the conformance suite's
  injectable clock make ties trivial — the O(k) acceptance fixture itself can
  silently degrade.
- **Impact (predicted)**: bounded by tie-group size in production (small), but
  the O(k) bound is not achieved by the shipped DDL, and the two decisions
  contradict each other's schema for one table.
- **Recommendation**: ship the composite `(last_active, user_id)` index as the
  only index on the table (it serves both the cursor and nothing else is
  needed); assert its existence in the migration test on both peers.
- **Experiment**: `EXPLAIN` the keyset page query against each peer with 100k
  rows, tie-heavy subset; assert index-scan (not sort) in the plan.

### F-P4 — Medium — Cursor path costs 4 queries per candidate, one provably redundant, and every `Get` drags the full history

- **Path/symbol**: `ListStaleAfter` returns `[]string` only (discards the
  `last_active` it just read); `sweepUser` (`sweep.go:50–62`) calls
  `Lifecycle.Get` (design's SQL `Get` = state select **plus ordered history
  select**) and `LastActive.LastActive` per candidate; decision 2 adds
  `Users.GetByID` per candidate (ghost guard). Total per candidate on SQL:
  `GetByID` + `Get`(2 queries) + `LastActive` = 4 round trips + 1/page cursor
  query.
- **Mechanism (Verified)**: the `LastActive` re-read is pure waste — the cursor
  query already fetched the value and threw it away. The history payload is the
  second driver: `Get` returns the full `Record` (memory `cloneRecord` copies
  the slice; SQL selects all history rows), while `nextState` needs only
  `rec.State` — a user with a long transition history makes every sweep
  candidate read unbounded in row count. Legacy path has the same Get shape but
  the cursor path makes the per-candidate cost the *whole* tick cost.
- **Impact (predicted)**: at k=10k dormant candidates, ~40k round trips ≈
  30–40 s per tick on Postgres at 1 ms RTT — a tick that exceeds
  `2× sweep_interval` (the design's own lease-TTL default) on every large
  sweep, making mid-run takeover (F-P5) the common case rather than the rare
  one.
- **Recommendation**: enumerator returns `(userID, lastActive)` pairs (removes
  the `LastActive` re-read); add a state-only accessor (e.g. `GetState`) for
  the sweep so candidates don't drag history; keep the ghost guard but note it
  is 1 of the remaining 2 reads. Optionally measure before adding batching.
- **Experiment**: query-counter conformance fixture — assert per-tick queries =
  pages + 3k (or 2k after the accessor), and a history-growth fixture (user with
  10k transitions) asserting sweep per-candidate cost is independent of history
  length.

### F-P5 — Medium — The lease as specified excludes no one; duplicate sweep work persists on SQL, and the TTL arithmetic invites mid-run takeover

- **Path/symbol**: decision 2 `sweep_lease (holder TEXT PRIMARY KEY)`, acquire
  `INSERT ... ON CONFLICT (holder) DO UPDATE ... WHERE sweep_lease.expires_at <
  $now`, per-process holder ids (hostname+pid+nonce); default TTL = 2×
  `sweep_interval`.
- **Mechanism (Verified)**: with the PK on `holder`, the conflict fires only
  when the **same** holder re-acquires; two replicas insert two rows and both
  acquire. The `WHERE expires_at < $now` guard never sees the other holder's
  row. So the production SQL backend delivers no exclusion — the exact
  N-replica duplicate-sweep behavior decision 2 exists to remove — while the
  memory single-flight mutex (proposed for `memory.Store`) hides it in the
  in-gate race test. Performance framing of the correctness bug: duplicate
  transitions and conflict churn scale with replica count; every tick every
  replica still pays the full page/candidate read cost. Separately, a sweep run
  that exceeds TTL (see F-P4) hands the lease to a second replica mid-run by
  design; the design calls this "rare", but with TTL = 2×interval and
  run-times of tens of seconds on large k, it is the scheduled outcome, not an
  edge case.
- **Impact (predicted)**: 2×–N× sweep write/read amplification in
  multi-replica production; the spec's headline acceptance ("two concurrent
  `SweepOnce` runs — exactly one applies") cannot pass on the SQL backend as
  written.
- **Recommendation**: singleton lease key with `holder` as a value column
  (`lease_key TEXT PRIMARY KEY` fixed value; `ON CONFLICT (lease_key) DO UPDATE
  ... WHERE expires_at < $now`; release stays holder-scoped so an expired
  holder cannot revoke a successor — QA F1's fix, which the performance case
  endorses). Set default TTL to `max(2×interval, 3× observed run duration)`
  with a floor, and emit a sweep-duration metric so the constant is
  data-driven.
- **Experiment**: two-holder `SweepOnce` race on memory + sqlite with acquire
  counters (exactly one `acquired=true`); plus a run-duration histogram over
  the §4 fleet-scale fixture to set the TTL default.

### F-P6 — Low — Orphan last-active rows grow without bound and sit in every tick's cursor prefix

- **Path/symbol**: `user_lifecycle_last_active` (decision 3) and
  `user_lifecycle_history` (decision 1) have no deletion path; user deletion has
  no cascade (documented non-goal).
- **Mechanism (Verified)**: one row per user ever seen, never reclaimed; ghosts
  are re-read by every tick's cursor query (F-P1's prefix, plus a guaranteed
  `GetByID` miss each). History grows per transition forever (design
  acknowledges; keeps for contract parity). Cardinality risk is bounded per
  user (1 last-active row) but unbounded in fleet lifetime and per-user history
  length.
- **Impact (predicted)**: slow index/table bloat and per-tick no-op reads that
  compound F-P1; admin `Get` latency grows with history length.
- **Recommendation**: record the growth in the baseline (§4 B6) and ship a
  retention knob (e.g. prune last-active rows older than `DormantAfter +
  ArchiveAfter + margin` for users whose lifecycle state is terminal) as a
  follow-up; not a blocker.
- **Experiment**: 12-month simulated growth fixture on sqlite (insert rate ×
  retention), assert per-tick read cost and index size are linear and bounded
  by the knob.

### F-P7 — Low — Memory-peer `StaleEnumerator` makes the in-gate O(k) test unable to see SQL costs; tie-break must be pinned

- **Path/symbol**: proposed `memory.ActivityTracker.ListStaleAfter`
  ("in-process filter over its map").
- **Mechanism (Verified)**: the memory filter is an O(N) map pass with no index
  — fine for a single-replica memory build (its whole point), but the O(k)
  acceptance fixture runs on it, so it asserts *semantics*, never the *query
  cost* the SQL path is designed for. The design leaves memory's ordering
  unspecified; `(last_active, user_id)` tie-break parity with SQL must be
  pinned or the paging test is order-dependent (clock-injectable ties make this
  trivial to hit).
- **Impact**: in-gate tests can pass while the production cursor is O(stale);
  order-dependent flake risk in the conformance suite.
- **Recommendation**: pin the tie-break in both peers; add the query-count
  assertion (F-P4) to the sqlite arm specifically; the memory arm asserts
  semantics only.
- **Experiment**: tie-group paging fixture (3 users, identical `last_active`,
  page size 1): disjoint pages, no duplicates, no skips, termination — on both
  peers.

### F-P8 — Info — No metrics exist to validate the O(k) claim or size the lease TTL in production

- **Path/symbol**: `SweepOnce` / `RunUserAutoDeprovision`
  (`options_admin.go:319–336`) emit no counters; the spec's "counted if a
  metric seam exists" for touch failures is dropped in the design.
- **Recommendation**: sweep counters (candidates scanned, skip-advanced, no-ops,
  transitions applied, lease acquired/lost, run duration) and a touch counter on
  the login path. These are the only way to verify F-P1/F-P4's predictions
  against the deployment's actual stale-set shape.
- **Experiment**: none needed beyond wiring; the §4 fixtures consume the same
  counters.

## 3. Critical-path table

| Path | Baseline (this revision) | Target (supplied?) | Bottleneck | Profiling method |
|---|---|---|---|---|
| Login, durable build | 0 lifecycle DB ops; bcrypt + session/token writes | none supplied; design must bound touch latency (F-P2) | lifecycle store RTT / pool wait under degradation | login latency histogram; timing around `touchUserActivity`; pprof on login handler |
| Sweep tick, legacy | 1 roster List + 3N queries | design claims O(k); not met as specified (F-P1, F-P3) | stale-prefix no-ops; per-candidate 4 queries incl. history + redundant LastActive (F-P4) | store query counter; `EXPLAIN ANALYZE` on cursor SQL |
| Sweep, multi-replica | N replicas × full walk | exactly-one-applies; broken by holder-PK schema (F-P5) | lease exclusion (absent); TTL vs run duration | acquire counter; run-duration histogram |
| Admin lifecycle GET | memory map read | none | history length growth (F-P6) | `EXPLAIN` on Get; history-size distribution |
| Memory builds | byte-identical | design preserves | n/a | n/a |

Baseline method: §4 B2/B4 establish the login and sweep-tick numbers at this
revision (no prior measurements exist anywhere).

## 4. Prioritized benchmark/load plan

All fixtures use the injectable clock (never `time.Now`) and counting store
wrappers; acceptance rules are regression deltas and structural assertions, not
invented SLOs.

| # | Benchmark | Dataset / concurrency / duration | Acceptance rule | Regression comparison |
|---|---|---|---|---|
| B1 | Sweep query-count + starvation (gate, sqlite + memory) | 100k users, k=1000 dormant ACTIVE, page 100; then F-P1 shape (`s1,s2` SUSPENDED @90d, `u` ACTIVE @40d, `MaxPerSweep=2`, `ArchiveAfter=0`) | `u` INACTIVE after one `SweepOnce`; scanned queries = O(pages + k) with no-ops not consuming the cap | `TestSweepOnce_*` (all 6) unchanged; legacy fixtures untouched |
| B2 | Login-path touch micro (gate: sqlite; manual: PG) | 10k users, concurrency 32/64, 30 s | per-op p99 < 1 ms (sqlite); PG p50 delta vs no-touch baseline ≤ 1 RTT; failing-store p99 ≤ chosen timeout bound | login handler with/without touch; memory builds must show zero delta (no `ActivityRecorder`) |
| B3 | Two-holder lease race (gate: memory + sqlite; manual: PG) | 2 holders, fixed clock, TTL ≫ run, acquire counters | exactly one `acquired=true`; `appliedA+appliedB == transitions`; loser `(0, nil)`; loser logs lost lease | — (new); also TTL-expiry-mid-run takeover variant |
| B4 | Fleet-scale sweep tick (manual, PG) | 1M users, 10k dormant, page 500, interval 1h | tick wall-time + query count measured; assert tick ≪ interval and record run duration to set lease TTL default | legacy roster walk on same dataset (3N+1 queries) |
| B5 | Keyset tie-group paging (gate, both peers) | 3 users identical `last_active`, page size 1 | disjoint pages, no duplicates, no skips, termination | memory vs sqlite identical page sequences |
| B6 | History/orphan growth (gate, sqlite) | user with 10k transitions; 12-month simulated last-active growth | per-candidate sweep cost independent of history length (after F-P4 accessor); growth linear, bounded by retention knob | admin Get p50 before/after growth |
| B7 | Full regression | repo suite | `go test ./... -race`, `make ci`, maintainability/architecture gates, PG conformance arm (DSN-gated manual) | all green vs revision baseline |

## 5. Optimization risks and measurements still needed

- **Async Touch (do not do now).** The design's synchronous choice is load-
  bearing for the failure-injection acceptance (deterministic inline call) and
  for monotonic ordering. If async is ever adopted, it must keep the monotone
  guard, a bounded queue with drop-on-full (fail-open), and the same 250 ms
  bound; otherwise logins buffer against a down store — strictly worse than
  today's fail-open-with-bounded-wait.
- **State filter vs no-record anchor.** Any SQL-side state filter on the cursor
  must keep `state IS NULL` (implicit-ACTIVE) candidates visible — the 
  unrecorded users are exactly the set `ListByState` cannot see. A Go-side
  skip-advance is the safer fix; verify the O(k) fixture includes unrecorded
  dormant users (design already requires this).
- **Lease TTL enlargement.** Raising the default TTL reduces takeover frequency
  but lengthens the dead-time after a replica crash; the default must be
  `max(2×interval, 3× measured run duration)` with a floor, driven by the B4
  histogram — never a blind constant.
- **Composite-index migration.** Must be additive and asserted on both peers;
  the single-column index from decision 3 must not ship alone.
- **Measurements still needed** (none exist today): login latency distribution
  with and without Touch on the durable backend; sweep tick duration and
  query counts at fleet scale (B4); stale-set shape (what fraction of users
  hold non-actionable rows — it determines whether F-P1's starvation or the
  O(stale) reading dominates); history-length distribution (F-P4/F-P6);
  multi-replica sweep duplicate-work rate before vs after the lease fix.

**Bottom line:** decisions 1 and 3's hot-path addition is bounded work and
acceptable with a 250 ms bound + metric (F-P2). Decision 2's sweep, as
specified, does not deliver its O(k) efficiency claim (F-P1, F-P3), its
per-candidate cost is 4 queries with one provably redundant read (F-P4), and
its lease provides no multi-replica exclusion on SQL (F-P5). The cursor and
lease should not be implemented as written; the conformance/query-count
fixtures (B1, B3, B5) must land with the first backend merge.
