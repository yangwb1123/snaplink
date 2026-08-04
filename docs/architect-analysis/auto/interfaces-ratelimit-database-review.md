# Database Architect Review: Post-Auth Rate Limiting (方向一) persistence

> Scope: the design at `docs/auto/interfaces-ratelimit-design.md` (Decisions
> 1–9) adds no new storage — it reuses the `ratelimit.Limiter` SPI. This
> review therefore audits the persistence correctness and production
> readiness of the stores the design consumes (Memory / SQLite / Redis) and
> the stock wiring it inherits, plus the new-key implications
> (`client:<id>`, `sub:<subject>`, `admin:<subject>`) for schema,
> tenant isolation, retention, and concurrency.
>
> Checks that actually ran this session: read the SPI
> (`interfaces/ratelimit/ratelimit.go`, `middleware.go`,
> `sqlite_limiter.go`), the Redis backend
> (`infrastructure/redis/ratelimit.go`, `universal.go`), the boot/reload
> wiring (`cmd/sso-server/build_app_security.go`, `build_bootstrap.go`,
> `main_wiring.go`, `serverbuildplatform/build_ratelimit_cluster.go`,
> `serverbuildsign/build_readiness.go`), the admin gate
> (`interfaces/admin/governance.go`), the migration runner
> (`platform/migrate/migrate.go`), the sibling SQLite pool pattern
> (`infrastructure/defaultimpl/sqlite/shareddb.go`, `busy_timeout.go`),
> and the driver source `modernc.org/sqlite@v1.50.1` (`tx.go`, `sqlite.go`).
> Executed: `go test -count=1 ./interfaces/ratelimit/` (pass, 0.084s) and
> `go vet ./interfaces/ratelimit/` (clean). Review-only; no code changed;
> no gates run (consistent with the design's standing note).

## 1. Store inventory

| Store | Purpose | Durability | Implementation | Stock wiring | Consistency requirement |
|---|---|---|---|---|---|
| `MemoryLimiter` (`interfaces/ratelimit/ratelimit.go`) | Per-replica brute-force/flood defense | **Hot only** — volatile, per-process; state resets on restart and on every SIGHUP rebuild | 16 shards × `map[string]*bucketEntry`, `golang.org/x/time/rate` token bucket, FNV-32a sharding, 1/64 sampled prune (10-min idle), optional `StartPruner` | **Verified** — `security.rate_limit.backend` `""`/`memory` (default) via `wireBodyAndRateLimit` → `BuildRateLimitPolicy` → `WithRateLimit` (`build_app_security.go:34-41`); SIGHUP via `wireRateLimitReload` (`main_wiring.go:129-160`) | Per-key decision atomicity in-process only (shard mutex). No cross-replica semantics (documented N× dilution) |
| `SQLiteLimiter` (`interfaces/ratelimit/sqlite_limiter.go`) | Cross-replica shared bucket state | **Durable** (file-persisted) — but the state is reconstructible defense data, not data-of-record | `rate_limit_buckets` table, PK `(bucket_name, key)`, custom token-bucket math on wall-clock refill; one `Allow` = deferred BEGIN → SELECT → upsert → sampled prune DELETE → COMMIT | **Verified** — `security.rate_limit.backend=sqlite` + `security.rate_limit.sqlite.dsn` (a DSN **private to the rate limiter**, distinct from the shared `sqlite.*` DSN sibling stores use); opened via bare `sql.Open` + `SetMaxOpenConns(1)` + `migrate.Run` (namespace `rate_limit`, v1) | Per-key decision atomicity **across processes** (the whole point of the backend) — **currently not met** (Finding F1); refill math assumes replica clocks agree (F3) |
| Redis `Limiter` (`infrastructure/redis/ratelimit.go`) | Hot cross-replica shared buckets | **Hot, volatile** — key TTL = window; eviction/restart resets limiting (fail-open direction) | **Fixed-window counter** (explicit, `ratelimit.go:14-22`), not a token bucket; Lua script INCR + conditional EXPIRE + PTTL, single key per invocation (single slot on Cluster) | **Verified** — `security.rate_limit.backend=redis` + redis block; shared client from `wireRedis` (`build_bootstrap.go:206-240`); zero `max_retries`/timeouts pass go-redis defaults through (`universal.go:133-135`, `config_keys.go:174+`) | Per-key decision atomicity cross-process — **met** (server-side script). Semantics differ from the token-bucket peers (F6) |
| Admin gate limiter (`interfaces/admin/governance.go`) | Admin-wide pre-auth throttle | Hot only (MemoryLimiter) | Constant key `"admin"`, `PolicyStore`-wrapped MemoryLimiter, `rate_limit_exceeded` body | **Not wired by the stock binary today** — no config key maps to `sso.WithAdminRateLimit`; `srv.AdminRateLimit()` returns `(0,0)` so `mw.SetRateLimit` is never called (`build_app.go:305-307`) → nil store → unlimited. The design's `admin.rate_limit.per_admin.*` is the first stock wiring | Per-key atomicity in-process only; two-tier split is a config change, not a storage change |

The design's Decision 7 "no new storage" claim is **Verified** — all three
phase-2 surfaces consume the existing SPI; the new keys land in the same
table/keyspace (SQLite rows, Redis `sso:ratelimit:<bucket>:<key>`), scoped
by `bucket_name`. Cardinality impact per surface is analyzed in §5.

## 2. Findings (by severity)

### F1 — High — SQLite cross-process decision race: code claims BEGIN IMMEDIATE, actually deferred BEGIN

**Evidence.** `SQLiteLimiter.Allow` calls `s.db.BeginTx(ctx, nil)`
(`sqlite_limiter.go:159`). The driver maps nil opts to `sql = "begin"`
(plain deferred) unless the DSN carries `_txlock` — verified in the vendored
driver `modernc.org/sqlite@v1.50.1/tx.go:21-24` (`if !opts.ReadOnly &&
c.beginMode != "" { sql = "begin " + c.beginMode }`) with `beginMode` parsed
only from the `_txlock` DSN query param (`sqlite.go:195-201`). The production
DSN (`security.rate_limit.sqlite.dsn`) carries no `_txlock` requirement —
nothing in `NewSQLiteLimiter`, `BuildRateLimitPolicy`, config validation, or
`docs/config-reference.md` imposes it. The comments claiming "BEGIN IMMEDIATE
transaction" (`sqlite_limiter.go:48,135`) and `loadBucketTokens`'s "MUST run
inside the caller's BEGIN IMMEDIATE tx to preserve token-bucket atomicity"
(`sqlite_limiter.go:134-137`) are **false as written**.

**Impact.** With a deferred BEGIN the read precedes the write lock. Two
replicas, burst=1, same key: both `SELECT tokens=1`, both write 0, both
admit — the exact "cross-replica defense" the backend exists to provide is
holey at the boundary. Second writer either hits `SQLITE_BUSY` (fail-open →
both admitted) or, under WAL, serializes its write from its pre-commit stale
read (both admitted). The persisted state converges to 0; the **decision**
is not atomic. This is a bounded over-admission (≈2× at the burst boundary),
in the fail-open direction — not a security break for a defense layer — but
it invalidates the SQLiteLimiter doc claim that "a request that drained the
bucket on replica A is visible to replica B before it grants the next
request" (`sqlite_limiter.go:12-14`) except in the sequential case. It also
makes any future concurrent cross-replica e2e assertion (A and B both admit,
then both 429) **flaky by construction**.

**Coverage gap.** `TestSQLiteLimiter_CrossInstanceSharing`
(`sqlite_limiter_test.go:121-141`) runs `limA.Allow` then `limB.Allow`
sequentially — no concurrent cross-instance Allow exists anywhere (the Redis
peer has `TestLimiter_ConcurrentIncrSingleCounter`; SQLite does not).

**Recommendation (required before phase-2 ships on the sqlite backend).**
Either (a) make `_txlock=immediate` (plus `_pragma=busy_timeout(5000)`,
`_pragma=journal_mode(WAL)`) a **documented, validated requirement** for
`security.rate_limit.sqlite.dsn` — BEGIN IMMEDIATE takes the write lock
before the read, so the loser blocks at BEGIN and reads post-commit state,
which actually closes the race — or (b) have `Allow` use the repo's existing
`beginImmediateRMW` pattern (`infrastructure/defaultimpl/sqlite/busy_timeout.go:36-45`)
via `db.Conn()` + `ExecContext("BEGIN IMMEDIATE")`. Add a concurrent
cross-instance test (two limiters, burst=1, same key, parallel Allow); it
fails today.

**Validation.** `go test -race -count=10 ./interfaces/ratelimit/` with the
new concurrent test; manual: two processes sharing one DSN, burst=1,
simultaneous `Allow` — currently both admit at high collision probability.

### F2 — High — SQLite journal-mode/sync posture is undocumented and the test's WAL is a no-op

**Evidence.** The test DSN is `?_journal=WAL&_pragma=busy_timeout(5000)`
(`sqlite_limiter_test.go:13`, also `:71,121-122`). `modernc.org/sqlite`
honors only `_pragma=` query params (`sqlite.go:143-158`); it has **no
`_journal` handling** (grep of the driver: zero matches). So every test runs
in rollback-journal mode; the WAL assumption is vacuous. Production is the
same: `NewSQLiteLimiter` never sets `journal_mode`/`synchronous`, and the
limiter's DSN is private to it — it does **not** use the sibling pattern
`sqlite.SharedDB` (WAL + `synchronous=NORMAL` + `busy_timeout=5000`,
`shareddb.go:44-53`) that every other SQLite store uses. Default posture is
therefore `journal_mode=delete` + `synchronous=FULL`: **two fsyncs per
`Allow`** (journal + db) instead of WAL's one. The perf budget's 16.5 µs
(Decision 9) was measured on this machine, but the doc comment
"SQLite's WAL mode delivers low-thousands writes/sec" (`sqlite_limiter.go:17-18`)
is drift: the limiter never enables WAL.

**Second layer — implicit dependency.** The rate-limit pool's
`busy_timeout=5000` comes **only** from the process-global connection hook
registered in `infrastructure/defaultimpl/sqlite/busy_timeout.go:21-30`
(`sqlited.RegisterConnectionHook`). That package is imported by the stock
binary, so production is fine today — but `interfaces/ratelimit` itself
imports neither the hook nor `SharedDB`, and nothing in `NewSQLiteLimiter`
guarantees the pragma. A build that stops importing
`infrastructure/defaultimpl/sqlite` silently runs the SQLite backend at
`busy_timeout=0` → immediate `SQLITE_BUSY` fail-open under any cross-process
contention. (The `busy_timeout=10000` from `migrate.Run`'s
`beginImmediate` — `migrate.go:203` — arms only the pinned migration
connection, and only at construction.)

**Recommendation (required).** State the required DSN contract for
`security.rate_limit.sqlite.dsn` in config-reference and validate it at boot,
or construct via `sqlite.SharedDB` + `NewSQLiteLimiterWithDB`
(`sqlite_limiter.go:73-82` — the seam exists). The design's Decision 9 note
("sqlite = one disk write per Allow") should read "two fsyncs in the default
rollback-journal posture; one under WAL-NORMAL".

**Validation.** `PRAGMA journal_mode; PRAGMA synchronous;` on a file created
by `NewSQLiteLimiter` with the documented DSN — currently returns
`delete`/`FULL`; and `PRAGMA busy_timeout` on a pooled conn without the
hook-importing binary — currently 0.

### F3 — Medium — SQLite token-bucket math is wall-clock coupled across replicas

**Evidence.** `nowNs := s.now().UnixNano()` (`sqlite_limiter.go:169`) and the
refill `elapsedSec := float64(nowNs-lastRefillNs)/...` read
`last_refill_at_ns` **persisted by whichever replica wrote last**
(`persistBucket` stamps `excluded.last_refill_at_ns = nowNs`, the writer's
own clock). With skew S: a forward-skewed replica over-refills (capped at
burst) and stamps a future timestamp; the other replicas then compute
negative elapsed, hit the `elapsedSec > 0` guard, and get **no refill until
their clocks catch up** — the fleet toggles between over- and under-admission
depending on who wrote last. NTP-scale skew is minor (skew × perSecond per
request); multi-minute skew creates real denial windows for the lagging
replica.

**Impact.** Design Decision 7's "No clock coupling: `rate.Limiter`
reservations are monotonic" is **Verified for Memory only** (x/time/rate uses
monotonic time) and **Verified immune for Redis** (server-side window/PTTL).
The blanket claim is wrong for SQLite.

**Recommendation.** Scope the claim and state an explicit skew bound for the
sqlite backend, matching the repo doctrine ("Production clocks slew; they do
not step backward" — AGENTS.md applies it to sessions; the limiter has no
such guard).

### F4 — Medium — Fail-open is silent: no log, no metric, on either backend's error path

**Evidence.** SQLite: `return true, 0` on BeginTx error, load error, persist
error, commit error (`sqlite_limiter.go:161,174,190-191,200-201`) — no
logger, no observable. Redis: `return true, 0` on script error / shape
mismatch / type mismatch (`infrastructure/redis/ratelimit.go:135-146`) — no
logger. The design's Decision 8 row "Verify the Redis/SQLite limiter's
fail-open on error is logged" **fails verification: it is not logged
anywhere**. AGENTS.md's fail-open doctrine pairs open behavior with
audit/logging for the listed helpers; the rate limiter is not in that list,
so this is a documented-gap decision, not a violation.

**Impact.** An outage of the limiting store is fully invisible: no
`recordRejection` fires (rejects never happen), no fail-open counter exists.
On the new post-auth checkpoints, an operator watching 429 metrics sees the
limiter vanish without a trace.

**Recommendation.** Either wire a fail-open counter at the `Checkpoint` layer
(`Policy.Metrics` exists and `Checkpoint` is the single choke point — the
design already centralizes there) or explicitly accept silent failure in
config-reference. The design must pick one; "fail-open-with-log doctrine"
currently overstates the codebase (also flagged by the security reviewer).

### F5 — Medium — Redis outage is not fast: no deadline, go-redis retry defaults turn each checkpoint into a multi-second stall

**Evidence.** `Allow` runs `context.Background()` with no deadline
(`infrastructure/redis/ratelimit.go:127-129`); the stock binary passes zero
`MaxRetries`/`DialTimeout`/`ReadTimeout` through `redisOptionsFromConfig`
(`build_bootstrap.go:252-259`) to `UniversalOptions` (`universal.go:133-135`)
— zero values mean go-redis defaults: 3 retries with backoff, 5 s dial,
3 s read. A dead or black-holed Redis turns **every** checkpoint (phase-1
login today; `/token`, `/userinfo`, admin tier-1 in phase-2) into a
multi-second stall before the fail-open allow. The common real-world trigger
— the flood itself saturating Redis — is precisely when the limiter stops
limiting, with added latency.

**Impact.** Availability cost hidden behind "Limiting silently off until
recovery" (Decision 8). SQLite's analogue is a hung filesystem: `Allow`'s
`context.Background()` blocks in the syscall indefinitely (fail-open only
fires on returned errors, not on hangs).

**Recommendation.** Document the bounded-stall behavior in config-reference
next to the phase-2 keys and recommend `redis.max_retries`/timeouts for the
auth path. Consider a per-`Allow` timeout at the `Checkpoint` layer so a
store hang degrades to fast fail-open instead of request-latency inflation.

### F6 — Medium — Backend parity: Redis is a fixed-window counter, not a token bucket

**Evidence.** Explicit in `infrastructure/redis/ratelimit.go:14-22`
("FIXED-WINDOW counter ... not the token-bucket the MemoryLimiter /
SQLiteLimiter peers use"). `NewLimiterFromRate` maps `(perSecond, burst)` →
`(limit=burst, window=burst/perSecond)`.

**Impact.** Three semantic deltas the design's Decision 7/9 numbers don't
surface: (a) **edge burst 2×** — a fixed window admits up to `limit` in a
burst straddling a boundary; (b) **no drip after exhaustion** — a token
bucket denies until the *next token* (~100 ms at 10/s), the fixed-window
equivalent denies **everything until the window resets** (up to `window`
seconds); (c) **Retry-After meaning differs** — time-to-next-token vs
time-to-window-reset. Deny-all config (`perSecond<=0`) yields a 365-day
window → `Retry-After: 31536000` (valid per RFC 6585, but a spike of
year-long retries if an operator misconfigures). The design's "bucket-exact
cross-replica limiting" is **not achievable today**: SQLite is bucket-exact
but racy (F1) and clock-coupled (F3); Redis is atomic but fixed-window. For
the phase-2 e2e sizing arithmetic (`burst ≥ flood + B + margin`), the Redis
backend changes the units from tokens to windowed allowances.

**Recommendation.** State Redis fixed-window semantics as the cross-replica
contract for phase-2 buckets (it is what `backend=redis` will actually
deliver), and note the drip-vs-window difference in config-reference beside
the new keys.

### F7 — Medium — SIGHUP reload: comment drift + phase-2 hook must close old limiters

**Evidence.** `closePolicyLimiters`'s doc claims SQLiteLimiter is a "silent
no-op" for `closeIfCloser` (`main_wiring.go:163-170`); `SQLiteLimiter`
implements `io.Closer` (`sqlite_limiter.go:85-92`), so `closeIfCloser`
(`main_shutdown.go:234-238`) **does** close it — the comment is wrong, the
behavior is safe (`sql.DB.Close` waits for in-flight queries; post-close
Allows fail open). The distributed-engineer pass verified the corollary:
every SIGHUP with a sqlite backend closes the old pool and re-runs
`migrate.Run` (idempotent BEGIN IMMEDIATE, but a write-lock acquisition per
limiter per reload).

**Impact.** If the design's new `SetPostAuthRateLimitHook` rebuilds phase-2
limiters without the `closePolicyLimiters` discipline, every SIGHUP leaks one
`*sql.DB` per phase-2 surface (plus one `MemoryLimiter` pruner goroutine when
`prune_interval` is set).

**Recommendation.** The design must state that the new hook closes replaced
limiters via the same helper, and fix the `main_wiring.go` comment in the
same change. Shared-backend note for sqlite: phase-2 limiters should prefer
`NewSQLiteLimiterWithDB` over a second `sql.Open` pool on the same file
(each pool is `MaxOpenConns(1)`, so pools don't share connections and the
file-level write lock serializes them).

### F8 — Low — Schema: no tenant dimension, no key-length bound; cross-tenant bucket collision is an unstated assumption

**Evidence.** `rate_limit_buckets` PK is `(bucket_name, key)`; keys are
unbounded `TEXT` (`sqlite_limiter.go:22-34`). There is no tenant column.
Phase-2 keys are `client:<id>` and `sub:<subject>` — both derive from
authenticated identities, so they are bounded by token/client sizes (no
attacker-controlled unbounded key), but their **global uniqueness across
tenants is an assumption**: subjects are resolved through
`ResolveLocalSubject` after the checkpoint, and the keying review already
found the setup-account username-as-ID case where two tenants share one sub
string (`server_setup.go:202-206`; `interfaces-ratelimit-keying-review.md`
§5, finding 11). If client IDs or subject IDs are ever scoped per tenant in a
multi-tenant deployment, tenant A's flood exhausts tenant B's bucket in the
shared table.

**Recommendation.** Document the global-ID-uniqueness invariant next to the
new config keys (one line in config-reference), and keep the 10-min idle
prune as the cardinality bound. No schema change warranted today.

### F9 — Info — No schema boot gate for the rate-limit namespace

**Evidence.** Every other SQLite-backed subsystem in the stock binary is
gated by `CheckSQLiteSchema` at boot (`build_app_core.go:64-71`, `build_app_oauth.go:157-208`,
jti/lockout in `build_app_security.go`) — the `rate_limit` namespace is not
(`SQLiteLimiter` exposes no `DB()` accessor, and `AppendRateLimitReadyChecks`
only wires `/readyz` Pings, `build_readiness.go:99-124`). A forward-migrated
v2 `rate_limit_buckets` would not trip the `ErrSchemaTooNew` boot gate; an
old binary would happily write to a schema it doesn't understand.

**Impact.** None today (v1 only, ephemeral state), but inconsistent with the
repo's rollback doctrine the moment the table ever evolves.

**Recommendation.** When the table's schema next changes, add a
`DB()` accessor + `CheckSQLiteSchema` wiring in the same change; note it as a
one-line follow-up in the design.

### F10 — Info — Pool/serialization behavior worth stating for phase-2

With `MaxOpenConns(1)` per limiter pool, concurrent `Allow`s on one limiter
queue on the pool; a wedged COMMIT (busy_timeout 5 s under cross-process
contention) queues every queued request behind it. Phase-2 puts two
checkpoints on `/token`+`/userinfo` on the same file as phase-1 when
`backend=sqlite`: the file-level write lock serializes all limiters, and the
Decision 9 budget (16.5 µs, uncontended single writer) does not include
cross-process or cross-limiter contention. No fix required — measure under
2+ replicas before promising the 100 µs p99 for the sqlite backend at fleet
scale.

## 3. Query/index and transaction analysis

**SQLite `Allow` — the demonstrated hot write path** (every limited request
on the sqlite backend):

1. `BEGIN` — **deferred** (F1; `tx.go:22-24`); with `_txlock=immediate` this
   becomes the write-lock acquisition and closes the decision race.
2. `SELECT tokens, last_refill_at_ns FROM rate_limit_buckets WHERE
   bucket_name = ? AND key = ?` — **PK probe**, O(log n); missing row =
   first request, bucket starts full.
3. Refill math on the wall clock (F3); `consumeToken` — deny path returns
   before persisting (denied requests are not charged, matching the Memory
   reservation-cancel contract).
4. `INSERT ... ON CONFLICT (bucket_name, key) DO UPDATE` — PK upsert,
   single statement, same O(log n) probe.
5. 1/64 sampled `DELETE FROM rate_limit_buckets WHERE last_seen_at_ns < ?`
   — served by `idx_rate_limit_buckets_last_seen` (exists, `sqlite_limiter.go:37-39`);
   note the sample is **millisecond-clock-based** (comment acknowledges),
   which at the measured 16.5 µs/op can only fire ≈1/64 of calls (≥64
   Allows/ms would be needed); under Memory's call-count sampling the same
   ratio holds.
6. `COMMIT` — in the default rollback-journal posture this is two fsyncs
   (F2).

No missing index: both access paths (PK probe, last_seen range) are covered;
the prune's range scan on the secondary index is the only non-PK statement
and it is amortized 1/64. Atomic-consume invariants (`DELETE RETURNING`-style
single-use stores) deliberately do **not** apply — rate limiting is not a
consume-once store; the design's Decision 7 statement is **Verified**.

**Redis `Allow`** — one Lua script (`allowScript`, `ratelimit.go:60-76`):
`INCR` + conditional `EXPIRE` + `PTTL` as one server-side op on one key
(single slot on Cluster — `build_ratelimit_cluster.go:100-102`). TTL is set
on the first hit of a window and can never be lost to a process death
between INCR and EXPIRE (the doc explains the pin-forever failure this
prevents) — this is the reference-correct atomic design among the three.
Denied requests still INCR (fixed-window convention); the counter therefore
counts all hits in the window, and TTL-bounded keyspace = active keys only.

**Memory `Allow`** — `shardIndex` (FNV-32a, allocation-free) → shard mutex →
map probe → `rate.Limiter.Reserve`; sampled 1/64 inline prune runs **inside
the shard lock** (the `StartPruner` escape hatch exists for
high-cardinality). In-process atomic; measured 0.19 µs/op (Decision 9).

**Per-key decision atomicity summary:**

| Backend | In-process | Cross-process |
|---|---|---|
| Memory | ✓ shard mutex | ✗ (per-replica by design) |
| SQLite | ✓ single conn serializes | ✗ **deferred-BEGIN stale-read race** (F1) |
| Redis | ✓ Lua | ✓ Lua, server-side |

## 4. Migration sequence

**No schema migration is required by this design** (Verified — the phase-2
surfaces add keys to the existing table/keyspace, scoped by `bucket_name`).
The migration-relevant obligations are therefore:

1. **DSN contract (config-only, no schema change).** If F1/F2 are fixed via
   DSN parameters, `security.rate_limit.sqlite.dsn` must require
   `_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)`
   (or the limiter must set them itself). This is a config/validation change
   with zero compatibility window: SQLite reads `_pragma`/`_txlock` per
   connection; existing files migrate themselves (journal_mode is a
   file-persisted property — the first WAL connection converts the file).
   Validation queries after rollout:
   - `PRAGMA journal_mode;` → `wal`
   - `PRAGMA busy_timeout;` → ≥5000 on every pooled connection
   - `SELECT count(*) FROM rate_limit_buckets;` and
     `SELECT max(last_seen_at_ns) FROM rate_limit_buckets;` → bounded by
     active identities, no unbounded growth
   - `SELECT version, name FROM schema_migrations_rate_limit;` → `1,
     baseline_rate_limit_buckets`
2. **Rollback/roll-forward.** Forward-only migrations per repo doctrine
   (`migrate.go` package doc: "Rollback is a restore-from-snapshot
   operation"). The rate-limit table is the one store where a restore is
   provably safe: reset buckets are full buckets (fail-open direction,
   defense layer). An old binary against a forward-migrated table is the
   F9 gap — close it when v2 ever ships.
3. **Data-integrity checks (bucket invariants).** If a future migration or a
   bug ever corrupts state, the invariants to assert are: `tokens ∈ [0,
   burst]` for every row (refill caps at burst; consume decrements by ≤1),
   `last_refill_at_ns ≤ now + skew_bound` absent clock rollback (F3), and
   `last_seen_at_ns` freshness within the prune horizon. None of these is
   enforced by a CHECK constraint today; adding one is a v2 candidate, not a
   phase-2 requirement.

## 5. Unknown volume, retention, and recovery assumptions

- **Volume.** The design's cardinality claims ("naturally bounded by
  registered clients/subjects/admins") are **Proposed, not measured**: no
  production data exists for (a) distinct `sub:` keys under token-cycling
  scrapes (bounded for 10 min by the prune, but the *rate* of new keys under
  attack is unmeasured), (b) per-IP tier-1 keys behind NAT fan-out, (c)
  pairwise-sub multipliers. Decision 9's 16.5 µs sqlite number is
  uncontended single-process; **cross-process contention on one file was not
  measured** (F10) — that is the measurement required before promising the
  sqlite p99 at fleet scale. Redis latency was estimated (50–200 µs loopback,
  no server measured) — the bench gate covers only `MemoryLimiter.Allow`.
- **Retention.** Memory: 10-min idle horizon, sampled prune (+ optional
  `StartPruner`). SQLite: same horizon via the sampled DELETE (indexed). 
  Redis: TTL = window (fixed-window; `EXPIRE` on first hit). No
  operator-facing retention knob exists; the design adds none — acceptable
  for defense data, but should be stated as a non-goal in config-reference.
- **Recovery.** State loss on restart/eviction/restore resets buckets to
  full (fail-open direction) — safe for a defense layer, and the one store
  where snapshot restore is trivially correct. Cross-replica recovery after
  a store outage: limiters silently resume enforcing when the store returns;
  the silent-fail-open window is unobservable (F4) and the stall during the
  outage is bounded only by go-redis defaults (F5).
- **Tenant isolation.** The table has no tenant dimension; the design's
  bucket keys assume globally unique client/subject IDs (F8). In a
  multi-tenant deployment with per-tenant ID namespaces, cross-tenant bucket
  interference is a real (if defense-layer-bounded) risk — document the
  invariant or namespace the keys.

## Bottom line

The design's storage decision (reuse the `Limiter` SPI, no new state) is
sound and the stock wiring is real for all three `security.rate_limit.*`
backends — **Verified**. The persistence layer it inherits has two
documented-behavior gaps that phase-2 will lean on harder than phase-1 did:
the SQLite backend's decision race + journal-mode posture (F1/F2, both High,
both cheap to fix via `_txlock=immediate`/WAL or `beginImmediateRMW`) and the
silent fail-open / unbounded-stall observability gap (F4/F5, Medium). The
design should also correct Decision 7's blanket "no clock coupling" (F3) and
"token-bucket entries" (F6) claims to their backend-scoped truths, and state
the phase-2 reload-hook close-old-limiters obligation (F7). None of the
findings invalidates the design's decisions; F1/F2 must be resolved before
phase-2 acceptance testing runs on the sqlite backend.
