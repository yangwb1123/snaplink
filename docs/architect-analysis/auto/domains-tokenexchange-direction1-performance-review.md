# Performance Review: `domains/tokenexchange` Direction 1 (ChainStore → revocation control plane)

Review basis: `ai-dev/prompts/README.md`, `ai-dev/prompts/performance_engineer.md`,
`docs/auto/domains-tokenexchange-direction1-design.md`,
`docs/auto/domains-tokenexchange-direction1-spec.md`, current executable code.
**Checks that ran:** source reads and greps only (`read`/`grep`/`wc -l`; symbol
cross-references; benchmark-file inventory). No build/test execution and no file
modifications — advisory analysis. The feature is **Proposed** (design + spec
only); all claims about current code are **Verified** unless labeled otherwise.
No SLOs, latency budgets, or dated benchmark results exist in the repository
for any surface this design touches (verified: `docs/observability.md` contains
no latency targets; the only Go benchmarks cover issuers, ratelimit, bind, JWKS
verify, and sharded memory stores — none cover chain stores, `/token/revoke`,
or the admin chain endpoints), so this review **designs baselines instead of
inventing targets** per the role prompt.

---

## 1. Workload assumptions and evidence quality

The design adds work to four surfaces. Assumed workloads, each with evidence
quality:

| Surface | Assumed workload | Evidence |
|---|---|---|
| `Validate` (all 3 issuers) | Sustained high QPS from resource-server middleware + introspection on every bearer request (`interfaces/middleware/middleware.go:59` calls `tokenIssuer.Validate` per protected request; `protocols/oauth/handle_introspect.go:267` per introspected token) | **Verified** (call sites) |
| `/token/revoke` | Public credential endpoint, attacker-reachable; per-request cost today is client auth + `RevokeAcrossIssuers` (per-issuer signature verification) + audit | **Verified** (`protocols/oauth/handle_revoke.go:60-82`); no traffic measurements exist |
| Token-exchange mint | In-request `RecordHop` after a successful exchange (`internal/handler/tokengrant/token_exchange.go:227`); `ChainStore.RecordHop` doc explicitly warns "a slow RecordHop still delays it" (`domains/tokenexchange/chainstore.go:88`) | **Verified** |
| Admin descendants/revoke | Low-volume, admin-gated, synchronous; operator-invoked | **Verified** (route design, D4) |
| Agent session cascade (`RevokeSession`/`RevokeAllForHuman`) | **Zero production callers today** (`domains/tokenexchange/agentidentity/revoke.go:17,28`; grep-verified) — dead code until a future surface wires it | **Verified** |

Chain-store breadth is attacker-influenceable: `MaxActChainDepth=10` caps
depth, not children per node (`internal/handler/tokengrant/token_exchange_stages.go:18`),
so any client holding one valid token can grow a subtree past `maxChainWalk=1000`
by repeated exchanges (each mints a new jti and records a hop). This is the
driver behind the top findings. No SLO exists to violate — the risk is
availability amplification on a public endpoint, not a documented target.

---

## 2. Findings

Sorted by severity. "Mechanism" distinguishes **measured** (none possible —
no execution) from **predicted** (code-verified structure, cost modeled from
the code's own operation counts and documented primitives).

### High

**P-1 — The cascade runs fully in-band on `/token/revoke`; worst case is ~1000 queries + ~1000 marks + ~1000 durable upserts + ~1000 bus publishes before the 200 is written.**
- Path: `HandleRevoke` (`protocols/oauth/handle_revoke.go:60-82`) → `revokeAccess` (`:152`, where D5's `chainRevokeCapability` type-assert lands) → `RevokeDescendants` → per-hop `expire`. The 200 is written **after** `revokeAccess` returns (verified: `ctx.JSON(200)` at `handle_revoke.go:80`; `revokeAccess` at `:72-77` runs first). The design's D5 "side channel / response already 200" phrasing is factually wrong — the security review independently reached the same correction. What holds is only "the 200 is *decided* and cannot be altered by the cascade."
- Mechanism (predicted, per-operation counts from code):
  - Walk: one `getChildren` query per visited node, up to `maxChainWalk=1000` (`domains/tokenexchange/sqlite/chain_store.go:185-205`), indexed on `parent_jti`; modernc.org/sqlite pure-Go query ≈ 20-100 µs each → **~20-100 ms** walk.
  - Per-hop `expire`: 3 issuer map marks + 1 durable upsert + 1 bus publish. The durable upsert (sqlite `INSERT ... ON CONFLICT`, WAL, `synchronous=NORMAL`) ≈ 50-200 µs each → **~50-200 ms**. The bus publish on the etcd backend is `Grant` + `Put` = **2 RTTs per event** (`platform/cluster/etcd/etcd.go:108-139`) → ≈ 2-4 ms per hop, **~2-4 s for 1000 hops**; the memory bus is a channel and negligible.
  - Total worst case: **~0.1-4 s added to a path whose baseline is ~1-5 ms** (client auth + per-issuer signature verify + audit). Amplification is attacker-influenceable (subtree breadth unbounded; see §1).
- Impact: availability amplification on a public credential endpoint; a large subtree revoke can tie up a request goroutine, sqlite connections, and the etcd bus for seconds. Re-walks re-pay the cost (marks are idempotent, the cost is not).
- Recommendation: keep the **in-process marks synchronous** (they are the denial) but move the **durable persist and bus legs off the request path** — a bounded async dispatcher with a work queue, or at minimum batch them per cascade (one sqlite transaction; one bus event carrying the jti list, or comma-joined into the existing `map[string]string` payload — 1000 jtis ≈ 30 KB, far under etcd's 1.5 MB value limit). The admin POST revoke must stay synchronous (it returns the revoked list), but it is admin-gated low-volume; `/token/revoke` is not.
- Experiment: benchmark `/token/revoke` on 1000-node subtrees with each leg isolated (walk-only, +marks, +persist, +bus) to attribute cost before choosing the async/batch split.

**P-2 — The lazy-prune discipline turns a cascade into O(1000 × deny-set size) exclusive-lock hold per issuer, stalling every concurrent `Validate`.**
- Path/symbol: `markRevoked`/`pruneRevoked` (`infrastructure/defaultimpl/revocation_set.go:53-83`) under each issuer's `revokedMu`; D2's `RevokeByJTI` reuses the same discipline (design D2: "same prune-not-early discipline ... lazily pruned under the existing write lock").
- Mechanism (predicted): every mark inserts **and sweeps the entire deny map** (`m[token]=exp; pruneRevoked(m, now)` — O(n) map iteration per mark). The per-token path pays this once per revoke; a cascade pays it **up to 1000× per issuer, ×3 issuers, in a burst**. With a steady-state deny map of n entries (n ≈ revoke rate × token TTL), a cascade holds each issuer's write lock for ~3000 × n iterations. At n=10k that is ~30M map iterations ≈ **0.5-3 s of exclusive lock time per issuer**, during which every `Validate` on that issuer (resource-server middleware, `interfaces/middleware/middleware.go:59`) blocks on `RLock`.
- Impact: the validation hot path — the one surface the design correctly calls "adds one O(1) map lookup" — stalls behind cascade bursts; the stall grows with deny-set cardinality, which is exactly the load profile of a busy deployment.
- Recommendation: amortize the sweep. Cheapest correct option: mark without pruning during a cascade and run one sweep at the end (or sweep on a size threshold, e.g. only when the map exceeds 2× its last observed size). Prune-not-early semantics unchanged; this is a discipline change in the shared helper, not the per-issuer code.
- Experiment: micro-benchmark `markRevoked` at n=1k/10k/100k × 1/100/1000 marks; assert total lock hold < 10 ms at n=10k for a 1000-hop cascade (or adopt the batched sweep and assert the same bound).

### Medium

**P-3 — `HopsBySession` (sqlite) sorts per call: the session index is not composite, and the silent `LIMIT 1000` cap doubles as an unbounded-sort risk on huge sessions.**
- Path/symbol: D1 `HopsBySession`, D3 migration `idx_tokenexchange_chain_hops_session` on `session_id` only; query `WHERE session_id=? ORDER BY recorded_at DESC LIMIT ?`.
- Mechanism (predicted): with the index on `session_id` alone, SQLite must temp-B-tree-sort every matching row before applying `LIMIT`. A session with tens of thousands of mints (an active agent's whole history) pays the sort per cascade call. The composite index `(session_id, recorded_at)` makes the ORDER BY index-ordered and the LIMIT short-circuit. The silent cap is a correctness defect already flagged by all three prior reviews (F1/Distributed F-1); the perf angle is that the *bounded* query is also the *sorted* query — fixing the index fixes both, and surfacing truncation (fail-closed, mirroring `ErrChainWalkTruncated`) is required regardless.
- Recommendation: `CREATE INDEX ... ON tokenexchange_chain_hops(session_id, recorded_at)` in migration v2; return a truncation signal from `HopsBySession` and fail closed in `RevokeSession`/`RevokeAllForHuman`.
- Experiment: sqlite `EXPLAIN QUERY PLAN` on the session query at 1k/10k/100k rows per session; assert no temp B-tree and bounded latency.

**P-4 — The sqlite chain store sets no pool limits, no `busy_timeout`, and no WAL pragma; the cascade's read burst + upsert burst can collide with concurrent exchange `RecordHop` writes.**
- Path/symbol: `domains/tokenexchange/sqlite/chain_store.go` `New`/`NewWithDB` — no `SetMaxOpenConns`, no `PRAGMA busy_timeout`, no journal pragma (verified: none present; contrast `infrastructure/defaultimpl/sqlite/auth_codes.go:214` and `account_lockout.go:55` which set `SetMaxOpenConns(1)` for WAL write serialization, and `platform/migrate/migrate.go:203` which sets busy_timeout per migration connection).
- Mechanism (predicted): the design's cascade issues up to ~1000 reads then ~1000 upserts against the same file the exchange path inserts into on every mint. Without WAL + busy_timeout on the operator-supplied DSN, `SQLITE_BUSY` errors surface as walk failures — which the design correctly treats as fail-closed 500s, turning a config issue into revoke failures; with rollback journal, readers block writers and vice versa. The distributed review independently flags the shared-file-over-NFS hazard.
- Recommendation: apply a runtime busy_timeout (and document WAL) in the store's `New`/`NewWithDB` regardless of DSN, mirroring `infrastructure/defaultimpl/sqlite/busy_timeout.go`'s per-connection approach; the cascade's fail-closed error path then only fires on genuine store failure, not lock contention.
- Experiment: load test with concurrent exchange mints (100 QPS) + repeated 1000-hop cascades; assert zero `SQLITE_BUSY`-sourced walk errors with the pragma set, and enumerate them without.

**P-5 — Migration v2's `CREATE INDEX` is O(rows) at boot, and the session index adds a per-`RecordHop` write-amplification tax on the exchange hot path.**
- Path/symbol: D3 migration; `RecordHop` (`domains/tokenexchange/sqlite/chain_store.go:66-91`), called in-request after every successful exchange (`token_exchange.go:227`, fail-open but latency-visible per the `ChainStore` doc).
- Mechanism (predicted): `ALTER TABLE ADD COLUMN ... DEFAULT 0/''` is metadata-only in SQLite (O(1)); the index build is O(existing rows) and runs once at the first boot after upgrade on a store whose entire purpose is accumulating history — seconds on large tables. Steady-state: every hop INSERT gains a third index write (parent index already exists). Marginal per-insert (~10-30% of an already-cheap insert), but it lands on the exchange response path.
- Recommendation: measure the migration on a synthetic large table; document the boot-time cost in the upgrade path (operators with big chain history should schedule the first boot). No design change needed; the composite index from P-3 replaces the session-only index, not adds to it.
- Experiment: migration timing on 1M-row chain table; `RecordHop` bench before/after v2 (target: < 30% regression).

**P-6 — Memory-store `GetDescendants` walk holds `s.mu.RLock` for the whole (currently unbounded) walk, blocking `RecordHop` writers on the exchange path.**
- Path/symbol: `domains/tokenexchange/memory/chain_store.go:78-108` (`RLock` across the walk; `RecordHop` takes `Lock`).
- Mechanism (predicted): the admin descendants read blocks concurrent exchange hop-recording for the walk duration; the walk is unbounded today (design's 1000-cap parity fixes the worst case, ~1-2 ms in-memory). With the cap, this drops to Low; listed as Medium only because the fix is already scheduled (D1) and the residual is small.
- Recommendation: accept with the D1 cap; do not snapshot-copy (speculative complexity for a sub-millisecond walk).

### Low

**P-7 — Introspection-cache staleness for jti kills (protocol review F2): bounded, cache-contract-consistent, and explicitly not fixable without the jti→token index D2 rejects.**
- Path/symbol: `protocols/oauth/introspect_cache.go` (`IntrospectionCache` TTL contract, "a revoked token might be served from cache for up to TTL seconds"); `InvalidateIntrospectionCache` is keyed by the raw token (`handle_revoke.go:66-73`), unreachable from a jti-only kill.
- Mechanism: a cascade-killed descendant answers `active:true` on `/token/introspect` for up to cache TTL while RS-side validation denies it immediately (`middleware.go:59` → `Validate` consults the jti map). Not a regression — the same window exists today for any revocation when the invalidator is unwired — but the admin surface sells "kill it now".
- Recommendation: document the residual window in the endpoint contract + OpenAPI description as a declared non-goal (no code cost). No optimization warranted.

**P-8 — `RevokeAllForHuman` cascade is an unbounded loop over sessions × hops × subtree walks; dead code today, but the future admin surface should get a work budget.**
- Path/symbol: D6 cascade sketch; `domains/tokenexchange/agentidentity/revoke.go:28` (zero production callers).
- Mechanism (predicted): each session contributes up to 1000 hops, each hop spawns a `RevokeDescendants` walk (up to 1000 nodes) — a single human's cohort can exceed the per-walk cap by orders of magnitude, all fail-closed on the first error.
- Recommendation: when the wiring surface lands, bound total work (budget across the loop), audit the partial list, and reuse the P-1 async legs. Explicitly deferred; note in the design's D6 residual.

### Info (design claims verified)

- **"One O(1) map lookup per validation" is accurate and negligible**: `jti` already decodes in all three payload structs (`infrastructure/defaultimpl/ed25519_types.go:30`, ecdsa/rsa siblings) — no extra parse; one `RLock` + map lookup ≈ 30-60 ns on a path dominated by ~10-100 µs signature verify. **Verified**.
- **Denied descendants pay full signature verify before rejection** (the jti check sits after claims decode, unlike the early token-string check at `rsa_validate.go:20-25`). Only denied tokens pay this — negligible; an early-jti check before verify would be fail-closed-direction-safe but reorders the design's verify-first discipline; not recommended.
- **Cascade aborts on request-context cancellation**: `revokeAccess` runs on `ctx.Request().Context()` (`handle_revoke.go:72`), so a client disconnect mid-walk aborts the cascade → partial revocation + audit (fail-closed, correct). Consequence: the side-effect legs (P-1) must use a detached context with a deadline, not the request context, if moved async.
- **Memory-store cap parity (D1) is a strict improvement** over today's unbounded walk.
- **No SLO, benchmark, or load-test exists for any affected surface** — the plan in §4 is a baseline-design, not a regression guard against dated numbers.

---

## 3. Critical-path table

Baseline = current code structure (no measurements exist; figures are operation-count models from verified code, marked "model"). Targets are proposed bounds, not supplied SLOs.

| Path | Baseline | Target (proposed) | Bottleneck | Profiling method |
|---|---|---|---|---|
| `Validate` (RS middleware + introspect, all issuers) | ~10-100 µs (signature verify dominates) | +1 map lookup ≈ 30-60 ns (no target needed) | RSA/ECDSA verify | existing `infrastructure/defaultimpl/issuer_bench_test.go`, extended with jti-deny hit/miss cases |
| `/token/revoke`, per-token (no cascade) | ~1-5 ms (model: client auth + per-issuer verify + audit) | unchanged | — | new bench + `pprof` trace |
| `/token/revoke` + cascade, 1000-node subtree | n/a (feature) | p99 < 500 ms in-process legs; bus/persist legs off-path or batched (P-1) | walk queries + per-hop marks (O(n) prune, P-2) + upserts + etcd 2-RTT publishes | new bench with per-leg isolation; `pprof` + sqlite trace |
| Token-exchange mint (`RecordHop`) | ~50-200 µs insert (model) | < 30% regression from v2 (P-5) | sqlite insert + 3 index writes | `RecordHop` micro-bench, `EXPLAIN QUERY PLAN` |
| Admin GET descendants | n/a (feature) | < 50 ms at 1000 visited (admin-gated, low volume) | walk (indexed) + sort | `pprof` trace on handler |
| Admin POST revoke | n/a (feature) | synchronous, bounded by walk cap; documented partial-list on failure | same as cascade | `pprof` trace |
| Boot migration v2 | n/a | one-time O(rows) index build; measure, document | `CREATE INDEX` | timed boot on synthetic table |

---

## 4. Prioritized benchmark/load plan

Baseline-design plan (no SLOs supplied); each item has dataset, concurrency,
duration, acceptance rule, and regression comparison. Runs only after
implementation, on the committed gates (`go test -race`, `make ci`).

1. **Prune-sweep micro-benchmark (P-2).** Dataset: deny maps at n=1k/10k/100k; 1 vs 1000 marks per burst. Concurrency: single-goroutine (lock-hold measurement). Duration: `-benchtime=1s -count=5`. Acceptance: 1000-mark burst lock hold < 10 ms at n=10k **or** batched-sweep adopted and proven. Regression: compare to the per-token `Revoke` path (1 mark).
2. **Chain-store walk bench (P-3/P-6).** Dataset: sqlite + memory stores seeded with 10/100/1000-node subtrees (depth ≤ 10, breadth-swept). Concurrency: 1. Duration: `-count=10`. Acceptance: sqlite `GetDescendants` < 50 ms at 1000 nodes; `EXPLAIN QUERY PLAN` shows index-only `parent_jti` lookup and, post-P-3, no temp B-tree on the session query. Regression: memory vs sqlite, and pre-/post-v2 schema.
3. **`/token/revoke` cascade load (P-1).** Dataset: 10/100/1000-node subtrees; mixed known/unknown/refresh tokens (oracle). Concurrency: 20 clients. Duration: 60 s. Acceptance: 200-always byte-identical (existing oracle tests `handle_revoke_test.go:134` pass unchanged); p99 < 500 ms in-process legs; zero `SQLITE_BUSY`-sourced walk failures (P-4). Regression: vs per-token revoke baseline from item 1 of the same run; `-race -count=10+` concurrent cascades for idempotency.
4. **Concurrent mint + cascade (P-4/P-5).** Dataset: 100 QPS exchange mints against the same sqlite file while repeated 1000-hop cascades run. Duration: 60 s. Acceptance: no walk errors attributable to lock contention; mint p50 regression < 30%.
5. **Keystone validation bench (D2 tripwire, perf side).** Mark a jti via the wired `expire`; `Validate` a real token carrying it on all three issuers. Acceptance: rejected; per-validation cost delta < 5% (map lookup). Regression: vs `issuer_bench_test.go` current numbers.
6. **Migration timing (P-5).** Dataset: synthetic 1M-row chain table. Acceptance: boot migration < 10 s (documented in upgrade path regardless).

---

## 5. Optimization risks and measurements still needed

**Risks.**
- Async off-request legs (P-1) must not weaken fail-closed semantics: the in-process marks stay synchronous (they are the denial); only persist/publish move. A crash between mark and persist reopens the documented restart-resurrection window — same gap the token deny-set's `RevocationStore` closes, and D8's re-seed covers it. Acceptable, but the audit event must carry the split.
- Batching bus events changes the D8 payload shape (currently singular `MetaRevokedJTI`); comma-joined jtis in the existing `map[string]string` payload keeps mixed-version compatibility (unknown-kind drop arm), but peers must parse the list. Keep the singular form for single-hop revokes.
- P-2's batched/threshold sweep must preserve prune-not-early (never drop an entry with exp ≥ now); the threshold variant changes worst-case map growth between sweeps — bound it (2× baseline) so memory stays O(deny set).
- Do not add speculative caching: the walk is already indexed, the jti lookup is O(1), and the introspection cache is a documented residual (P-7) — caching the deny set or the walk would violate the role prompt's no-speculative-complexity rule.

**Measurements still needed (absent from the repository; no SLOs supplied).**
- Real subtree-size distribution in deployments that wire a ChainStore (none exist in-repo; the whole data plane is currently zero-caller).
- Production bus backend (etcd vs memory) and its RTT — determines whether P-1's bus leg is seconds or microseconds.
- Token TTL distribution (drives deny-map steady-state size n for P-2).
- Operator-supplied chain-store DSN journal mode / busy_timeout (drives P-4 severity).
- Per-hop persist cost when the JTIRevocationStore shares the chain store's sqlite file vs a separate backend (Redis is named in D2 as "natural third backend" — an RTT per hop if not pipelined; the async/batch recommendation in P-1 covers it either way).

No code was modified.
