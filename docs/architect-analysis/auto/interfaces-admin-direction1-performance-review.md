# Performance Review — interfaces/admin Direction 1 (capability language, tenant dimension, delegation grading)

Reviewer role: performance engineer (`ai-dev/prompts/performance_engineer.md` +
`ai-dev/prompts/README.md` baseline). Advisory only; **no files in the repo
modified**. All evidence re-verified against the working tree at commit
`5ce7b81d`; measurements were taken with the repository's own benchmarks plus
a standalone harness in `/tmp/perfcheck` (module-replace, outside the repo).
Claims are labeled **Verified** (read in code / measured), **Proposed**
(design commitment), or **Unknown** (no in-tree evidence).

## 1. Workload assumptions and evidence quality

**No SLOs exist in-tree.** Verified: no latency/throughput targets in
`AGENTS.md`, `docs/observability.md`, or the agent-os docs; the only
performance gate is `ops/deploy/benchgate/benchmarks.yaml` — a **10%
regression threshold vs. a recorded baseline** (`compare-baseline.sh`,
`count: 6`), covering only JWT issue/validate, JWS verify, OAuth memory
stores, bind params, and ratelimit. **The admin gate and the permissions
providers are not in the gate set** (verified: zero `Benchmark*` in
`interfaces/admin/`, `domains/permissions/`, `interfaces/sso/`). No load
tests or volume figures exist in-tree. The DBA review independently confirms
"no workload evidence in-tree."

**Workload assumptions (stated, not sourced):**

| Assumption | Rationale |
|---|---|
| Admin HTTP/gRPC surface: low QPS (single-digit to low-hundreds ops/s), bursty, latency-tolerant | Operator console + CI automation; per-request cost dominated by correctness, not throughput |
| **SCIM provisioning (`/api/v1/scim/*`) is the demonstrated bulk path through the same gate** | Verified: `IsProtectedPath` (middleware.go) gates SCIM; SCIM syncs are bulk read/write traffic (10k-user initial syncs are the canonical SCIM shape) |
| Break-glass mint + approval: rare, synchronous, emergency-latency-tolerant | One human waiting on a UI |
| D2 tenant-scoped roles raise role cardinality | Tenants each add roles to the same client's role table |

**Measured baseline (this review; AMD RYZEN AI MAX+ 395, go1.26.5, today's
tree):**

| Symbol | Result (benchmem) |
|---|---|
| JWT validate (existing repo benches, run now) | Ed25519 **34.3 µs**, 3.8 KB, 48 allocs; ECDSA **43.3 µs**; RSA **23.9 µs** |
| `permissions.Matches` (new harness) | **5.2 ns**, 0 allocs |
| `MemoryProvider.Permissions` (10 roles/client, 3 assigned) | **1.0 µs**, 2.1 KB, 7 allocs |
| `MemoryProvider.ResolveResource` hit, 60-entry catalog | **4.3 µs**, 5.8 KB, 61 allocs |
| `MemoryProvider.ResolveResource` **miss** (full scan) | **7.2 µs**, 10.6 KB, **121 allocs** |
| sqlite `Permissions`, 10 roles/client | **33 µs**, 18.3 KB, 321 allocs |
| sqlite `Permissions`, 200 roles/client | **377 µs**, 286 KB, 5265 allocs (**11.4× for 20× roles**) |

## 2. Findings

### F1 — High — The gate's permissions fetch is O(client's total role count) on every durable backend; D2 grows exactly that table

**Path/symbol:** `sqlite.Provider.Roles` → `ListAllRoles`
(`domains/permissions/sqlite/menus.go:69-105`); identical shape in
`infrastructure/postgres/permissions_menus.go:66-95` and
`infrastructure/postgres/permissions_roles.go:100`. **Verified.**
**Mechanism (measured):** every gate check runs `Permissions` → assignment
PK query + **`SELECT ... FROM permissions_roles WHERE client_id = ?` — the
entire per-client role table** — then JSON-decodes every role, builds a map,
and sorts. Cost scales with total roles defined for the client, not the
user's assignment: 33 µs / 321 allocs at 10 roles → 377 µs / 5265 allocs at
200 roles (11.4× for 20× roles). Postgres adds network RTT to the same scan
(the prod overlay is `permissions.backend: postgres`, verified
`ops/deploy/kustomize/overlays/prod/config.yaml:68`); redis is the one
backend that is O(user's roles) (SMEMBERS + HMGet, `infrastructure/redis/
permissions.go` — verified).
**Impact:** the dominant per-request gate cost on the production path scales
linearly with role cardinality — and **D2's tenant-tagged roles grow that
same per-client table by design**, so the gate degrades as tenants (not
users) are added. A tenant dimension without a query-shape fix makes the
headline security feature the mechanism of a latency regression.
**Recommendation:** in D2's already-required sqlite migration (M-2 per the
architecture review), implement `PermissionsForTenant` as **one JOIN
(`permissions_assignments` ⋈ `permissions_roles` on client_id + tenant_id,
with a `(client_id, tenant_id)` index)** instead of inheriting the
`Roles`+`ListAllRoles` pattern — two full scans per request would double the
dominant cost. Fix the base `Permissions` with the same JOIN in the same
milestone (the schema change is already being made; the sort/dedup output
contract is pinned by `permissionstest.ConformanceSuite`).
**Experiment:** extend the harness: sqlite `PermissionsForTenant` as written
(two fetch paths) vs JOIN — assert JOIN ≤ current `Permissions` cost and the
two-fetch variant ≥ 1.8×.

### F2 — High — D1 step 2 adds a per-request full-catalog scan to every admin request; the common case (miss) is the most allocation-heavy CPU step in the gate

**Path/symbol:** Proposed `Middleware` resolution chain step 2 →
`MemoryProvider.ResolveResource` (`domains/permissions/memory_resources.go:
100-124`); chain runs for every request not caught by the capability table —
i.e., ~55 of 61 routes. **Verified** (design text) + **Measured** (harness).
**Mechanism (measured):** platform bucket lookup + tenant bucket lookup = up
to **2 linear scans per request**. Miss (the common case) costs **7.2 µs /
121 allocs / 10.6 KB each** — dominated by `strings.Split` per candidate in
`matchPath`. On the memory backend the gate today is ~35 µs/request
(JWT 34 µs + fetch 1 µs); D1 as designed adds ~14 µs + ~240 allocs (+40%
CPU, +allocation pressure) for a catalog that is **inert on the durable
backends** (no `ResourceProvider` there — architecture finding H-2) and
inert in the stock binary (only seeded platform entries exist).
**Impact:** pure per-request overhead on the low-QPS admin surface, but it
is the exact path SCIM bulk syncs traverse; at 10k sync ops it is ~140 ms
CPU + ~2.4 MB allocations of dead work.
**Recommendation:** materialize the platform-bucket catalog into the
`CapabilityTable` **once, post-bootstrap** (same ordering fix as
architecture M-1 — the table is static after the versioned seed step), and
run the per-request catalog lookup **only for the tenant bucket and only
when a tenant actually resolved** (D2). In the stock binary that makes step
2's per-request cost exactly zero; the design's "tables cannot drift"
invariant is preserved because both transports share the one construction
object.
**Experiment:** gate-level benchmark (bearer → `scopeForHTTP` → fallback
expansion → authorizer) over the memory provider, before/after the
materialization; assert < 2 µs added per request vs. today's chain.

### F3 — Medium — D2's `SetTenantResolver` can add a per-request store op to the whole admin surface; the design sets no cost bound

**Path/symbol:** Proposed `Middleware.SetTenantResolver(func(r) (string,
bool))` (D2 step 2). **Proposed.**
**Mechanism:** if the wired resolver performs a host→tenant lookup per
request (tenant table query), every admin/SCIM request gains one store
round-trip on top of the permissions fetch. The design specifies the wiring
but not the cost bound; `tenant.FromHandlerContext` (step 1) is free when
the admin middleware runs inside the tenant middleware, but the security
review verified the stock binary mounts admin outside `domains/tenant`'s
per-route middleware.
**Impact:** for a deployment that wires a naive resolver, the gate's store
op count doubles (or triples on write routes with quota) — material on the
SCIM bulk path, trivial on the console path.
**Recommendation:** specify that a standalone resolver must be backed by an
in-process TTL cache over the small, durable tenant table (or state that
resolvers are expected to reuse the tenant middleware's context); document
the per-request op inventory per wiring mode in the design's failure-mode
table.
**Experiment:** k6 run of the tenant-route matrix with a resolver doing a
real lookup vs. a cached resolver; assert p95 delta < 10% or document the
difference as the accepted cost of the wiring.

### F4 — Medium — D3 `CanImpersonate` worst case is 4 permissions fetches (up to 8 serialized queries on postgres) at mint time

**Path/symbol:** Proposed `CanImpersonate` replacing `TargetHoldsAdminScope`
(`interfaces/sso/accessors_feature_gates.go:291-316`); today's loop is 1-2
fetches with early exit. **Proposed** vs **Verified** (current code).
**Mechanism:** actor + target × {clientID, ""} = 4 `Permissions` fetches;
on durable backends each fetch is 2 queries (assignment + full role scan,
F1) → up to 8 serialized queries. The subset check itself is negligible
(`Matches` = 5 ns; O(A×T) with single-digit code sets).
**Impact:** bounded — mint is rare, synchronous, emergency-latency-tolerant
— but it is the exact moment a human is waiting during an incident, and it
fails closed on store errors.
**Recommendation:** keep the empty-client fallback short-circuit exactly as
today (`ErrUserNotFound` under the primary client → skip the second lookup),
so the common case is 2 fetches; state the 4-fetch worst case as the
documented bound. Do not cache grants for this path (revocation immediacy is
the design's invariant).
**Experiment:** 100-iteration mint benchmark with a 200-role client,
asserting p95 < 2 s and reporting fetch count distribution.

### F5 — Low — `matchPath` allocates per candidate (`strings.Split`); the memory catalog miss path is allocation-dominated

**Path/symbol:** `matchPath` (`domains/permissions/memory_resources.go:
175-190`). **Verified + Measured** (121 allocs / 10.6 KB on a 60-entry
miss).
**Impact:** only material if any per-request catalog lookup survives (F2's
tenant bucket) and the catalog grows ("a few hundred entries" is the
current bound; tenant-scoped resources push it toward thousands → ~100 µs+
per lookup).
**Recommendation:** if the tenant-bucket lookup ships per-request, replace
the per-candidate `Split` with a segment walk (no allocation) or a
per-Type dispatch index; the deterministic platform bucket is already
covered by F2's materialization.
**Experiment:** `BenchmarkMemoryResolveResourceMiss` before/after — assert
allocs drop from ~121 to < 10 per lookup.

### F6 — Low — sqlite permissions backend serializes every gate query on one connection

**Path/symbol:** `db.SetMaxOpenConns(1)` (`domains/permissions/sqlite/
sqlite.go:85`). **Verified.**
**Mechanism:** at 33-377 µs per fetch, the single connection bounds the
per-process gate at ~2.6k-30k checks/s; the "cluster-shared" sqlite backend
(shared file across replicas) serializes further on `busy_timeout` (5 s).
**Impact:** a throughput ceiling for the whole admin surface on that
backend; D2's second query (F1) would halve it unless JOINed. Not a defect
— the comment documents the intent (one writer, no lock convoy).
**Recommendation:** record the ceiling in the D2 design notes; the JOIN (F1)
is what keeps D2 from compounding it.
**Experiment:** `go test -race -count=10` on the sqlite conformance suite
plus a 32-goroutine concurrent `Permissions` benchmark; assert no lock-wait
stalls beyond the busy_timeout.

### F7 — Info — The benchgate has no coverage for the surface this design changes

**Verified:** `ops/deploy/benchgate/benchmarks.yaml` gated set excludes
admin gate, permissions providers, and `Matches`; zero benchmarks exist in
`interfaces/admin`, `domains/permissions`, `interfaces/sso`.
**Impact:** the design's #1 regression risk (fallback omission) and its
per-request cost deltas (F1, F2) would ship unmeasured; the 10% gate cannot
catch a gate-path regression it does not sample.
**Recommendation:** add two benchmarks to the gate in the same change as
D1: (a) full HTTP gate resolution chain over the memory provider, (b)
`Permissions` fetch per backend (memory, sqlite, redis) at fixed role
cardinality; record baselines with `record-baseline.sh`. This is a
reviewed, deliberate extension of the gate set — exactly what the file's
own comment demands.

### F8 — Info — No caching in the gate, and none should be added

**Verified:** every request re-fetches grants (immediate revocation is an
invariant; the design preserves it). The correct optimizations are
query-shape (F1) and startup materialization (F2), not caching. The
`MemoryProvider` global RWMutex is uncontended at admin QPS (readers share;
SCIM group-sync writes are µs-scale); no finding.

## 3. Critical-path table

No latency SLOs supplied anywhere; "target" = today's measured baseline
(same machine), the only objective reference in-tree is the benchgate 10%
regression rule.

| Path | Baseline (measured today) | Target (supplied) | Bottleneck | Profiling method |
|---|---|---|---|---|
| HTTP admin gate, memory backend | ~35 µs/req (JWT 34.3 + Permissions 1.0) | none; **guard: D1 adds < 2 µs** (F2 fix) | JWT verify (47-60 allocs) | `go test -bench` gate-chain bench + `-benchmem` |
| HTTP admin gate, sqlite (10 roles) | ~67 µs/req (JWT + 33) | none | **full role-table scan + JSON decode** (321 allocs) | pprof on k6 SCIM run; sqlite `EXPLAIN QUERY PLAN` |
| HTTP admin gate, sqlite (200 roles) | ~411 µs/req (JWT + 377) | none; **D2 must not scale with role count** (F1) | same scan, 5265 allocs | `EXPLAIN QUERY PLAN` + bench before/after JOIN |
| HTTP admin gate, postgres (prod overlay) | JWT + scan + RTT (Unknown RTT in-tree) | none | scan + per-request RTT | pprof + pg_stat_statements; bench harness with `_test` pg fixture |
| D1 catalog step (memory, per request) | n/a today (0 consumers); designed: 2× 7.2 µs/121 allocs | **0 µs in stock binary** (F2 materialization) | `matchPath` Split allocs | `BenchmarkMemoryResolveResource{Miss}` |
| D2 tenant resolution (host resolver wired) | n/a; +1 store op/req if naive (F3) | +0 ops via context/cache | resolver store lookup | k6 tenant-route matrix, cached vs uncached |
| D3 break-glass mint | 1-2 fetches (today) | common case 2 fetches, worst 4 documented (F4) | fetch count × scan | 100-iter mint benchmark |
| D3 approval decision | 0 fetches (today) | +1 fetch, rare | permissions fetch | unit bench, assert < 1 ms memory / < 2× sqlite fetch |

## 4. Prioritized benchmark/load plan

No load evidence exists in-tree; the plan below is the baseline the design
should ship with. Datasets and acceptance rules are proposed; the 10%
regression rule (benchgate) is the only existing acceptance standard.

1. **M1 (pure language core):** `BenchmarkMatches` fallback-expansion matrix
   (perf of the #1-regression-risk helper). Dataset: 2-8 codes × 6
   requirements. Acceptance: < 50 ns/call, 0 allocs (measured today: 5 ns).
2. **M2 (gate resolution):** gate-chain benchmark over the memory provider:
   bearer parse → `scopeForHTTP` → fallback expansion → authorizer (single
   fetch) → denial/allow. Concurrency 1; `-count=6` for benchstat.
   Acceptance: **< 2 µs added per request vs. today's chain** (F2 fix) and
   0% vs. `record-baseline.sh` baseline. Regression comparison:
   `compare-baseline.sh` on the same machine.
3. **M3 (tenant dimension):** `BenchmarkPermissionsFetch_{Memory,SQLite,
   Redis}` at 10/100/500 roles/client + `BenchmarkPermissionsForTenant`
   (JOIN vs two-fetch variant). Dataset: 3 assigned roles/user, 1 tagged
   tenant role. Acceptance: `PermissionsForTenant`(JOIN) ≤ 1.1×
   `Permissions` at same cardinality; two-fetch variant rejected if ≥ 1.8×.
4. **M3 (load):** k6 SCIM bulk sync (the demonstrated hot path) through the
   real mux: 10k users, 200 roles, concurrency 50, 5 min. Metrics: gate
   p95, allocs/op, sqlite lock waits, 429/500 rate. Acceptance: gate p95
   < 250 ms, zero gate-induced 5xx; regression vs. pre-change run of the
   same script (≤ 10% p95 delta).
5. **M3 (tenant routes):** k6 matrix of `:id` tenant routes with a cached
   vs. uncached host resolver (F3). Acceptance: cached resolver p95 ≤ 1.1×
   no-resolver baseline.
6. **M4 (break-glass):** 100-iteration mint benchmark, 200-role client,
   equal-level refused + strictly-lower minted. Acceptance: p95 < 2 s,
   common-case fetch count = 2 (F4).
7. **M7 (gate):** add the two new benchmarks to
   `ops/deploy/benchgate/benchmarks.yaml` and record baselines (F7).
   Acceptance: benchgate green on the same runner as baseline recording.

## 5. Optimization risks and measurements still needed

**Risks:**
- **JOIN rewrite (F1)** touches the sqlite/postgres conformance surface —
  output sort/dedup and `ErrUserNotFound` semantics are pinned by
  `permissionstest.ConformanceSuite`; the rewrite must stay within it. The
  migration is additive-only (AGENTS.md discipline); the JOIN needs the new
  `(client_id, tenant_id)` index or it silently degrades to a cross join.
- **Startup materialization (F2)** has the same ordering hazard as M-1: run
  post-bootstrap or the table is empty and the design's "unknown resource
  names fail at startup" guarantee turns into a silent no-op.
- **Do not cache grants.** Revocation immediacy is an invariant; every
  optimization above is query-shape or construction-time, never staleness.
- **Benchgate coupling:** new benchmarks join a 10%-threshold gate; baselines
  are machine-specific (`compare-baseline.sh`), so recording must happen on
  the gate runner, and the two new benchmarks must be stable (fixed
  cardinality, no wall-clock dependence).

**Measurements still needed (all currently Unknown in-tree):**
- Postgres permissions fetch on a real DB (scan cost + RTT + query plan);
  redis fetch RTT under load.
- Production role/tenant cardinality and admin/SCIM QPS per deployment —
  no telemetry evidence exists; the k6 plan above is the first source.
- The benchgate baseline for the gate chain (no baseline exists for this
  path today).
- D2 tenant-role growth rate (roles/tenant) — determines whether the
  full-scan hazard (F1) becomes a production incident or stays theoretical.

**Bottom line:** the design is performance-sound in shape — the single-fetch
`CapabilityAuthorizer`, the 5 ns matcher, and the closure-injected approval
check are all the right cost profile, and the two genuinely hot decisions
(break-glass, approval) are rare. The two High findings are both
**query-shape and construction-time**, not caching: the durable-backend
permissions fetch is O(role cardinality) per request today and D2 grows that
cardinality (F1), and D1's catalog step as written adds ~14 µs / ~240 allocs
of dead per-request work on the memory backend while being absent on the
durable backends (F2). Both are fixable inside milestones M-2/M-3 already in
the sequencing plan, at zero wire-contract cost, and both deserve the
benchgate coverage F7 proposes.
