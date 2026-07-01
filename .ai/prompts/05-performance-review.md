# Stage 05: Performance Review

## Roles Active
Performance Engineer · Database Architect

## Objective
Identify performance bottlenecks that will materialize at production scale.
Distinguish real bottlenecks from premature optimization.
Produce a performance budget and an optimization roadmap ranked by impact/effort.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Repository**: {{REPO_PATH}}

**Primary Files**:
{{PRIMARY_FILES}}

**Expected Load**:
{{LOAD_PROFILE}}
(e.g., "500 req/s peak, 10k concurrent sessions, p99 target < 200ms")

**Infrastructure**:
{{INFRA_SUMMARY}}
(e.g., "3-node Redis Cluster, PostgreSQL primary + 1 read replica, 4-pod deployment")

---

## Review Tasks

### 1. Hot Path Identification
- What is the most frequently called code path in this subsystem?
- What code executes on every single request vs. once per session vs. once at startup?
- Are there per-request cryptographic operations (signing, verification) that could be cached or batched?
- Are there per-request database queries that could be replaced with in-memory lookups?

### 2. Memory Allocation
- Are there slice/map allocations inside hot loops that could be pre-allocated?
- Are there string concatenations that could use `strings.Builder`?
- Are large objects allocated per-request that could be pooled (`sync.Pool`)?
- Are goroutines spawned without bounds? (Unbounded goroutine fan-out is a memory leak under load.)
- Are there deferred operations that hold references preventing GC?

### 3. Database Query Analysis
- List every query that executes per user request. Are they all necessary?
- Are there N+1 patterns? (Loop executes N queries where 1 batch query would suffice.)
- Are all `WHERE` clauses on indexed columns?
- Are there `SELECT *` projections that load unused columns?
- Are there queries without `LIMIT` that could return unbounded result sets?
- Are read queries routed to read replicas where available?

### 4. Redis Analysis
- Are multi-key operations in the same hash slot? (CROSSSLOT kills performance in Redis Cluster.)
- Are pipelining/batching used for multi-read operations in a single request handler?
- What is the TTL strategy? Are short-lived keys wasting memory with frequent allocation?
- Are Lua scripts used? If yes, are they efficient (no loops over large key sets)?
- Is `SCAN` used anywhere? (Blocks Redis for large keyspaces — use indexed sets instead.)

### 5. Serialization Overhead
- Are objects serialized to JSON/protobuf on every cache write and deserialized on every read?
- Are there opportunities to cache the serialized form (pre-computed byte slice)?
- Are large blobs stored in Redis that could be stored in object storage instead?
- Is there redundant deserialization (deserialize → re-serialize without modification)?

### 6. Connection Management
- Is the database connection pool sized for expected peak concurrency?
- Is the Redis connection pool shared across the application, or created per-request?
- Are connections properly returned to the pool in all code paths (including error paths)?
- Is there a connection leak possible under the timeout/cancellation logic?

### 7. Concurrency Efficiency
- Are sequential operations that could run in parallel actually sequential?
- Are parallel operations properly bounded to prevent resource exhaustion?
- Are `context.Context` cancellations respected to avoid wasted work?
- Are there global mutexes held during I/O? (This serializes all requests.)

### 8. Benchmark Coverage
- Does a benchmark exist for the hot path?
- Does the benchmark reflect production data size? (Single-item benchmarks miss cache effects.)
- Is `go test -bench` integrated into CI or available for regression detection?

---

## Required Output

### Performance Budget

| Operation | Current Latency (est.) | Target p50 | Target p99 | Gap |
|-----------|------------------------|------------|------------|-----|
| [endpoint or operation] | | | | |

### Top-5 Optimization Targets
Ranked by: estimated user-visible impact ÷ implementation effort.

For each:
- **What**: Specific function or query
- **Problem**: Why it is slow
- **Fix**: Specific change
- **Expected Gain**: Quantified estimate (%, ms, allocations)
- **Effort**: Hours | 1-2 days | 1 week

### Premature Optimization List
Things that look slow but are NOT worth changing yet — with justification.

### Capacity Model
Given the expected load, what are the resource limits?
- Max requests/second per pod before CPU saturation
- Max concurrent connections before connection pool exhaustion
- Redis memory usage at peak session count
- Database IOPS at peak write rate

Produce findings using `.ai/prompts/shared/output-format.md`.
Sort: Critical → High → Medium → Low → Info.

Conclude with the Stage Summary Block.
