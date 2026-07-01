# Stage 03: Distributed Systems Review

## Roles Active
Distributed Systems Engineer · Database Architect

## Objective
Identify correctness failures that only manifest under multi-replica, multi-region, or failure-mode conditions.
Assume: multiple pods, Redis Cluster, PostgreSQL, clock skew, network partition, rolling deployment, retry storms, leader switches.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Repository**: {{REPO_PATH}}

**Primary Files**:
{{PRIMARY_FILES}}

**Storage Layer**:
{{STORAGE_SUMMARY}}
(e.g., "Redis Cluster for sessions/tokens, PostgreSQL for consent/clients, in-memory for tests")

**Stage 01 Architecture Output (if available)**:
{{ARCHITECTURE_OUTPUT}}

---

## Review Tasks

### 1. Consistency Model
- What consistency model does this subsystem require? (Strong / Causal / Eventual)
- Is the actual implementation consistent with that requirement?
- Are there operations that require strong consistency but use eventually-consistent storage?
- Are there cross-store transactions (e.g., write to Redis AND Postgres atomically)?

### 2. Race Conditions
- Are there any check-then-act patterns without atomic locking?
  (Example: read token → validate → delete. An attacker could replay between validate and delete.)
- Are token consume operations atomic? (`DELETE RETURNING` in SQL, Lua script in Redis)
- Can two concurrent requests both succeed at creating the same resource (duplicate insert)?
- Is rate limiting enforced atomically, or can bursts bypass it with concurrent requests?

### 3. Idempotency
- Are all mutating operations idempotent (safe to retry without unintended side effects)?
- What happens if a client retries a token exchange request after a network timeout?
- What happens if a consent grant is submitted twice (double-click, network retry)?
- Is there a deduplication key or idempotency token for operations that must execute exactly once?

### 4. Locking Strategy
- What is the lock granularity? (Per-user, per-session, per-client, global)
- Are locks held for the minimum necessary duration?
- Is there a deadlock scenario if two operations lock resources in different orders?
- What is the behavior when a lock holder crashes mid-operation? (TTL? Cleanup job? Compensating transaction?)
- Is Redis `SETNX` / `SET NX PX` used for distributed locks? Is the Redlock pattern used? (If yes: is it necessary? Redlock has known failure modes under clock drift.)

### 5. Cache Invalidation
- When a client is updated, are all cached representations invalidated across all replicas?
- When a session is revoked, is the revocation reflected immediately on all pods or only after TTL expiry?
- Is there a thundering herd scenario when a popular cache key expires simultaneously?
- Does cache miss behavior (cache-aside) introduce a TOCTOU window?

### 6. Clock Drift & Temporal Correctness
- Are token TTLs calculated with monotonic time or wall clock?
- What happens if the system clock steps backward? (NTP slew is expected; step is a bug.)
- Are `iat`/`exp` comparisons done with a configurable clock skew tolerance (recommend ±30s)?
- Is there any ordering dependency on wall clock across replicas?

### 7. Partition Tolerance
- What happens when the Redis cluster is unreachable? (Fail-open: allow? Fail-closed: deny?)
- What happens when the database primary is unreachable during a write?
- Is the fallback behavior documented, tested, and consistent with the fail-open/fail-closed catalog?
- See `engineering-principles.md` for the project's fail-open/fail-closed catalog.

### 8. Rolling Deployment Scenarios
- Does this subsystem have any state that is schema-incompatible between N and N+1?
- During a rolling deploy, can pod-A (old) and pod-B (new) both service the same session without corruption?
- Are database migrations backward-compatible with the running old version? (Add-only, never drop-then-add)
- Is there any in-memory cache that is warm on old pods and cold on new pods, causing inconsistency?

### 9. Redis-Specific
- Are multi-key operations in the same hash slot? (CROSSSLOT error in Redis Cluster if not)
- Is `EVAL` / Lua used for atomic multi-step operations? If so, is the script idempotent?
- Is `cjson` used in Lua scripts? (Real Redis `cjson` encodes `[]` → `{}`. Miniredis encodes `[]` → `[]`. Tests pass but production fails.)
- Is pipeline/batch used where applicable to reduce round trips?

### 10. Database-Specific
- Are all foreign key relationships enforced at the database level, not just application level?
- Are migrations run with `BEGIN IMMEDIATE` (SQLite) or equivalent serializable isolation?
- Are there any long-running transactions that hold locks during user-interactive operations?
- Are N+1 query patterns present in any list or batch endpoint?
- Are indexes present for every column used in `WHERE` clauses with high-cardinality data?

---

## Required Output

### Consistency Model Declaration
State the required consistency model for each state type managed by this subsystem.

### Failure Matrix
For each failure scenario, describe the actual behavior:

| Failure | Expected Behavior | Actual Behavior | Gap |
|---------|-------------------|-----------------|-----|
| Redis unreachable | | | |
| DB primary down | | | |
| Clock step backward | | | |
| Duplicate request (retry) | | | |
| Rolling deploy (N+1 pods) | | | |
| Lock holder crash | | | |

### State Machine (if stateful)
Draw the state transitions including failure transitions and recovery paths.

Produce findings using `.ai/prompts/shared/output-format.md`.
Sort: Critical → High → Medium → Low → Info.

Conclude with the Stage Summary Block.
