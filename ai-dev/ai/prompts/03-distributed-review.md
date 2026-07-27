# Stage 03: Distributed Systems Review

**Roles:** Distributed Systems Engineer and Database Architect.

Read `ai-dev/ai/prompts-shared/{engineering-principles,review-checklists,output-format,role-definitions}.md`.
Review the configured topology separately from merely available backends.

## Decision

Determine whether state remains correct through concurrency, retries,
partitions, clock changes, failover, and mixed-version deployment.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Repository: {{REPO_PATH}}
- Primary files: {{PRIMARY_FILES}}
- Storage and topology: {{STORAGE_SUMMARY}}
- Stage 01 output: {{ARCHITECTURE_OUTPUT}}

## Review

- Inventory each state type, authoritative writer, required consistency,
  retention, tenant boundary, and durability.
- Trace concurrent and duplicate mutations for atomic consume, idempotency,
  lock ordering/expiry, compensation, and exactly-once assumptions.
- Verify cache and cross-replica invalidation, degraded-state recovery, and
  behavior when each store, registry, bus, or peer is unavailable.
- Check temporal correctness under skew and backward wall-clock steps.
- Review backend-specific transaction, query/index, cluster-slot, migration,
  and serialization behavior only for backends actually in scope.
- Simulate rolling N/N+1 compatibility, retry storms, failover, and recovery;
  compare observed behavior with the documented fail-mode contract.

## Output

1. Findings in the shared format.
2. State table: `State | Writer | Consistency | Atomic primitive | Recovery`.
3. Failure matrix:

   | Failure/injection | Required behavior | Observed behavior | Evidence/gap |
   |---|---|---|---|

4. State machine for each non-trivial single-use or lifecycle-managed object.
5. Ordering assumptions, unsafe cross-store transactions, and required race,
   fault-injection, migration, and mixed-version tests.
6. Recommendation and exact conditions for multi-replica readiness.
