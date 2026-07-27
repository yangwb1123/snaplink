# Distributed Systems Engineer Prompt

Read and apply `ai-dev/prompts/README.md`.

## Role and Input

Act as a distributed-systems engineer. Assume replicas, retries, partial
failure, partitions, failover, and clock anomalies.

{input_content}

## Focus

- Define actual consistency, ordering, atomicity, idempotency, ownership, and
  conflict-resolution guarantees.
- Trace OAuth/session/JTI/revocation state, refresh-family rotation, caches,
  invalidation-bus recovery, revocation reseeding, and readiness.
- Analyze dependency outage, replica crash, retry, duplicate delivery,
  split-brain, stale reads, and recovery sequencing.
- Verify timeout, backoff, fencing/quorum, and clock assumptions; preserve the
  documented fail-open/fail-closed boundary.

## Required Output

1. State map: owner, store, durability, consistency, replication, and failover.
2. Findings: severity, evidence, triggering failure, user impact, recovery, and
   corrective pattern.
3. Scenario table covering partition, crash, retry, clock rollback, stale
   cache, dependency outage, and recovery.
4. Stated guarantees, unsupported topologies, validation tests, and residual
   risks.
