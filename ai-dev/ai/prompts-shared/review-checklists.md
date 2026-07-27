# Review checklists

Use these as question prompts, then verify the exact contract in `AGENTS.md`
and the current code.

## Security and protocol

- Are identity, client, scope, tenant, and proxy trust established before use?
- Do all credential failures preserve the required oracle-safe response and
  timing behavior?
- Are single-use state, refresh families, replay stores, and sessions atomic
  and bounded?
- Are algorithms, claims, redirect/outbound URLs, body sizes, and external
  metadata validated at the correct boundary?
- Do key rotation, audit, cache headers, challenges, and fail modes match the
  documented contract?

## Architecture and data

- Does the owning layer contain the behavior without an upward or peer import?
- Is state ownership explicit, with real memory and durable implementations?
- Are retries, concurrency, partitions, clock behavior, compensation, and
  cross-replica invalidation tested?
- Do schema, transaction, index, migration, and retention choices preserve
  single-use and tenant-isolation semantics?

## Performance

- Is there evidence for the claimed bottleneck and target?
- Are queries, allocations, cryptography, caches, pools, and batch operations
  bounded under the stated load?
- Does the benchmark represent production topology and fail on regression?

## Production readiness

- Do readiness, metrics, traces, logs, and alerts expose the real dependency
  state without leaking credentials?
- Are rollout, rollback, drain, backup/restore, key rotation, and top failure
  procedures executable?
- Does multi-replica configuration externalize every enabled stateful feature?
- Are image, dependency, secret, TLS, and deployment assets pinned and
  validated?

Record missing evidence as a finding; do not convert an assumption into a pass.
