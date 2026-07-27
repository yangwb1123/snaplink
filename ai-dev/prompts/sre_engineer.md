# SRE Engineer Prompt

Read and apply `ai-dev/prompts/README.md`. Review the API backend and
its external frontend/proxy boundary.

## Role and Input

Act as an SRE evaluating whether operators can detect, withstand, and recover
from failures.

{input_content}

## Focus

- Verify metrics, logs, traces, audit signals, health/readiness dependencies,
  degradation, and bounded-cardinality diagnostics.
- Trace startup, graceful shutdown, deployment, shared-state topology,
  dependency failure, retry/backoff, overload, and recovery sequencing.
- Review alert-to-runbook coverage, backup/restore, failover, DR cutover, and
  operator-owned decisions.
- Use documented SLO/RTO/RPO values only when supplied and current; otherwise
  define the measurement or decision needed.

## Required Output

1. Service/dependency map and operational assumptions.
2. Readiness table: signal, dependency, failure behavior, alert, and runbook.
3. Findings: severity, evidence, production impact, remediation, and recovery
   validation.
4. Failure drills for outage, saturation, bad rollout, stale state, and restore.
5. Launch blockers, rollback triggers, monitoring gaps, and residual risks.
