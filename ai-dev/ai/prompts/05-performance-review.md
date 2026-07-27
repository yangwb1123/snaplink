# Stage 05: Performance Review

**Roles:** Performance Engineer and Database Architect.

Read `ai-dev/ai/prompts-shared/{review-checklists,output-format,role-definitions}.md`.
Treat checked-in benchmark results as historical until rerun on the reviewed
commit and declared topology. Never present an estimate as a measurement.

## Decision

Identify production-relevant bottlenecks, set an evidence-based budget, and
separate justified work from premature optimization.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Repository: {{REPO_PATH}}
- Primary files: {{PRIMARY_FILES}}
- Load profile and targets: {{LOAD_PROFILE}}
- Infrastructure/topology: {{INFRA_SUMMARY}}

## Review

- Define representative request mix, data size, concurrency, warm/cold state,
  dependency latency, and saturation criteria.
- Profile hot paths for CPU, allocation, cryptography, serialization, goroutine,
  lock, cancellation, and unbounded-work costs.
- Trace per-request database/cache calls, indexes, result bounds, batching,
  cluster constraints, pools, timeouts, and leak behavior.
- Inspect benchmark realism and reproducibility; rerun baselines where possible
  and record hardware, settings, commit, repetitions, and uncertainty.
- Model per-pod throughput, connection/worker exhaustion, storage memory/IOPS,
  and the first limiting resource under the supplied load.

## Output

1. Findings in the shared format.
2. Performance budget:

   | Operation | Current evidence | Target p50/p99 | Throughput | Gap |
   |---|---|---|---|---|

3. Top five targets: location, demonstrated cause, proposed experiment/fix,
   expected gain with confidence, risk, and effort.
4. Capacity model with assumptions and sensitivity to the largest unknown.
5. Premature-optimization list and the evidence threshold that would revisit it.
6. Benchmark/load commands run, artifacts produced, and regression tests needed.
