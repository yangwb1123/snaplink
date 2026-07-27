# Stage 06: Production Readiness Review

**Roles:** SRE, DevOps Engineer, QA Lead, and Security Engineer.

Read `ai-dev/ai/prompts-shared/{engineering-principles,review-checklists,output-format,role-definitions}.md`.
Snaplink is API-only; include the reverse proxy and separately deployed
frontend when the reviewed journey depends on them.

## Decision

Make an evidence-based production go/no-go decision: can operators observe,
degrade, recover, roll back, and safely support this subsystem?

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Repository: {{REPO_PATH}}
- Primary files: {{PRIMARY_FILES}}
- Deployment target/topology: {{DEPLOYMENT_TARGET}}
- SLO targets: {{SLO_TARGETS}}
- Prior Critical/High findings: {{PRIOR_FINDINGS}}

## Review

- Map runtime components, enabled stateful features, dependencies, secrets,
  traffic boundaries, ownership, and deployment artifacts.
- Verify SLI instrumentation, readiness/liveness, cardinality-safe telemetry,
  sensitive-data handling, alerts, dashboards, and trace continuity.
- Exercise startup, drain, cancellation, dependency loss, capacity exhaustion,
  failover, backup/restore, key rotation, and cross-replica recovery.
- Validate rollout, canary/kill switch, schema compatibility, rollback or
  forward-fix, configuration defaults, image/dependency pinning, and TLS.
- Require executable evidence for staging, fault injection, restore drills, and
  unresolved prior findings; an available runbook is not proof of a drill.

## Output

1. Findings in the shared format.
2. Release checklist: `Item | PASS/FAIL/N/A/NEEDS WORK | Evidence | Owner`.
3. SLO table: `User signal | SLI formula/source | Target/window | Alert`.
4. Top three runbooks, each with symptom, diagnosis commands, remediation,
   verification, rollback boundary, and escalation owner.
5. Ordered rollout and rollback/forward-fix procedures with time estimates.
6. Validation performed versus still required, residual risks, and a precise
   **Go**, **Conditional Go**, or **No-Go** decision.
