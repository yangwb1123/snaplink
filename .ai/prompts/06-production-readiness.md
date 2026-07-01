# Stage 06: Production Readiness Review

## Roles Active
SRE · DevOps Engineer · QA Lead · Security Engineer

## Objective
Determine whether this subsystem can be operated safely in production.
Not "does it work?" — but "can we run it, observe it, troubleshoot it, and roll it back?"

Read `.ai/prompts/shared/review-checklists.md` (Production Readiness section) before starting.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Repository**: {{REPO_PATH}}

**Primary Files**:
{{PRIMARY_FILES}}

**Deployment Target**:
{{DEPLOYMENT_TARGET}}
(e.g., "Kubernetes 3-pod, Redis Cluster, PostgreSQL HA, Prometheus/Grafana stack")

**SLO Targets**:
{{SLO_TARGETS}}
(e.g., "99.9% availability, p99 < 200ms, error rate < 0.1%")

**Prior Stage Findings (Critical/High)**:
{{PRIOR_FINDINGS}}

---

## Review Tasks

### 1. Observability — Metrics (RED)
- Is a **Rate** metric exported for every endpoint? (requests/second)
- Is an **Error** metric exported, broken down by error code?
- Is a **Duration** histogram exported with meaningful buckets?
- Are business metrics exported? (active sessions, token issuance rate, consent grant rate)
- Are cardinality-safe labels used? (No user_id or token_id in metric labels — they explode cardinality.)

### 2. Observability — Logging
- Does every state-changing operation emit a structured log event with: `trace_id`, `span_id`, `user_id` (or `client_id`), operation name, outcome?
- Are log levels used correctly? (DEBUG = verbose, INFO = state change, WARN = recoverable error, ERROR = requires investigation)
- Are sensitive values (tokens, passwords, PII) excluded from all log lines?
- Is there a log level that can be changed at runtime without restart?

### 3. Observability — Tracing
- Are distributed trace spans created at service boundaries?
- Do span names identify the operation, not the implementation? (`token.exchange`, not `handleTokenPost`)
- Are spans propagated through async operations (goroutines, queues)?
- Are span attributes sufficient to reconstruct the request flow from the trace alone?

### 4. Health Checks
- Does `/readyz` reflect the actual readiness of this subsystem? (Not just "server is up" — is the storage layer connected and responsive?)
- Does `/livez` accurately reflect whether the process is healthy vs. deadlocked?
- Do health checks fail fast on real failure, not after a multi-second timeout?

### 5. Graceful Shutdown
- Does the subsystem complete in-flight requests before shutting down?
- Is there a maximum drain timeout that prevents indefinite hanging?
- Are background goroutines/workers cleanly stopped on SIGTERM?
- Are connections returned to pools and closed on shutdown?

### 6. Feature Flags & Canary Readiness
- Can this subsystem be enabled/disabled via configuration without redeployment?
- Can a subset of traffic be routed to the new behavior for canary validation?
- Is there a kill switch for the riskiest new behavior?
- Is the default state of any new feature flag "off" (safe) or "on" (risky)?

### 7. Rollback Plan
- What is the rollback procedure if this deploy causes incidents in production?
- Are database migrations reversible? If not, what is the "forward fix" strategy?
- Is there any state created by the new version that is incompatible with the old version?
- Is the rollback achievable within the team's RTO (Recovery Time Objective)?

### 8. Alerting
- Is there an alert that fires when error rate exceeds SLO threshold?
- Is there an alert that fires when p99 latency exceeds budget?
- Are alerts linked to a runbook?
- Do alerts fire within 5 minutes of an incident onset?

### 9. Chaos Engineering
- What is the expected behavior when Redis is unavailable for 30 seconds?
- What is the expected behavior when the database primary fails over?
- What is the expected behavior when a pod is killed mid-request?
- Have these scenarios been tested (chaos testing, failover drills)?

### 10. Security Hardening for Production
- Are all debug endpoints (`/debug/pprof`, etc.) disabled or authentication-protected in production?
- Are all internal endpoints (admin, metrics) on a separate non-public port?
- Are TLS certificates validated? No `InsecureSkipVerify: true` in production configuration?
- Are rate limits configured to prevent credential stuffing at authentication endpoints?

---

## Required Output

### Release Checklist
A go/no-go checklist that must be signed off before deploying to production.
Mark each item: PASS | FAIL | N/A | NEEDS WORK

### SLO/SLI Definition

| Signal | SLI | SLO |
|--------|-----|-----|
| Availability | 1 - (error_rate) | ≥ 99.9% |
| Latency | p99 response time | < 200ms |
| Correctness | token validation success rate | ≥ 99.99% |

### Runbook (Top 3 Scenarios)
For each:
1. **Symptom**: What the operator sees
2. **Diagnosis**: Commands to run to confirm
3. **Remediation**: Steps to resolve
4. **Escalation**: Who to page if unresolved in 15 minutes

### Rollback Plan
Step-by-step procedure. Time estimate per step. Who executes.

Produce findings using `.ai/prompts/shared/output-format.md`.
Sort: Critical → High → Medium → Low → Info.

Conclude with the Stage Summary Block.
