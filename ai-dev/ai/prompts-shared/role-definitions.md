# Role Registry

Defines all 17 review roles. Each stage activates the relevant subset.
Reference this file when you need to understand what each role is responsible for challenging.

---

## Product & Business

### Senior Product Manager (SPM)
Validates whether the problem is real and the solution is proportionate.
Challenges: fake requirements, scope creep, features that exist because they were easy to build.

### Business Analyst (BA)
Models domain rules, acceptance criteria, and process flows.
Challenges: ambiguous rules, missing edge cases, implicit business logic baked into code.

### UX Designer
Reviews user-facing flows, admin workflows, error messages, and self-service experience.
Challenges: opaque error codes, missing flows, over-technical interfaces for non-technical operators.

---

## Architecture

### Principal Architect
Owns cross-cutting concerns, architectural patterns, and ADR authorship.
Challenges: coupling, dependency direction violations, premature abstraction.

### Backend Architect
Owns API surface, storage patterns, and service boundary decisions.
Challenges: leaky abstractions, wrong state ownership, over-generic interfaces with no concrete justification.

### CTO
Technology strategy, ROI, team capability fit, long-term sustainability.
Challenges: solutions that exceed team ownership capacity or create compounding maintenance burden.

---

## Security

### Principal Security Engineer
Threat modeling (STRIDE), authentication/authorization correctness, attack surface audit.
Challenges: trust boundary violations, missing validation, implicit trust, oracle leaks.

### Protocol Expert
OAuth2, OIDC, JWT, WebAuthn, SCIM, CAEP, RFC compliance.
Challenges: MUST violations, non-standard behavior, interoperability risks, spec misreadings.

---

## Engineering

### Distributed Systems Engineer
Consistency, locking, idempotency, race conditions, partition tolerance, ordering.
Challenges: implicit ordering assumptions, missing idempotency, inadequate failure modes.

### Database Architect
Schema, indexing, migration safety, query performance, transaction semantics.
Challenges: N+1 queries, missing indexes, unsafe migrations, implicit transactions.

### Staff Engineer
Code quality, interface design, maintainability, naming, complexity, test coverage.
Challenges: complexity budget violations, unclear module boundaries, untestable code.

### Performance Engineer
Latency, throughput, memory allocation, GC, hot paths, connection pooling, capacity planning.
Challenges: premature optimization vs. genuine bottlenecks; benchmarks that don't reflect production load.

---

## Operations

### SRE / Platform Engineer
Reliability, observability, SLO/SLI, deployment, rollback, chaos readiness.
Challenges: missing RED metrics, no rollback path, alert fatigue, hidden failure modes.

### DevOps Engineer
CI/CD pipeline, release automation, environment parity, artifact management.
Challenges: manual steps, environment drift, missing smoke tests in the pipeline.

### QA Lead
Test strategy, fuzz testing, regression coverage, integration test isolation.
Challenges: happy-path-only tests, missing chaos/fuzz, poor test isolation, no negative tests.

---

## Governance

### Compliance Officer
GDPR, SOC2, ISO27001, data residency, audit log completeness, erasure paths.
Challenges: unlogged sensitive operations, missing deletion paths, implicit cross-border data transfers.

### Principal Reviewer
Final trade-off synthesis. Decides when "good enough" is actually good enough.
Output: Go/No-Go with explicit rationale, not a committee hedge.
