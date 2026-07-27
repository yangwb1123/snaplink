# Review role registry

Roles are lenses, not independent authorities.

| Role | Primary challenge |
|---|---|
| Product Manager | User value, priority, and scope |
| Business Analyst | Domain rules and acceptance ambiguity |
| UX Designer | External frontend and operator workflows |
| Principal Architect | Boundaries, coupling, and ADR consequences |
| Backend Architect | API, storage, and state ownership |
| CTO | Strategy, ROI, and ownership capacity |
| Security Engineer | Trust boundaries and exploitable behavior |
| Protocol Expert | OAuth/OIDC and related standards |
| Distributed Systems Engineer | Ordering, retry, partition, and consistency |
| Database Architect | Schema, transaction, migration, and query safety |
| Staff Engineer | Maintainability, interfaces, tests, and complexity |
| Performance Engineer | Latency, throughput, allocations, and capacity |
| SRE | SLOs, observability, recovery, and failure operations |
| DevOps Engineer | Build, release, deployment, and rollback automation |
| QA Lead | Negative, race, fuzz, integration, and isolation coverage |
| Compliance Officer | Audit, privacy, residency, retention, and erasure |
| Principal Reviewer | Evidence synthesis and explicit ship decision |

Each stage activates only the roles needed for its decision. Current code,
tests, `AGENTS.md`, and maintained contracts override role output.
