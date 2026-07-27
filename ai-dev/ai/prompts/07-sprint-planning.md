# Stage 07: Sprint Planning

**Roles:** Product Manager, Principal Architect, and Tech Lead.

Read `ai-dev/ai/prompts-shared/{engineering-principles,role-definitions}.md`.
Only schedule requirements accepted in `docs/feature-matrix.md`,
`docs/deferred-backlog.md`, or an explicitly approved current feature spec.
Historical reviews supply candidates, not backlog authority.

## Decision

Build a deliverable backlog around one sprint goal, respecting actual capacity
and making every story independently verifiable and reversible.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Sprint goal: {{SPRINT_GOAL}}
- Team size: {{TEAM_SIZE}}
- Sprint duration: {{SPRINT_DURATION}}
- Accepted Critical/High findings: {{CRITICAL_HIGH_FINDINGS}}
- Stage 01 architecture: {{ARCHITECTURE_OUTPUT}}
- Previous velocity/evidence: {{VELOCITY}}

## Planning Rules

- Confirm scope authority, urgency, dependencies, owners, and the evidence
  needed to close every accepted Critical/High finding.
- Split work into the smallest independently testable/deployable increments;
  use a time-boxed spike when uncertainty prevents a responsible estimate.
- Sequence architecture, compatible migration, implementation, negative/race
  tests, contract docs, observability, rollout, and rollback work.
- Derive each Definition of Done from `AGENTS.md` and changed contracts; do not
  copy generic checklist items that do not apply.
- Reserve capacity for review, integration, incidents, and unknowns; expose
  over-commitment rather than silently deferring required work.

## Output

1. Epic title, goal, measurable outcome, and explicit non-goals.
2. Story table:

   | # | User value/finding | Acceptance evidence | DoD | Owner | Estimate | Dependencies | Risk/rollback |
   |---|---|---|---|---|---|---|---|

3. For each story, list exact acceptance tests and contract/document changes.
4. Dependency order and critical path; identify externally blocked work.
5. Capacity calculation using supplied team, duration, and velocity, followed
   by **Over-committed**, **Achievable**, or **Under-committed**.
6. Explicit deferrals with reason, owner, target condition, and risk accepted.
