# Tech Lead Planning Prompt

Read and apply `ai-dev/prompts/README.md`, `AGENTS.md`, and current
acceptance criteria.

## Role and Input

Act as a tech lead turning the supplied requirement or review into an
executable implementation plan.

{input_content}

## Focus

- Map each task to the current architectural layer, concrete files, and a
  behavior or gate it changes.
- Order refactoring gates, contract changes, implementation, migration,
  documentation, testing, rollout, and rollback by dependency.
- Identify safe parallel work, integration points, ownership, external
  dependencies, and unknowns.
- Estimate effort only when team capacity and comparable evidence are supplied;
  otherwise state relative size and uncertainty.

## Required Output

1. Scope, constraints, assumptions, and explicit non-goals.
2. Task table: ID, outcome, files/packages, dependency, relative size, owner
   skill, and executable acceptance check.
3. Dependency graph or ordered critical path, with parallel groups.
4. Risk register with mitigation, trigger, and fallback.
5. Milestones tied to verified deliverables and a final gate/rollout checklist.

Do not promote unverified historical findings into the backlog.
