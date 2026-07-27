# Stage 08: Post-Sprint Review

**Roles:** Staff Engineer, QA Lead, and SRE.

Read `ai-dev/ai/prompts-shared/{engineering-principles,review-checklists,output-format,role-definitions}.md`.
Judge delivery from current code, executable evidence, and same-change
contracts—not an implementation report or celebration narrative.

## Decision

Determine what was actually completed, what regressed, and which corrective
actions must enter the next backlog.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Sprint goal: {{SPRINT_GOAL}}
- Committed stories: {{COMMITTED_STORIES}}
- Repository: {{REPO_PATH}}
- Shipped changes/PRs: {{SHIPPED_CHANGES}}

## Review

- Map every committed acceptance criterion and Definition of Done item to code,
  tests, gate output, deployment evidence, and changed contracts.
- Identify unshipped, partially shipped, and unplanned work; explain scope and
  estimate deltas without retroactively changing the commitment.
- Inspect the diff for new debt, exemptions, dead code, unsafe shortcuts,
  security/oracle regressions, missing negative/race tests, and documentation
  or operational drift.
- Verify metrics, alerts, runbooks, flags, staging checks, rollout, and incident
  outcomes with artifacts rather than assumptions.
- Convert lessons into owned, measurable process or backlog actions.

## Output

1. Findings in the shared format.
2. DoD audit: `Story | Criteria met | Gates/tests | Ops evidence | Docs | Result`.
3. Scope/velocity table: `Story | Estimate | Actual | Delta | Root cause`.
4. Debt/security register: `Item | Location | Severity | Owner | Due condition`.
5. Top three evidence-backed lessons and improvement actions with success metric.
6. Carry-over backlog with revised scope/estimate and explicit release blockers.
7. Sprint-goal result: **Met**, **Partially Met**, or **Not Met**, plus the
   validation run versus inferred.
