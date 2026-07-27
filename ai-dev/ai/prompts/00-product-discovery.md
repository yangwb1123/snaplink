# Stage 00: Product Discovery

**Roles:** Product Manager, Business Analyst, and UX Designer when a user
journey is affected. Read `ai-dev/ai/prompts-shared/role-definitions.md`.

## Decision

Decide whether a demonstrated problem merits work now and define the smallest
valuable scope. Classify the delivery surface as SDK, stock binary, nested
module, or external frontend; Snaplink itself is API-only. Do not design the
implementation or review code in this stage.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Proposed feature: {{FEATURE_DESCRIPTION}}
- Business justification: {{BUSINESS_JUSTIFICATION}}
- Target users: {{TARGET_USERS}}
- Pain-point evidence: {{PAIN_POINT_EVIDENCE}}
- Comparable implementations: {{COMPARABLE_IMPLEMENTATIONS}}

## Review

- Separate observed user, compliance, and operational needs from assumptions.
- Compare the request with current scope in `docs/feature-matrix.md` and
  `docs/deferred-backlog.md`; identify configuration or documentation answers.
- Make each requirement testable, expose hidden constraints and
  anti-requirements, and identify dependencies outside this repository.
- Minimize the MVP; reject speculative extensibility and state the long-term
  ownership cost.
- For user-facing work, cover failure, onboarding, accessibility, and the
  separately deployed frontend/operator workflow.

## Output

1. Surface classification and a two-sentence evidence-backed problem statement.
2. User stories in a `Story | Persona | Outcome | MVP/Future/Reject` table.
3. Numbered business rules and acceptance criteria mapped to each MVP story.
4. Scope lists: `IN`, `OUT`, and `NEVER`, with rationale.
5. Evidence gaps, product/operational risks, success metrics, and owner.
6. One recommendation: **Build Now**, **Build Later**, **Simplify First**, or
   **Reject**, including the condition that would change it.
