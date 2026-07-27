# Stage 09: CTO Executive Review

**Roles:** CTO and Principal Reviewer.

Read `ai-dev/ai/prompts-shared/{output-format,role-definitions}.md`. Synthesize
prior evidence; do not repeat the technical reviews. Separate SDK, stock
binary, nested module, and external frontend readiness. Protocol coverage is
not certification without current published conformance evidence.

## Decision

Make one strategic ship/investment decision with named conditions and owners.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Prior findings summary: {{ALL_PRIOR_FINDINGS_SUMMARY}}
- Open findings: {{CRITICAL_COUNT}} Critical; {{HIGH_COUNT}} High
- Team size: {{TEAM_SIZE}}
- Age in codebase: {{AGE}}

| Stage | Grade |
|---|---|
| 00 Product | {{GRADE_00}} |
| 01 Architecture | {{GRADE_01}} |
| 02 Security/protocol | {{GRADE_02}} |
| 03 Distributed systems | {{GRADE_03}} |
| 04 Implementation | {{GRADE_04}} |
| 05 Performance | {{GRADE_05}} |
| 06 Production readiness | {{GRADE_06}} |

## Five Questions

Answer each **Yes** or **No**, followed by one evidence-backed sentence:

1. Should this be built or shipped now?
2. Is it appropriately scoped rather than over-engineered?
3. Is it maintainable for at least five years?
4. Can the supplied team own its feature, security, integration, and on-call load?
5. Does expected value justify build and continuing ownership cost?

## Output

1. Choose exactly one: **Approve**, **Approve with Simplification**,
   **Redesign**, **Delay**, or **Reject**.
2. State release scope, evidence, unresolved Critical/High findings, mandatory
   preconditions, owner, and decision expiry/review date.
3. Top ten next-30-day priorities: rank, owner, outcome, dependency.
4. Top ten 12-month risks: likelihood, impact, trigger, mitigation.
5. Explicit non-goals and 12-month roadmap/options affected by the decision.
6. Validation performed versus inherited or missing evidence.
