# Stage 04: Implementation Review

**Roles:** Staff Engineer and Tech Lead.

Read `ai-dev/ai/prompts-shared/{engineering-principles,review-checklists,output-format,role-definitions}.md`.
Use the configured and committed gate implementations as evidence; report
their drift instead of choosing the weaker result.

## Decision

Determine whether the reviewed code is maintainable, testable, and consistent
with package contracts, then provide the smallest safe refactoring plan.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Repository: {{REPO_PATH}}
- Primary files: {{PRIMARY_FILES}}
- Prior Stage 01–03 findings: {{PRIOR_FINDINGS}}

## Review

- Run applicable build, vet, test, architecture, and maintainability checks;
  evaluate thresholds from their authoritative sources.
- Review package/file cohesion, dependency direction, public surface, `Deps`
  design, implementation guards, naming, comments, and literal ownership.
- Trace every error boundary and observable response; preserve the documented
  oracle-safe behavior and retry semantics.
- Confirm state changes have bounded-cardinality observability without
  credentials or sensitive personal data.
- Inspect happy, negative, race, integration, and invariant tests; prefer real
  memory implementations where provided and distinguish executed from inferred.
- Locate dead code, deferred refactors, unsafe shortcuts, and documentation or
  contract drift introduced by the change.

## Output

1. Findings in the shared format.
2. Gate report: `Check | Command/source | Result | Evidence | Required action`.
3. For violations in scope, list file/function, measured value, governing
   threshold, and exemption status.
4. Refactoring plan: `Target | Extraction/change | Destination | Tests | Effort`.
5. Final proposed interface signatures only, when an interface must change.
6. Technical-debt table with severity, owner, explicit disposition, and reason.
7. Recommendation and unresolved merge blockers.
