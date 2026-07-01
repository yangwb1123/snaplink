# Stage 07: Sprint Planning

## Roles Active
Product Manager · Principal Architect · Tech Lead

## Objective
Convert confirmed review findings and approved designs into a deliverable sprint backlog.
Scope for a team of 3 engineers, 2-week sprint.
Every story must have a clear Definition of Done before planning ends.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Sprint Goal**:
{{SPRINT_GOAL}}

**Team Size**: {{TEAM_SIZE}} engineers

**Sprint Duration**: {{SPRINT_DURATION}} (e.g., 2 weeks)

**Critical + High Findings to Address**:
{{CRITICAL_HIGH_FINDINGS}}

**Architecture Output (Stage 01)**:
{{ARCHITECTURE_OUTPUT}}

**Previous Sprint Velocity**:
{{VELOCITY}}
(e.g., "delivered 24 story points last sprint")

---

## Review Tasks

### 1. Scope Validation
- Are all Critical and High findings from Stages 02-06 represented in this sprint?
- Is the sprint goal achievable given team size and sprint duration?
- Are there stories that depend on external teams or infrastructure that are not in this sprint's control?
- Is there anything in this sprint that is actually a Medium finding and could be deferred?

### 2. Story Decomposition
For each story, challenge:
- Is this the smallest increment that delivers value and can be independently deployed?
- Does this story have a clear acceptance test that can be run in CI?
- Is this story blocked by another story in the same sprint? (Minimize intra-sprint dependencies.)
- Can this story be reviewed in a single PR with < 500 lines of diff?

### 3. Risk Assessment
- Which story has the highest technical uncertainty?
- Which story has the widest potential scope expansion?
- Which story requires modifying the most existing code (regression risk)?
- Is there a spike story needed to resolve any uncertainty before committing to an estimate?

### 4. Migration & Compatibility
- Does any story require a database migration? Is it backward-compatible with the running version?
- Does any story change a public API? Is the change backward-compatible for existing clients?
- Does any story require a feature flag to enable safely?
- Is there a migration story for existing data?

### 5. Definition of Done (per story)
Every story must define:
- Acceptance tests that pass in CI
- Unit tests covering happy path and all error paths
- No new maintainability gate violations
- Structured log events for all state changes
- RED metrics exported
- Runbook updated if operational behavior changes
- `docs/error-codes.md` updated if new error codes introduced
- `docs/openapi.yaml` updated if API surface changes

---

## Required Output

### Epic

**Epic Title**: [Subsystem] — [Sprint Goal]

**Epic Goal**: 1-2 sentences.

**Epic Non-Goals**: Explicit list of what this epic will NOT address.

---

### Stories

For each story:

---

**Story [N]**: [Title]

**Type**: Feature | Bug Fix | Security Fix | Refactor | Spike | Tech Debt

**As a** [persona], **I want** [goal] **so that** [outcome].

**Acceptance Criteria**:
- [ ] Criteria 1
- [ ] Criteria 2

**Definition of Done**:
- [ ] Tests pass in CI (unit + integration + race)
- [ ] No new gate violations
- [ ] Logs and metrics verified in staging
- [ ] [Any story-specific DoD items]

**Dependencies**: [List blocked-by stories or external dependencies]

**Estimate**: [S = 1-2 days | M = 3-4 days | L = 1 week | XL = needs splitting]

**Owner**: [Engineer or TBD]

**Breaking Change Risk**: None | Low | Medium | High

**Rollback Strategy**: [How to revert if this causes an incident]

---

### Sprint Backlog Summary

| # | Story | Type | Owner | Estimate | Dependencies | Risk |
|---|-------|------|-------|----------|--------------|------|
| | | | | | | |

**Total Estimate**: [N days across N engineers]

**Sprint Capacity**: [Team size × sprint days × 0.7 focus factor]

**Fit Assessment**: Over-committed | Achievable | Under-committed

### Explicitly Deferred to Next Sprint
Stories that are important but didn't fit. Include brief justification for each deferral.

### Non-Goals for This Sprint
Things that might be requested but should not be accepted into this sprint scope.
