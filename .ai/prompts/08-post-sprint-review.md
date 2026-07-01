# Stage 08: Post-Sprint Review

## Roles Active
Staff Engineer · QA Lead · SRE

## Objective
Determine whether the sprint actually delivered what was committed.
Identify new technical debt introduced.
Extract lessons that improve the next sprint.
Do not celebrate — assess honestly.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Sprint Goal**:
{{SPRINT_GOAL}}

**Committed Stories (from Stage 07)**:
{{COMMITTED_STORIES}}

**Repository**: {{REPO_PATH}}

**Changes Shipped** (git log or PR list):
{{SHIPPED_CHANGES}}

---

## Review Tasks

### 1. Definition of Done Audit
For each committed story:
- Was the acceptance criteria demonstrably met?
- Do all tests pass, including race tests (`go test -race -count=10`)?
- Are there any gate violations introduced? (Run: `go test -run 'TestMaintainability_|TestArchitecture_' .`)
- Were structured logs and metrics verified in staging, or only assumed?
- Were `docs/error-codes.md` and `docs/openapi.yaml` updated if required?

### 2. Scope Delta
- What was committed but NOT shipped? Why?
- What was shipped that was NOT committed? (Scope creep — is it justified?)
- Were any stories partially completed and merged in an incomplete state?
- Were any tests skipped to hit a deadline?

### 3. New Technical Debt
- List every shortcut explicitly taken during the sprint.
- For each: is it acceptable to leave until next sprint? Or does it create a compounding maintenance burden?
- Are there any `TODO` comments added? (Per convention, these should not exist — flag them.)
- Did any code violate the "no mocks where Memory* exists" rule?
- Were any error codes hardcoded instead of added to `consts.go`?

### 4. Security Regressions
- Were any oracle-leak protections weakened or bypassed?
- Were any new endpoints added without `tokenNoStoreHeaders` or cache-control headers?
- Were any new error messages added that reveal state information they shouldn't?
- Were any new inbound URLs or redirects added without pre-registration validation?

### 5. Test Coverage Delta
- What is the coverage delta for the subsystem?
- Are there new code paths with no test?
- Did any integration test require mocking instead of using `Memory*`?
- Were race conditions tested with sufficient `-count`?

### 6. Operational Readiness Delta
- Were all metrics and alerts deployed alongside the feature?
- Was the runbook updated before or after the deploy?
- Was there a staging validation step before production deploy?
- Were any feature flags used? Are they set to the correct default?

### 7. Lessons Learned
- What slowed the sprint down unexpectedly?
- What assumption turned out to be wrong?
- What would you do differently if starting this sprint over?
- What process improvement would have the highest leverage for the next sprint?

---

## Required Output

### DoD Audit Table

| Story | DoD Met | Gates Pass | Logs/Metrics | Docs Updated | Notes |
|-------|---------|------------|--------------|--------------|-------|
| | Yes/No/Partial | Yes/No | Yes/No | Yes/No | |

### New Technical Debt Register

| Item | File | Severity | Introduced By | Target Sprint |
|------|------|----------|---------------|---------------|
| | | High/Med/Low | | |

### Security Regression Report
List any security invariants weakened. For each: severity, file, recommended fix.

### Velocity Actuals vs. Estimate
| Story | Estimated | Actual | Delta | Root Cause |
|-------|-----------|--------|-------|------------|
| | | | | |

### Top 3 Lessons Learned
1. [Lesson — specific and actionable]
2. [Lesson — specific and actionable]
3. [Lesson — specific and actionable]

### Improvement Actions for Next Sprint
| Action | Owner | Success Metric |
|--------|-------|----------------|
| | | |

### Carry-Over to Next Sprint Backlog
Stories or tasks that were not completed, with updated estimates.
