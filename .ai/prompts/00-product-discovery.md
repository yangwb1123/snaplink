# Stage 00: Product Discovery

## Roles Active
Senior Product Manager · Business Analyst · UX Designer (if UI-facing)

## Objective
Determine whether this feature deserves to be built at all.
Reject fake requirements before engineering work begins.
Define the smallest viable scope.

Do not propose an implementation. Do not review code. Do not discuss architecture.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem / Feature**: {{SUBSYSTEM}}

**Proposed Description**:
{{FEATURE_DESCRIPTION}}

**Stated Business Justification**:
{{BUSINESS_JUSTIFICATION}}

**Target Personas**:
{{TARGET_USERS}}

**Observable Pain Point / Evidence**:
{{PAIN_POINT_EVIDENCE}}

**Comparable Implementations (optional)**:
{{COMPARABLE_IMPLEMENTATIONS}}

---

## Review Tasks

### 1. Problem Validation
- Is there observable evidence (user complaints, compliance mandates, operational burden) that this problem exists, or is it hypothetical?
- What is the cost of NOT solving this? (user loss, compliance risk, support volume)
- Could an existing feature solve this with minor configuration or documentation?
- Is the problem scoped tightly enough to build a targeted solution?

### 2. Requirement Quality
- Are stated requirements testable? (If you cannot write an acceptance test, the requirement is incomplete.)
- What hidden requirements are buried in the description? (performance, concurrency, audit trail, backward compatibility, migration path)
- Are there anti-requirements — things that must NOT happen?
- Do any requirements exist only because "other systems have them" with no stated business need?

### 3. Scope & MVP Analysis
- What is the minimal version that delivers measurable user value?
- What can be deferred to a follow-up sprint without blocking the core use case?
- What is likely to be requested but is actually premature optimization?
- What should be explicitly declared out of scope and never built?

### 4. Simplification Challenge
- Could this be solved with a configuration option rather than new code?
- Could this be solved by improving documentation rather than adding features?
- Could this be solved by composing existing subsystems rather than building a new one?
- What is the maintenance burden of this feature in 3 years with a team that did not build it?

### 5. UX Review (if user-facing)
- What happens when the feature fails? Is the error message actionable for the end user?
- Can a non-technical operator configure and monitor this without reading source code?
- Does this require changes to admin portal, developer documentation, or onboarding?

---

## Required Output

### Problem Statement
2-3 sentences. What is the real problem? Why does it matter now?

### User Stories
Format: "As a [persona], I want [goal] so that [outcome]."
Label each: **MVP** | **Future** | **Reject**

### Business Rules
Explicit invariants the implementation must enforce. Numbered list.

### Acceptance Criteria
Testable conditions. Each criterion maps to one User Story.

### MVP Scope
**IN** (ships in this sprint):
**OUT** (explicitly deferred):
**NEVER** (will not be built regardless of requests):

### Risk Register
What could go wrong even if the implementation is technically correct?

### Recommendation
**Build Now** | **Build Later** | **Simplify First** | **Reject**
Explain in 2-3 sentences.
