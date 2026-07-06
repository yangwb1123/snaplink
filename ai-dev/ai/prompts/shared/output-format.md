# Standard Output Format

All review stages produce findings in this format.
Every finding must be independently verifiable — evidence first, not assertion first.
Do not produce findings you cannot substantiate with evidence from the provided code or spec.

---

## Finding Block

**Category**: Security | Architecture | Protocol | Performance | Reliability | ROI | Compliance | Distributed

**Severity**: Critical | High | Medium | Low | Info

**Title**: One sentence, present tense, names the flaw specifically.

**Affected Files**: Repo-relative paths with line ranges where applicable.

**Evidence**: Exact code snippet, config value, or protocol excerpt. Do not paraphrase. Quote the line.

**Root Cause**: Why does this exist? (Incorrect assumption, missing validation, wrong abstraction, spec misread.)

**Failure Scenario**: Concrete steps to trigger in production. Include specific inputs, states, or timing. No hypotheticals without mechanistic justification.

**Production Impact**: What breaks, for how many users, how visibly? Is this data loss, auth bypass, unavailability, or silent degradation?

**Likelihood**: Certain | Likely | Possible | Unlikely | Theoretical

**RFC / Standard Reference**: RFC number + section. Omit if not applicable.

**Recommended Fix**: Specific change — code, config, or design. Not "consider improving."

**Estimated Effort**: Hours | 1-2 days | 1 week | 1 sprint | Multiple sprints

**Breaking Change Risk**: None | Low | Medium | High

---

## Severity Definitions

| Level | Criteria |
|-------|----------|
| Critical | Exploitable now; blocks merge; data at risk or auth bypass possible |
| High | Exploitable with moderate effort, or will fail under realistic production load |
| Medium | Design flaw that degrades reliability, security posture, or maintainability over time |
| Low | Code quality issue with no direct security or reliability impact |
| Info | Observation worth tracking; no immediate action required |

---

## Stage Summary Block

Conclude every stage with:

**Overall Grade**: A | B | C | D | F

**Engineering Readiness**:
Production Ready | Needs Minor Fixes | Needs Refactoring | Needs Security Fixes | Needs Redesign | Reject

**Critical Finding Count**: [N Critical, N High]

**Should this ship?**: Yes | No | Conditional — (state the condition)

**Must fix before merge**: Bulleted list of Critical/High finding titles.

**Can wait for next sprint**: Bulleted list of Medium finding titles.

**Explicitly out of scope going forward**: Things that should NOT be added even if requested.
