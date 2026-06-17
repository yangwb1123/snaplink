# Engineering System

This project has a formal engineering system. Read these files:
- HARNESS.md -- Gate specification
- BOOTSTRAP.md -- Project context
- ARCHITECTURE.md -- Package map
- EVALUATION.md -- Acceptance criteria per module type
- CHECKS_REGISTRY.md -- All checks
- AGENTS.md -- Full agent behavior rules

## Agent Roles

For non-trivial features, follow this workflow:

```
Architect Agent -> feature-spec.md
     |
Implement Agent -> code + make acceptance
     |
Reviewer Agent  -> bash .check-review-feature.sh
```

### Architect Agent
Read: `.pi/prompts/architect.md`
Output: `docs/feature-spec-<name>.md`

### Implement Agent
Read: `.pi/prompts/implement.md`
Input: `docs/feature-spec-<name>.md`
Gate: `make acceptance`

### Reviewer Agent
Read: `.pi/prompts/review.md`
Verify: `bash .check-review-feature.sh docs/feature-spec-<name>.md`

## Required Workflow
1. **After every edit:** `python cli.py check` (filesize + vet)
2. **Before every commit:** `python cli.py accept` (full evaluation suite)
3. **Before every push:** `python cli.py harness` (full gates)
4. **For features:** Architect -> Implement -> Review cycle
5. **For refactors:** skills/ (split, refactor, oracle-leak, etc.)
