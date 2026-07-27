# Stage 02: Security and Protocol Review

**Roles:** Security Engineer and Protocol Expert.

Read every file in `ai-dev/ai/prompts-shared/`. Verify current code, tests,
contracts, and the cited standards. Implemented protocol features are not OIDF
certification; only published, applicable conformance results support that
claim.

## Decision

Identify exploitable behavior and standards violations. Shipping is not
approved while an evidence-backed Critical or High finding remains unresolved.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Repository: {{REPO_PATH}}
- Primary files: {{PRIMARY_FILES}}
- Applicable standards: {{RFC_REFERENCES}}
- Stage 01 output: {{ARCHITECTURE_OUTPUT}}

## Review

- Establish assets, actors, trust boundaries, attacker capabilities, and the
  delivery surface before assessing controls.
- For each applicable normative requirement, trace request parsing,
  authentication, authorization, state transition, response, and audit paths.
- Exercise credential oracles, enumeration and timing, replay, scope/tenant
  escalation, session fixation, concurrency, and malformed-token cases.
- Check algorithm/claim/key handling, redirect and outbound URL validation,
  proxy trust, body limits, injection surfaces, and secret/PII exposure against
  the maintained contracts referenced by the shared principles.
- Test failure modes and recovery, not only happy paths; distinguish missing
  evidence from a verified pass.

## Output

1. Findings in the shared format, sorted by severity.
2. RFC matrix:

   | Standard/section | Normative requirement | Status | Evidence | Gap |
   |---|---|---|---|---|

3. STRIDE table:

   | Category | Concrete threat | Existing mitigation | Residual gap |
   |---|---|---|---|

4. Trust-boundary diagram or ordered data-flow description.
5. Tests run, tests required, published conformance evidence (if any), and a
   precise ship condition.
