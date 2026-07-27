# Shared Rules for Role Prompts

These rules apply to every role prompt in this directory. Role-specific
instructions narrow the review; they do not replace this baseline.

## Authority and Scope

1. Follow the user request and repository `AGENTS.md` hard gates.
2. Establish current behavior from executable code, configuration, tests, and
   build/deployment assets.
3. Use canonical references such as `docs/architecture/DIRECTORY_MAP.md`,
   `docs/feature-matrix.md`, `docs/config-reference.md`, `docs/error-codes.md`,
   and `docs/openapi.yaml` for navigation and declared contracts.
4. Treat roadmaps, generated reports, and historical plans as proposals until
   current implementation or tests verify them.
5. Report conflicts between sources; never silently choose the weaker rule.

Snaplink is an API-only backend. Distinguish the reusable SDK, stock
`sso-server` wiring, independently built nested modules, and external frontend
projects. An SPI or implementation existing in the tree does not prove that
the stock binary exposes it.

## Evidence Standard

- Label material claims as **Verified**, **Partial**, **Missing**, **Proposed**,
  or **Unknown**.
- Cite repository paths plus a symbol, test, configuration key, or command
  result whenever available.
- State which checks actually ran for the reviewed revision; do not turn a
  documented command, old result, or presence-only scan into passing evidence.
- Do not invent benchmarks, SLOs, deadlines, staffing, compliance scope,
  certification, or support status. Mark missing inputs as unknown.
- Separate observed facts from inference and recommendation.

## Severity

| Level | Use when |
|---|---|
| Critical | A verified exploit, data-loss path, hard-gate violation, or release blocker exists |
| High | A likely material security, correctness, interoperability, or availability failure exists |
| Medium | A bounded weakness or maintainability/operability gap needs planned work |
| Low | A low-risk improvement has clear value |
| Info | Context, uncertainty, or a suggestion without a demonstrated defect |

## Findings and Decisions

- Sort findings by severity and include evidence, impact, recommendation, and
  an executable validation step.
- If no supported finding exists, say so and list the remaining evidence gaps.
- Distinguish required fixes from optional improvements and explicit non-goals.
- Review roles produce advisory analysis only. They do not approve releases,
  bind maintainers, or modify files unless their prompt explicitly says to
  implement changes.
