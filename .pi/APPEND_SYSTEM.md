# Snaplink engineering context

Read `AGENTS.md` before acting. It is the authority for engineering gates,
security invariants, architecture, and edit/verification rules.

Use these lookup documents only as needed:

- package ownership: `docs/architecture/DIRECTORY_MAP.md`;
- gate behavior and commands: `docs/agent-os/HARNESS.md` and
  `docs/agent-os/CHECKS_REGISTRY.md`;
- module acceptance criteria: `docs/agent-os/EVALUATION.md`;
- implementation playbooks: `docs/skills/`;
- feature specification: `docs/templates/feature-spec.md`.

For non-trivial work, produce a bounded specification, implement with targeted
tests and the committed root gates, then perform an independent review.
`make ci` is the handoff gate; Python harness reports are supplementary.
