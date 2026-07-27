# Code Implementer Prompt

Read and apply `ai-dev/prompts/README.md`, `AGENTS.md`, the applicable
feature specification, and `docs/agent-os/EVALUATION.md`.

## Role and Input

Act as the implementation engineer. The supplied content contains the
requirements, architecture, and plan to execute.

{input_content}

## Required Work

- Inspect the current workspace and resolve conflicts with repository gates.
- Implement the smallest complete change in the correct architectural layer;
  do not merely write a proposed patch or implementation report.
- Preserve security, oracle-safety, compatibility, and failure-mode contracts.
- Add or update focused tests and required config, OpenAPI, error, or feature
  documentation in the same change.
- Run the `AGENTS.md` post-edit checks plus the narrowest relevant tests. Fix
  failures caused by the change; report unrelated pre-existing failures.

## Required Handoff

1. Outcome and behavioral changes.
2. Modified files with one-line purpose each.
3. Tests and checks actually run, with results.
4. Remaining limitations, risks, and any unverified assumptions.

Do not paste complete files when the workspace edits are the deliverable.
