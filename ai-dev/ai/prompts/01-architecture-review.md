# Stage 01: Architecture Review

**Roles:** Principal Architect, Backend Architect, and CTO.

Read `ai-dev/ai/prompts-shared/{engineering-principles,role-definitions,output-format}.md`.
Use `docs/architecture/DIRECTORY_MAP.md` for current package ownership; treat
dated plans as historical evidence.

## Decision

Approve, reshape, or reject the proposed boundaries and state ownership.
Prefer the smallest design that satisfies verified Stage 00 requirements.

## Inputs

- Project: {{PROJECT_NAME}}
- Subsystem: {{SUBSYSTEM}}
- Repository: {{REPO_PATH}}
- Primary files: {{PRIMARY_FILES}}
- Proposed architecture: {{ARCHITECTURE_SUMMARY}}
- Stage 00 output: {{PRODUCT_DISCOVERY_OUTPUT}}

## Review

- Give the subsystem one responsibility and identify overlapping owners.
- Trace proposed imports against the canonical layer map and gate tests.
- Justify each public API, SPI, implementation, and configuration option from a
  current use case; flag broad `Deps` interfaces and speculative abstraction.
- Name the authoritative writer and durability requirement for every state
  type, including atomicity, invalidation, restart, and multi-replica behavior.
- Verify external dependencies sit behind appropriate ports and that real
  memory/durable implementations and deterministic tests are possible.
- Check placement, build impact, migration compatibility, and applicable
  engineering gates without restating their numeric thresholds.

## Output

1. Findings in the shared format.
2. A proposed ADR: title, status, context, decision, consequences, risks, and
   at least two considered alternatives with rejection reasons.
3. A minimal package tree plus incoming/outgoing import map; flag cycles.
4. Public API/SPI signatures only, with compatibility and ownership notes.
5. State-ownership table: `State | Writer | Store | Consistency | Recovery`.
6. Recommendation: **Approve**, **Approve with Changes**, **Redesign**, or
   **Reject**, with exact preconditions.
