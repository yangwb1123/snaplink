# AI-SDLC role index

`ai-dev/` provides two complementary prompt sets:

| Mode | Files | Use |
|---|---|---|
| Pipeline roles | `ai-dev/prompts/*.md` | Individual expert or implementation tasks composed by `ai-dev/pipelines/*.yaml` |
| Staged reviews | `ai-dev/ai/prompts/*.md` | Ten end-to-end review stages run by `ai-dev/ai/run-review.py` |

The staged framework's shared role definitions live in
[`../ai/prompts-shared/role-definitions.md`](../ai/prompts-shared/role-definitions.md).
The pipeline set adds a dedicated code implementer, giving it 18 templates
instead of 17 review-only roles.

## Select only the needed roles

| Concern | Roles |
|---|---|
| Product and scope | Product Manager, Business Analyst, UX Designer |
| Architecture and decisions | Architect, CTO, Tech Lead, Principal Reviewer |
| Security and protocols | Security Engineer, Protocol Expert, Compliance Officer |
| Implementation quality | Code Implementer, Staff Engineer, QA Lead |
| Data and distributed behavior | Database Architect, Distributed Systems Engineer |
| Operations and scale | SRE, DevOps, Performance Engineer |

Example:

```bash
python ai-dev/pi-batch.py \
  --pipeline ai-dev/pipelines/pipeline-code-impl.yaml \
  --dry-run
```

Pipelines aggregate upstream outputs per role template when a stage sets
`aggregate: true`, and post-stage command failures now fail the run with a
non-zero exit. Inspect long pipelines with `--dry-run` first; invoke a
bounded role independently and run repository checks directly before treating
any result as implementation evidence.

## Boundary

Role and stage output is advisory. It becomes a project requirement only after
verification against current code and promotion into
`docs/feature-matrix.md`, `docs/deferred-backlog.md`, `docs/ROADMAP.md`,
OpenAPI, or an approved feature specification.

Snaplink is an API backend. UI findings target the separate frontend projects.
Executable tests, `AGENTS.md`, and the current contract documents override
prompt output.

See [`AUTOMATION_WORKFLOW_SUMMARY.md`](AUTOMATION_WORKFLOW_SUMMARY.md) for the
runner workflow and [`../ai/README.md`](../ai/README.md) for staged reviews.
