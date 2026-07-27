# AI-SDLC staged reviews

This optional framework fills project context into ten review prompts and
invokes a `pi`-compatible agent. It supplements executable tests; it is not a
scanner, requirements source, or release gate.

For Snaplink, read `AGENTS.md` and
`docs/architecture/DIRECTORY_MAP.md`. Product claims must be verified against
current code, `docs/feature-matrix.md`, and `docs/deferred-backlog.md`. UI work
belongs to separately deployed frontend projects.

## Stages

| Stage | Focus |
|---|---|
| 00 | Product discovery |
| 01 | Architecture |
| 02 | Security and protocol compliance |
| 03 | Distributed systems |
| 04 | Implementation quality |
| 05 | Performance |
| 06 | Production readiness |
| 07 | Sprint planning |
| 08 | Post-sprint review |
| 09 | CTO decision |

Run only the stages that match the decision: `02 → 04 → 06` for a pre-merge
feature review, `02 → 03 → 06` for production hardening, or one focused stage
for a specific question.

## Current runner limits

`--dry-run` reliably renders the selected prompt. Live runs currently stream
agent output to the terminal but do not persist the advertised
`stage-NN.out.md` file because the subprocess is not captured. `--all` runs
stages in order but does not inject one stage's output into the next.

Until the runner is repaired, capture output explicitly and copy any prior
finding into the context fields needed by the next stage. Exploratory review
directories are ignored by Git; promote verified conclusions into maintained
project documents instead of committing the raw corpus.

Omitted values are not all neutral: the current mapper assumes
`Redis Cluster, PostgreSQL` for storage, team size `3`, and a two-week sprint.
Override those fields or treat them as unknown rather than project facts.
The context file's `repo:` value fills the prompt only; pass `--repo /path`
explicitly to set the live agent process working directory.

## Usage

Context YAML requires PyYAML, which this repository does not install as a
managed Python dependency: `python -m pip install PyYAML`.

Render a prompt without invoking an agent:

```bash
python ai-dev/ai/run-review.py \
  --stage 02 \
  --context ai-dev/ai/examples/oidc-logout-context.yaml \
  --dry-run
```

Run one stage:

```bash
python ai-dev/ai/run-review.py \
  --stage 02 \
  --context ai-dev/ai/examples/oidc-logout-context.yaml \
  --model claude-sonnet
```

A context file may provide:

```yaml
project: Snaplink SSO
subsystem: OIDC logout
repo: /path/to/sso
files:
  - interfaces/sso/server_logout.go
rfcs:
  - OIDC RP-Initiated Logout 1.0
architecture_summary: existing design
storage: Redis and PostgreSQL
load_profile: peak and latency target
infra: deployment topology
slo_targets: availability and latency
stage_03:
  ARCHITECTURE_OUTPUT: paste verified Stage 01 output here
```

Unfilled variables are marked as not provided. Stage-specific overrides live
under `stage_NN`.

## Files

- `sdlc.yaml` — stage names and required variables;
- `prompts/` — stage templates;
- `prompts-shared/` — shared role, engineering, checklist, and output guidance;
- `examples/` — context example;
- `run-review.py` — renderer and agent launcher.

To add or rename a stage, update `sdlc.yaml` and its prompt; the runner loads
the stage map dynamically. Preserve every `{{VARIABLE}}` used by the schema.

For individual role prompts, or to inspect multi-input pipelines with
`--dry-run`, use `ai-dev/pi-batch.py`; see its current limitations in
[`../docs/AUTOMATION_WORKFLOW_SUMMARY.md`](../docs/AUTOMATION_WORKFLOW_SUMMARY.md).
