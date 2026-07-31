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

## Runner status

- `--dry-run` renders the selected prompt without invoking an agent.
- Live runs stream agent output to the terminal and persist it to
  `stage-NN.out.md` under the review output directory (default
  `ai-dev/ai/reviews/<context>`; `--output-dir` overrides). Partial output is
  kept when a stage fails, so failures leave inspectable evidence.
- `--all` runs stages in order and injects each completed stage's output into
  the paste-style variables of downstream stages (Stage 00 →
  `PRODUCT_DISCOVERY_OUTPUT`; Stage 01 → `ARCHITECTURE_OUTPUT`; completed
  stages → `PRIOR_FINDINGS`, `CRITICAL_HIGH_FINDINGS`,
  `ALL_PRIOR_FINDINGS_SUMMARY`, `COMMITTED_STORIES`). Explicit context or CLI
  values win over chained output.
- Omitted context fields render as `(not provided: ...)` or `(unknown)`; the
  runner no longer fabricates storage, team-size, or sprint-length facts.
- `--agent-bin` overrides the agent binary configured in
  `ai-dev/pi-batch.yaml` (default `pi`).
- Agent results are validated before saving: non-zero exit, empty output, or
  a provider/CLI failure signature (quota, rate limit, billing, auth error
  codes such as `insufficient_quota` or `rate_limit_error`, `429 Too Many
  Requests`, offline/DNS/TLS/proxy failures such as `network is unreachable`,
  `connection refused`, `curl: (7)`, leading `ERROR:`/`fatal:` banners)
  rejects the stage and no `stage-NN.out.md` is written. Generic words like
  "error" or "timeout" are not treated as failures, so review findings about
  timeouts or unauthorized responses are not misclassified. A per-stage
  deadline (`--timeout`, default 600s) kills a hung agent so an offline
  machine cannot block the runner. Rejected stages fail the run and are
  skipped by downstream chaining.

Exploratory review directories are ignored by Git; promote verified
conclusions into maintained project documents instead of committing the raw
corpus. The context file's `repo:` value fills the prompt only; pass
`--repo /path` explicitly to set the live agent process working directory.

## Usage

Context YAML requires PyYAML, which is managed in `pyproject.toml`;
install the project with `uv sync` (or `pip install -e .`) before running
the runners.

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
`--dry-run`, use `ai-dev/pi-batch.py`; see its runner status in
[`../docs/AUTOMATION_WORKFLOW_SUMMARY.md`](../docs/AUTOMATION_WORKFLOW_SUMMARY.md).
