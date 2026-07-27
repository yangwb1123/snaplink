# AI-SDLC Automation Overview

`ai-dev/` contains an optional review orchestrator. It supplements the
repository's executable tests and does not replace them.

## Components

- `ai-dev/ai/run-review.py` — fills and runs one of the ten staged review
  prompts.
- `ai-dev/pi-batch.py` — executes task or pipeline YAML, serially or in
  parallel.
- `ai-dev/ai/prompts/` — product, architecture, security, distributed-systems,
  implementation, performance, readiness, planning, retrospective, and CTO
  review stages.
- `ai-dev/prompts/` — individual expert-role prompts.
- `ai-dev/git-auto-commit.sh` — interactive helper that stages **every**
  worktree change; see the safety warning in
  [`GIT_AUTO_COMMIT_GUIDE.md`](GIT_AUTO_COMMIT_GUIDE.md).

## Current runner limits

Use pipelines for dry-run inspection only until these defects are fixed:

- post-stage `commands` currently raise an internal `subprocess` binding error;
  the runner logs only a warning and still exits successfully, so configured
  build, vet, test, or `make ci` commands are **not** release gates;
- `from_outputs` fans every upstream artifact into an independent downstream
  task instead of aggregating role results, so implementation pipelines can
  repeat or conflict rather than apply one combined design.
- pipeline `mode`, `workers`, and `timeout` come from each stage; the matching
  top-level CLI flags do not override them;
- `pi-batch.py` looks for optional `pi-batch.yaml` in the process working
  directory. Repository-root commands therefore ignore `ai-dev/pi-batch.yaml`;
  pass `--agent-bin` explicitly when its built-in `pi` default is unsuitable.

`ai-dev/pipelines/pipeline-full-sdlc.yaml` is a retained design experiment, not
a supported runner path: the current executor expands each upstream output
against every downstream task instead of aggregating stage results.

## Recommended use

YAML task and pipeline loading requires PyYAML, which is not managed as a
repository Python dependency: `python -m pip install PyYAML`.

1. Put a bounded proposal in `docs/feature-spec-<name>.md` using
   `docs/templates/feature-spec.md`.
2. Dry-run the relevant review stage and inspect the filled prompt.
3. Run only the stages that add evidence for the change.
4. Reproduce every reported finding against the current code. AI-generated
   reports are not requirements, test results, or release approval.
5. Implement through the normal repository workflow and run the applicable
   package tests plus `make ci` directly, outside the pipeline runner.

Example:

```bash
python ai-dev/ai/run-review.py \
  --stage 02 \
  --context ai-dev/ai/examples/oidc-logout-context.yaml \
  --dry-run
```

Generated review directories are ignored by Git. Promote a verified conclusion
into an appropriate maintained document rather than committing the raw review
corpus. Pipeline auto-commit is disabled by default and must be enabled
explicitly only after inspecting the worktree.

## Sources of truth

- Product requirements: `docs/feature-matrix.md` and
  `docs/deferred-backlog.md`.
- HTTP contract: `docs/openapi.yaml`.
- Configuration: `docs/config-reference.md`.
- Architecture and gates: `AGENTS.md`, `docs/architecture/DIRECTORY_MAP.md`,
  and `docs/agent-os/`.

The service in this repository is a pure API backend. Any AI-SDLC proposal for
hosted login, admin, self-service, developer, or setup UI must target the
separate frontend project rather than recreating `interfaces/web`.
