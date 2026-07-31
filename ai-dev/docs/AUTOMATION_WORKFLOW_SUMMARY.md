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

## Runner status

- `run-review.py` live runs persist each stage to `stage-NN.out.md` (partial
  output is kept on failure), and `--all` injects completed stage outputs
  into downstream paste-style variables; explicit context/CLI values win.
- Post-stage pipeline `commands` failures now fail the run with a non-zero
  exit, so configured build, vet, test, or `make ci` hooks act as failure
  gates when a pipeline defines them. Commands still only run when a stage
  declares them.
- `from_outputs` stages accept `aggregate: true`, which merges every upstream
  artifact into one combined prompt per role template (`{input_stem}` becomes
  `combined`) instead of fanning each artifact into an independent task.
- Pipeline `mode`, `workers`, and `timeout` are overridden by the matching
  top-level CLI flags when those flags are passed explicitly (`--mode`,
  `-w`/`--workers`, `--timeout`).
- `pi-batch.py` resolves `pi-batch.yaml` next to the script first, then the
  process working directory, so repository-root invocations pick up
  `ai-dev/pi-batch.yaml`. `--agent-bin` still overrides it explicitly.

`ai-dev/pipelines/pipeline-full-sdlc.yaml` is a long-running experimental
graph; its stages use `aggregate: true` so downstream roles see all upstream
evidence. Inspect it with `--dry-run` before executing.

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
