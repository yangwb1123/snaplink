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

- `run-review.py` live runs persist each stage to `stage-NN.out.md` (only
  after validation: rejected or failed stages leave no file), and `--all`
  injects completed stage outputs into downstream paste-style variables;
  explicit context/CLI values win. `--all --resume` skips stages with a
  saved output and chains from those files, so an interrupted session
  continues from its last completed stage.
- Post-stage pipeline `commands` failures now fail the run with a non-zero
  exit, so configured build, vet, test, or `make ci` hooks act as failure
  gates when a pipeline defines them. Commands still only run when a stage
  declares them.
- `from_outputs` stages accept `aggregate: true`, which merges every upstream
  artifact into one combined prompt per role template (`{input_stem}` becomes
  `combined`) instead of fanning each artifact into an independent task.
  `--reuse` now also skips `from_outputs` tasks (aggregate and fan-out) whose
  output file already exists and keeps the reused paths visible to
  downstream stages, so a pipeline resumes without re-running completed work.
- Pipeline `mode`, `workers`, and `timeout` are overridden by the matching
  top-level CLI flags when those flags are passed explicitly (`--mode`,
  `-w`/`--workers`, `--timeout`).
- `pi-batch.py` resolves `pi-batch.yaml` next to the script first, then the
  process working directory, so repository-root invocations pick up
  `ai-dev/pi-batch.yaml`. `--agent-bin` still overrides it explicitly.
- `--validate-cmd` runs an engineering gate against every agent result
  BEFORE its output is committed: the result is written to a temp file
  (`{output}` placeholder), the command must exit 0, then the file is
  atomically renamed into place; a failing gate deletes the temp file and
  marks the task/stage failed, so generated artifacts that do not pass
  project checks (e.g. `go build ./... && go vet ./...`, `gofmt -l`,
  `python cli.py check`) never land on disk. Works in serial, parallel,
  pipeline, and `run-review.py` modes, and integrates with retries/rounds.
- 24x7 operation: `--retries` (serial mode) retries failed tasks with
  exponential backoff (`--retry-delay`/`--retry-backoff`; rate-limit and
  network failures wait at least 30s), `--min-interval` throttles successful
  tasks, and `--max-rounds` (0 = forever) reruns the batch until every task
  passes with `--round-delay` rest between rounds; combined with `--reuse`
  each round runs only the failures. `--log-file` appends a timestamped log
  for supervision. See `RUNNING_247.md` for nohup/systemd deployment.
- Session reuse: `--session-mode shared` runs every task of a batch/pipeline
  in one agent session (the first call starts it with `--session-id` and
  `--name`, later calls continue it), `--session-mode per-stage` gives each
  pipeline stage its own session, and the default `new` starts a fresh
  session per call. Session ids are derived from `--session-name` (default:
  task source stem), so resumed runs continue the same session. Shared
  sessions require serial execution; the flags come from
  `pi-batch.yaml` `agent.session_flags` (pi-style by default) so other agent
  CLIs can be adapted. `run-review.py --all` supports the same with
  `--session-mode shared`.
- Task results are validated before saving: non-zero exit, empty output, or
  a provider/CLI failure signature (quota, rate limit, billing, auth error
  codes such as `insufficient_quota` or `rate_limit_error`, `429 Too Many
  Requests`, offline/DNS/TLS/proxy failures such as `network is unreachable`,
  `connection refused`, `curl: (7)`, leading `ERROR:`/`fatal:` banners)
  marks the task failed and no output file is written; generic words like
  "error" or "timeout" are not treated as failures, so review prose is not
  misclassified. `run-review.py` also enforces a per-stage deadline
  (`--timeout`, default 600s) so a hung agent cannot block the run.

`ai-dev/pipelines/pipeline-full-sdlc.yaml` is a long-running experimental
graph; its stages use `aggregate: true` so downstream roles see all upstream
evidence. Inspect it with `--dry-run` before executing.

## Recommended use

YAML task and pipeline loading requires PyYAML, which is managed in
`pyproject.toml`; install the project with `uv sync` (or
`pip install -e .`) before running the runners.

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
