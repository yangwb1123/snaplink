# Running ai-dev 24x7

How to keep `pi-batch.py` executing continuously — for example, feeding one
prompt template to an agent a thousand times to generate feature-requirement
proposals — with automatic retry, resumption, throttling, and supervision.

The machinery composes existing safeguards: outputs are saved only after
validation (quota/rate-limit/offline replies and timeouts are rejected),
`--reuse` skips tasks whose output already exists, and every round reruns
only what is still missing.

## One-shot batch

Define the thousand proposals as tasks — either a YAML file or a directory of
prompt files:

```yaml
# proposals.yaml
tasks:
  - prompt: "Propose one feature requirement for the SSO SDK, evidence-backed."
    output: proposals/001.md
  - prompt: "Propose one feature requirement for the SSO SDK, evidence-backed."
    output: proposals/002.md
  # ... 998 more
```

```bash
python ai-dev/pi-batch.py proposals.yaml \
  --mode serial \
  --min-interval 5 \
  --log-file logs/pi-batch.log
```

`--min-interval 5` sleeps five seconds between successful tasks so a long
batch does not hammer the provider into a rate limit.

## Automatic retry with backoff

Transient failures (rate limit, quota, offline, timeout) are retried in
serial mode with exponential backoff. Two timeout layers matter for long
analysis tasks: the per-task hard timeout `--timeout` (default 300s, kills
the whole process group at an absolute deadline) and pi's own HTTP idle
timeout `httpIdleTimeoutMs` (default 300s; this repo raises it to 900s via
`.pi/settings.json`). Deep analysis routinely exceeds 300s, so run such
pipelines with `--timeout 900`:

```bash
python ai-dev/pi-batch.py proposals.yaml \
  --mode serial \
  --retries 3 \
  --retry-delay 30 \
  --retry-backoff 2
```

Rate-limit/network failures always wait at least 30 seconds per attempt so a
rate window can clear. `--max-rounds` (see below) covers parallel mode and
pipeline runs, where retry happens between rounds instead.

## Round loop until everything passes

`--max-rounds N` reruns the batch up to N times; `--max-rounds 0` loops
forever. Combined with `--reuse`, each round executes only the tasks that
failed or were rejected in the previous round:

```bash
python ai-dev/pi-batch.py proposals.yaml \
  --mode serial \
  --reuse \
  --retries 2 \
  --max-rounds 0 \
  --round-delay 300 \
  --log-file logs/pi-batch.log
```

- Every task that passes is saved and skipped afterwards (`--reuse`).
- Failures are retried in-round (`--retries`), then again in the next round
  after a `--round-delay` rest (default 60s; 300s above gives rate limits
  time to reset).
- The process exits 0 only when every task passes. With `--max-rounds 0` it
  keeps looping; interrupt with Ctrl-C (exit 130).

The same loop applies to pipelines (`--pipeline file.yaml`), where `--reuse`
already skips completed stage tasks and `aggregate: true` merges upstream
outputs.

## Engineering gates on generated results

Generated artifacts are only committed after the project's engineering
checks pass. Validators are declared once in `pi-batch.yaml`, like
`engineering.yaml` declares the gates for `cli.py`, and referenced by name:

```yaml
# pi-batch.yaml
validators:
  quick: "python cli.py check"          # filesize + vet
  gofmt: 'test -z "$(gofmt -l {output})"'
  build: "go build ./... && go vet ./..."
  config: "python cli.py config-validate"
  root: "python cli.py check-root"
```

```bash
# named validators, AND semantics (all must pass)
python ai-dev/pi-batch.py code-tasks.yaml --validate quick,gofmt

# add a one-off raw command without touching the registry
python ai-dev/pi-batch.py code-tasks.yaml --validate-cmd "python cli.py check"

# review output must pass a doc-level gate before stage-NN.out.md lands
python ai-dev/ai/run-review.py --all --context ctx.yaml --validate gofmt
```

A `validate` value on a task or stage overrides the CLI default and may also
be a registry name (`validate: gofmt`) or a raw command; an empty value
disables the gate for that task/stage (see next section).

Heavy full gates (`make ci`) belong in pipeline stage `commands`, which run
once per stage; `--validate-cmd` runs per artifact and should stay light
(compile/vet/fmt/lint of the generated file). Combined with `--retries` and
`--max-rounds`, a generated artifact that fails validation is regenerated
automatically until it passes or the budget is exhausted.

## Validation is optional per stage

Not every flow generates code. An analysis task ("analyze the project and
propose three new feature points") produces a markdown proposal, so forcing
`go build` on it is meaningless. The gate is therefore configurable at three
levels, with per-task overrides:

```yaml
# tasks.yaml — per-task gates
# precedence: task validate > stage validate_cmd > CLI --validate-cmd > none
tasks:
  # analysis-only: explicitly skip validation ("" = disabled)
  - prompt: "Analyze the project and propose 3 new feature points"
    output: proposals/analysis.md
    validate: ""

  # code generation: gate this task even when the CLI default is off
  - prompt: "Write a Go helper"
    output: gen/helper.go
    validate: 'test -z "$(gofmt -l {output})"'

  # unset: inherit the CLI --validate-cmd (or no gate at all)
  - prompt: "Draft an RFC"
    output: docs/rfc.md
```

```yaml
# pipeline.yaml — stage-level gates
stages:
  - name: analysis
    from_dir: docs/proposals
    validate_cmd: ""   # analysis stage: no engineering gate

  - name: implementation
    from_outputs: analysis
    aggregate: true
    validate_cmd: "go build ./... && go vet ./..."
```

A stage or task without any configuration simply inherits the CLI default
(no validation when `--validate-cmd` is absent), so the common case of
"analysis batches never validate, code batches opt in" needs no boilerplate.

## Self-optimizing role orchestration (meta stages)

For analyzing arbitrary projects and ideas, a pipeline stage with `meta: true`
discovers its review roles at run time instead of fixing them in YAML. The
starting point can be a one-sentence prompt (no input files needed):

```yaml
stages:
  - name: kickoff
    from_prompt: "Analyze the idea: offline-first sync for the todo app."  # one sentence
    output: docs/reviews/kickoff.md

  - name: review
    from_outputs: kickoff
    meta: true                       # orchestrator picks the roles
    role_dir: ai-dev/prompts         # point at the target project's role templates
    output_dir: docs/reviews
    max_iterations: 3
```

`from_prompt` is a full stage type: it runs as a single task, honors
`--reuse`/validation/sessions, and its output feeds downstream `from_outputs`
stages. `from_dir` remains available when the input is a directory of
documents.

Each iteration:

1. the orchestrator agent reads the current deliverables and `Available roles`
   from `role_dir`, and replies with a JSON plan: role names (e.g.
   `["security_engineer", "qa_lead"]`) and/or ad-hoc role objects
   (`{"role": "perf_reviewer", "task": "Analyze performance bottlenecks"}`),
   or `[]` when done;
2. every chosen role runs **concurrently, each in its own agent session**:
   named roles load their `role_dir` template, ad-hoc roles use their task
   description plus the current deliverables as context (no template
   needed);
3. the deliverables fold back into the evidence, so the next orchestrator
   round sees what previous roles concluded;
4. the loop stops when the orchestrator says `[]` or `max_iterations` is
   reached.

The orchestrator output is untrusted input: named roles must resolve to `.md`
files inside `role_dir` (path traversal rejected) and ad-hoc role names are
sanitized for output paths. `role_dir` may be absent — ad-hoc roles alone are
enough. All other machinery (retries, `--reuse`, rounds, validation,
sessions) applies to meta stages too.

## One session, many steps

By default every call starts a fresh agent session. When later steps should
see the conversation context of earlier ones — for example the stages of a
pipeline building on each other's discussion — reuse one session:

```bash
# one session for the whole pipeline (every stage continues it)
python ai-dev/pi-batch.py --pipeline sdlc.yaml \
  --session-mode shared --session-name sdlc-2026-07

# one session per pipeline stage (parallel roles inside a stage share it)
python ai-dev/pi-batch.py --pipeline sdlc.yaml \
  --session-mode per-stage --session-name sdlc-2026-07

# one session across all ten review stages
python ai-dev/ai/run-review.py --all --context ctx.yaml \
  --session-mode shared --session-name review-2026-07
```

- The first call starts the session with `--session-id <id> --name <name>`;
  later calls pass `--session-id <id>` only. Session ids are derived from
  `--session-name`, so a resumed run (`--reuse`/`--resume`) continues the
  same conversation instead of starting over.
- Shared sessions require serial execution (`--mode serial`); parallel calls
  would interleave inside one session and corrupt the conversation order, so
  the runner rejects that combination.
- The flags come from `pi-batch.yaml` `agent.session_flags` (pi-style by
  default). For another agent CLI, point those flags at its own
  continue-session option.
- Keep sessions small: one long-lived session accumulates context until the
  model window fills, so prefer `per-stage` over `shared` for long pipelines
  and start a new `--session-name` per campaign.

## Running detached (nohup)

```bash
nohup python ai-dev/pi-batch.py proposals.yaml \
  --mode serial \
  --reuse \
  --retries 3 \
  --max-rounds 0 \
  --min-interval 5 \
  --log-file logs/pi-batch.log \
  > /dev/null 2>&1 &

echo $! > run.pid
```

Watch progress via the log and the output directory:

```bash
tail -f logs/pi-batch.log
ls proposals/ | wc -l        # how many of the 1000 are done
```

## Running as a systemd service

```ini
# /etc/systemd/system/ai-proposals.service
[Unit]
Description=ai-dev 1000 proposals batch
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/u1/workspace/demo/snaplink
ExecStart=/usr/bin/python ai-dev/pi-batch.py /srv/proposals.yaml --mode serial --reuse --retries 3 --max-rounds 0 --min-interval 5 --log-file /var/log/ai-proposals.log
Restart=always
RestartSec=30
Environment=HOME=/home/u1

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai-proposals
journalctl -u ai-proposals -f
```

`Restart=always` restarts the process after a crash; because every saved
output is on disk and `--reuse` skips it, a restart continues from exactly
where the run stopped — no work is lost and none is repeated.

## Generating a new batch each day

The runner reruns the same task list; it does not invent new proposals on its
own. To feed it fresh prompts daily, generate a new task file from a
template (cron or a systemd timer) and point the service at it:

```bash
# cron: 02:00 daily
python /srv/gen_proposals.py > /srv/proposals-$(date +%F).yaml
```

Then start one batch process per file, or rotate `proposals.yaml` before
restarting the service.

## Supervision notes

- Quota, rate-limit, offline, and timeout replies are never saved as outputs
  (see `AUTOMATION_WORKFLOW_SUMMARY.md`), so a failed run leaves no bogus
  proposal files behind.
- `--log-file` appends a timestamped log; combine with `tail -f` or a log
  collector for alerting.
- Budget guardrails: `--min-interval` throttles serial batches, `--workers`
  caps parallel fan-out, and `--retries`/`--max-rounds` bound how many times
  a failing task is re-attempted before the run reports failure.
