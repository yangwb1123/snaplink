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
serial mode with exponential backoff:

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
