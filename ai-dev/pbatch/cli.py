"""Command-line entry points: parser, main, round loop, and the
single-batch / pipeline dispatch."""

from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import config
from .config import (AGENT_BIN, AGENT_DEFAULT_WORKERS, COMMIT_PREFIX_DEFAULT, log, yaml)
from .models import Pipeline, Task
from .pipeline import (_append_decision_log, _archive_outputs, load_pipeline,
                       load_tasks, load_tasks_from_dir, run_pipeline)
from .runner import print_summary, run_parallel, run_serial

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="pi-batch -- serial/parallel batch executor for pi agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    _add_source_args(p)
    _add_runtime_args(p)
    _add_batch_args(p)
    return p


def _add_source_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("source", nargs="?",
                   help="YAML task file / JSON file / plain text prompt")
    p.add_argument("-p", "--prompt", help="inline prompt (single task shortcut)")
    p.add_argument("-o", "--output", help="output file path (single task only)")
    p.add_argument("--from-dir", metavar="DIR",
                   help="load one task per .md file in DIR")
    p.add_argument("--suffix", default=".md",
                   help="file suffix for --from-dir (default: .md)")


def _add_runtime_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--pipeline", metavar="FILE",
                   help="run a multi-stage pipeline from YAML file")
    p.add_argument("--reuse", action="store_true",
                   help="reuse existing .out.md files (skip regeneration)")
    p.add_argument("--force", action="store_true",
                   help="force regeneration, overwrite existing .out.md (default)")
    p.add_argument("--git-commit", action="store_true",
                   help="auto git commit after each stage (overrides pipeline setting)")
    p.add_argument("--no-git-commit", action="store_true",
                   help="disable git commit (overrides pipeline setting)")
    p.add_argument("--commit-prefix", default=COMMIT_PREFIX_DEFAULT,
                   help=f"prefix for auto-generated commit messages (default: {COMMIT_PREFIX_DEFAULT})")
    p.add_argument("--log-file", default="",
                   help="Append run log to FILE for 24x7 supervision")
    p.add_argument("--decision-log", default="",
                   help="Append structured per-stage decision records to FILE (overrides pipeline 'decision_log')")
    p.add_argument("--archive-dir", default="",
                   help="Move completed deliverables into DIR/<label>-<timestamp>/ after a fully successful run (keeps the worktree clean; git history retains everything)")
    p.add_argument("--session-mode", choices=["new", "shared", "per-stage"], default="new",
                   help="Session reuse: new = fresh session per call (default), shared = one session for the whole batch/pipeline, per-stage = one session per pipeline stage")
    p.add_argument("--session-name", default="",
                   help="Reproducible session base name (default: task source file stem); shared sessions continue across runs")
    p.add_argument("--validate", default="",
                   help="Named validators from pi-batch.yaml validators registry, comma-separated (e.g. 'quick,gofmt'); AND semantics. Unknown names are treated as raw shell commands")
    p.add_argument("--validate-cmd", default="",
                   help="Engineering gate run against every agent result BEFORE its output is saved (e.g. 'go build ./... && go vet ./...', 'python cli.py check'); {output} and {cwd} placeholders are substituted. Non-zero exit rejects the result and leaves no file")
    p.add_argument("--dry-run", action="store_true",
                   help="print task list without executing")
    return p


def _add_batch_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--mode", choices=["serial", "parallel"], default="serial",
                   help="execution mode (default: serial)")
    p.add_argument("-w", "--workers", type=int, default=AGENT_DEFAULT_WORKERS,
                   help=f"parallel worker count (default: {AGENT_DEFAULT_WORKERS})")
    p.add_argument("--agent-bin", default=AGENT_BIN,
                   help=f"agent CLI binary to invoke per task (default: {AGENT_BIN}; "
                        "set agent.bin in pi-batch.yaml to change the default)")
    p.add_argument("--model", default="",
                   help="default model override for all tasks")
    p.add_argument("--timeout", type=int, default=0,
                   help="default timeout override for all tasks (seconds)")
    p.add_argument("--retries", type=int, default=0,
                   help="Retry failed tasks up to N extra attempts with exponential backoff (serial mode)")
    p.add_argument("--retry-delay", type=float, default=10.0,
                   help="Base retry wait in seconds (default: 10; rate-limit/network failures wait at least 30s)")
    p.add_argument("--retry-backoff", type=float, default=2.0,
                   help="Retry backoff multiplier (default: 2)")
    p.add_argument("--min-interval", type=float, default=0.0,
                   help="Minimum seconds between successful serial tasks (throttle for 24x7 runs)")
    p.add_argument("--max-rounds", type=int, default=1,
                   help="Max execution rounds; 0 = loop forever until every task passes (default: 1)")
    p.add_argument("--round-delay", type=float, default=60.0,
                   help="Seconds to wait between rounds (default: 60)")


def main() -> None:
    args = build_parser().parse_args()
    config.AGENT_BIN = args.agent_bin

    _auto_detect_pipeline(args)

    # Append run log to FILE for 24x7 supervision
    if args.log_file:
        fh = logging.FileHandler(args.log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        log.addHandler(fh)

    pipeline = _setup_pipeline(args)
    timeout_override = args.timeout if "--timeout" in sys.argv else 0

    session_name = _derive_session_name(args)
    _validate_session_flags(args)

    # Validation gates: named validators (--validate) and the raw command
    # (--validate-cmd) both apply, in that order, with AND semantics.
    cli_validate = ",".join(x for x in (args.validate, args.validate_cmd) if x)

    try:
        _run_rounds(args, pipeline, session_name, cli_validate, timeout_override)
    except KeyboardInterrupt:
        log.warning("\nInterrupted by user. Rerun with --reuse to continue later.")
        sys.exit(130)


def _validate_session_flags(args) -> None:
    """Shared/per-stage sessions require serial execution; per-stage needs
    a pipeline (single-batch has no stages)."""
    if args.session_mode != "new" and args.mode == "parallel" and not args.pipeline:
        log.error("--session-mode %s requires --mode serial (parallel would interleave one session)", args.session_mode)
        sys.exit(1)
    if args.session_mode == "per-stage" and not args.pipeline:
        log.error("--session-mode per-stage requires --pipeline (there are no stages in single-batch mode)")
        sys.exit(1)


def _run_rounds(args, pipeline: Optional[Pipeline], session_name: str, cli_validate: str, timeout_override: int) -> None:
    """The 24x7 round loop: rerun only the tasks/stages that failed or were
    rejected each round; --max-rounds 0 loops forever with --round-delay
    rest between rounds so quota and rate-limit windows can clear."""
    max_rounds = args.max_rounds
    stdin_tasks = None  # stdin is consumed once; later rounds reuse it
    round_no = 0
    while True:
        round_no += 1
        log.info("")
        log.info("=" * 60)
        log.info("ROUND %d of %s", round_no, "unlimited" if max_rounds == 0 else max_rounds)
        log.info("=" * 60)

        if pipeline is not None:
            round_failed = _run_pipeline_round(args, pipeline, session_name, cli_validate,
                                               timeout_override, reuse_outputs=args.reuse and not args.force)
        else:
            round_failed = _run_batch_round(args, stdin_tasks, session_name, cli_validate,
                                            max_rounds, round_no)

        if not round_failed:
            log.info("All tasks passed in round %d", round_no)
            return
        if max_rounds > 0 and round_no >= max_rounds:
            log.error("Max rounds (%d) reached with tasks still failing; rerun with --reuse to continue later", max_rounds)
            sys.exit(1)
        log.warning("Round %d finished with failures; waiting %.0fs before round %d",
                    round_no, args.round_delay, round_no + 1)
        time.sleep(args.round_delay)


def _auto_detect_pipeline(args) -> None:
    """A YAML source with a top-level 'stages' key is a pipeline definition,
    not a task list, so `pi-batch.py pipeline.yaml --reuse` works without the
    --pipeline flag."""
    if not (args.source and not args.pipeline and yaml):
        return
    src = Path(args.source)
    if src.exists() and src.suffix in (".yaml", ".yml"):
        try:
            data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
        if isinstance(data, dict) and "stages" in data:
            log.info("Detected pipeline file (top-level 'stages'): switching to pipeline mode")
            args.pipeline = args.source
            args.source = ""


def _setup_pipeline(args) -> Optional[Pipeline]:
    """Load the pipeline (one-time) and apply CLI overrides: git_commit,
    mode/workers (explicit flags only, scanned from argv because argparse
    cannot report defaults), and the commit-message prefix."""
    if not args.pipeline:
        return None
    pipeline = load_pipeline(args.pipeline)

    if args.git_commit and not args.no_git_commit:
        for stage in pipeline.stages:
            stage.git_commit = True
    elif args.no_git_commit:
        for stage in pipeline.stages:
            stage.git_commit = False

    if "--mode" in sys.argv:
        for stage in pipeline.stages:
            stage.mode = args.mode
    if "-w" in sys.argv or "--workers" in sys.argv:
        for stage in pipeline.stages:
            stage.workers = args.workers

    for stage in pipeline.stages:
        if stage.git_commit and not stage.commit_message:
            stage.commit_message = "%s Stage: %s" % (args.commit_prefix, stage.name)
    return pipeline


def _derive_session_name(args) -> str:
    """Reproducible session base name: explicit --session-name wins, else the
    source stem (pipeline/source/dir), else 'batch'."""
    if args.session_name:
        return args.session_name
    if args.pipeline:
        return Path(args.pipeline).stem
    if args.source:
        return Path(args.source).stem
    if args.from_dir:
        return Path(args.from_dir).name
    return "batch"


def _load_batch_tasks(args, stdin_tasks) -> list:
    """Single-batch task sources: --from-dir files, -p prompt, task file,
    or stdin (consumed once, reused by later rounds)."""
    if args.from_dir:
        tasks = load_tasks_from_dir(args.from_dir, args.suffix)
        if not tasks:
            log.error("No %s files found in %s", args.suffix, args.from_dir)
            sys.exit(1)
        return tasks
    if args.prompt:
        return [Task(prompt=args.prompt, output=args.output or "")]
    if args.source:
        return load_tasks(args.source)
    if stdin_tasks is not None:
        return stdin_tasks
    stdin = sys.stdin.read().strip()
    if stdin:
        return [Task(prompt=stdin)]
    log.error("Provide a prompt (-p), a task file, --from-dir, or --pipeline")
    sys.exit(1)


def _apply_task_overrides(args, tasks) -> None:
    """Single-task output shortcut and global model/timeout overrides."""
    if args.output and len(tasks) == 1:
        tasks[0].output = args.output
    if args.model:
        for t in tasks:
            t.model = args.model
    if args.timeout:
        for t in tasks:
            t.timeout = args.timeout


def _run_pipeline_round(args, pipeline: Pipeline, session_name: str, cli_validate: str,
                        timeout_override: int, reuse_outputs: bool) -> bool:
    """One round of pipeline mode; True when the round failed."""
    if args.dry_run:
        run_pipeline(pipeline, model_override=args.model, dry_run=True, reuse=reuse_outputs)
        return False
    all_results, failed_stages = run_pipeline(pipeline, model_override=args.model, reuse=reuse_outputs, timeout_override=timeout_override,
                                              session_mode=args.session_mode, session_name=session_name, validate_cmd=cli_validate,
                                              decision_log=args.decision_log, archive_dir=args.archive_dir)
    print_summary(all_results)
    if failed_stages or any(not r.success for r in all_results):
        log.error("Failed stages: %s", ", ".join(failed_stages) if failed_stages else "(task failures)")
        return True
    return False


def _run_batch_round(args, stdin_tasks, session_name: str, cli_validate: str, max_rounds: int, round_no: int) -> bool:
    """One round of single-batch mode: load tasks, apply overrides and reuse
    filtering, execute, record decisions and archive on full success.
    Returns True when the round failed (caller may loop again)."""
    tasks = _load_batch_tasks(args, stdin_tasks)
    _apply_task_overrides(args, tasks)

    if not tasks:
        log.error("No tasks to execute: a YAML source must contain a 'tasks' list (pipelines use 'stages' and are auto-detected)")
        sys.exit(1)

    tasks = _filter_reused(tasks, args.reuse and not args.force)
    if not tasks:
        log.info("All tasks already have outputs; nothing to run")
        return False

    if args.dry_run:
        _print_dry_run(tasks, args.mode)
        return False

    results, round_failed = _execute_batch(tasks, args, session_name, cli_validate)
    _finalize_batch_round(args, results, round_failed)
    return round_failed


def _finalize_batch_round(args, results: list, round_failed: bool) -> None:
    """Decision log, git commit, and archive for a finished single-batch
    round (archive only when the round fully succeeded)."""
    # Structured decision record for single-batch runs (rolling
    # re-analysis keeps a history of what each round decided and why,
    # instead of overwriting the artifact silently)
    if args.decision_log and results:
        source_name = Path(args.source).stem if args.source else (args.from_dir or "batch")
        _append_decision_log(args.decision_log, source_name, results, not round_failed, None)

    # Git commit for single-batch modes (per round)
    if args.git_commit and not args.no_git_commit:
        outputs = [r.task.output for r in results if r.success and r.task.output]
        if outputs:
            try:
                subprocess.run(["git", "rev-parse", "--git-dir"],
                               capture_output=True, timeout=5)
                subprocess.run(["git", "add"] + outputs,
                               capture_output=True, timeout=10)
                msg = "%s Single batch: %d tasks" % (args.commit_prefix, len(outputs))
                subprocess.run(["git", "commit", "-m", msg],
                               capture_output=True, timeout=10)
                log.info("GIT COMMIT: %s (files: %d)", msg, len(outputs))
            except Exception as e:
                log.warning("Git commit skipped: %s", e)

    # Rolling re-analysis produces many artifacts; archive them once a
    # round fully succeeded so the worktree stays clean.
    if not round_failed and args.archive_dir and results:
        outputs = [r.task.output for r in results if r.success and r.task.output]
        _archive_outputs(outputs, args.archive_dir, "batch")



def _filter_reused(tasks: list, reuse: bool) -> list:
    """Drop tasks whose output already exists when reuse is on, so a later
    round reruns only the failures."""
    if not reuse:
        return tasks
    kept = [t for t in tasks if not (t.output and Path(t.output).exists())]
    skipped = len(tasks) - len(kept)
    if skipped:
        log.info("Reuse: %d task(s) already have outputs, skipped", skipped)
    return kept


def _print_dry_run(tasks: list, mode: str) -> None:
    """Print what single-batch would execute without running it."""
    print("Tasks: %d" % len(tasks))
    print("Mode:  %s" % mode)
    print()
    for i, t in enumerate(tasks, 1):
        print("  [%d] %s..." % (i, t.prompt[:80]))
        print("      model=%s  dir=%s  output=%s" %
              (t.model or "default", t.workdir(), t.output or "(stdout)"))


def _execute_batch(tasks: list, args, session_name: str, cli_validate: str) -> tuple[list, bool]:
    """Run the single-batch tasks (serial with retries, or parallel) and
    print the summary. Returns (results, round_failed)."""
    if args.mode == "serial":
        results = run_serial(tasks, retries=args.retries, retry_delay=args.retry_delay,
                             backoff=args.retry_backoff, min_interval=args.min_interval,
                             session_mode=args.session_mode, session_id=session_name, session_name=session_name,
                             validate_cmd=cli_validate)
    else:
        results = run_parallel(tasks, args.workers, validate_cmd=cli_validate)
    print_summary(results)
    return results, any(not r.success for r in results)


