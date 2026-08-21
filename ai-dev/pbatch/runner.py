"""Task execution: run one agent call with a hard deadline, failure
signatures, retries, validation gates, and summaries."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from . import config
from .config import AGENT_BIN, AGENT_DEFAULT_WORKERS, _resolve_validators, _session_flags, log
from .models import Task, TaskResult

def _read_stream(stream, prefix: str, collector: list) -> None:
    """Read lines from *stream*, print them (with prefix), and collect."""
    try:
        for line in iter(stream.readline, ""):
            if prefix:
                print(f"{prefix}{line}", end="", flush=True)
            else:
                print(line, end="", flush=True)
            collector.append(line)
    except ValueError:
        # stream closed
        pass
    finally:
        stream.close()


_AGENT_ERROR_PATTERNS = (
    # provider error codes (quota, rate limit, billing, auth)
    re.compile(r"rate_?limit_?error", re.IGNORECASE),
    re.compile(r"insufficient_?quota", re.IGNORECASE),
    re.compile(r"quota_?exceeded", re.IGNORECASE),
    re.compile(r"credit_?balance_?too_?low", re.IGNORECASE),
    re.compile(r"billing_?error", re.IGNORECASE),
    re.compile(r"payment_?required", re.IGNORECASE),
    re.compile(r"invalid_?api_?key", re.IGNORECASE),
    re.compile(r"authentication_?error", re.IGNORECASE),
    re.compile(r"context_?length_?exceeded", re.IGNORECASE),
    re.compile(r"overloaded_?error", re.IGNORECASE),
    re.compile(r"429 too many requests", re.IGNORECASE),
    # network connectivity failures (offline, DNS, TLS, proxy)
    re.compile(r"network is unreachable", re.IGNORECASE),
    re.compile(r"no route to host", re.IGNORECASE),
    re.compile(r"temporary failure in name resolution", re.IGNORECASE),
    re.compile(r"name or service not known", re.IGNORECASE),
    re.compile(r"dns resolution failed", re.IGNORECASE),
    re.compile(r"getaddrinfo", re.IGNORECASE),
    re.compile(r"max retries exceeded", re.IGNORECASE),
    re.compile(r"certificate verify failed", re.IGNORECASE),
    re.compile(r"connectionerror", re.IGNORECASE),
    re.compile(r"sslerror", re.IGNORECASE),
    re.compile(r"proxyerror", re.IGNORECASE),
    re.compile(r"econnrefused", re.IGNORECASE),
    re.compile(r"econnreset", re.IGNORECASE),
    re.compile(r"etimedout", re.IGNORECASE),
    re.compile(r"curl: \(\d+\)", re.IGNORECASE),
    re.compile(r"connection timed out", re.IGNORECASE),
    re.compile(r"connect timed out", re.IGNORECASE),
    re.compile(r"operation timed out", re.IGNORECASE),
    re.compile(r"connection refused", re.IGNORECASE),
    re.compile(r"connection reset", re.IGNORECASE),
    re.compile(r"connection closed", re.IGNORECASE),
    re.compile(r"broken pipe", re.IGNORECASE),
    re.compile(r"failed to connect", re.IGNORECASE),
    re.compile(r"unable to connect", re.IGNORECASE),
    re.compile(r"could not connect", re.IGNORECASE),
    # CLI-level failure banners
    re.compile(r"^\[?error\]?:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^fatal:", re.IGNORECASE | re.MULTILINE),
)


def agent_failure_reason(returncode: int, output: str) -> str:
    """Return a short reason when the agent result must be discarded, or ''
    when the output is a usable result. Non-zero exit, empty output, and
    provider/CLI failure signatures (quota, rate limit, auth, billing) all
    reject the result so error replies are never saved as task outputs."""
    if returncode != 0:
        return f"agent exited {returncode}"
    if not output or not output.strip():
        return "agent produced no output"
    for pattern in _AGENT_ERROR_PATTERNS:
        if pattern.search(output):
            return f"agent reported provider failure ({pattern.pattern})"
    return ""


def run_task(task: Task, task_index: int = 0, total: int = 0, parallel: bool = False, session_flags: Optional[list] = None) -> TaskResult:
    """Execute one pi task, streaming output in real-time, and return the result.
    session_flags (e.g. --session-id for a shared session) are appended to
    the agent command when provided."""
    cmd = task.to_cmd(session_flags=session_flags)
    workdir = task.workdir()
    start = time.monotonic()

    # Build a prefix for output lines
    prefix = f"[task-{task_index}] " if (parallel and total > 1) else ""

    brief = " ".join(cmd[:4]) + ("..." if len(cmd) > 4 else "")
    log.info(">>  %s  [model=%s]  [timeout=%ss]  [dir=%s]",
             brief, task.model or "default", task.timeout, workdir)

    env = os.environ.copy()
    env.update(task.env)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=workdir,
            env=env,
            start_new_session=True,  # own process group so the whole child tree can be killed on timeout
        )

        # Read stdout and stderr concurrently via threads, then wait on a
        # hard deadline (kills the process group when task.timeout elapses).
        stdout_lines, stderr_lines = _stream_proc(proc, prefix, start, task.timeout)

        elapsed = time.monotonic() - start
        return _result_from_proc(task, proc, stdout_lines, stderr_lines, elapsed)

    except subprocess.TimeoutExpired:
        return _timeout_result(task, proc, start)

    except FileNotFoundError:
        log.error("'%s' not found in PATH. Is it installed? (configure agent.bin in pi-batch.yaml)", config.AGENT_BIN)
        return TaskResult(task=task, success=False, stderr=f"{config.AGENT_BIN} not found in PATH", reason="agent binary not found")

    except Exception as e:
        elapsed = time.monotonic() - start
        log.error("ERROR  [%.1fs]  [%s]", elapsed, e)
        return TaskResult(task=task, success=False, stderr=str(e), elapsed=elapsed, reason=str(e))


def save_result(task: Task, result: TaskResult) -> None:
    """Write a successful task result to its output file, or print to stdout.
    Failed or rejected results are never written to disk: quota or rate-limit
    replies must not become committed artifacts, so the error is logged only.
    """
    out_path = task.output_path()
    if out_path is None:
        sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return

    if not result.success:
        log.error("NOT SAVED %s: task failed (exit=%d, %.1fs)", out_path, result.returncode, result.elapsed)
        return

    if len(result.stdout.encode("utf-8")) > config.OUTPUT_MAX_BYTES:
        log.error("NOT SAVED %s: output exceeds %d bytes", out_path, config.OUTPUT_MAX_BYTES)
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    unresolved = Path(task.output)
    if not unresolved.is_absolute():
        unresolved = Path(task.workdir()) / unresolved
    if unresolved.is_symlink():
        log.error("NOT SAVED %s: output path is a symlink", out_path)
        return
    fd, temporary = tempfile.mkstemp(prefix=out_path.name + ".", suffix=".tmp",
                                     dir=str(out_path.parent))
    os.close(fd)
    temporary_path = Path(temporary)
    try:
        temporary_path.write_text(result.stdout, encoding="utf-8")
        temporary_path.replace(out_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    log.info("WROTE %s  (%d bytes)", out_path, len(result.stdout))


_RETRYABLE_REASON = re.compile(r"rate|429|quota|network|connect|unreachable|timeout", re.IGNORECASE)


def _retry_wait(result: TaskResult, attempt: int, retry_delay: float, backoff: float) -> float:
    """Exponential backoff for a retry attempt; provider/network failures wait
    at least 30s so a rate-limit window can clear."""
    wait = retry_delay * (backoff ** (attempt - 1))
    if _RETRYABLE_REASON.search(result.reason or ""):
        wait = max(wait, 30.0)
    return wait


def _save_validated(task: Task, result: TaskResult, validate_cmd: str) -> bool:
    """Save a successful result through the engineering gates. The output is
    written to a temp file, every resolved validator command must exit 0
    (AND semantics), then the file is atomically renamed into place; a
    failing gate deletes the temp file and leaves no artifact. {output}
    points at the temp file so gates can inspect the generated content.
    validate_cmd is a comma-separated list of registry names or raw shell
    commands (see _resolve_validators). Returns True when saved."""
    if not result.success:
        return False
    commands = _resolve_validators(validate_cmd)
    if not commands:
        save_result(task, result)
        return True
    out_path = task.output_path()
    if out_path is None:
        # no file target: nothing to validate against, print as usual
        save_result(task, result)
        return True
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(result.stdout, encoding="utf-8")
    for raw in commands:
        cmd = raw.replace("{output}", str(tmp)).replace("{cwd}", task.workdir())
        log.info("VALIDATE: %s", cmd)
        try:
            proc = subprocess.run(cmd, shell=True, cwd=task.workdir(), capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            proc = None
        if proc is not None and proc.returncode == 0:
            continue
        tmp.unlink(missing_ok=True)
        log.warning("VALIDATION FAILED%s: %s; output NOT saved",
                    f" (exit={proc.returncode})" if proc is not None else " (timeout)", cmd)
        if proc is not None:
            for line in (proc.stdout or "").strip().splitlines()[-10:]:
                log.warning("  | %s", line)
            for line in (proc.stderr or "").strip().splitlines()[-10:]:
                log.warning("  | %s", line)
        return False
    tmp.rename(out_path)
    log.info("WROTE %s (validated)", out_path)
    return True


def _result_from_proc(task: Task, proc: subprocess.Popen, stdout_lines: list, stderr_lines: list, elapsed: float) -> TaskResult:
    """Assemble the TaskResult from a finished process: failure-signature
    rejection (quota/rate-limit/offline/timeout text) overrides exit code 0."""
    stdout_text = "".join(stdout_lines)
    stderr_text = "".join(stderr_lines)
    reason = agent_failure_reason(proc.returncode, stdout_text)
    success = proc.returncode == 0 and not reason
    if reason:
        log.warning("agent output REJECTED: %s", reason)
    if success:
        log.info("OK  done  [%.1fs]  [output=%s]", elapsed, task.output or "(stdout)")
    else:
        log.warning("FAIL  [code=%d]  [%.1fs]", proc.returncode, elapsed)
    return TaskResult(
        task=task, success=success, stdout=stdout_text, stderr=stderr_text,
        elapsed=elapsed, returncode=proc.returncode, reason=reason or "",
    )


def _timeout_result(task: Task, proc: subprocess.Popen, start: float) -> TaskResult:
    """Kill the whole process group (the direct child may have spawned
    helpers that keep pipes open) and return a timed-out result."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        proc.kill()
    elapsed = time.monotonic() - start
    log.error("TIMEOUT  [%.1fs]  [limit=%ss]", elapsed, task.timeout)
    return TaskResult(
        task=task, success=False, stderr=f"Task timed out after {task.timeout}s",
        elapsed=elapsed, returncode=-1, reason="task timed out",
    )


def _stream_proc(proc: subprocess.Popen, prefix: str, start: float, timeout: int) -> tuple[list[str], list[str]]:
    """Drain stdout/stderr concurrently via daemon threads, then wait on a
    hard deadline. Thread joins only drain pipes and must not extend the
    window, so each join/wait gets the remaining budget (they return early
    when the agent exits). Raises TimeoutExpired when the deadline hits."""
    from threading import Thread
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    tout = Thread(target=_read_stream, args=(proc.stdout, prefix, stdout_lines), daemon=True)
    terr = Thread(target=_read_stream, args=(proc.stderr, prefix, stderr_lines), daemon=True)
    tout.start()
    terr.start()
    deadline = start + timeout
    tout.join(timeout=max(0, deadline - time.monotonic()))
    terr.join(timeout=max(0, deadline - time.monotonic()))
    proc.wait(timeout=max(0.1, deadline - time.monotonic()))
    return stdout_lines, stderr_lines


def run_serial(tasks: list[Task], retries: int = 0, retry_delay: float = 10.0, backoff: float = 2.0, min_interval: float = 0.0,
               session_mode: str = "new", session_id: str = "", session_name: str = "", validate_cmd: str = "") -> list[TaskResult]:
    """Execute tasks one by one with real-time output streaming. Failed tasks
    are retried with exponential backoff up to `retries` extra attempts, and
    successful tasks are throttled by `min_interval` seconds so long-running
    24x7 batches do not hammer the provider.

    validate_cmd runs against each agent result before the output file is
    committed (engineering gate); a non-zero exit marks the task failed and
    leaves no artifact, so the retry/round machinery regenerates it.

    With session_mode "shared", every task in this list continues the same
    agent session (the first call starts it with the configured start flags,
    later calls pass the continue flags); "per-stage" behaves the same here
    and is differentiated by the caller via session_id."""
    results = []
    total = len(tasks)
    session_active = False
    for i, task in enumerate(tasks, 1):
        log.info("-- [%d/%d] --", i, total)
        flags = None
        if session_mode != "new":
            if not session_active:
                flags = _session_flags("start", session_id, session_name)
                session_active = True
            else:
                flags = _session_flags("continue", session_id, session_name)
        result = run_task(task, task_index=i, total=total, parallel=False, session_flags=flags)
        if result.success:
            result.success = _save_validated(task, result, task.validate if task.validate is not None else validate_cmd)
            if not result.success:
                result.reason = "validation failed"
        attempt = 0
        while not result.success and attempt < retries:
            attempt += 1
            wait = _retry_wait(result, attempt, retry_delay, backoff)
            log.warning("RETRY %d/%d for task [%d/%d] in %.0fs (reason: %s)",
                        attempt, retries, i, total, wait, result.reason or f"exit {result.returncode}")
            time.sleep(wait)
            # retries stay inside the same session
            retry_flags = _session_flags("continue", session_id, session_name) if session_mode != "new" else None
            result = run_task(task, task_index=i, total=total, parallel=False, session_flags=retry_flags)
            if result.success:
                result.success = _save_validated(task, result, task.validate if task.validate is not None else validate_cmd)
                if not result.success:
                    result.reason = "validation failed"
        results.append(result)
        if result.success and min_interval > 0:
            time.sleep(min_interval)
    return results


def run_parallel(tasks: list[Task], workers: int = 0, validate_cmd: str = "") -> list[TaskResult]:
    workers = workers or config.AGENT_DEFAULT_WORKERS
    """Execute tasks concurrently with a thread pool and real-time output.
    Each result passes the engineering validation gate before its output file
    is committed; a non-zero validation exit leaves no artifact."""
    total = len(tasks)
    log.info("PARALLEL x%d  (%d tasks)", workers, total)

    def _run_one(task: Task, index: int) -> TaskResult:
        result = run_task(task, task_index=index, total=total, parallel=True)
        if result.success:
            result.success = _save_validated(task, result, task.validate if task.validate is not None else validate_cmd)
            if not result.success:
                result.reason = "validation failed"
        return result

    results: list[TaskResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Pass task_index so parallel output lines are prefixed
        fut_map = {pool.submit(_run_one, t, i): t for i, t in enumerate(tasks, 1)}
        for i, fut in enumerate(as_completed(fut_map), 1):
            task = fut_map[fut]
            result = fut.result()
            results.append(result)
            log.info("PROGRESS: %d/%d done", i, total)

    return results


def print_summary(results: list[TaskResult]) -> None:
    """Print an execution summary table."""
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    failed = total - succeeded
    total_elapsed = sum(r.elapsed for r in results)
    wall_time = max(r.elapsed for r in results) if results else 0

    print()
    print("=" * 56)
    print("  pi-batch execution report")
    print("=" * 56)
    print("  total:     %d" % total)
    print("  succeeded: %d" % succeeded)
    print("  failed:    %d" % failed)
    print("  CPU time:  %.1fs" % total_elapsed)
    print("  wall time: %.1fs" % wall_time)
    print()
    for r in results:
        icon = "PASS" if r.success else "FAIL"
        brief = r.task.prompt[:60].replace("\n", " ")
        print("  %s  [%6.1fs] %s..." % (icon, r.elapsed, brief))
    print("=" * 56)
