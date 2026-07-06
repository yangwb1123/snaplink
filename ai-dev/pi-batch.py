#!/usr/bin/env python3
"""pi-batch -- serial/parallel batch executor for a CLI coding agent.

The agent binary (default: `pi`) and other defaults are declared in
pi-batch.yaml, not hardcoded -- copy pi-batch.py + pi-batch.yaml into another
project and edit `agent.bin` to point at a different agent CLI (claude,
codex, gemini, opencode, ...); see pi-batch.yaml's header comment.

Usage:
  # From YAML task file
  python pi-batch.py tasks.yaml

  # Single task via CLI
  python pi-batch.py -p "analyze this project" -o output.md

  # Parallel execution
  python pi-batch.py tasks.yaml --mode parallel --workers 4

  # Serial execution (default)
  python pi-batch.py tasks.yaml --mode serial

Example tasks.yaml:
  ---
  tasks:
    - prompt: "Analyze the project expansion directions"
      output: docs/expansion.md
      model: claude-sonnet
      cwd: /home/dwp/snaplink

    - prompt: "Review security edge cases"
      output: docs/security-review.md
      model: claude-sonnet:high
      cwd: /home/dwp/snaplink

    - prompt: |
        Based on the current codebase, list performance bottlenecks
      output: docs/perf.md
      model: claude-haiku
      cwd: /home/dwp/snaplink
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None


# -- declarative config (pi-batch.yaml) ----------------------------------
def _load_batch_config(path: str = "pi-batch.yaml") -> dict:
    """Optional defaults for pi-batch.py. Missing file -> {} (built-in
    defaults below apply), so the script still runs standalone with zero
    config -- copy pi-batch.yaml alongside pi-batch.py to point it at a
    different agent CLI."""
    p = Path(path)
    if not yaml or not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


_BATCH_CFG = _load_batch_config()
_AGENT_CFG = _BATCH_CFG.get("agent", {})
AGENT_BIN = _AGENT_CFG.get("bin", "pi")
AGENT_DEFAULT_MODEL = _AGENT_CFG.get("default_model", "")
AGENT_DEFAULT_TIMEOUT = _AGENT_CFG.get("default_timeout", 300)
AGENT_DEFAULT_WORKERS = _AGENT_CFG.get("default_workers", 4)
COMMIT_PREFIX_DEFAULT = _BATCH_CFG.get("commit", {}).get("prefix", "[pi-batch]")


# -- Pipeline data structures -------------------------------------------
@dataclass
class Stage:
    """One stage in a pipeline."""
    name: str
    from_dir: str = ""
    from_outputs: str = ""  # name of previous stage
    suffix: str = ".md"
    output_suffix: str = ".out.md"
    mode: str = "serial"
    workers: int = AGENT_DEFAULT_WORKERS
    tasks: list = field(default_factory=list)
    commands: list = field(default_factory=list)
    commands_parallel: bool = False  # if True, run commands concurrently
    cwd: str = ""
    git_commit: bool = False
    commit_message: str = ""
    
    def to_dict(self):
        return {
            "name": self.name,
            "from_dir": self.from_dir,
            "from_outputs": self.from_outputs,
            "suffix": self.suffix,
            "output_suffix": self.output_suffix,
            "mode": self.mode,
            "workers": self.workers,
            "tasks": self.tasks,
            "commands": self.commands,
            "commands_parallel": self.commands_parallel,
            "cwd": self.cwd,
            "git_commit": self.git_commit,
            "commit_message": self.commit_message,
        }


@dataclass
class Pipeline:
    """Multi-stage pipeline definition."""
    stages: list[Stage] = field(default_factory=list)
    
    def to_dict(self):
        return {"stages": [s.to_dict() for s in self.stages]}


def load_pipeline(path: str) -> Pipeline:
    """Load pipeline definition from YAML file."""
    if not yaml:
        log.error("PyYAML not installed. Run: pip install pyyaml")
        sys.exit(1)
    
    fpath = Path(path)
    if not fpath.exists():
        log.error("Pipeline file not found: %s", path)
        sys.exit(1)
    
    raw = fpath.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    
    if not isinstance(data, dict) or "stages" not in data:
        log.error("Invalid pipeline format. Expected 'stages' key.")
        sys.exit(1)
    
    # Global settings (applied to all stages that don't set it explicitly)
    global_git_commit = data.get("git_commit", False)
    
    stages = []
    for s in data["stages"]:
        stage = Stage(
            name=s.get("name", ""),
            from_dir=s.get("from_dir", ""),
            from_outputs=s.get("from_outputs", ""),
            suffix=s.get("suffix", ".md"),
            output_suffix=s.get("output_suffix", ".out.md"),
            mode=s.get("mode", "serial"),
            workers=s.get("workers", AGENT_DEFAULT_WORKERS),
            tasks=s.get("tasks", []),
            commands=s.get("commands", []),
            commands_parallel=s.get("commands_parallel", False),
            cwd=s.get("cwd", ""),
            git_commit=s.get("git_commit", global_git_commit),
            commit_message=s.get("commit_message", ""),
        )
        stages.append(stage)
    
    return Pipeline(stages=stages)


def execute_stage(stage: Stage, stage_outputs: dict[str, list[str]], model_override: str = "", reuse: bool = False) -> list[TaskResult]:
    """Execute one stage and return results.
    
    Args:
        stage: Stage definition
        stage_outputs: dict mapping stage name -> list of output file paths
        model_override: override model for all tasks
        reuse: if True, skip tasks whose output files already exist
    """
    log.info("")
    log.info("=" * 60)
    log.info("STAGE: %s", stage.name)
    if reuse:
        log.info("(reusing existing outputs if available)")
    log.info("=" * 60)
    
    tasks: list[Task] = []
    
    # Stage type 1: from_dir - read .md files from directory
    if stage.from_dir:
        dir_path = Path(stage.from_dir)
        if not dir_path.is_dir():
            log.error("Directory not found: %s", stage.from_dir)
            return []
        
        for fpath in sorted(dir_path.glob(f"*{stage.suffix}")):
            if fpath.name.endswith(stage.output_suffix):
                continue
            prompt = fpath.read_text(encoding="utf-8")
            out_path = fpath.parent / (fpath.stem + stage.output_suffix)
            
            # Check if output already exists and reuse flag is set
            if reuse and out_path.exists():
                log.info("REUSE: %s (output exists: %s)", fpath.name, out_path.name)
                stage_outputs.setdefault(stage.name, []).append(str(out_path))
                continue
            
            task = Task(
                prompt=prompt,
                output=str(out_path),
                cwd=str(fpath.parent),
            )
            if model_override:
                task.model = model_override
            tasks.append(task)
        
        log.info("Loaded %d tasks from %s", len(tasks), stage.from_dir)
    
    # Stage type 2: from_outputs - use outputs from previous stage
    elif stage.from_outputs:
        if stage.from_outputs not in stage_outputs:
            log.error("Previous stage '%s' not found", stage.from_outputs)
            return []
        
        prev_outputs = stage_outputs[stage.from_outputs]
        
        # For each output file from previous stage, create tasks based on task templates
        for out_path_str in prev_outputs:
            out_path = Path(out_path_str)
            if not out_path.exists():
                log.warning("Output file not found: %s", out_path)
                continue
            
            input_content = out_path.read_text(encoding="utf-8")
            input_stem = out_path.stem
            
            # Create tasks from templates
            for task_def in stage.tasks:
                prompt_template_path = Path(task_def.get("prompt_template", ""))
                if not prompt_template_path.exists():
                    log.error("Prompt template not found: %s", prompt_template_path)
                    continue
                
                template = prompt_template_path.read_text(encoding="utf-8")
                
                # Replace placeholders
                prompt = template.replace("{input_content}", input_content)
                prompt = prompt.replace("{input_stem}", input_stem)
                prompt = prompt.replace("{input_path}", str(out_path))
                
                # Resolve output path
                output_template = task_def.get("output", "")
                output_path = output_template.replace("{input_stem}", input_stem)
                
                task = Task(
                    prompt=prompt,
                    output=output_path,
                    model=task_def.get("model", ""),
                    cwd=task_def.get("cwd", ""),
                    timeout=task_def.get("timeout", 300),
                )
                if model_override:
                    task.model = model_override
                tasks.append(task)
        
        log.info("Loaded %d tasks from %d outputs of stage '%s'", 
                 len(tasks), len(prev_outputs), stage.from_outputs)
    
    else:
        log.error("Stage '%s' must have either 'from_dir' or 'from_outputs'", stage.name)
        return []
    
    if not tasks:
        log.warning("No tasks to execute in stage '%s'", stage.name)
        return []
    
    # Execute tasks
    if stage.mode == "parallel":
        results = run_parallel(tasks, stage.workers)
    else:
        results = run_serial(tasks)
    
    # Collect output paths
    outputs = []
    for r in results:
        if r.success and r.task.output:
            outputs.append(r.task.output)
    
    stage_outputs[stage.name] = outputs
    
    log.info("")
    log.info("Stage '%s' completed: %d/%d tasks succeeded", 
             stage.name, len(outputs), len(tasks))
    
    # Execute shell commands after pi tasks
    if stage.commands:
        log.info("")
        log.info("Running %d commands for stage '%s'... (parallel=%s)",
                 len(stage.commands), stage.name, stage.commands_parallel)
        cmd_cwd = stage.cwd or os.getcwd()
        
        def run_single_cmd(cmd: str, index: int) -> tuple:
            log.info("CMD [%d/%d]: %s", index, len(stage.commands), cmd)
            try:
                proc = subprocess.run(
                    cmd, shell=True, cwd=cmd_cwd,
                    capture_output=True, text=True, timeout=600
                )
                if proc.returncode == 0:
                    log.info("CMD OK (exit=0) [%d/%d]", index, len(stage.commands))
                    if proc.stdout:
                        for line in proc.stdout.strip().split("\n")[-10:]:
                            log.info("  | %s", line)
                else:
                    log.warning("CMD FAILED (exit=%d) [%d/%d]", proc.returncode, index, len(stage.commands))
                    if proc.stderr:
                        for line in proc.stderr.strip().split("\n")[-10:]:
                            log.warning("  | %s", line)
                    if proc.stdout:
                        for line in proc.stdout.strip().split("\n")[-5:]:
                            log.info("  | %s", line)
                return True if proc.returncode == 0 else False
            except Exception as e:
                log.warning("CMD ERROR [%d/%d]: %s", index, len(stage.commands), e)
                return False
        
        if stage.commands_parallel:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=len(stage.commands)) as pool:
                futs = {pool.submit(run_single_cmd, cmd, i): cmd for i, cmd in enumerate(stage.commands, 1)}
                cmd_results = [f.result() for f in as_completed(futs)]
                all_cmd_ok = all(cmd_results)
        else:
            all_cmd_ok = True
            for i, cmd in enumerate(stage.commands, 1):
                if not run_single_cmd(cmd, i):
                    all_cmd_ok = False
        
        if all_cmd_ok:
            log.info("All %d commands passed for stage '%s'", len(stage.commands), stage.name)
        else:
            log.warning("Some commands failed for stage '%s'", stage.name)
    
    # Git commit after stage
    if stage.git_commit and outputs:
        try:
            import subprocess
            commit_msg = stage.commit_message or "[pi-batch] Stage: %s - %d tasks completed" % (stage.name, len(outputs))
            file_list = " ".join(["\"%s\"" % o for o in outputs])
            
            # Check if git repo exists
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Add and commit
                subprocess.run(
                    ["git", "add"] + outputs,
                    capture_output=True, timeout=10
                )
                subprocess.run(
                    ["git", "commit", "-m", commit_msg],
                    capture_output=True, timeout=10
                )
                log.info("GIT COMMIT: %s (files: %d)", commit_msg, len(outputs))
            else:
                log.warning("Not a git repository, skipping git commit")
        except Exception as e:
            log.warning("Git commit failed: %s", e)
    
    return results


def run_pipeline(pipeline: Pipeline, model_override: str = "", dry_run: bool = False, reuse: bool = False) -> list[TaskResult]:
    """Execute all stages in a pipeline sequentially.
    
    Args:
        pipeline: Pipeline definition
        model_override: override model for all tasks
        dry_run: if True, only print task list without executing
        reuse: if True, skip tasks whose output files already exist
    
    Returns:
        All task results from all stages
    """
    all_results: list[TaskResult] = []
    stage_outputs: dict[str, list[str]] = {}  # stage_name -> [output_file_paths]
    
    log.info("")
    log.info("=" * 60)
    log.info("PIPELINE START (%d stages)", len(pipeline.stages))
    if reuse:
        log.info("Mode: REUSE existing outputs")
    else:
        log.info("Mode: FORCE regeneration")
    log.info("=" * 60)
    
    for stage in pipeline.stages:
        if dry_run:
            log.info("")
            log.info("STAGE: %s (dry-run)", stage.name)
            if stage.from_dir:
                log.info("  Will read .md files from: %s", stage.from_dir)
                if reuse:
                    log.info("  Will skip files with existing outputs")
            elif stage.from_outputs:
                log.info("  Will use outputs from stage: %s", stage.from_outputs)
                log.info("  Task templates: %d", len(stage.tasks))
            if stage.commands:
                log.info("  Commands: %d (parallel=%s)", len(stage.commands), stage.commands_parallel)
                for cmd in stage.commands:
                    log.info("    | %s", cmd)
            if stage.git_commit:
                log.info("  Git commit: YES")
            log.info("  Mode: %s", stage.mode)
            continue
        
        results = execute_stage(stage, stage_outputs, model_override, reuse)
        all_results.extend(results)
    
    return all_results


# -- logging ----------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pi-batch")


# -- data model -------------------------------------------------------
@dataclass
class Task:
    """A single pi invocation task."""

    prompt: str
    output: str = ""
    model: str = AGENT_DEFAULT_MODEL
    provider: str = ""
    thinking: str = ""
    tools: str = ""
    exclude_tools: str = ""
    cwd: str = ""
    timeout: int = AGENT_DEFAULT_TIMEOUT
    env: dict = field(default_factory=dict)

    def to_cmd(self) -> list[str]:
        cmd = [AGENT_BIN, "-p", self.prompt]
        if self.model:
            cmd.extend(["--model", self.model])
        if self.provider:
            cmd.extend(["--provider", self.provider])
        if self.thinking:
            cmd.extend(["--thinking", self.thinking])
        if self.tools:
            cmd.extend(["--tools", self.tools])
        if self.exclude_tools:
            cmd.extend(["--exclude-tools", self.exclude_tools])
        return cmd

    def workdir(self) -> str:
        return self.cwd or os.getcwd()

    def output_path(self) -> Optional[Path]:
        return Path(self.output).resolve() if self.output else None

    def resolve_prompt(self, base_dir: str = "") -> str:
        """Resolve @file references in the prompt to file contents.

        Supports:
          @file.md              -> loads file.md content
          @docs/analysis.md     -> loads docs/analysis.md
          prefix text @file.md  -> prepends file content before prefix text

        Returns the resolved prompt string.
        """
        def replace(match: re.Match) -> str:
            fpath = Path(match.group(1))
            if not fpath.is_absolute():
                fpath = Path(base_dir) / fpath
            if fpath.exists():
                return fpath.read_text(encoding="utf-8")
            log.warning("referenced file not found: %s", fpath)
            return match.group(0)

        return re.sub(r"@(\S+)", replace, self.prompt)


# -- task loading -----------------------------------------------------
def load_tasks(source: str) -> list[Task]:
    """Load tasks from a YAML file, JSON file, or plain text prompt.

    Supports @file.md references in the prompt field.
    """
    path = Path(source)
    if not path.exists():
        return [Task(prompt=source)]

    base_dir = str(path.parent) if path.parent else "."
    raw = path.read_text(encoding="utf-8")

    # YAML
    if yaml and (source.endswith((".yaml", ".yml")) or raw.lstrip().startswith("tasks:")):
        data = yaml.safe_load(raw)
        tasks_data = data.get("tasks", []) if isinstance(data, dict) else data
        tasks = []
        for t in tasks_data:
            task = Task(**{k: v for k, v in t.items() if k in Task.__dataclass_fields__})
            task.prompt = task.resolve_prompt(base_dir)
            tasks.append(task)
        return tasks

    # JSON
    try:
        tasks_data = json.loads(raw)
        if isinstance(tasks_data, dict):
            tasks_data = tasks_data.get("tasks", tasks_data)
        if isinstance(tasks_data, list):
            tasks = []
            for t in tasks_data:
                task = Task(**{k: v for k, v in t.items() if k in Task.__dataclass_fields__})
                task.prompt = task.resolve_prompt(base_dir)
                tasks.append(task)
            return tasks
    except json.JSONDecodeError:
        pass

    # Plain text prompt
    return [Task(prompt=raw.strip())]


def load_tasks_from_dir(directory: str, suffix: str = ".md") -> list[Task]:
    """Create one task per file in a directory.

    Each file's content becomes the prompt, and the output is saved as
    <filename>.out.md in the same directory (or specified output dir).
    """
    tasks = []
    basedir = Path(directory)
    if not basedir.is_dir():
        log.error("not a directory: %s", directory)
        return tasks

    for fpath in sorted(basedir.glob(f"*{suffix}")):
        if fpath.name.endswith(".out.md"):
            continue
        prompt = fpath.read_text(encoding="utf-8")
        out_name = fpath.stem + ".out.md"
        tasks.append(Task(
            prompt=prompt,
            output=str(basedir / out_name),
            cwd=str(basedir),
        ))
        log.info("loaded task from %s -> %s", fpath.name, out_name)

    return tasks


# -- execution engine -------------------------------------------------
@dataclass
class TaskResult:
    task: Task
    success: bool
    stdout: str = ""
    stderr: str = ""
    elapsed: float = 0.0
    returncode: int = -1


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


def run_task(task: Task, task_index: int = 0, total: int = 0, parallel: bool = False) -> TaskResult:
    """Execute one pi task, streaming output in real-time, and return the result."""
    cmd = task.to_cmd()
    workdir = task.workdir()
    start = time.monotonic()

    # Build a prefix for output lines
    if parallel and total > 1:
        prefix = f"[task-{task_index}] "
    else:
        prefix = ""

    brief = " ".join(cmd[:4]) + ("..." if len(cmd) > 4 else "")
    log.info(">>  %s  [model=%s]  [timeout=%ss]  [dir=%s]",
             brief, task.model or "default", task.timeout, workdir)

    env = os.environ.copy()
    env.update(task.env)

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=workdir,
            env=env,
        )

        # Read stdout and stderr concurrently via threads
        from threading import Thread
        tout = Thread(target=_read_stream, args=(proc.stdout, prefix, stdout_lines), daemon=True)
        terr = Thread(target=_read_stream, args=(proc.stderr, prefix, stderr_lines), daemon=True)
        tout.start()
        terr.start()

        # Wait with timeout
        tout.join(timeout=task.timeout)
        terr.join(timeout=task.timeout)
        proc.wait(timeout=max(1, task.timeout - (time.monotonic() - start)))

        elapsed = time.monotonic() - start
        success = proc.returncode == 0
        stdout_text = "".join(stdout_lines)
        stderr_text = "".join(stderr_lines)

        if success:
            log.info("OK  done  [%.1fs]  [output=%s]", elapsed, task.output or "(stdout)")
        else:
            log.warning("FAIL  [code=%d]  [%.1fs]", proc.returncode, elapsed)

        return TaskResult(
            task=task,
            success=success,
            stdout=stdout_text,
            stderr=stderr_text,
            elapsed=elapsed,
            returncode=proc.returncode,
        )

    except subprocess.TimeoutExpired:
        proc.kill()
        elapsed = time.monotonic() - start
        log.error("TIMEOUT  [%.1fs]  [limit=%ss]", elapsed, task.timeout)
        return TaskResult(
            task=task,
            success=False,
            stderr=f"Task timed out after {task.timeout}s",
            elapsed=elapsed,
            returncode=-1,
        )

    except FileNotFoundError:
        log.error("'%s' not found in PATH. Is it installed? (configure agent.bin in pi-batch.yaml)", AGENT_BIN)
        return TaskResult(task=task, success=False, stderr=f"{AGENT_BIN} not found in PATH")

    except Exception as e:
        elapsed = time.monotonic() - start
        log.error("ERROR  [%.1fs]  [%s]", elapsed, e)
        return TaskResult(task=task, success=False, stderr=str(e), elapsed=elapsed)


def save_result(task: Task, result: TaskResult) -> None:
    """Write task result to its output file, or print to stdout."""
    out_path = task.output_path()
    if out_path is None:
        sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)

    if result.success:
        out_path.write_text(result.stdout, encoding="utf-8")
        log.info("WROTE %s  (%d bytes)", out_path, len(result.stdout))
    else:
        content = "# TASK FAILED (exit=%d, elapsed=%.1fs)\n\n" % (result.returncode, result.elapsed)
        if result.stderr:
            content += "## stderr\n\n```\n%s\n```\n\n" % result.stderr
        content += result.stdout
        out_path.write_text(content, encoding="utf-8")
        log.info("WROTE (with error info) %s", out_path)


# -- serial / parallel dispatch ---------------------------------------
def run_serial(tasks: list[Task]) -> list[TaskResult]:
    """Execute tasks one by one with real-time output streaming."""
    results = []
    total = len(tasks)
    for i, task in enumerate(tasks, 1):
        log.info("-- [%d/%d] --", i, total)
        result = run_task(task, task_index=i, total=total, parallel=False)
        save_result(task, result)
        results.append(result)
    return results


def run_parallel(tasks: list[Task], workers: int = AGENT_DEFAULT_WORKERS) -> list[TaskResult]:
    """Execute tasks concurrently with a thread pool and real-time output."""
    total = len(tasks)
    log.info("PARALLEL x%d  (%d tasks)", workers, total)

    results: list[TaskResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Pass task_index so parallel output lines are prefixed
        fut_map = {pool.submit(run_task, t, i, total, True): t for i, t in enumerate(tasks, 1)}
        for i, fut in enumerate(as_completed(fut_map), 1):
            task = fut_map[fut]
            result = fut.result()
            save_result(task, result)
            results.append(result)
            log.info("PROGRESS: %d/%d done", i, total)

    return results


# -- summary report ---------------------------------------------------
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


# -- CLI ---------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="pi-batch -- serial/parallel batch executor for pi agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("source", nargs="?",
                   help="YAML task file / JSON file / plain text prompt")
    p.add_argument("-p", "--prompt", help="inline prompt (single task shortcut)")
    p.add_argument("-o", "--output", help="output file path (single task only)")
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
    p.add_argument("--from-dir", metavar="DIR",
                   help="load one task per .md file in DIR")
    p.add_argument("--suffix", default=".md",
                   help="file suffix for --from-dir (default: .md)")
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
    p.add_argument("--dry-run", action="store_true",
                   help="print task list without executing")
    return p


def main() -> None:
    global AGENT_BIN
    args = build_parser().parse_args()
    AGENT_BIN = args.agent_bin

    # -- pipeline mode --
    if args.pipeline:
        pipeline = load_pipeline(args.pipeline)
        reuse_outputs = args.reuse and not args.force
        
        # Apply git_commit override to all stages
        if args.git_commit and not args.no_git_commit:
            for stage in pipeline.stages:
                stage.git_commit = True
        elif args.no_git_commit:
            for stage in pipeline.stages:
                stage.git_commit = False
        
        # Apply commit message prefix
        for stage in pipeline.stages:
            if stage.git_commit and not stage.commit_message:
                stage.commit_message = "%s Stage: %s" % (args.commit_prefix, stage.name)
        
        if dry_run := args.dry_run:
            run_pipeline(pipeline, model_override=args.model, dry_run=True, reuse=reuse_outputs)
            return
        
        try:
            all_results = run_pipeline(pipeline, model_override=args.model, reuse=reuse_outputs)
            print_summary(all_results)
            if any(not r.success for r in all_results):
                sys.exit(1)
        except KeyboardInterrupt:
            log.warning("Interrupted by user")
            sys.exit(130)
        return

    # -- single-stage modes --
    if args.from_dir:
        tasks = load_tasks_from_dir(args.from_dir, args.suffix)
        if not tasks:
            log.error("No %s files found in %s", args.suffix, args.from_dir)
            sys.exit(1)
    elif args.prompt:
        tasks = [Task(prompt=args.prompt, output=args.output or "")]
    elif args.source:
        tasks = load_tasks(args.source)
    else:
        stdin = sys.stdin.read().strip()
        if stdin:
            tasks = [Task(prompt=stdin)]
        else:
            log.error("Provide a prompt (-p), a task file, --from-dir, or --pipeline")
            sys.exit(1)

    # Apply single-task output shortcut
    if args.output and len(tasks) == 1:
        tasks[0].output = args.output

    # Apply global overrides
    if args.model:
        for t in tasks:
            t.model = args.model
    if args.timeout:
        for t in tasks:
            t.timeout = args.timeout

    if not tasks:
        log.error("No tasks to execute")
        sys.exit(1)

    # -- dry-run --
    if args.dry_run:
        print("Tasks: %d" % len(tasks))
        print("Mode:  %s" % args.mode)
        print()
        for i, t in enumerate(tasks, 1):
            print("  [%d] %s..." % (i, t.prompt[:80]))
            print("      model=%s  dir=%s  output=%s" %
                  (t.model or "default", t.workdir(), t.output or "(stdout)"))
        return

    # -- execute --
    try:
        if args.mode == "serial":
            results = run_serial(tasks)
        else:
            results = run_parallel(tasks, args.workers)

        print_summary(results)

        # Git commit for single-stage modes
        if not args.pipeline and args.git_commit and not args.no_git_commit:
            import subprocess
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

        if any(not r.success for r in results):
            sys.exit(1)

    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()
