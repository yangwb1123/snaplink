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
import signal
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
    """Optional defaults for pi-batch.py. Resolution order: the file next to
    this script (ai-dev/pi-batch.yaml when run from the repository root),
    then the process working directory. Missing file -> {} (built-in defaults
    below apply), so the script still runs standalone with zero config --
    copy pi-batch.yaml alongside pi-batch.py to point it at a different
    agent CLI."""
    for p in (Path(__file__).resolve().parent / Path(path).name, Path(path)):
        if not yaml or not p.exists():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            return data
    return {}


_BATCH_CFG = _load_batch_config()
_AGENT_CFG = _BATCH_CFG.get("agent", {})
AGENT_BIN = _AGENT_CFG.get("bin", "pi")
AGENT_DEFAULT_MODEL = _AGENT_CFG.get("default_model", "")
AGENT_DEFAULT_TIMEOUT = _AGENT_CFG.get("default_timeout", 300)
AGENT_DEFAULT_WORKERS = _AGENT_CFG.get("default_workers", 4)
COMMIT_PREFIX_DEFAULT = _BATCH_CFG.get("commit", {}).get("prefix", "[pi-batch]")

# pi-style session flags, used when pi-batch.yaml does not define
# agent.session_flags (other agent CLIs can override via that key).
# {session} and {name} placeholders are substituted per run.
_DEFAULT_SESSION_FLAGS = {
    "start": ["--session-id", "{session}", "--name", "{name}"],
    "continue": ["--session-id", "{session}"],
}


def _session_flags(key: str, session_id: str, session_name: str) -> list:
    """Resolve the configured session flags for a call (start or continue),
    replacing {session} and {name} placeholders. Falls back to pi-style
    flags when the config does not define agent.session_flags."""
    cfg = (_AGENT_CFG.get("session_flags") or {}) if isinstance(_AGENT_CFG.get("session_flags"), dict) else {}
    flags = cfg.get(key) or _DEFAULT_SESSION_FLAGS[key]
    return [f.replace("{session}", session_id).replace("{name}", session_name) for f in flags]


def _load_validators() -> dict:
    """Read the named validators registry from pi-batch.yaml (like the
    project's engineering.yaml declares gates for cli.py); empty when absent
    so the script stays portable."""
    if not yaml:
        return {}
    path = Path(__file__).resolve().parent / "pi-batch.yaml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    v = data.get("validators")
    return dict(v) if isinstance(v, dict) else {}


VALIDATORS = _load_validators()


def _resolve_validators(value: str) -> list:
    """Expand a comma-separated list into validation commands: registry names
    are replaced by their pi-batch.yaml command, anything else is used as a
    raw shell command. Empty value -> no validation."""
    out = []
    for item in [x.strip() for x in (value or "").split(",") if x.strip()]:
        out.append(VALIDATORS.get(item, item))
    return out


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
    aggregate: bool = False  # from_outputs: merge all upstream outputs into one prompt per template
    validate_cmd: Optional[str] = None  # None = inherit CLI --validate-cmd, "" = disabled, else command
    meta: bool = False  # dynamic role orchestration: agent picks review roles per iteration
    meta_prompt: str = ""  # custom orchestrator prompt ({roles}/{input_content} placeholders)
    role_dir: str = ""  # directory of role templates the orchestrator may choose from
    output_dir: str = ""  # where role deliverables are written (required for meta stages)
    max_iterations: int = 3  # orchestrator -> roles -> fold -> re-ask loop limit
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
            "aggregate": self.aggregate,
            "validate_cmd": self.validate_cmd,
            "meta": self.meta,
            "meta_prompt": self.meta_prompt,
            "role_dir": self.role_dir,
            "output_dir": self.output_dir,
            "max_iterations": self.max_iterations,
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
        log.error("PyYAML not installed. Install the project: uv sync (or pip install pyyaml)")
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
            aggregate=s.get("aggregate", False),
            validate_cmd=s.get("validate_cmd"),
            meta=s.get("meta", False),
            meta_prompt=s.get("meta_prompt", ""),
            role_dir=s.get("role_dir", ""),
            output_dir=s.get("output_dir", ""),
            max_iterations=s.get("max_iterations", 3),
            tasks=s.get("tasks", []),
            commands=s.get("commands", []),
            commands_parallel=s.get("commands_parallel", False),
            cwd=s.get("cwd", ""),
            git_commit=s.get("git_commit", global_git_commit),
            commit_message=s.get("commit_message", ""),
        )
        stages.append(stage)
    
    return Pipeline(stages=stages)


def _task_from_def(task_def: dict, prompt: str, output_path: str, model_override: str = "", timeout_override: int = 0) -> Task:
    """Build a task from a pipeline template definition, applying CLI-level
    model and timeout overrides on top of per-task values."""
    task = Task(
        prompt=prompt,
        output=output_path,
        model=task_def.get("model", ""),
        cwd=task_def.get("cwd", ""),
        timeout=task_def.get("timeout", 300),
    )
    if model_override:
        task.model = model_override
    if timeout_override:
        task.timeout = timeout_override
    return task


def _combine_outputs(prev_outputs: list) -> str:
    """Concatenate upstream artifacts into one evidence block."""
    parts = []
    for out_path_str in prev_outputs:
        out_path = Path(out_path_str)
        if not out_path.exists():
            log.warning("Output file not found: %s", out_path)
            continue
        parts.append("--- %s ---\n%s" % (out_path.stem, out_path.read_text(encoding="utf-8")))
    return "\n\n".join(parts)


def _aggregate_tasks(stage: Stage, prev_outputs: list, model_override: str = "", timeout_override: int = 0, reuse: bool = False) -> tuple[list[Task], list[str]]:
    """Combine every upstream artifact into one prompt per task template so
    downstream roles see all evidence (input_stem becomes 'combined') instead
    of fanning each artifact into an independent task.

    Returns (new_tasks, reused_output_paths). With reuse=True, a template
    whose combined output file already exists is skipped and its path is
    returned as reused so downstream stages still see it.
    """
    combined = _combine_outputs(prev_outputs)
    if not combined:
        log.warning("No upstream outputs available for aggregate stage '%s'", stage.name)
        return [], []

    tasks = []
    reused = []
    for task_def in stage.tasks:
        prompt_template_path = Path(task_def.get("prompt_template", ""))
        if not prompt_template_path.exists():
            log.error("Prompt template not found: %s", prompt_template_path)
            continue
        template = prompt_template_path.read_text(encoding="utf-8")
        prompt = template.replace("{input_content}", combined)
        prompt = prompt.replace("{input_stem}", "combined")
        prompt = prompt.replace("{input_path}", ", ".join(prev_outputs))
        output_path = task_def.get("output", "").replace("{input_stem}", "combined")
        if reuse and output_path and Path(output_path).exists():
            log.info("REUSE: %s (output exists)", output_path)
            reused.append(output_path)
            continue
        tasks.append(_task_from_def(task_def, prompt, output_path, model_override, timeout_override))
    return tasks, reused


# Orchestrator prompt for meta stages: the agent looks at the current
# deliverables and picks the review roles that still add value.
_DEFAULT_META_PROMPT = """Analyze the deliverables below and decide which expert review roles are still needed to harden them.

Available roles: {roles}

Rules:
- Only choose roles that add real value for this deliverable set.
- Output ONLY a JSON array of role names, e.g. ["security_engineer", "qa_lead"].
- Output [] when the deliverables are complete.

Deliverables:
{input_content}
"""


def _available_roles(role_dir: str) -> list:
    """List role template names (file stems) inside role_dir."""
    base = Path(role_dir).resolve()
    if not base.is_dir():
        log.error("Role dir not found: %s", role_dir)
        return []
    return sorted(p.stem for p in base.glob("*.md") if p.stem != "README")


def _load_role_template(role_dir: str, role: str) -> Optional[str]:
    """Load a role template by name, refusing anything outside role_dir (the
    orchestrator output is untrusted input)."""
    base = Path(role_dir).resolve()
    target = (base / (role + ".md")).resolve()
    if not base.is_dir() or not target.is_file() or not str(target).startswith(str(base)):
        log.warning("Unknown role template: %s (must be a .md file inside %s)", role, role_dir)
        return None
    return target.read_text(encoding="utf-8")


def _parse_role_list(stdout: str) -> list:
    """Parse a JSON role list from the orchestrator output, tolerating prose
    and markdown fences around the array. Unparseable output -> [] (treat as
    'no more roles needed')."""
    m = re.search(r"\[[^\]]*\]", stdout or "", re.S)
    if m:
        try:
            data = json.loads(m.group(0))
            if isinstance(data, list):
                return [str(x).strip() for x in data if str(x).strip()]
        except json.JSONDecodeError:
            pass
    log.warning("META orchestrator output did not contain a JSON role list; treating as complete")
    return []


def _run_meta_stage(stage: Stage, stage_outputs: dict, model_override: str = "", timeout_override: int = 0,
                    validate_cmd: str = "") -> tuple[list[TaskResult], bool]:
    """Dynamic role orchestration: ask the agent which roles the current
    deliverables still need, execute each chosen role template against the
    aggregated inputs, fold the role deliverables back into the evidence, and
    iterate until the orchestrator reports no more roles or max_iterations is
    reached. This is the self-optimizing part: the role set is discovered
    during execution instead of fixed in the pipeline."""
    if stage.from_outputs not in stage_outputs:
        log.error("Previous stage '%s' not found", stage.from_outputs)
        return [], False
    if not stage.output_dir:
        log.error("Meta stage '%s' requires output_dir for role deliverables", stage.name)
        return [], False

    combined = _combine_outputs(stage_outputs[stage.from_outputs])
    if not combined:
        log.warning("No upstream outputs available for meta stage '%s'", stage.name)
        return [], True

    role_names = _available_roles(stage.role_dir)
    if not role_names:
        log.error("Meta stage '%s': no role templates found in %s", stage.name, stage.role_dir)
        return [], False
    out_dir = Path(stage.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results: list[TaskResult] = []
    role_outputs: list[str] = []
    for iteration in range(1, stage.max_iterations + 1):
        log.info("META iteration %d/%d for stage '%s' (roles available: %s)",
                 iteration, stage.max_iterations, stage.name, ", ".join(role_names))
        meta_prompt = (stage.meta_prompt or _DEFAULT_META_PROMPT)
        meta_prompt = meta_prompt.replace("{roles}", ", ".join(role_names)).replace("{input_content}", combined)
        meta_task = Task(prompt=meta_prompt)
        if model_override:
            meta_task.model = model_override
        if timeout_override:
            meta_task.timeout = timeout_override
        meta_result = run_task(meta_task)
        if not meta_result.success:
            log.warning("META orchestrator call failed: %s; stopping role expansion", meta_result.reason)
            break
        roles = _parse_role_list(meta_result.stdout)
        if not roles:
            log.info("META orchestrator: no more roles needed (iteration %d)", iteration)
            break
        log.info("META orchestrator selected roles: %s", ", ".join(roles))

        iteration_ok = True
        for role in roles:
            template = _load_role_template(stage.role_dir, role)
            if template is None:
                iteration_ok = False
                continue
            prompt = template.replace("{input_content}", combined).replace("{input_stem}", stage.name)
            out_path = out_dir / f"{role}.md"
            task = Task(prompt=prompt, output=str(out_path))
            if model_override:
                task.model = model_override
            if timeout_override:
                task.timeout = timeout_override
            result = run_task(task)
            if result.success:
                result.success = _save_validated(task, result, validate_cmd)
                if not result.success:
                    result.reason = "validation failed"
            all_results.append(result)
            if not result.success:
                iteration_ok = False
            role_outputs.append(str(out_path))
            # fold the role deliverable back into the evidence for the next
            # orchestrator round (self-optimization loop)
            if out_path.exists():
                combined += f"\n\n--- {role} deliverable ---\n" + out_path.read_text(encoding="utf-8")
        if not iteration_ok:
            log.warning("META stage '%s': some role tasks failed in iteration %d", stage.name, iteration)
            break

    stage_outputs[stage.name] = role_outputs
    return all_results, all(r.success for r in all_results)


def execute_stage(stage: Stage, stage_outputs: dict[str, list[str]], model_override: str = "", reuse: bool = False, timeout_override: int = 0,
                  session_mode: str = "new", session_name: str = "", validate_cmd: str = "") -> tuple[list[TaskResult], bool]:
    """Execute one stage and return (task_results, stage_ok).

    stage_ok is False when any task or configured post-stage command failed,
    so command hooks act as a failure gate for the pipeline.

    Args:
        stage: Stage definition
        stage_outputs: dict mapping stage name -> list of output file paths
        model_override: override model for all tasks
        reuse: if True, skip tasks whose output files already exist
        timeout_override: per-task timeout override (seconds)
        session_mode: "new" (fresh session per call), "shared" (one session
            for the whole pipeline), or "per-stage" (one session per stage)
        session_name: reproducible base name for shared/per-stage sessions
        validate_cmd: engineering validation run before each output is saved
    """
    log.info("")
    log.info("=" * 60)
    log.info("STAGE: %s", stage.name)
    if reuse:
        log.info("(reusing existing outputs if available)")
    log.info("=" * 60)
    
    tasks: list[Task] = []
    reused_outputs: list[str] = []

    # Dynamic role orchestration (meta stage) is handled entirely here.
    if stage.meta:
        return _run_meta_stage(stage, stage_outputs, model_override, timeout_override, validate_cmd)
    
    # Stage type 1: from_dir - read .md files from directory
    if stage.from_dir:
        dir_path = Path(stage.from_dir)
        if not dir_path.is_dir():
            log.error("Directory not found: %s", stage.from_dir)
            return [], False
        
        for fpath in sorted(dir_path.glob(f"*{stage.suffix}")):
            if fpath.name.endswith(stage.output_suffix):
                continue
            prompt = fpath.read_text(encoding="utf-8")
            out_path = fpath.parent / (fpath.stem + stage.output_suffix)
            
            # Check if output already exists and reuse flag is set
            if reuse and out_path.exists():
                log.info("REUSE: %s (output exists: %s)", fpath.name, out_path.name)
                reused_outputs.append(str(out_path))
                continue
            
            task = Task(
                prompt=prompt,
                output=str(out_path),
                cwd=str(fpath.parent),
            )
            if model_override:
                task.model = model_override
            if timeout_override:
                task.timeout = timeout_override
            tasks.append(task)
        
        log.info("Loaded %d tasks from %s", len(tasks), stage.from_dir)
    
    # Stage type 2: from_outputs - use outputs from previous stage
    elif stage.from_outputs:
        if stage.from_outputs not in stage_outputs:
            log.error("Previous stage '%s' not found", stage.from_outputs)
            return [], False

        prev_outputs = stage_outputs[stage.from_outputs]

        if stage.aggregate:
            # Merge every upstream artifact into one combined prompt per
            # template so downstream roles see all evidence, instead of
            # fanning each artifact into independent (and conflicting) tasks.
            agg_tasks, agg_reused = _aggregate_tasks(stage, prev_outputs, model_override, timeout_override, reuse)
            tasks.extend(agg_tasks)
            reused_outputs.extend(agg_reused)
        else:
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

                    if reuse and output_path and Path(output_path).exists():
                        log.info("REUSE: %s (output exists)", output_path)
                        reused_outputs.append(output_path)
                        continue

                    tasks.append(_task_from_def(task_def, prompt, output_path, model_override, timeout_override))

        log.info("Loaded %d tasks from %d outputs of stage '%s'",
                 len(tasks), len(prev_outputs), stage.from_outputs)

    else:
        log.error("Stage '%s' must have either 'from_dir' or 'from_outputs'", stage.name)
        return [], False

    if not tasks:
        if reused_outputs:
            stage_outputs[stage.name] = reused_outputs
            log.info("Stage '%s' fully reused (%d outputs)", stage.name, len(reused_outputs))
            return [], True
        log.warning("No tasks to execute in stage '%s'", stage.name)
        return [], True

    # Shared sessions must not run in parallel: interleaved calls would
    # corrupt the conversation order inside one session.
    if session_mode != "new" and stage.mode == "parallel":
        log.error("Stage '%s': --session-mode %s requires serial execution (parallel would interleave one session)",
                  stage.name, session_mode)
        return [], False

    stage_session_id = session_name
    if session_mode == "per-stage":
        stage_session_id = f"{session_name}-{stage.name}"

    # Per-stage engineering gate: the stage's own validate_cmd wins over the
    # CLI default ("" disables validation for this stage), and per-task
    # validate fields override both inside run_serial/run_parallel.
    stage_validate = stage.validate_cmd if stage.validate_cmd is not None else validate_cmd

    # Execute tasks
    if stage.mode == "parallel":
        results = run_parallel(tasks, stage.workers, validate_cmd=stage_validate)
    else:
        results = run_serial(tasks, retries=0, session_mode=session_mode, session_id=stage_session_id, session_name=session_name,
                             validate_cmd=stage_validate)
    
    # Collect output paths (reused outputs keep feeding downstream stages)
    outputs = list(reused_outputs)
    for r in results:
        if r.success and r.task.output:
            outputs.append(r.task.output)
    
    stage_outputs[stage.name] = outputs
    
    log.info("")
    log.info("Stage '%s' completed: %d/%d tasks succeeded", 
             stage.name, len(outputs), len(tasks))

    stage_ok = all(r.success for r in results)
    
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
            stage_ok = False
            log.warning("Stage '%s' FAILED: some post-stage commands failed", stage.name)
    
    # Git commit after stage
    if stage.git_commit and outputs:
        try:
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
    
    return results, stage_ok


def run_pipeline(pipeline: Pipeline, model_override: str = "", dry_run: bool = False, reuse: bool = False, timeout_override: int = 0,
                 session_mode: str = "new", session_name: str = "", validate_cmd: str = "") -> tuple[list[TaskResult], list[str]]:
    """Execute all stages in a pipeline sequentially.
    
    Args:
        pipeline: Pipeline definition
        model_override: override model for all tasks
        dry_run: if True, only print task list without executing
        reuse: if True, skip tasks whose output files already exist
        timeout_override: per-task timeout override (seconds)
        session_mode: "new", "shared" (one session for the whole pipeline),
            or "per-stage" (one session per stage)
        session_name: reproducible base name for shared/per-stage sessions
        validate_cmd: engineering validation run before each output is saved
    
    Returns:
        (all task results, names of stages that failed tasks or commands)
    """
    all_results: list[TaskResult] = []
    failed_stages: list[str] = []
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
        
        results, stage_ok = execute_stage(stage, stage_outputs, model_override, reuse, timeout_override, session_mode, session_name, validate_cmd)
        all_results.extend(results)
        if not stage_ok:
            failed_stages.append(stage.name)
    
    return all_results, failed_stages


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
    validate: Optional[str] = None  # per-task engineering gate; None = inherit, "" = disabled

    def to_cmd(self, session_flags: Optional[list] = None) -> list[str]:
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
        if session_flags:
            cmd.extend(session_flags)
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
    reason: str = ""  # human-readable failure cause (agent rejection, timeout, ...)


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


# Provider/CLI failure signatures. Only signatures that never appear in
# legitimate agent output are matched across the whole stdout; generic words
# like "error" or "timeout" are intentionally absent so that review findings
# about timeouts or unauthorized responses are not misclassified. The network
# group covers offline/DNS/TLS/proxy failures, which agent CLIs report with
# these exact phrases when the machine loses connectivity.
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
            start_new_session=True,  # own process group so the whole child tree can be killed on timeout
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
        reason = agent_failure_reason(proc.returncode, stdout_text)
        if reason:
            success = False
            log.warning("agent output REJECTED: %s", reason)

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
            reason=reason or "",
        )

    except subprocess.TimeoutExpired:
        # Kill the whole group: the direct child may have spawned helpers
        # (e.g. a shell running sleep) that keep the pipes open.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            proc.kill()
        elapsed = time.monotonic() - start
        log.error("TIMEOUT  [%.1fs]  [limit=%ss]", elapsed, task.timeout)
        return TaskResult(
            task=task,
            success=False,
            stderr=f"Task timed out after {task.timeout}s",
            elapsed=elapsed,
            returncode=-1,
            reason="task timed out",
        )

    except FileNotFoundError:
        log.error("'%s' not found in PATH. Is it installed? (configure agent.bin in pi-batch.yaml)", AGENT_BIN)
        return TaskResult(task=task, success=False, stderr=f"{AGENT_BIN} not found in PATH", reason="agent binary not found")

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

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.stdout, encoding="utf-8")
    log.info("WROTE %s  (%d bytes)", out_path, len(result.stdout))


# -- serial / parallel dispatch ---------------------------------------
# Failure reasons that typically clear up on their own (rate limits, quota,
# offline conditions) deserve a longer retry backoff.
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


def run_parallel(tasks: list[Task], workers: int = AGENT_DEFAULT_WORKERS, validate_cmd: str = "") -> list[TaskResult]:
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
    p.add_argument("--log-file", default="",
                   help="Append run log to FILE for 24x7 supervision")
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


def main() -> None:
    global AGENT_BIN
    args = build_parser().parse_args()
    AGENT_BIN = args.agent_bin

    # Append run log to FILE for 24x7 supervision
    if args.log_file:
        fh = logging.FileHandler(args.log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        log.addHandler(fh)

    # -- pipeline setup (one-time) --
    pipeline = None
    reuse_outputs = False
    timeout_override = 0
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
        
        # Explicit CLI flags override per-stage mode/workers; --timeout is
        # threaded through execute_stage so every task inherits it. argparse
        # cannot report whether a flag that has a default was passed, so scan
        # argv for the exact flag names.
        if "--mode" in sys.argv:
            for stage in pipeline.stages:
                stage.mode = args.mode
        if "-w" in sys.argv or "--workers" in sys.argv:
            for stage in pipeline.stages:
                stage.workers = args.workers
        timeout_override = args.timeout if "--timeout" in sys.argv else 0
        
        # Apply commit message prefix
        for stage in pipeline.stages:
            if stage.git_commit and not stage.commit_message:
                stage.commit_message = "%s Stage: %s" % (args.commit_prefix, stage.name)

    # -- round loop for 24x7 operation --
    # Each round reruns only the tasks/stages that failed or were rejected
    # (reuse skips existing outputs). --max-rounds 0 loops forever until every
    # task passes, with --round-delay seconds of rest between rounds so quota
    # and rate-limit windows can clear.
    max_rounds = args.max_rounds
    stdin_tasks = None  # stdin is consumed once; later rounds reuse it
    round_no = 0

    # Session semantics: shared/per-stage require serial execution and a
    # reproducible session name so a resumed run continues the same session.
    session_name = args.session_name
    if not session_name:
        if args.pipeline:
            session_name = Path(args.pipeline).stem
        elif args.source:
            session_name = Path(args.source).stem
        elif args.from_dir:
            session_name = Path(args.from_dir).name
        else:
            session_name = "batch"
    if args.session_mode != "new" and args.mode == "parallel" and not args.pipeline:
        log.error("--session-mode %s requires --mode serial (parallel would interleave one session)", args.session_mode)
        sys.exit(1)
    if args.session_mode == "per-stage" and not args.pipeline:
        log.error("--session-mode per-stage requires --pipeline (there are no stages in single-batch mode)")
        sys.exit(1)

    # Validation gates: named validators (--validate) and the raw command
    # (--validate-cmd) both apply, in that order, with AND semantics.
    cli_validate = ",".join(x for x in (args.validate, args.validate_cmd) if x)

    try:
        while True:
            round_no += 1
            log.info("")
            log.info("=" * 60)
            log.info("ROUND %d of %s", round_no, "unlimited" if max_rounds == 0 else max_rounds)
            log.info("=" * 60)

            round_failed = False

            if pipeline is not None:
                # -- pipeline mode --
                if args.dry_run:
                    run_pipeline(pipeline, model_override=args.model, dry_run=True, reuse=reuse_outputs)
                    return
                all_results, failed_stages = run_pipeline(pipeline, model_override=args.model, reuse=reuse_outputs, timeout_override=timeout_override,
                                                         session_mode=args.session_mode, session_name=session_name, validate_cmd=cli_validate)
                print_summary(all_results)
                round_failed = bool(failed_stages or any(not r.success for r in all_results))
                if round_failed:
                    log.error("Failed stages: %s", ", ".join(failed_stages) if failed_stages else "(task failures)")
            else:
                # -- single-batch modes --
                if args.from_dir:
                    tasks = load_tasks_from_dir(args.from_dir, args.suffix)
                    if not tasks:
                        log.error("No %s files found in %s", args.suffix, args.from_dir)
                        sys.exit(1)
                elif args.prompt:
                    tasks = [Task(prompt=args.prompt, output=args.output or "")]
                elif args.source:
                    tasks = load_tasks(args.source)
                elif stdin_tasks is not None:
                    tasks = stdin_tasks
                else:
                    stdin = sys.stdin.read().strip()
                    if stdin:
                        stdin_tasks = [Task(prompt=stdin)]
                        tasks = stdin_tasks
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

                # reuse: drop tasks whose output already exists, so a later
                # round reruns only the failures
                if args.reuse and not args.force:
                    kept = [t for t in tasks if not (t.output and Path(t.output).exists())]
                    skipped = len(tasks) - len(kept)
                    if skipped:
                        log.info("Reuse: %d task(s) already have outputs, skipped", skipped)
                    tasks = kept
                    if not tasks:
                        log.info("All tasks already have outputs; nothing to run")
                        return

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
                if args.mode == "serial":
                    results = run_serial(tasks, retries=args.retries, retry_delay=args.retry_delay,
                                         backoff=args.retry_backoff, min_interval=args.min_interval,
                                         session_mode=args.session_mode, session_id=session_name, session_name=session_name,
                                         validate_cmd=cli_validate)
                else:
                    results = run_parallel(tasks, args.workers, validate_cmd=cli_validate)

                print_summary(results)
                round_failed = any(not r.success for r in results)

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

            if not round_failed:
                log.info("All tasks passed in round %d", round_no)
                return
            if max_rounds > 0 and round_no >= max_rounds:
                log.error("Max rounds (%d) reached with tasks still failing; rerun with --reuse to continue later", max_rounds)
                sys.exit(1)
            log.warning("Round %d finished with failures; waiting %.0fs before round %d",
                        round_no, args.round_delay, round_no + 1)
            time.sleep(args.round_delay)
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()
