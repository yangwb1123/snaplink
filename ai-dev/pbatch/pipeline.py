"""Pipeline execution: stage task builders, meta role orchestration,
verdict gates, decision logs, archiving, and task-source loading."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import config
from .config import AGENT_DEFAULT_TIMEOUT, AGENT_DEFAULT_WORKERS, log, yaml
from .models import Pipeline, Stage, Task
from .runner import _save_validated, print_summary, run_parallel, run_serial, run_task

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

    stages = [_parse_stage_def(s, global_git_commit) for s in data["stages"]]
    
    return Pipeline(stages=stages, decision_log=data.get("decision_log", ""),
                    archive_dir=data.get("archive_dir", ""), name=Path(path).stem)


def _parse_stage_def(s: dict, global_git_commit: bool) -> Stage:
    """Map one YAML stage definition onto a Stage (untrusted keys ignored;
    unknown keys simply do not exist on the dataclass)."""
    return Stage(
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
        gate=s.get("gate", False),
        from_prompt=s.get("from_prompt", ""),
        output=s.get("output", ""),
        tasks=s.get("tasks", []),
        commands=s.get("commands", []),
        commands_parallel=s.get("commands_parallel", False),
        cwd=s.get("cwd", ""),
        git_commit=s.get("git_commit", global_git_commit),
        commit_message=s.get("commit_message", ""),
    )


def _task_prompt(task_def: dict, input_content: str, input_stem: str, input_path: str) -> str:
    """Build the prompt for a task definition: a literal 'prompt' string or
    a 'prompt_template' file, both with {input_content}/{input_stem}/{input_path}
    placeholders. Returns '' when neither is present (caller skips it)."""
    prompt = task_def.get("prompt", "")
    prompt_template_path = Path(task_def.get("prompt_template", ""))
    if task_def.get("prompt_template") and prompt_template_path.exists():
        prompt = prompt_template_path.read_text(encoding="utf-8")
    if not prompt:
        log.error("Task in stage needs 'prompt' or an existing 'prompt_template' file")
        return ""
    return (prompt.replace("{input_content}", input_content)
                 .replace("{input_stem}", input_stem)
                 .replace("{input_path}", input_path))


def _task_from_def(task_def: dict, prompt: str, output_path: str, model_override: str = "", timeout_override: int = 0) -> Task:
    """Build a task from a pipeline template definition, applying CLI-level
    model and timeout overrides on top of per-task values."""
    task = Task(
        prompt=prompt,
        output=output_path,
        model=task_def.get("model", ""),
        cwd=task_def.get("cwd", ""),
        timeout=task_def.get("timeout", AGENT_DEFAULT_TIMEOUT),
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
        prompt = _task_prompt(task_def, combined, "combined", ", ".join(prev_outputs))
        if not prompt:
            continue
        output_path = task_def.get("output", "").replace("{input_stem}", "combined")
        if reuse and output_path and Path(output_path).exists():
            log.info("REUSE: %s (output exists)", output_path)
            reused.append(output_path)
            continue
        tasks.append(_task_from_def(task_def, prompt, output_path, model_override, timeout_override))
    return tasks, reused


_DEFAULT_META_PROMPT = """Analyze the deliverables below and decide which expert review roles are still needed to harden them.

Available roles: {roles}

Rules:
- Only choose roles that add real value for this deliverable set.
- Prefer a role name from the list above.
- When no listed role fits, define an ad-hoc role as a JSON object
  {{\"role\": \"<name>\", \"task\": \"<assignment for this reviewer>\"}}.
- Output ONLY a JSON array of role names and/or role objects, e.g.
  ["security_engineer", {{\"role\": \"perf_reviewer\", \"task\": \"Analyze performance bottlenecks\"}}].
- Output [] when the deliverables are complete.

Deliverables:
{input_content}
"""


def _available_roles(role_dir: str) -> list:
    """List role template names (file stems) inside role_dir; empty when the
    dir is missing (meta stages may still run with ad-hoc roles only)."""
    base = Path(role_dir).resolve()
    if not base.is_dir():
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


def _parse_role_plan(stdout: str) -> list:
    """Parse the orchestrator plan from its JSON output, tolerating prose and
    markdown fences. Each plan item is either a role name (string, resolved
    against role_dir) or an ad-hoc role {"role": ..., "task": ...}. Unparseable
    output -> [] (treat as 'no more roles needed')."""
    m = re.search(r"\[[^\]]*\]", stdout or "", re.S)
    if m:
        try:
            data = json.loads(m.group(0))
            if isinstance(data, list):
                plan = []
                for item in data:
                    if isinstance(item, str) and item.strip():
                        plan.append({"role": item.strip(), "task": ""})
                    elif isinstance(item, dict) and str(item.get("role", "")).strip():
                        plan.append({"role": str(item["role"]).strip(),
                                     "task": str(item.get("task", "")).strip()})
                return plan
        except json.JSONDecodeError:
            pass
    log.warning("META orchestrator output did not contain a JSON role plan; treating as complete")
    return []


def _run_meta_stage(stage: Stage, stage_outputs: dict, model_override: str = "", timeout_override: int = 0,
                    validate_cmd: str = "") -> tuple[list[TaskResult], bool]:
    """Dynamic role orchestration: ask the agent which roles the current
    deliverables still need, execute each chosen role against the aggregated
    inputs, fold the role deliverables back into the evidence, and iterate
    until the orchestrator reports no more roles or max_iterations is
    reached (self-optimizing: the role set is discovered at run time)."""
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
    out_dir = Path(stage.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results: list[TaskResult] = []
    role_outputs: list[str] = []
    for iteration in range(1, stage.max_iterations + 1):
        done, ok, combined = _run_meta_iteration(stage, combined, role_names, model_override, timeout_override,
                                                 validate_cmd, iteration, all_results, role_outputs)
        if done or not ok:
            break

    stage_outputs[stage.name] = role_outputs
    return all_results, all(r.success for r in all_results)


def _run_meta_iteration(stage: Stage, combined: str, role_names: list, model_override: str, timeout_override: int,
                        validate_cmd: str, iteration: int, all_results: list, role_outputs: list) -> tuple[bool, bool, str]:
    """One orchestrator round: ask which roles are needed, run them
    concurrently (each in its own session), fold deliverables back into the
    evidence (returned as the new combined context). Returns (done, ok,
    combined): done=True stops the loop (orchestrator failure, no roles
    left, or role failures)."""
    log.info("META iteration %d/%d for stage '%s' (roles available: %s)",
             iteration, stage.max_iterations, stage.name, ", ".join(role_names) or "(none)")
    meta_task = _build_meta_prompt_task(stage, role_names, combined, model_override, timeout_override)
    meta_result = run_task(meta_task)
    if not meta_result.success:
        log.warning("META orchestrator call failed: %s; stopping role expansion", meta_result.reason)
        return True, False, combined
    roles = _parse_role_plan(meta_result.stdout)
    if not roles:
        log.info("META orchestrator: no more roles needed (iteration %d)", iteration)
        return True, True, combined
    log.info("META orchestrator selected %d role(s)", len(roles))

    role_tasks, iteration_ok = _build_role_tasks(stage, roles, combined, model_override, timeout_override)

    def _run_role(item):
        role, task = item
        result = run_task(task, parallel=True)
        if result.success:
            result.success = _save_validated(task, result, validate_cmd)
            if not result.success:
                result.reason = "validation failed"
        return role, result

    with ThreadPoolExecutor(max_workers=max(1, stage.workers or config.AGENT_DEFAULT_WORKERS)) as pool:
        futures = [pool.submit(_run_role, item) for item in role_tasks]
        for fut in as_completed(futures):
            role, result = fut.result()
            all_results.append(result)
            if not result.success:
                iteration_ok = False
            if result.task.output:
                role_outputs.append(result.task.output)
                # fold the role deliverable back into the evidence for
                # the next orchestrator round (self-optimization loop)
                out_path = Path(result.task.output)
                if out_path.exists():
                    combined += f"\n\n--- {role} deliverable ---\n" + out_path.read_text(encoding="utf-8")
    if not iteration_ok:
        log.warning("META stage '%s': some role tasks failed in iteration %d", stage.name, iteration)
        return True, False, combined
    return False, True, combined


def _build_meta_prompt_task(stage: Stage, role_names: list, combined: str, model_override: str, timeout_override: int) -> Task:
    """Assemble the orchestrator prompt (custom meta_prompt or the default,
    with {roles}/{input_content} placeholders) as a task."""
    meta_prompt = (stage.meta_prompt or _DEFAULT_META_PROMPT)
    meta_prompt = meta_prompt.replace("{roles}", ", ".join(role_names) or "(none - define ad-hoc roles)")
    meta_prompt = meta_prompt.replace("{input_content}", combined)
    task = Task(prompt=meta_prompt)
    if model_override:
        task.model = model_override
    if timeout_override:
        task.timeout = timeout_override
    return task


def _build_role_tasks(stage: Stage, roles: list, combined: str, model_override: str, timeout_override: int) -> tuple[list, bool]:
    """Turn the orchestrator plan into tasks: ad-hoc roles ({"role",
    "task"}) get their task description plus the current context; named
    roles load the role_dir template. Output names are sanitized (the
    orchestrator output is untrusted). Returns ([(role, Task)], ok); ok is
    False when a named role had no template."""
    role_tasks = []
    ok = True
    for item in roles:
        role = item["role"]
        task_desc = item["task"]
        if task_desc:
            prompt = f"{task_desc}\n\nContext (current deliverables):\n{combined}"
        else:
            template = _load_role_template(stage.role_dir, role)
            if template is None:
                ok = False
                continue
            prompt = template.replace("{input_content}", combined).replace("{input_stem}", stage.name)
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", role) or "role"
        out_path = Path(stage.output_dir) / f"{safe_name}.md"
        task = Task(prompt=prompt, output=str(out_path))
        if model_override:
            task.model = model_override
        if timeout_override:
            task.timeout = timeout_override
        role_tasks.append((role, task))
    return role_tasks, ok


def _stage_from_prompt_tasks(stage: Stage, reuse: bool, model_override: str, timeout_override: int) -> tuple[list[Task], list[str]]:
    """One-sentence starting point: a single task whose output feeds
    downstream from_outputs stages (no input file needed)."""
    if not stage.output:
        log.error("Stage '%s': from_prompt requires output", stage.name)
        return [], []
    if reuse and Path(stage.output).exists():
        log.info("REUSE: %s (output exists)", stage.output)
        return [], [stage.output]
    task = Task(prompt=stage.from_prompt, output=stage.output)
    if model_override:
        task.model = model_override
    if timeout_override:
        task.timeout = timeout_override
    log.info("Loaded 1 task from from_prompt for stage '%s'", stage.name)
    return [task], []


def _stage_from_dir_tasks(stage: Stage, reuse: bool, model_override: str, timeout_override: int) -> tuple[list[Task], list[str]]:
    """Read .md files from a directory; one task per file, output next to
    the input with the stage's output suffix."""
    dir_path = Path(stage.from_dir)
    if not dir_path.is_dir():
        log.error("Directory not found: %s", stage.from_dir)
        return [], []
    tasks: list[Task] = []
    reused: list[str] = []
    for fpath in sorted(dir_path.glob(f"*{stage.suffix}")):
        if fpath.name.endswith(stage.output_suffix):
            continue
        out_path = fpath.parent / (fpath.stem + stage.output_suffix)
        if reuse and out_path.exists():
            log.info("REUSE: %s (output exists: %s)", fpath.name, out_path.name)
            reused.append(str(out_path))
            continue
        task = Task(prompt=fpath.read_text(encoding="utf-8"), output=str(out_path), cwd=str(fpath.parent))
        if model_override:
            task.model = model_override
        if timeout_override:
            task.timeout = timeout_override
        tasks.append(task)
    log.info("Loaded %d tasks from %s", len(tasks), stage.from_dir)
    return tasks, reused


def _stage_from_outputs_tasks(stage: Stage, stage_outputs: dict, reuse: bool, model_override: str, timeout_override: int) -> tuple[list[Task], list[str]]:
    """Tasks fed by the previous stage's artifacts: one combined task per
    template (aggregate) or one task per artifact per template."""
    if stage.from_outputs not in stage_outputs:
        log.error("Previous stage '%s' not found", stage.from_outputs)
        return [], []
    prev_outputs = stage_outputs[stage.from_outputs]
    tasks: list[Task] = []
    reused: list[str] = []
    if stage.aggregate:
        # Merge every upstream artifact into one combined prompt per
        # template so downstream roles see all evidence, instead of
        # fanning each artifact into independent (and conflicting) tasks.
        agg_tasks, agg_reused = _aggregate_tasks(stage, prev_outputs, model_override, timeout_override, reuse)
        return agg_tasks, agg_reused
    for out_path_str in prev_outputs:
        out_path = Path(out_path_str)
        if not out_path.exists():
            log.warning("Output file not found: %s", out_path)
            continue
        input_content = out_path.read_text(encoding="utf-8")
        input_stem = out_path.stem
        # Create tasks from templates (prompt string or template file,
        # both with {input_content}/{input_stem} placeholders)
        for task_def in stage.tasks:
            prompt = _task_prompt(task_def, input_content, input_stem, str(out_path))
            if not prompt:
                continue
            output_path = task_def.get("output", "").replace("{input_stem}", input_stem)
            if reuse and output_path and Path(output_path).exists():
                log.info("REUSE: %s (output exists)", output_path)
                reused.append(output_path)
                continue
            tasks.append(_task_from_def(task_def, prompt, output_path, model_override, timeout_override))
    log.info("Loaded %d tasks from %d outputs of stage '%s'",
             len(tasks), len(prev_outputs), stage.from_outputs)
    return tasks, reused


def execute_stage(stage: Stage, stage_outputs: dict[str, list[str]], model_override: str = "", reuse: bool = False, timeout_override: int = 0,
                  session_mode: str = "new", session_name: str = "", validate_cmd: str = "") -> tuple[list[TaskResult], bool]:
    """Execute one stage and return (task_results, stage_ok). stage_ok is
    False when any task or configured post-stage command failed, so command
    hooks act as a failure gate for the pipeline."""
    _log_stage_header(stage, reuse)
    
    tasks, reused_outputs, early = _build_stage_tasks(stage, stage_outputs, reuse, model_override, timeout_override, validate_cmd)
    if early is not None:
        return early

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

    stage_session_id = f"{session_name}-{stage.name}" if session_mode == "per-stage" else session_name
    # Per-stage engineering gate: the stage's own validate_cmd wins over the
    # CLI default ("" disables validation for this stage), and per-task
    # validate fields override both inside run_serial/run_parallel.
    stage_validate = stage.validate_cmd if stage.validate_cmd is not None else validate_cmd

    results, outputs = _execute_stage_tasks(stage, tasks, reused_outputs, stage_validate,
                                            session_mode, session_name, stage_session_id)
    stage_outputs[stage.name] = outputs

    log.info("")
    log.info("Stage '%s' completed: %d/%d tasks succeeded",
             stage.name, len(outputs), len(tasks))

    stage_ok = all(r.success for r in results)

    if not _run_stage_commands(stage):
        stage_ok = False

    _git_commit_stage(stage, outputs)  # failures are advisory, not a stage failure

    return results, stage_ok


def _log_stage_header(stage: Stage, reuse: bool) -> None:
    """Print the stage banner and whether reuse applies."""
    log.info("")
    log.info("=" * 60)
    log.info("STAGE: %s", stage.name)
    if reuse:
        log.info("(reusing existing outputs if available)")
    log.info("=" * 60)


def _build_stage_tasks(stage: Stage, stage_outputs: dict, reuse: bool, model_override: str, timeout_override: int, validate_cmd: str) -> tuple[list, list, Optional[tuple]]:
    """Build the stage's task list from its input source (from_prompt,
    from_dir, or from_outputs). Returns (tasks, reused, early_result);
    early_result is not None when the stage must stop immediately."""
    tasks: list[Task] = []
    reused_outputs: list[str] = []

    # Dynamic role orchestration (meta stage) is handled entirely here.
    if stage.meta:
        return [], [], _run_meta_stage(stage, stage_outputs, model_override, timeout_override, validate_cmd)

    if stage.from_prompt:
        tasks, reused_outputs = _stage_from_prompt_tasks(stage, reuse, model_override, timeout_override)
        if not tasks and not reused_outputs:
            return [], [], ([], False)
    elif stage.from_dir:
        tasks, reused_outputs = _stage_from_dir_tasks(stage, reuse, model_override, timeout_override)
    elif stage.from_outputs:
        tasks, reused_outputs = _stage_from_outputs_tasks(stage, stage_outputs, reuse, model_override, timeout_override)
        if stage.from_outputs not in stage_outputs and not tasks:
            return [], [], ([], False)
    else:
        log.error("Stage '%s' must have either 'from_dir' or 'from_outputs'", stage.name)
        return [], [], ([], False)
    return tasks, reused_outputs, None


def _execute_stage_tasks(stage: Stage, tasks: list, reused_outputs: list, stage_validate: str,
                         session_mode: str, session_name: str, stage_session_id: str) -> tuple[list, list]:
    """Run the stage's tasks (serial or parallel) and collect the output
    paths that downstream stages will consume (reused outputs included)."""
    if stage.mode == "parallel":
        results = run_parallel(tasks, stage.workers, validate_cmd=stage_validate)
    else:
        results = run_serial(tasks, retries=0, session_mode=session_mode, session_id=stage_session_id, session_name=session_name,
                             validate_cmd=stage_validate)
    outputs = list(reused_outputs)
    for r in results:
        if r.success and r.task.output:
            outputs.append(r.task.output)
    return results, outputs


def _run_stage_commands(stage: Stage) -> bool:
    """Run the stage's shell commands (post-task hooks); False when any
    command failed, making hooks act as a failure gate for the stage."""
    if not stage.commands:
        return True
    log.info("")
    log.info("Running %d commands for stage '%s'... (parallel=%s)",
             len(stage.commands), stage.name, stage.commands_parallel)
    cmd_cwd = stage.cwd or os.getcwd()

    if stage.commands_parallel:
        with ThreadPoolExecutor(max_workers=len(stage.commands)) as pool:
            futs = {pool.submit(_run_single_cmd, cmd, i, len(stage.commands), cmd_cwd): cmd for i, cmd in enumerate(stage.commands, 1)}
            cmd_results = [f.result() for f in as_completed(futs)]
        all_cmd_ok = all(cmd_results)
    else:
        all_cmd_ok = True
        for i, cmd in enumerate(stage.commands, 1):
            if not _run_single_cmd(cmd, i, len(stage.commands), cmd_cwd):
                all_cmd_ok = False

    if all_cmd_ok:
        log.info("All %d commands passed for stage '%s'", len(stage.commands), stage.name)
    else:
        log.warning("Stage '%s' FAILED: some post-stage commands failed", stage.name)
    return all_cmd_ok


def _run_single_cmd(cmd: str, index: int, total: int, cmd_cwd: str) -> bool:
    """Run one post-stage shell command and stream the tail of its output."""
    log.info("CMD [%d/%d]: %s", index, total, cmd)
    try:
        proc = subprocess.run(
            cmd, shell=True, cwd=cmd_cwd,
            capture_output=True, text=True, timeout=600
        )
        if proc.returncode == 0:
            log.info("CMD OK (exit=0) [%d/%d]", index, total)
            if proc.stdout:
                for line in proc.stdout.strip().split("\n")[-10:]:
                    log.info("  | %s", line)
        else:
            log.warning("CMD FAILED (exit=%d) [%d/%d]", proc.returncode, index, total)
            if proc.stderr:
                for line in proc.stderr.strip().split("\n")[-10:]:
                    log.warning("  | %s", line)
            if proc.stdout:
                for line in proc.stdout.strip().split("\n")[-5:]:
                    log.info("  | %s", line)
        return proc.returncode == 0
    except Exception as e:
        log.warning("CMD ERROR [%d/%d]: %s", index, total, e)
        return False


def _git_commit_stage(stage: Stage, outputs: list) -> bool:
    """Commit the stage's deliverables into git; failures are advisory
    (a commit problem must not fail the stage itself)."""
    if not stage.git_commit or not outputs:
        return True
    try:
        commit_msg = stage.commit_message or "[pi-batch] Stage: %s - %d tasks completed" % (stage.name, len(outputs))
        file_list = " ".join(["\"%s\"" % o for o in outputs])

        if subprocess.run(["git", "rev-parse", "--git-dir"], capture_output=True, text=True, timeout=10).returncode != 0:
            log.warning("Not a git repository, skipping git commit")
            return False
        subprocess.run(["git", "add"] + outputs, capture_output=True, timeout=10)
        subprocess.run(["git", "commit", "-m", commit_msg], capture_output=True, timeout=10)
        log.info("GIT COMMIT: %s (files: %d)", commit_msg, len(outputs))
    except Exception as e:
        log.warning("Git commit failed: %s", e)
        return False
    return True


_GATE_VERDICT_RE = re.compile(r"VERDICT\s*:\s*(PASS|FAIL|REJECT)", re.IGNORECASE)


def _archive_outputs(outputs: list, archive_dir: str, label: str) -> list:
    """Move finished deliverables into a timestamped archive subdirectory
    once the stage/pipeline completed (all tasks succeeded, gates passed).
    The worktree stays clean; git history (committed artifacts) retains
    everything, and the decision log points at the original paths. Returns
    the moved destinations for logging."""
    if not archive_dir or not outputs:
        return []
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = Path(archive_dir) / f"{label}-{stamp}"
    target.mkdir(parents=True, exist_ok=True)
    moved = []
    for o in outputs:
        p = Path(o)
        if p.exists():
            dest = target / p.name
            shutil.move(str(p), str(dest))
            moved.append(str(dest))
    if moved:
        log.info("ARCHIVED %d deliverable(s) -> %s", len(moved), target)
    return moved


def _gate_verdict(output_paths: list) -> Optional[str]:
    """Read a gate stage's deliverables and return its verdict
    (PASS/FAIL/REJECT) or None when no VERDICT: line is present. The
    verdict is untrusted text from the agent, so an absent verdict is a
    FAIL (fail closed): a gate without an explicit pass does not unlock."""
    for p in output_paths:
        path = Path(p)
        if not path.exists():
            continue
        m = _GATE_VERDICT_RE.search(path.read_text(encoding="utf-8"))
        if m:
            return m.group(1).upper()
    return None


def _extract_decisions(text: str, limit: int = 5) -> list[str]:
    """Pull decision points (markdown headings) with their first sentence
    from a deliverable: an index into the full reasoning stored in the
    artifact, so the decision log stays readable while pointing at the
    complete rationale."""
    out = []
    for i, line in enumerate((text or "").splitlines()):
        if re.match(r"^#{2,3}\s+", line):
            heading = line.lstrip("# ").strip()
            nxt = ""
            for n in (text or "").splitlines()[i + 1:i + 4]:
                if n.strip() and not n.lstrip().startswith("#"):
                    nxt = n.strip()[:120]
                    break
            out.append(f"{heading}: {nxt}" if nxt else heading)
            if len(out) >= limit:
                break
    return out


def _append_decision_log(path: str, stage_name: str, results: list, stage_ok: bool, verdict: Optional[str]) -> None:
    """Append one structured decision record per finished stage: the
    stage, its status, each decision point extracted from the deliverables
    (heading + first sentence, the full reasoning lives in the artifacts),
    and the evidence file paths. Appending keeps the whole history; the
    log is a first-class deliverable of the pipeline."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as f:
        f.write(f"\n## {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — stage '{stage_name}' — "
                f"{'PASS' if stage_ok else 'FAIL'}")
        if verdict:
            f.write(f" (gate verdict: {verdict})")
        f.write("\n")
        for r in results:
            decisions = _extract_decisions(r.stdout)
            label = r.task.output or "(stdout)"
            status = "ok" if r.success else f"FAILED: {r.reason}"
            f.write(f"- task {label} [{status}]")
            if decisions:
                f.write(": " + "; ".join(decisions))
            f.write("\n")
        evidence = [r.task.output for r in results if r.task.output]
        if evidence:
            f.write(f"- evidence: {', '.join(evidence)}\n")


def run_pipeline(pipeline: Pipeline, model_override: str = "", dry_run: bool = False, reuse: bool = False, timeout_override: int = 0,
                 session_mode: str = "new", session_name: str = "", validate_cmd: str = "", decision_log: str = "", archive_dir: str = "") -> tuple[list[TaskResult], list[str]]:
    """Execute all stages sequentially; returns (all task results, names of
    stages that failed tasks or commands). Gates halt the pipeline, decision
    logs record every stage, and completed runs archive their deliverables."""
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
            _describe_stage(stage, reuse)
            continue

        results, stage_ok = execute_stage(stage, stage_outputs, model_override, reuse, timeout_override, session_mode, session_name, validate_cmd)
        all_results.extend(results)
        if not stage_ok:
            failed_stages.append(stage.name)

        gate_verdict = _handle_gate(stage, stage_outputs)

        # Structured decision record for this stage (append-only history)
        log_path = decision_log or pipeline.decision_log
        if log_path and results:
            _append_decision_log(log_path, stage.name, results, stage_ok, gate_verdict)

        if gate_verdict in ("FAIL", "REJECT"):
            failed_stages.append(stage.name)
            log.error("Pipeline halted by gate: %s", stage.name)
            break

    # The pipeline completed (no failed stages, no gate rejection): move the
    # committed deliverables into the archive so the worktree stays clean.
    if not failed_stages and (pipeline.archive_dir or archive_dir):
        outputs = [r.task.output for r in all_results if r.success and r.task.output]
        _archive_outputs(outputs, archive_dir or pipeline.archive_dir, pipeline.name)
    
    return all_results, failed_stages


def _describe_stage(stage: Stage, reuse: bool) -> None:
    """Dry-run: print what the stage would do without executing it."""
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


def _handle_gate(stage: Stage, stage_outputs: dict) -> Optional[str]:
    """Evaluate a gate stage's deliverables: VERDICT: PASS/FAIL/REJECT.
    A missing verdict fails closed (no explicit pass, no unlock). Returns
    the verdict or None when the stage is not a gate."""
    if not stage.gate:
        return None
    verdict = _gate_verdict(stage_outputs.get(stage.name, []))
    if verdict is None:
        verdict = "FAIL"
        log.error("GATE stage '%s' produced no VERDICT: line; failing closed", stage.name)
    elif verdict in ("FAIL", "REJECT"):
        log.error("GATE REJECTED at stage '%s' (verdict: %s) — later stages blocked", stage.name, verdict)
    else:
        log.info("GATE PASSED at stage '%s'", stage.name)
    return verdict


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
        try:
            data = yaml.safe_load(raw)
        except Exception as e:
            log.warning("Task file '%s' is not valid YAML (%s); treating it as a plain-text prompt", source, e)
            return [Task(prompt=raw.strip())]
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
