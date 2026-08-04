"""Data model for pi-batch: Task, TaskResult, Stage, Pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import os
from pathlib import Path
from typing import Optional

from . import config
from .config import AGENT_DEFAULT_MODEL, AGENT_DEFAULT_TIMEOUT, AGENT_DEFAULT_WORKERS

@dataclass
class Stage:
    """One stage in a pipeline."""
    name: str
    from_dir: str = ""
    from_outputs: str = ""  # name of previous stage
    suffix: str = ".md"
    output_suffix: str = ".out.md"
    mode: str = "serial"
    workers: int = AGENT_DEFAULT_WORKERS  # config value captured at import; overrides go through config
    aggregate: bool = False  # from_outputs: merge all upstream outputs into one prompt per template
    validate_cmd: Optional[str] = None  # None = inherit CLI --validate-cmd, "" = disabled, else command
    meta: bool = False  # dynamic role orchestration: agent picks review roles per iteration
    meta_prompt: str = ""  # custom orchestrator prompt ({roles}/{input_content} placeholders)
    role_dir: str = ""  # directory of role templates the orchestrator may choose from
    output_dir: str = ""  # where role deliverables are written (required for meta stages)
    max_iterations: int = 3  # orchestrator -> roles -> fold -> re-ask loop limit
    gate: bool = False  # verdict gate: output must contain VERDICT: PASS/FAIL/REJECT; FAIL/REJECT blocks later stages
    from_prompt: str = ""  # one-sentence starting prompt instead of from_dir files
    output: str = ""  # output file for the from_prompt task (required with from_prompt)
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
            "from_prompt": self.from_prompt,
            "output": self.output,
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
    decision_log: str = ""  # append structured decisions per finished stage
    archive_dir: str = ""  # move completed deliverables here after a successful run
    name: str = "pipeline"  # label for archive subdirectories
    
    def to_dict(self):
        return {"stages": [s.to_dict() for s in self.stages]}


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
        cmd = [config.AGENT_BIN, "-p", self.prompt]
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


@dataclass
class TaskResult:
    task: Task
    success: bool
    stdout: str = ""
    stderr: str = ""
    elapsed: float = 0.0
    returncode: int = -1
    reason: str = ""
