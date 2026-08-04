"""pbatch: the pi-batch runner, organized as a package.

Thin entry script pi-batch.py re-exports everything; importing pbatch
directly also works.
"""

from .config import (AGENT_BIN, AGENT_DEFAULT_MODEL, AGENT_DEFAULT_TIMEOUT,
                     AGENT_DEFAULT_WORKERS, COMMIT_PREFIX_DEFAULT, VALIDATORS,
                     log, yaml)
from .models import Pipeline, Stage, Task, TaskResult
from .runner import (agent_failure_reason, print_summary, run_parallel,
                     run_serial, run_task, save_result)
from .config import ROLE_KEYWORDS, _session_flags
from .pipeline import _archive_outputs, _parse_role_plan, _role_suggestions
from .runner import _resolve_validators
from .pipeline import (execute_stage, load_pipeline, load_tasks,
                       load_tasks_from_dir, run_pipeline)
from .cli import build_parser, main

__all__ = [
    "AGENT_BIN", "AGENT_DEFAULT_MODEL", "AGENT_DEFAULT_TIMEOUT",
    "AGENT_DEFAULT_WORKERS", "COMMIT_PREFIX_DEFAULT", "VALIDATORS", "log", "yaml",
    "Pipeline", "Stage", "Task", "TaskResult",
    "agent_failure_reason", "print_summary", "run_parallel", "run_serial",
    "run_task", "save_result", "execute_stage", "load_pipeline", "load_tasks",
    "load_tasks_from_dir", "run_pipeline", "build_parser", "main",
    "_session_flags", "_archive_outputs", "_resolve_validators",
    "ROLE_KEYWORDS", "_role_suggestions", "_parse_role_plan",
]
