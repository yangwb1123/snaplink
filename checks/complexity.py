#!/usr/bin/env python3
"""Cyclomatic and cognitive complexity gate.

Thresholds, exempt functions, ignore pattern, and tool paths live in
engineering.yaml (`complexity:` section) — see checks/config.py.
"""
import subprocess
import sys
from pathlib import Path

# Allow standalone invocation (python checks/complexity.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

_cx = get_config().complexity
MAX_CYCLO = _cx.max_cyclomatic
MAX_COGNIT = _cx.max_cognitive
EXEMPT_FUNCS = list(_cx.exempt_functions)
IGNORE_PATTERN = _cx.ignore_pattern


def is_exempt(name: str) -> bool:
    return any(e in name for e in EXEMPT_FUNCS)


def run_gocyclo(tool: str) -> list[dict]:
    result = subprocess.run(
        [tool, "--ignore", IGNORE_PATTERN, "."],
        capture_output=True, text=True, check=False
    )
    funcs = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0].isdigit():
            location = parts[3]
            line_num = int(location.split(":")[1]) if ":" in location else int(location)
            funcs.append({"cyclo": int(parts[0]), "name": parts[2], "line": line_num})
    return funcs


def run_tool(tool: str, name: str, max_val: int) -> int:
    print(f"--- {name} (max {max_val}) ---")
    if subprocess.run(["which", tool], capture_output=True).returncode != 0:
        print("  (tool not found)")
        return 0
    funcs = run_gocyclo(tool)
    has_fail = 0
    for f in funcs:
        if is_exempt(f["name"]):
            continue
        if f["cyclo"] > max_val:
            print(f"  FAIL: {f['name']} at {f['line']} - {f['cyclo']} > {max_val}")
            has_fail = 1
    if not has_fail:
        print("  PASS")
    return has_fail


def run() -> int:
    gocyclo = str(Path(_cx.gocyclo_path).expanduser())
    gocognit = str(Path(_cx.gocognit_path).expanduser())
    ec = 0
    ec += run_tool(gocyclo, "cyclomatic complexity", MAX_CYCLO)
    ec += run_tool(gocognit, "cognitive complexity", MAX_COGNIT)
    return 1 if ec > 0 else 0


if __name__ == "__main__":
    sys.exit(run())
