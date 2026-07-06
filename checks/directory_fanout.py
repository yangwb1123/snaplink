#!/usr/bin/env python3
"""Directory fan-out gate: no directory may hold more than the configured
number of subdirectories.

Max subdirs and exempt dirs live in engineering.yaml (`directory_fanout:`
section) — see checks/config.py. This is the Python-side mirror of the Go
`directory_fanout_test.go` committed gate (AGENTS.md §0.1); checks/adr_compliance.py
(ADR-0007) reuses `check()` below instead of re-walking the tree itself.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/directory_fanout.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

_df = get_config().directory_fanout
MAX_SUBDIRS = _df.max_subdirs
EXEMPT_DIRS = set(_df.exempt_dirs)


def check(root: Path = None) -> list[str]:
    """Return one message per directory exceeding MAX_SUBDIRS, no prefix/indent."""
    root = root or Path.cwd()
    violations = []
    for dirpath in sorted(root.rglob("*")):
        if not dirpath.is_dir():
            continue
        rel = str(dirpath.relative_to(root))
        if any(part in EXEMPT_DIRS for part in Path(rel).parts):
            continue
        if rel.startswith("."):
            continue
        subdirs = [d for d in dirpath.iterdir() if d.is_dir() and not d.name.startswith(".")]
        subdir_count = len(subdirs)
        if subdir_count > MAX_SUBDIRS:
            violations.append(f"{rel}/ has {subdir_count} subdirs (max {MAX_SUBDIRS})")
    return violations


def run() -> int:
    violations = check()
    if violations:
        print(f"FAIL: {len(violations)} directory fan-out violation(s)")
        for v in violations:
            print(f"  {v}")
        return 1
    print(f"PASS: directory fan-out (max {MAX_SUBDIRS} subdirs)")
    return 0


if __name__ == "__main__":
    sys.exit(run())
