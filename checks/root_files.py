#!/usr/bin/env python3
"""Root file count gate: non-exempt files must be <= the configured max.

Max count and the allowed-file list live in engineering.yaml
(`root_policy:` section) — see checks/config.py.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/root_files.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

_rp = get_config().root_policy
EXEMPT = set(_rp.allowed_files)
MAX = _rp.max_files


def run() -> int:
    root = Path.cwd()
    count = 0
    violations = []
    for f in sorted(root.iterdir()):
        if not f.is_file():
            continue
        name = f.name
        if name in EXEMPT:
            continue
        if name.startswith(".check-") and name.endswith(".sh"):
            continue
        if name.startswith(".") and not name.endswith(".sh"):
            continue
        count += 1
        violations.append(f"  {name}")

    if count > MAX:
        print(f"FAIL: {count} non-exempt files in root (max {MAX})")
        print("\n".join(violations))
        return 1
    print(f"PASS: root file count {count} <= {MAX}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
