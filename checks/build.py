#!/usr/bin/env python3
"""Build gate: compile the project's binaries into the configured output dir.

Binary list and output dir live in engineering.yaml (`build:` section) — see
checks/config.py.
"""
import subprocess
import sys
from pathlib import Path

# Allow standalone invocation (python checks/build.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config


def run() -> int:
    cfg = get_config().build
    bin_dir = Path.cwd() / cfg.output_dir
    bin_dir.mkdir(exist_ok=True)
    for binary in cfg.binaries:
        out = bin_dir / binary["name"]
        result = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(out), binary["path"]],
            capture_output=False, text=True, check=False,
        )
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(run())
