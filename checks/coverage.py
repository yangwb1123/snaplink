#!/usr/bin/env python3
"""Coverage regression check with per-package targets.

Targets live in engineering.yaml (`coverage.targets`) — see checks/config.py.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

# Allow standalone invocation (python checks/coverage.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

TARGETS = dict(get_config().coverage_targets)


def run() -> int:
    root = Path.cwd()
    print("--- coverage check ---")
    with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as tmp:
        profile = tmp.name
    subprocess.run(
        ["go", "test", "-count=1", "-coverprofile=" + profile, "./..."],
        cwd=str(root), capture_output=True, check=False
    )
    ec = 0
    for pkg, target in TARGETS.items():
        if pkg == ".":
            result = subprocess.run(
                ["go", "tool", "cover", "-func=" + profile],
                capture_output=True, text=True, check=False, cwd=str(root)
            )
            for line in result.stdout.split("\n"):
                if line.startswith("total:"):
                    pct = line.strip().split()[-1].replace("%", "")
                    break
            else:
                print(f"  SKIP: {pkg}")
                continue
        else:
            result = subprocess.run(
                ["go", "tool", "cover", "-func=" + profile],
                capture_output=True, text=True, check=False, cwd=str(root)
            )
            pct = "0"
            for line in result.stdout.split("\n"):
                if line.startswith(f"{pkg}/"):
                    pct = line.strip().split()[-1].replace("%", "")
            if pct == "0":
                print(f"  SKIP: {pkg}")
                continue
        pct_float = float(pct)
        if pct_float < target:
            print(f"  FAIL: {pkg} -- {pct}% (target {target}%)")
            ec = 1
        else:
            print(f"  PASS: {pkg} -- {pct}% (target {target}%)")
    Path(profile).unlink(missing_ok=True)
    if ec == 0:
        print("PASS")
    else:
        print("FAIL")
    return ec


if __name__ == "__main__":
    sys.exit(run())
