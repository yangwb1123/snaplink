#!/usr/bin/env python3
"""Feature review: verify implementation against feature-spec."""
import re
import subprocess
import sys
from pathlib import Path


def run(spec_path: str | None = None) -> int:
    if not spec_path or not Path(spec_path).exists():
        print(f"Usage: python checks/review_feature.py <feature-spec.md>")
        return 1

    root = Path.cwd()
    spec = Path(spec_path)
    content = spec.read_text()

    pass_count = 0
    fail_count = 0

    def g(msg: str):
        nonlocal pass_count
        pass_count += 1
        print(f"  PASS {msg}")

    def r(msg: str):
        nonlocal fail_count
        fail_count += 1
        print(f"  FAIL {msg}")

    def w(msg: str):
        print(f"  WARN {msg}")

    print(f"=== Feature Review: {spec.name} ===")

    # R1: make acceptance
    print("[R1] make acceptance")
    result = subprocess.run(
        [sys.executable, "cli.py", "accept"],
        capture_output=True, text=True, check=False, cwd=str(root)
    )
    if result.returncode == 0:
        g("acceptance suite")
    else:
        r("acceptance suite")

    # R2: file scope
    print("[R2] File scope")
    sec4 = content.split("## 4.")[1].split("## 5.")[0] if "## 4." in content else ""
    spec_files = set()
    for line in sec4.split("\n"):
        line = line.strip().strip('"').strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            spec_files.add(line)

    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", "HEAD"],
        capture_output=True, text=True, check=False, cwd=str(root)
    )
    if result.returncode == 0 and result.stdout.strip():
        changed = [l.strip() for l in result.stdout.split("\n") if l.strip().endswith(".go")]
        unexpected = [f for f in changed if f not in spec_files]
        if unexpected:
            for f in unexpected:
                w(f"unexpected: {f}")
            g("file scope (warnings)")
        else:
            g("file scope only")
    else:
        g("file scope only (no git changes)")

    # R3: boundary integrity
    print("[R3] Boundary integrity")
    sec6 = content.split("## 6.")[1].split("## 7.")[0] if "## 6." in content else ""
    boundary_files = set()
    for line in sec6.split("\n"):
        line = line.strip().strip('"').strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            boundary_files.add(line)

    bh = 0
    if boundary_files:
        result = subprocess.run(
            ["git", "log", "--oneline", "HEAD", "--"] + list(boundary_files),
            capture_output=True, text=True, check=False, cwd=str(root)
        )
        if result.stdout.strip():
            r("boundary file(s) changed")
            bh = 1
    if bh == 0:
        g("boundary untouched")

    print()
    if fail_count == 0:
        print(f"REVIEW PASSED ({pass_count}/{pass_count})")
        return 0
    print(f"REVIEW FAILED ({pass_count}/{pass_count + fail_count} -- {fail_count} failures)")
    return 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))
