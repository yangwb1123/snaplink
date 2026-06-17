#!/usr/bin/env python3
"""Environment setup: git hooks, Go tooling."""
import subprocess
import sys
from pathlib import Path


def run() -> int:
    root = Path.cwd()
    print("=== snaplink/sso Engineering System Setup ===")
    subprocess.run(["git", "config", "core.hooksPath", ".githooks"],
                   capture_output=True, check=False)
    print("  [+] git hooks: .githooks/")
    for tool in ["gocyclo", "gocognit"]:
        which = subprocess.run(["which", tool], capture_output=True, check=False)
        home_bin = Path.home() / "go" / "bin" / tool
        if which.returncode != 0 and not home_bin.exists():
            print(f"  [*] Installing {tool}...")
            subprocess.run(
                ["go", "install", f"github.com/fzipp/gocyclo/cmd/gocyclo@latest"],
                capture_output=True, check=False
            ) if tool == "gocyclo" else subprocess.run(
                ["go", "install", f"github.com/uudashr/gocognit/cmd/gocognit@latest"],
                capture_output=True, check=False
            )
    print("  [+] Go tooling: gocyclo + gocognit")
    result = subprocess.run(["python", "cli.py", "harness"],
                           capture_output=True, text=True, check=False)
    print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
    print("=== Setup complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(run())
