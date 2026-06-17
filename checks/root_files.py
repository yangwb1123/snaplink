#!/usr/bin/env python3
"""Root file count gate: non-exempt files must be <= 15."""
import sys
from pathlib import Path

EXEMPT = {
    "README.md", "CHANGELOG.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md",
    "RELEASE.md", "ROADMAP.md",
    "AGENTS.md", "HARNESS.md", "ARCHITECTURE.md", "EVALUATION.md",
    "BOOTSTRAP.md", "CHECKS_REGISTRY.md", "TODO.md", "CLAUDE.md",
    "go.mod", "go.sum", "Makefile", "Taskfile.yml", "cli.py", "pyproject.toml",
    "Dockerfile", ".gitignore", ".editorconfig", ".golangci.yml", ".goreleaser.yaml",
}


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

    MAX = 15
    if count > MAX:
        print(f"FAIL: {count} non-exempt files in root (max {MAX})")
        print("\n".join(violations))
        return 1
    print(f"PASS: root file count {count} <= {MAX}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
