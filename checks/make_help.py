#!/usr/bin/env python3
"""Print Makefile help."""
import sys
from pathlib import Path


def run() -> int:
    root = Path.cwd()
    makefile = root / "Makefile"
    if not makefile.exists():
        print("Makefile not found")
        return 1

    content = makefile.read_text()
    print("=" * 80)
    print("  snaplink/sso -- Engineering Make Targets")
    print("=" * 80)
    print()

    has_help = []
    no_help = []
    for line in content.split("\n"):
        if ":" not in line:
            continue
        if line.startswith("\t") or line.startswith(" ") or line.startswith("."):
            continue
        if "##" in line:
            target = line.split(":")[0].strip()
            desc = line.split("##", 1)[1].strip()
            has_help.append((target, desc))
        elif line.strip().endswith(":") and not line.strip().startswith("."):
            target = line.split(":")[0].strip()
            if target not in [t for t, _ in has_help]:
                no_help.append(target)

    for target, desc in sorted(has_help):
        print(f"  {target:28s} {desc}")
    if no_help:
        print()
        print("  Other targets (no help text):")
        for target in sorted(no_help):
            print(f"  {target:28s}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
