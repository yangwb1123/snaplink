#!/usr/bin/env python3
"""Gate: forbid business code files in root directory."""
import sys
from pathlib import Path

BANNED_PATTERNS = [
    "*_handler.go", "*_service.go", "*_store.go", "*_grant.go",
    "*_helpers.go", "*_bundle.go", "*_assertion.go", "*_cache.go",
    "*_rotation.go", "*_revocation.go", "*_aggregation.go",
    "*_configuration.go", "*_metadata.go", "*_resolution.go",
]

EXEMPT = {
    "options.go", "options_misc.go", "options_passwd.go",
    "options_security.go", "types.go", "consts.go",
}


def run() -> int:
    root = Path.cwd()
    count = 0
    violations = []
    for pattern in BANNED_PATTERNS:
        glob_pattern = pattern  # e.g. "*_handler.go"
        for f in root.glob(glob_pattern):
            if not f.is_file():
                continue
            if f.name in EXEMPT:
                continue
            count += 1
            violations.append(f"  {f.name}")

    if count > 0:
        print(f"FAIL: {count} business code file(s) in root")
        print("\n".join(violations))
        print("\nThese files MUST be in internal/ module dirs, not root.")
        print("Apply: python skills/project-reorganization/run.py")
        return 1
    print("PASS: no business code in root")
    return 0


if __name__ == "__main__":
    sys.exit(run())
