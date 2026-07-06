#!/usr/bin/env python3
"""Gate: forbid business code files in root directory.

This check enforces the Root Directory Policy defined in AGENTS.md. Root
should only contain server composition files, not business logic. The
banned patterns/files, exempt list, and allowed prefixes live in
engineering.yaml (`root_policy:` section) — see checks/config.py.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/root_business_code.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

_rp = get_config().root_policy
BANNED_PATTERNS = list(_rp.banned_patterns)
BANNED_FILES = list(_rp.banned_files)
EXEMPT = set(_rp.exempt_files)
ALLOWED_PREFIXES = tuple(_rp.allowed_prefixes)


def _allowed_by_prefix(name: str) -> bool:
    return name.endswith(".go") and name.startswith(ALLOWED_PREFIXES)


def run() -> int:
    root = Path.cwd()
    violations = []

    for pattern in BANNED_PATTERNS:
        for f in root.glob(pattern):
            if not f.is_file():
                continue
            if f.name in EXEMPT or _allowed_by_prefix(f.name):
                continue
            violations.append(f"  {f.name} (matches pattern {pattern})")

    for filename in BANNED_FILES:
        f = root / filename
        if f.is_file() and filename not in EXEMPT and not _allowed_by_prefix(filename):
            violations.append(f"  {filename} (business logic)")

    if violations:
        print(f"FAIL: {len(violations)} business code file(s) in root")
        print("\n".join(sorted(set(violations))))
        print("\n" + "=" * 70)
        print("Root Directory Policy Violation")
        print("=" * 70)
        print("\nRoot should only contain server composition files:")
        print("  - sso.go, handler.go, handlers.go")
        print("  - server_extensions.go, server_routes.go, server_helpers.go")
        print("  - accessors.go, aliases.go")
        print("  - options*.go")
        print("\nBusiness logic MUST be in domain packages:")
        print("  - oauth/      → OAuth handlers, grants")
        print("  - oidc/       → OIDC handlers, discovery")
        print("  - security/   → DPoP, mTLS, JAR")
        print("  - cluster/    → Coordination, invalidation")
        print("  - tenant/     → Tenant logic")
        print("  - selfservice/ → Signup, password reset, etc.")
        print("\nMigration strategy:")
        print("  1. Extract logic to pure functions in target package")
        print("  2. Keep thin wrapper methods in root")
        print("  3. Update Deps interface if needed")
        print("\nSee AGENTS.md §0.6 Root Directory Policy")
        return 1

    print("PASS: no business code in root")
    return 0


if __name__ == "__main__":
    sys.exit(run())
