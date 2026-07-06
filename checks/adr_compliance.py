#!/usr/bin/env python3
"""ADR compliance gate — enforces ADRs that lack dedicated checks.

ADR-0003 (protocol grouping): ensures protocol packages stay under protocols/.
ADR-0004 (domain boundaries): scans test files for mock usage where Memory* exists.
ADR-0007 (directory fan-out): checks per-directory subdir count ≤ 15.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/adr_compliance.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.directory_fanout import MAX_SUBDIRS, EXEMPT_DIRS
from checks.directory_fanout import check as _fanout_check

ROOT = Path.cwd()

# ADR-0003: Protocol packages live under protocols/ (confirmed by current directory map).
# AGENTS.md: protocols/ contains {oauth, oidc, scim, fapi, caep, selfservice, compliance}
KNOWN_PROTOCOL_PACKAGES = {"oauth", "oidc", "scim", "fapi", "caep", "selfservice", "compliance"}
KNOWN_NESTED_PROTOCOL_MODULES = {"saml", "ldap", "kerberos", "radius", "extauthz"}

# ADR-0004: Known Memory* types — if present, tests SHOULD NOT use mocks for them.
MEMORY_PROVIDERS = {
    "MemoryProvider": "core.UserProvider",
    "MemorySink": "audit.Sink",
    "MemoryRegistry": "registry.Registry",
    "memory.UserStore": "core.UserStore",
    "memory.ClientStore": "core.ClientStore",
    "memory.SessionStore": "core.SessionStore",
    "memory.TokenStore": "core.TokenStore",
    "memory.AuthCodeStore": "core.AuthCodeStore",
    "memory.RefreshTokenStore": "core.RefreshTokenStore",
    "memory.DeviceCodeStore": "core.DeviceCodeStore",
    "memory.PARStore": "core.PARStore",
}

# ADR-0007: Directory fan-out budget (mirrors directory_fanout_test.go;
# MAX_SUBDIRS/EXEMPT_DIRS come from the shared checks/directory_fanout.py
# gate, itself driven by engineering.yaml's `directory_fanout:` section).

# Known layer directories under root (from AGENTS.md DIRECTORY_MAP)
RECOGNIZED_LAYER_DIRS = {
    "shared", "domains", "protocols", "platform",
    "interfaces", "infrastructure", "cmd", "deploy",
    "proto", "gen", "checks", "scripts", "docs",
    "test", "examples", "config", "migrate", "internal",
    "admin", "kms", "cluster", "permissions",
}


def check_adr0003() -> list[str]:
    """ADR-0003: Protocol packages stay under protocols/ layer."""
    violations = []
    protocols_dir = ROOT / "protocols"

    if not protocols_dir.is_dir():
        violations.append("  ADR-0003: 'protocols/' layer directory missing")
        return violations

    # 1. Verify known protocol packages exist under protocols/
    existing_protocols = {d.name for d in protocols_dir.iterdir() if d.is_dir()}
    for pkg in KNOWN_PROTOCOL_PACKAGES:
        if pkg not in existing_protocols:
            violations.append(
                f"  ADR-0003 WARN: Known protocol '{pkg}/' not found under protocols/. "
                f"This is ok if not yet implemented."
            )

    # 2. Verify nested protocol modules are NOT at root (they belong in infrastructure/)
    root_dirs = {d.name for d in ROOT.iterdir() if d.is_dir() and not d.name.startswith(".")}
    for mod in KNOWN_NESTED_PROTOCOL_MODULES:
        if mod in root_dirs:
            violations.append(
                f"  ADR-0003: Protocol module '{mod}/' found at root. "
                f"It should live under infrastructure/{mod}/ per the nested module convention."
            )

    # 3. Verify no protocol files leak to root level
    for pkg in KNOWN_PROTOCOL_PACKAGES:
        pkg_root = ROOT / pkg
        if pkg_root.is_dir():
            violations.append(
                f"  ADR-0003: '{pkg}/' found at root. Should be under protocols/{pkg}/."
            )

    # 4. Check for unexpected root-level Go package dirs
    for d in sorted(root_dirs):
        if d in RECOGNIZED_LAYER_DIRS or d.startswith("."):
            continue
        go_files = list((ROOT / d).rglob("*.go"))
        if go_files and d not in KNOWN_NESTED_PROTOCOL_MODULES:
            violations.append(
                f"  ADR-0003: Unexpected root-level Go directory '{d}/'. "
                f"Recognized layer dirs: shared/, domains/, protocols/, platform/, "
                f"interfaces/, infrastructure/, cmd/, ..."
            )

    return violations


def check_adr0004() -> list[str]:
    """ADR-0004: Domain boundaries — prefer Memory* over mocks in tests."""
    violations = []
    test_files = list(ROOT.rglob("*_test.go"))

    for tf in test_files:
        rel = str(tf.relative_to(ROOT))
        if "/.git/" in rel or "/.claude/" in rel or "/vendor/" in rel or "/gen/" in rel:
            continue
        # Skip nested modules (they have their own governance)
        if any(nm in rel for nm in ["kms/", "redis/", "saml/", "ldap/",
                                     "kerberos/", "radius/", "extauthz/",
                                     "postgres/"]):
            continue

        content = tf.read_text()

        # Check for mock imports
        if 'gomock' in content or 'mockgen' in content or '"github.com/golang/mock/' in content:
            # Check if Memory* alternative exists in the codebase
            for mem_name, spi in MEMORY_PROVIDERS.items():
                if mem_name in content:
                    # If both mock and Memory* used in same file, it's a flag
                    violations.append(
                        f"  ADR-0004: {rel} uses both mock and {mem_name}. "
                        f"Prefer {mem_name} over mocks ({spi})."
                    )
                    break
            else:
                # No Memory* found in this test — check if the mock replaces a Memory* provider
                violations.append(
                    f"  ADR-0004: {rel} uses mock/gomock. "
                    f"Consider Memory* implementations for testing instead."
                )

    return violations


def check_adr0007() -> list[str]:
    """ADR-0007: Directory fan-out — delegates to the generic directory_fanout gate."""
    return [f"  ADR-0007: {v}" for v in _fanout_check(ROOT)]


def run() -> int:
    print("=== ADR Compliance Check ===")
    ec = 0

    print("\n--- ADR-0003: Protocol packages stay under protocols/ ---")
    violations3 = check_adr0003()
    if violations3:
        for v in violations3:
            print(v)
            ec = 1
    else:
        print("  PASS: Protocol structure is consistent with ADR-0003")

    print("\n--- ADR-0004: Domain boundaries (prefer Memory* over mocks) ---")
    violations4 = check_adr0004()
    if violations4:
        for v in violations4[:10]:  # Show first 10
            print(v)
            ec = 1
        if len(violations4) > 10:
            print(f"  ... and {len(violations4) - 10} more")
    else:
        print("  PASS: No mock usage where Memory* is preferred")

    print("\n--- ADR-0007: Directory fan-out (≤15 subdirs) ---")
    violations7 = check_adr0007()
    if violations7:
        for v in violations7:
            print(v)
            ec = 1
    else:
        print("  PASS: All directories within fan-out budget")

    if ec == 0:
        print("\nPASS: ADR compliance")
    else:
        print("\nFAIL: ADR violations found")
    return ec


if __name__ == "__main__":
    sys.exit(run())
