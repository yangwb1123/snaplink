#!/usr/bin/env python3
"""Check that exemption lists in filesize script match expected files."""
import re
import sys
from pathlib import Path


def run() -> int:
    root = Path.cwd()
    filesize_py = root / "checks" / "filesize.py"
    content = filesize_py.read_text()
    # Extract EXEMPTIONS list
    match = re.search(r"EXEMPTIONS\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if not match:
        print("  FAIL: could not parse EXEMPTIONS from checks/filesize.py", file=sys.stderr)
        return 1
    exempts = re.findall(r'"([^"]+)"', match.group(1))

    print("=== Exemption Sync ===")
    print(f"  script exemptions: {len(exempts)}")
    ec = 0
    for f in ["interfaces/sso/handlers.go", "interfaces/sso/server_extensions.go", "interfaces/sso/sso.go", "interfaces/sso/accessors.go"]:
        if any(f in e for e in exempts):
            print(f"  [+] {f} in script exemptions")
        else:
            print(f"  [-] {f} MISSING")
            ec = 1
    if ec == 0:
        print("  PASS")
    else:
        print("  FAIL")
    return ec


if __name__ == "__main__":
    sys.exit(run())
