#!/usr/bin/env python3
"""Check that engineering.yaml's filesize exemption list hasn't lost a
required entry (`filesize.required_exemptions`) — see checks/config.py.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/exemptions.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config


def run() -> int:
    fs = get_config().filesize
    exempts = fs.exemptions

    print("=== Exemption Sync ===")
    print(f"  configured exemptions: {len(exempts)}")
    ec = 0
    for f in fs.required_exemptions:
        if any(f in e for e in exempts):
            print(f"  [+] {f} in configured exemptions")
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
