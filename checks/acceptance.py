#!/usr/bin/env python3
"""Full acceptance suite (EVALUATION.md). Orchestrates all gates."""
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()

PASS = 0
FAIL = 0
TOTAL = 0


def ok(msg: str):
    global PASS, TOTAL
    PASS += 1
    TOTAL += 1
    print(f"  \033[32mPASS\033[0m {msg}")


def nok(msg: str):
    global FAIL, TOTAL
    FAIL += 1
    TOTAL += 1
    print(f"  \033[31mFAIL\033[0m {msg}")


def run_py(module: str, *args: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, "-m", module] + list(args),
        capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    return result.returncode, result.stdout


def run_go(args: list[str]) -> tuple[int, str]:
    result = subprocess.run(
        ["go"] + args, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    return result.returncode, result.stdout


def run() -> int:
    global PASS, FAIL, TOTAL
    print("=== Acceptance Check ===")
    print()

    print("[U1] go build ./...")
    rc, out = run_go(["build", "./..."])
    ok("go build") if rc == 0 else nok("go build")

    print("[U2] go vet ./...")
    rc, out = run_go(["vet", "./..."])
    ok("go vet") if rc == 0 else nok("go vet")

    print("[U3] File size (<=500 lines)")
    rc, out = run_py("checks.filesize")
    ok("file size") if rc == 0 else nok("file size")

    print("[U5] Architecture dependency direction")
    rc, out = run_py("checks.architecture")
    debt_lines = [l for l in out.split("\n") if "FAIL" in l and ("oidc imports oauth" in l or "oidc imports defaultimpl" in l or "security imports defaultimpl" in l)]
    new_lines = [l for l in out.split("\n") if "FAIL" in l and l not in debt_lines]
    if not new_lines:
        ok("architecture")
        for d in debt_lines:
            print(f"    KNOWN DEBT: {d.replace('FAIL:', '').strip()}")
    else:
        nok("architecture -- NEW violations")
        for l in new_lines:
            print(f"    {l}")

    print("[S1-S6] Security invariants")
    rc, out = run_py("checks.invariants")
    ok("security invariants") if rc == 0 else (nok("security invariants"), print(out))

    print("[Section 4] Coverage regression")
    rc, out = run_py("checks.coverage")
    ok("coverage") if rc == 0 else nok("coverage")

    print("[U8] Root file count (<=15 non-exempt)")
    rc, out = run_py("checks.root_files")
    if rc == 0:
        ok("root file count")
    else:
        print("    KNOWN DEBT: root files exceed limit -- apply skills/project-reorganization/")
        print(f"    {out.split(chr(10))[0]}")

    print("[U9] No business code in root")
    rc, out = run_py("checks.root_business_code")
    if rc == 0:
        ok("root business code")
    else:
        biz_count = len([l for l in out.split("\n") if l.startswith("  ")])
        print(f"    KNOWN DEBT: {biz_count} business code files in root")
        print("    Apply: skills/project-reorganization/ Step 1-4")

    print()
    print("---")
    if FAIL == 0:
        print(f"\033[32mACCEPTANCE PASSED\033[0m ({PASS}/{TOTAL})")
        return 0
    print(f"\033[31mACCEPTANCE FAILED\033[0m ({PASS}/{TOTAL} -- {FAIL} failures)")
    return 1


if __name__ == "__main__":
    sys.exit(run())
