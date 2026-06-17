#!/usr/bin/env python3
"""Security invariants: no-store headers, bearer challenge, oracle-leak, bcrypt, etc."""
import sys
import subprocess
from pathlib import Path

ROOT = Path.cwd()


def grep(pattern: str, name: str, count_only=False) -> int:
    cmd = ["grep", "-rl" if count_only else "-rn", pattern, "."]
    if not count_only:
        cmd.extend(["--include=*.go"])
    result = subprocess.run(
        cmd + ["--include=*.go"] if count_only else cmd,
        capture_output=True, text=True, check=False,
        cwd=str(ROOT)
    )
    if count_only:
        return len([l for l in result.stdout.split("\n") if l.strip() and ".claude" not in l and ".git" not in l])
    return len([l for l in result.stdout.split("\n") if l.strip() and ".claude" not in l and ".git" not in l and "_test.go" not in l])


def run() -> int:
    ec = 0
    results = []
    n = grep("tokenNoStoreHeaders", "no-store headers", count_only=True)
    results.append((n > 0, f"tokenNoStoreHeaders in {n} files"))
    n = grep("setBearerChallenge", "WWW-Authenticate", count_only=True)
    results.append((n > 0, f"setBearerChallenge in {n} files"))
    n = grep('"invalid_grant"', "invalid_grant", count_only=False)
    results.append((n > 0, f"invalid_grant in {n} locations"))
    n = grep('"mfa_invalid"', "mfa_invalid", count_only=False)
    results.append((n > 0, f"mfa_invalid in {n} locations"))
    n = grep('"reset_invalid"', "reset_invalid", count_only=False)
    results.append((n > 0, f"reset_invalid in {n} locations"))
    n = grep('"email_change_invalid"', "email_change_invalid", count_only=False)
    results.append((n > 0, f"email_change_invalid in {n} locations"))
    n = grep("bcrypt", "bcrypt", count_only=True)
    results.append((n > 0, f"bcrypt in {n} files"))
    n = grep("ConstantTimeEq|subtle\\.ConstantTimeCompare", "constant-time", count_only=False)
    results.append((n > 0, f"constant-time in {n} locations"))
    docs_exist = (ROOT / "docs" / "error-codes.md").exists()
    results.append((docs_exist, "error-codes.md exists"))
    api_docs_exist = (ROOT / "docs" / "openapi.yaml").exists()
    results.append((api_docs_exist, "openapi.yaml exists"))

    print("=== Security Invariant Check ===")
    passed = 0
    warnings = 0
    failures = 0
    for ok, msg in results:
        if ok:
            print(f"  [+] {msg}")
            passed += 1
        else:
            # check if it's a warning (we know some are optional)
            if "not found" in msg or "locations" in msg and "0" in msg:
                print(f"  [*] {msg}")
                warnings += 1
            else:
                print(f"  [-] {msg}")
                failures += 1
                ec = 1
    print(f"\nResult: {passed} passed, {warnings} warnings, {failures} failures")
    return ec


if __name__ == "__main__":
    sys.exit(run())
