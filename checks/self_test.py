#!/usr/bin/env python3
"""Test that the harness itself works."""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()


def run() -> int:
    passed = 0
    failed = 0

    def p(msg: str):
        nonlocal passed
        passed += 1
        print(f"  [+] {msg}")

    def f(msg: str):
        nonlocal failed
        failed += 1
        print(f"  [-] {msg}")

    print("=== Harness Self-Test ===")
    print("--- 1. filesize gate ---")
    # Test oversized file detection
    with tempfile.NamedTemporaryFile(mode="w", suffix=".go", delete=False) as t:
        for i in range(600):
            t.write(f"// line {i}\n")
        tmp_path = t.name
    result = subprocess.run(
        [sys.executable, "checks/filesize.py", tmp_path],
        capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    Path(tmp_path).unlink(missing_ok=True)
    if "FAIL" in result.stdout:
        p("detects oversized file")
    else:
        f("missed oversized file")

    # Test exempted file
    result = subprocess.run(
        [sys.executable, "checks/filesize.py", "interfaces/sso/handlers.go"],
        capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    if "PASS" in result.stdout:
        p("skips exempted files")
    else:
        f("flagged exempted file")

    print("--- 2. complexity gate ---")
    home = Path.home()
    gocyclo = home / "go" / "bin" / "gocyclo"
    gocognit = home / "go" / "bin" / "gocognit"
    if gocyclo.exists() or subprocess.run(["which", "gocyclo"], capture_output=True).returncode == 0:
        p("gocyclo installed")
    else:
        f("gocyclo missing")
    if gocognit.exists() or subprocess.run(["which", "gocognit"], capture_output=True).returncode == 0:
        p("gocognit installed")
    else:
        f("gocognit missing")

    print("--- 3. architecture gate ---")
    result = subprocess.run(
        ["grep", "-r", '"github.com/snaplink/sso/protocols/oidc"', "protocols/oauth/", "--include=*.go"],
        capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    if not result.stdout.strip():
        p("oauth does not import oidc")
    else:
        f("oauth imports oidc")

    result = subprocess.run(
        ["grep", "-r", '"github.com/snaplink/sso/interfaces/admin"', "protocols/oidc/", "--include=*.go"],
        capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    if not result.stdout.strip():
        p("oidc does not import admin")
    else:
        f("oidc imports admin")

    print("--- 4. docs ---")
    for d in ["HARNESS.md", "BOOTSTRAP.md", "ARCHITECTURE.md", "EVALUATION.md"]:
        if (ROOT / "docs" / "agent-os" / d).exists():
            p(f"{d} exists")
        else:
            f(f"{d} missing")
    if (ROOT / "skills").is_dir():
        p("skills/ exists")
    else:
        f("skills/ missing")
    if (ROOT / "checks" / "filesize.py").exists():
        p("checks/ package exists")
    else:
        f("checks/ missing")

    print(f"\nResult: {passed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    sys.exit(run())
