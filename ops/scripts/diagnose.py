#!/usr/bin/env python3
"""Self-diagnosis: file health, coverage, complexity, architecture, security."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path.cwd()


def run() -> int:
    critical = 0
    warnings = 0
    info = 0

    def pc(msg: str):
        nonlocal critical
        critical += 1
        print(f"  [CRITICAL] {msg}")

    def pw(msg: str):
        nonlocal warnings
        warnings += 1
        print(f"  [WARNING]  {msg}")

    def pi(msg: str):
        nonlocal info
        info += 1
        print(f"  [INFO]     {msg}")

    def ps(msg: str):
        print(f"  [OK]       {msg}")

    print("\n" + "=" * 72)
    print("  snaplink/sso -- Self-Diagnosis Report")
    print(f"  {datetime.now().isoformat()}")
    print("=" * 72)

    print("\n--- 1. File Health ---")
    result = subprocess.run(
        "find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' "
        "-not -path './gen/proto/*' -not -path './vendor/*' -exec wc -l {} +",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) == 2 and parts[0].isdigit() and int(parts[0]) > 2000:
            pc(f"Files >2000 lines: {parts[1]}")

    print("\n--- 2. Test Coverage ---")
    for pkg in ["core", "oauth", "oidc", "security", "defaultimpl"]:
        pkg_dir = ROOT / pkg
        if not pkg_dir.is_dir():
            continue
        src = len(list(pkg_dir.rglob("*.go")))
        test = len(list(pkg_dir.rglob("*_test.go")))
        if src > 0 and test == 0:
            pc(f"{pkg}/ has {src} source files, ZERO test files")
        elif src > 0:
            ratio = test * 100 // src
            if ratio < 30:
                pw(f"{pkg}/ only {test} tests for {src} src ({ratio}%)")

    print("\n--- 3. Complexity Hotspots ---")
    gocyclo = str(Path.home() / "go" / "bin" / "gocyclo")
    if Path(gocyclo).exists():
        result = subprocess.run(
            [gocyclo, "-top", "15", "-ignore", "gen/proto/", "."],
            capture_output=True, text=True, check=False, cwd=str(ROOT)
        )
        if result.stdout.strip():
            pi("Top 15 by cyclomatic complexity:")
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split()
                if parts and parts[0].isdigit() and int(parts[0]) > 15:
                    print(f"           !  {line}")
                else:
                    print(f"           {line}")

    print("\n--- 4. Architecture ---")
    violations = 0
    result = subprocess.run(
        ["grep", "-rq", '"github.com/snaplink/sso/oidc"', "oauth/", "--include=*.go"],
        capture_output=True, check=False, cwd=str(ROOT)
    )
    if result.returncode == 0:
        pc("oauth/ imports oidc/")
        violations = 1
    result = subprocess.run(
        ["grep", "-rq", '"github.com/snaplink/sso/admin"', "oidc/", "--include=*.go"],
        capture_output=True, check=False, cwd=str(ROOT)
    )
    if result.returncode == 0:
        pc("oidc/ imports admin/")
        violations = 1
    if violations == 0:
        ps("No architecture violations")

    print("\n--- 5. Security ---")
    for pat in ["tokenNoStoreHeaders", "setBearerChallenge", "bcrypt", "ConstantTimeEq"]:
        result = subprocess.run(
            ["grep", "-rl", pat, ".", "--include=*.go"],
            capture_output=True, text=True, check=False, cwd=str(ROOT)
        )
        files = [l for l in result.stdout.split("\n") if l.strip() and ".claude" not in l and ".git" not in l]
        if files:
            ps(f"{pat} found in {len(files)} files")
        else:
            pw(f"{pat} not found")

    print("\n" + "=" * 72)
    print(f"  Summary: {critical} critical, {warnings} warnings, {info} info")
    print("=" * 72)
    return critical


if __name__ == "__main__":
    sys.exit(run())
