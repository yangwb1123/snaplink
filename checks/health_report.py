#!/usr/bin/env python3
"""Health report: file sizes, recent changes, deps, security."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path.cwd()


def run() -> int:
    print("=" * 72)
    print("  snaplink/sso -- Architecture Health Report")
    print(f"  {datetime.now().isoformat()}")
    print("=" * 72)

    print("\n--- 1. File Size Report (limit: 500 lines) ---")
    for f in sorted(ROOT.rglob("*.go")):
        rel = str(f.relative_to(ROOT))
        if "/.git/" in rel or "/.claude/" in rel or "/gen/proto/" in rel or "/vendor/" in rel:
            continue
        lines = len(f.read_text().splitlines())
        if lines > 500:
            result = subprocess.run(
                [sys.executable, "checks/filesize.py", str(f)],
                capture_output=True, text=True, check=False, cwd=str(ROOT)
            )
            if "FAIL" in result.stdout:
                print(f"  XX {lines:4d}  {rel}")
            else:
                print(f"  ** {lines:4d}  {rel} (exempted)")

    print("\n--- 2. Recent Changes (top 10) ---")
    result = subprocess.run(
        "find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' -printf '%T@ %p\\n'",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    lines = sorted(result.stdout.strip().split("\n"), reverse=True)[:10]
    for line in lines:
        if not line.strip():
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2:
            ts = float(parts[0])
            dt = datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
            print(f"  {dt}  {parts[1]}")

    print("\n--- 3. Package Dependencies ---")
    for pkg in ["core", "oauth", "oidc", "security"]:
        pkg_dir = ROOT / pkg
        if not pkg_dir.is_dir():
            continue
        go_files = list(pkg_dir.rglob("*.go"))
        src_files = [f for f in go_files if not f.name.endswith("_test.go")]
        imports = set()
        for f in src_files:
            for line in f.read_text().split("\n"):
                if '"github.com/snaplink/sso/' in line:
                    imp = line.split('"github.com/snaplink/sso/')[1].split('"')[0]
                    imports.add(imp.split("/")[0])
        imp_str = " ".join(sorted(imports))
        print(f"  {pkg}/ ({len(src_files)} files) -> {imp_str}")

    print("\n--- 4. Security ---")
    no_store = subprocess.run(
        "grep -rl tokenNoStoreHeaders . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    challenge = subprocess.run(
        "grep -rl setBearerChallenge . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    print(f"  {no_store.stdout.strip()} files with no-store")
    print(f"  {challenge.stdout.strip()} files with challenge")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(run())
