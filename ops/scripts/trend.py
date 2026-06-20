#!/usr/bin/env python3
"""Record engineering trend snapshot to .trends/YYYY-MM.md."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path.cwd()


def run() -> int:
    now = datetime.now()
    snapshot_dir = ROOT / ".trends"
    snapshot_dir.mkdir(exist_ok=True)
    snapshot = snapshot_dir / f"{now.year}-{now.month:02d}.md"
    now_str = now.isoformat()

    print("=== Engineering Trend Snapshot ===")
    print(f"Date: {now_str}")

    total = subprocess.run(
        "find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' "
        "-not -path './gen/proto/*' -not -path './vendor/*' | wc -l",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    total_files = int(total.stdout.strip())

    over_500 = subprocess.run(
        "find . -name '*.go' -not -path './.git/*' -not -path './.claude/*' "
        "-not -path './gen/proto/*' -not -path './vendor/*' -exec wc -l {} + 2>/dev/null "
        "| sort -rn | awk '$1 > 500' | wc -l",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    over_500_count = int(over_500.stdout.strip())

    print(f"  Total .go files: {total_files}")
    print(f"  Files > 500 lines: {over_500_count}")

    ratios = {}
    for pkg in ["core", "oauth", "oidc", "security", "defaultimpl"]:
        pkg_dir = ROOT / pkg
        if not pkg_dir.is_dir():
            continue
        src = len(list(pkg_dir.rglob("*.go"))) - len(list(pkg_dir.rglob("*_test.go")))
        tst = len(list(pkg_dir.rglob("*_test.go")))
        if src > 0:
            ratio = tst * 100 // src
            ratios[pkg] = (tst, src, ratio)
            print(f"  {pkg}/ test ratio: {ratio}% ({tst} test / {src} src)")

    no_store = subprocess.run(
        "grep -rl tokenNoStoreHeaders . --include='*.go' 2>/dev/null | grep -v '.claude/' | grep -v '.git/' | wc -l",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    no_store_count = int(no_store.stdout.strip())

    bcrypt = subprocess.run(
        "grep -rl bcrypt . --include='*.go' 2>/dev/null | grep -v '.claude/' | "
        "grep -v '.git/' | grep -v '_test.go' | wc -l",
        shell=True, capture_output=True, text=True, check=False, cwd=str(ROOT)
    )
    bcrypt_count = int(bcrypt.stdout.strip())

    print(f"  Files with no-store: {no_store_count}")
    print(f"  Files with bcrypt: {bcrypt_count}")

    with open(snapshot, "a") as f:
        f.write(f"\n## {now_str}\n")
        f.write(f"- Total: {total_files}, >500: {over_500_count}\n")
        f.write(f"- no-store: {no_store_count}, bcrypt: {bcrypt_count}\n")

    print(f"Snapshot appended to {snapshot}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
