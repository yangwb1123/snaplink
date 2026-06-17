#!/usr/bin/env python3
import subprocess, sys

def check():
    print("=== Post-Edit Check ===")
    r = subprocess.run(["make", "check-quick"], capture_output=True, text=True, check=False)
    print(r.stdout)
    if r.stderr: print(r.stderr, file=sys.stderr)
    if r.returncode != 0:
        print("FAIL: make check-quick -- fix before continuing", file=sys.stderr); return 1
    changed = subprocess.run(["git", "diff", "--name-only"], capture_output=True, text=True, check=False)
    if changed.stdout.strip():
        go_files = [f for f in changed.stdout.strip().split("\n") if f.endswith(".go")]
        if go_files:
            print(f"\nModified Go files ({len(go_files)}):")
            for f in go_files: print(f"  {f}")
    print("\nPASS: post-edit checks passed"); return 0

if __name__ == "__main__":
    sys.exit(check())
