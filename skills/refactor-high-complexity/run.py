#!/usr/bin/env python3
import argparse, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.fs import count_lines

def run_gocyclo(filepath: Path):
    result = subprocess.run(["gocyclo", str(filepath)], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"WARN: gocyclo not available: {result.stderr.strip()}", file=sys.stderr); return []
    funcs = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0].isdigit():
            location = parts[3]
            line_num = int(location.split(":")[1]) if ":" in location else int(location)
            funcs.append({"cyclo": int(parts[0]), "name": parts[2], "line": line_num})
    return funcs

def analyze(filepath: Path, func_filter: str | None = None):
    if not filepath.exists():
        print(f"ERROR: {filepath} not found", file=sys.stderr); return 1
    total = count_lines(filepath)
    print(f"=== Complexity Analysis: {filepath} ({total} lines) ===")
    funcs = run_gocyclo(filepath)
    if not funcs:
        return 0
    failures = [(f, ["Guard Clauses", "Strategy Table", "Extract Sub-Functions", "Separation of Concerns"][:3])
                for f in funcs if f["cyclo"] > 15 and (func_filter is None or f["name"] == func_filter)]
    if not failures:
        print("All functions within cyclo <= 15 limit"); return 0
    for f, strategies in failures:
        print(f"\n  FAIL: {f['name']} (cyclo={f['cyclo']}, line {f['line']})")
        print(f"  Suggested: {', '.join(strategies)}")
    return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str)
    parser.add_argument("--function", "-f", type=str)
    args = parser.parse_args()
    sys.exit(analyze(Path(args.file), args.function))
