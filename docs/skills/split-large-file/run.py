#!/usr/bin/env python3
import argparse, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.fs import list_exported_functions, count_lines

def analyze(filepath: Path):
    if not filepath.exists():
        print(f"ERROR: {filepath} not found", file=sys.stderr); return 1
    total = count_lines(filepath)
    print(f"=== Split Analysis: {filepath} ({total} lines) ===")
    if total <= 500:
        print("OK: under 500-line limit"); return 0
    exports = list_exported_functions(filepath)
    print(f"\nExported functions ({len(exports)}):")
    for name, line in exports:
        print(f"  {name:40s} line {line}")
    print("\nSuggested split by concern:")
    print("  Group by domain concern. Naming: <prefix>_<concern>.go")
    print("  Target: each new file < 500 lines")
    return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Go file for splitting")
    parser.add_argument("file", type=str)
    sys.exit(analyze(Path(parser.parse_args().file)))
