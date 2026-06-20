#!/usr/bin/env python3
import argparse, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.git import root as git_root
from shared.fs import count_lines

ROOT_EXEMPT = {
    # Project docs live under docs/ and .github/; agent-OS docs under
    # docs/agent-os/. Only the canonical agent entry points (AGENTS.md +
    # its CLAUDE.md loader) and build/config remain at root.
    "README.md","LICENSE",
    "AGENTS.md","CLAUDE.md",
    "go.mod","go.sum","Makefile","Taskfile.yml","cli.py","pyproject.toml",
    "Dockerfile",".dockerignore",".gitignore",".editorconfig",
    ".golangci.yml",".goreleaser.yaml",
}
BANNED = {"util.py","utils.py","helper.py","helpers.py","temp.py","demo.py","fix.py","run.py","util.go","helper.go","fix.go","temp.go"}

def analyze(dry_run=True):
    repo = git_root()
    root_files = sorted(f for f in repo.iterdir() if f.is_file() and not f.name.startswith("."))
    go_files = [f for f in root_files if f.suffix == ".go"]
    non_exempt = [f for f in root_files if f.name not in ROOT_EXEMPT and f.suffix != ".go" and not f.name.startswith(".check-")]
    total_non_exempt = len(go_files) + len(non_exempt)
    print(f"=== Project Structure Analysis ===")
    print(f"Root Go files: {len(go_files)}")
    print(f"Other non-exempt: {len(non_exempt)}")
    print(f"Total violations: {total_non_exempt} (target <= 15)")
    if total_non_exempt > 0:
        print(f"\n--- Go files ({len(go_files)}) ---")
        for f in go_files:
            print(f"  {f.name:50s} ({count_lines(f)} lines)")
        if non_exempt:
            print(f"\n--- Other ---")
            for f in non_exempt:
                print(f"  {f.name}")
    for banned in BANNED:
        if any(f.name == banned for f in root_files):
            print(f"\n  BANNED: {banned}")
    print(f"\nTo reorganize: create module dirs, move files, update imports")
    if dry_run:
        print("[Dry-run] No changes made. Re-run without --dry-run to apply.")
    return total_non_exempt

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--analyze-only", action="store_true")
    p.add_argument("--dry-run", action="store_true", default=True)
    sys.exit(analyze(dry_run=p.parse_args().dry_run or p.parse_args().analyze_only))
