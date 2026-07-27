#!/usr/bin/env python3
"""Regenerate disposable engineering scaffolding.

Project Markdown is source-controlled and hand-maintained. This script verifies
the tracked agent-OS, review, feature-spec, and pi prompt documents exist; it
does not overwrite them with embedded point-in-time copies.
"""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def cp(src: str, dst: str):
    full_src = ROOT / src
    full_dst = ROOT / dst
    full_dst.parent.mkdir(parents=True, exist_ok=True)
    if full_src.exists():
        shutil.copy2(full_src, full_dst)
        return True
    return False


def ensure_dir(path: str):
    (ROOT / path).mkdir(parents=True, exist_ok=True)


def symlink_skills():
    (ROOT / ".pi" / "skills").mkdir(parents=True, exist_ok=True)
    for skill in ["split-large-file", "refactor-high-complexity", "add-new-handler",
                  "oracle-leak", "post-edit-check", "architecture-fix", "project-reorganization"]:
        src = f"../../docs/skills/{skill}"
        dst = ROOT / ".pi" / "skills" / skill
        dst.unlink(missing_ok=True)
        dst.symlink_to(src)


def require_tracked_markdown(path: str):
    target = ROOT / path
    if not target.is_file():
        raise FileNotFoundError(f"required tracked Markdown missing: {path}")


def write_todo_md():
    require_tracked_markdown("docs/agent-os/TODO.md")


def write_review_checklist():
    require_tracked_markdown("docs/review-checklist.md")


def write_feature_spec_template():
    require_tracked_markdown("docs/templates/feature-spec.md")


def write_pi_files():
    require_tracked_markdown(".pi/APPEND_SYSTEM.md")
    (ROOT / ".pi" / "settings.json").write_text(
        '{\n  "additionalSystemFiles": [".pi/APPEND_SYSTEM.md"]\n}\n'
    )
    for name in ["architect.md", "implement.md", "review.md", "diagnose.md",
                 "refactor.md", "split.md"]:
        require_tracked_markdown(f".pi/prompts/{name}")


def write_githooks():
    (ROOT / ".githooks").mkdir(exist_ok=True)
    pre_commit = """#!/usr/bin/env python3
import subprocess, sys
from pathlib import Path
def main():
    r = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"], capture_output=True, text=True)
    staged = [f for f in r.stdout.strip().split("\\n") if f.endswith(".go")]
    if not staged: return 0
    for f in staged:
        if not Path(f).exists(): continue
        r2 = subprocess.run([sys.executable, "checks/filesize.py", f], capture_output=True, text=True)
        if "FAIL" in r2.stdout: print(f"pre-commit FAILED: {f} exceeds 500 lines"); return 1
    r3 = subprocess.run(["gofmt", "-l"] + staged, capture_output=True, text=True)
    if r3.stdout.strip(): print("pre-commit: gofmt needed in:\\n" + r3.stdout); return 1
    return 0
if __name__ == "__main__": sys.exit(main())
"""
    (ROOT / ".githooks" / "pre-commit").write_text(pre_commit)

    pre_push = """#!/usr/bin/env python3
import subprocess, sys
def main():
    r = subprocess.run([sys.executable, "cli.py", "harness"], capture_output=True, text=True)
    if r.returncode != 0: print("pre-push FAILED"); return 1
    return 0
if __name__ == "__main__": sys.exit(main())
"""
    (ROOT / ".githooks" / "pre-push").write_text(pre_push)
    for f in ["pre-commit", "pre-push"]:
        (ROOT / ".githooks" / f).chmod(0o755)


def run():
    print("  [gen] Generating engineering scaffolding...")
    print("  [gen] checks/ (source-controlled)")

    # Core documents are tracked sources, not generated copies.
    for doc in ["HARNESS.md", "BOOTSTRAP.md", "ARCHITECTURE.md", "EVALUATION.md", "CHECKS_REGISTRY.md"]:
        require_tracked_markdown(f"docs/agent-os/{doc}")
        print(f"  [check] docs/agent-os/{doc}")
    write_todo_md()
    print("  [check] docs/agent-os/TODO.md")

    # Git hooks
    write_githooks()
    print("  [gen] .githooks/pre-commit, .githooks/pre-push")

    # Skills (source-controlled, ensure symlinks)
    print("  [gen] skills/ (7 dirs, 21 files, source-controlled)")
    symlink_skills()

    # Scripts
    print("  [gen] scripts/ (3 .py files, source-controlled)")

    # .pi/ Markdown is tracked; only settings.json is deterministic output.
    write_pi_files()
    print("  [check] .pi/ tracked prompts; [gen] settings.json")

    # Review documents are tracked sources.
    write_review_checklist()
    print("  [check] docs/review-checklist.md")

    # docs/templates/feature-spec.md
    write_feature_spec_template()
    print("  [check] docs/templates/feature-spec.md")

    print()
    print("  [gen] Done: disposable hooks/settings refreshed; tracked Markdown preserved")
    return 0


if __name__ == "__main__":
    sys.exit(run())
