#!/usr/bin/env python3
"""File size gate: source files must stay under the configured line budget.

Thresholds, ignore patterns, and exemptions live in engineering.yaml
(`filesize:` section) — see checks/config.py. MAX_LINES/IGNORE_PATTERNS/
EXEMPTIONS below are read from that config at import time so existing
callers/tests can keep using them as plain constants.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/filesize.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

_fs = get_config().filesize
MAX_LINES = _fs.max_lines
IGNORE_PATTERNS = tuple(_fs.ignore_patterns)
EXEMPTIONS = list(_fs.exemptions)


def is_exempt(path: Path, rel: str, exemptions: list = None) -> bool:
    if exemptions is None:
        exemptions = EXEMPTIONS
    for e in exemptions:
        if e.endswith("/*"):
            base = e[:-2]
            if rel.startswith(base):
                return True
        if e == rel or rel.endswith("/" + e):
            return True
    return False


def check_file(path: Path, root: Path) -> bool:
    if path.suffix != ".go":
        return True
    path = path.resolve()
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        # path isn't under root (e.g. a CLI arg outside the repo tree) --
        # fall back to the absolute path; no ignore-pattern/exemption can
        # sensibly match it, so it still gets the plain line-count check.
        rel = str(path)
    for pat in IGNORE_PATTERNS:
        if pat in rel:
            return True
    if is_exempt(path, rel):
        return True
    lines = len(path.read_text().splitlines())
    if lines > MAX_LINES:
        print(f"  FAIL: {rel} ({lines} lines, max {MAX_LINES})")
        return False
    return True


def run(files: list[Path] = None) -> int:
    root = Path.cwd()
    if files:
        ok = all(check_file(f, root) for f in files)
    else:
        go_files = sorted(root.rglob("*.go"))
        ok = True
        for f in go_files:
            rel = str(f.relative_to(root))
            if "/.git/" in rel or "/.claude/" in rel:
                continue
            if not check_file(f, root):
                ok = False
    if ok:
        print("PASS: filesize")
        return 0
    print("FAIL: split before continuing")
    return 1


if __name__ == "__main__":
    args = [Path(a) for a in sys.argv[1:]] if len(sys.argv) > 1 else None
    sys.exit(run(args))
