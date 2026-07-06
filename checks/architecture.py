#!/usr/bin/env python3
"""Architecture dependency direction gate.

The forbidden-import map and excluded dirs live in engineering.yaml
(`architecture:` section) — see checks/config.py and AGENTS.md §0.2.
"""
import sys
from pathlib import Path

# Allow standalone invocation (python checks/architecture.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

ROOT = Path.cwd()

_cfg = get_config()
_arch = _cfg.architecture
FORBIDDEN = dict(_arch.forbidden)
EXCLUDED_DIRS = set(_arch.excluded_dirs)
MODULE_PREFIX = f'"{_cfg.project.module}/'


def get_package(dir_path: Path) -> str:
    rel = dir_path.relative_to(ROOT)
    return rel.parts[0] if rel.parts else "sso"


def check_package(dir_path: Path) -> list[str]:
    pkg = get_package(dir_path)
    if pkg == "sso" or pkg == "cmd":
        return []
    forbidden_pkgs = FORBIDDEN.get(pkg, [])
    if not forbidden_pkgs:
        return []
    violations = []
    for go_file in sorted(dir_path.glob("*.go")):
        if go_file.name.endswith("_test.go"):
            continue
        content = go_file.read_text()
        for line in content.split("\n"):
            if MODULE_PREFIX not in line:
                continue
            imp = line.split(MODULE_PREFIX)[1].split('"')[0]
            imp_pkg = imp.split("/")[0]
            if imp_pkg in forbidden_pkgs:
                rel_dir = dir_path.relative_to(ROOT)
                violations.append(f"  FAIL: {rel_dir} imports {imp} (forbidden)")
    return violations


def run(package_dirs: list[Path] = None) -> int:
    print("--- architecture check ---")
    all_violations = []
    if package_dirs:
        for d in package_dirs:
            all_violations.extend(check_package(d.resolve()))
    else:
        for d in sorted(ROOT.iterdir()):
            if not d.is_dir() or d.name.startswith(".") or d.name in EXCLUDED_DIRS:
                continue
            has_go = len(list(d.glob("*.go"))) > 0
            if not has_go:
                continue
            all_violations.extend(check_package(d))
            for sub in sorted(d.rglob("*")):
                if not sub.is_dir() or sub.name.startswith(".") or sub.parent.name in EXCLUDED_DIRS:
                    continue
                if any(part in EXCLUDED_DIRS for part in sub.relative_to(ROOT).parts):
                    continue
                if len(list(sub.glob("*.go"))) > 0:
                    all_violations.extend(check_package(sub))

    for v in sorted(set(all_violations)):
        print(v)
    if all_violations:
        return 1
    print("  PASS")
    return 0


if __name__ == "__main__":
    args = [Path(a) for a in sys.argv[1:]] if len(sys.argv) > 1 else None
    sys.exit(run(args))
