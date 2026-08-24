#!/usr/bin/env python3
"""Coverage regression check with per-package targets.

Targets live in engineering.yaml (`coverage.targets`) — see checks/config.py.
"""
import subprocess
import sys
import tempfile
from pathlib import Path
import re

# Allow standalone invocation (python checks/coverage.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

_CONFIG = get_config()
TARGETS = dict(_CONFIG.coverage_targets)
MODULE = _CONFIG.project.module

# The target names are intentionally short in engineering.yaml because they
# are also used in health reports. Coverage files, however, contain complete
# Go import paths. Resolve the human names before matching or invoking `go`.
PACKAGE_ALIASES = {
    "core": "shared/core",
    "oauth": "protocols/oauth",
    "oidc": "protocols/oidc",
    "security": "shared/security",
    "defaultimpl": "infrastructure/defaultimpl",
}
_TOTAL_RE = re.compile(r"^total:\s+.*\s([0-9]+(?:\.[0-9]+)?)%\s*$")
_PACKAGE_RE = re.compile(r"coverage:\s*([0-9]+(?:\.[0-9]+)?)%")


def resolve_package_path(package: str, module: str = MODULE) -> str:
    """Return the full import path represented by a configured target."""
    if package == ".":
        return "."
    path = PACKAGE_ALIASES.get(package, package).lstrip("./")
    if path == module or path.startswith(module + "/"):
        return path
    return f"{module}/{path}"


def parse_total_coverage(output: str) -> float:
    """Extract the aggregate percentage from `go tool cover -func`."""
    for line in output.splitlines():
        match = _TOTAL_RE.match(line.strip())
        if match:
            return float(match.group(1))
    raise ValueError("coverage profile did not contain a total row")


def parse_package_coverage(output: str) -> float:
    """Extract the package percentage emitted by `go test -coverprofile`."""
    matches = _PACKAGE_RE.findall(output)
    if not matches:
        raise ValueError("go test output did not contain package coverage")
    return float(matches[-1])


def _run(args: list[str], root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(root), capture_output=True,
                          text=True, check=False)


def _report_failure(label: str, result: subprocess.CompletedProcess) -> None:
    print(f"  FAIL: {label} -- command exited {result.returncode}")
    details = (result.stdout + result.stderr).strip()
    if details:
        print(details)


def run() -> int:
    root = Path.cwd()
    print("--- coverage check ---")
    with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as tmp:
        profile = tmp.name
    ec = 0
    try:
        result = _run(["go", "test", "-count=1", "-coverprofile=" + profile, "./..."], root)
        if result.returncode != 0:
            _report_failure("./... test", result)
            return 1
        total_result = _run(["go", "tool", "cover", "-func=" + profile], root)
        if total_result.returncode != 0:
            _report_failure("coverage profile", total_result)
            return 1
        try:
            total_pct = parse_total_coverage(total_result.stdout)
        except ValueError as exc:
            print(f"  FAIL: . -- {exc}")
            return 1

        for pkg, target in TARGETS.items():
            if pkg == ".":
                pct = total_pct
            else:
                full_path = resolve_package_path(pkg)
                with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as target_tmp:
                    target_profile = target_tmp.name
                try:
                    target_result = _run(
                        ["go", "test", "-count=1", "-coverprofile=" + target_profile, full_path],
                        root,
                    )
                    if target_result.returncode != 0:
                        _report_failure(pkg, target_result)
                        ec = 1
                        continue
                    try:
                        pct = parse_package_coverage(target_result.stdout + target_result.stderr)
                    except ValueError as exc:
                        print(f"  FAIL: {pkg} ({full_path}) -- {exc}")
                        ec = 1
                        continue
                finally:
                    Path(target_profile).unlink(missing_ok=True)
            if pct < target:
                print(f"  FAIL: {pkg} -- {pct:.1f}% (target {target}%)")
                ec = 1
            else:
                print(f"  PASS: {pkg} -- {pct:.1f}% (target {target}%)")
    finally:
        Path(profile).unlink(missing_ok=True)
    if ec == 0:
        print("PASS")
    else:
        print("FAIL")
    return ec


if __name__ == "__main__":
    sys.exit(run())
