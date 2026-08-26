#!/usr/bin/env python3
"""Guard generated SDK outputs and the optional deployment artifact tree."""

from __future__ import annotations

import argparse
import difflib
import itertools
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGEN_CMD = ["go", "run", "./cmd/gensdk", "--lang=all"]
DIFF_SAMPLE_LINES = 10
STATIC_DIR = Path("ops/deploy/openresty/fullstack/static")
REGEN_OUTPUTS = (
    (Path("docs/sdks/typescript/client.ts"), "client.ts"),
    (Path("docs/sdks/python/client.py"), "client.py"),
)
DEPLOY_OUTPUTS = (
    (Path("docs/openapi.yaml"), Path("docs/openapi.yaml")),
    (Path("docs/sdks/typescript/client.ts"), Path("docs/sdks/client.ts")),
    (Path("docs/sdks/python/client.py"), Path("docs/sdks/client.py")),
)


def run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run git through one seam so git failures remain fail-closed and testable."""
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def _display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _diff_sample(expected: bytes, actual: bytes, expected_name: str, actual_name: str) -> list[str]:
    """Return a bounded byte-aware unified diff sample, never the whole artifact."""
    diff = difflib.diff_bytes(
        difflib.unified_diff,
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile=expected_name.encode(),
        tofile=actual_name.encode(),
        n=0,
    )
    sample = list(itertools.islice(diff, DIFF_SAMPLE_LINES + 1))
    truncated = len(sample) > DIFF_SAMPLE_LINES
    lines = ["  diff sample:"]
    for line in sample[:DIFF_SAMPLE_LINES]:
        lines.append("    " + line.decode("utf-8", errors="replace").rstrip("\n"))
    if truncated:
        lines.append(f"    ... diff sample truncated at {DIFF_SAMPLE_LINES} lines ...")
    return lines


def _compare_files(expected_path: Path, actual_path: Path, root: Path, context: str) -> list[str]:
    try:
        expected = expected_path.read_bytes()
    except OSError as exc:
        return [f"{context}: cannot read {_display(expected_path, root)}: {exc}"]
    try:
        actual = actual_path.read_bytes()
    except OSError as exc:
        return [f"{context}: cannot read {_display(actual_path, root)}: {exc}"]
    if expected == actual:
        return []
    expected_name = _display(expected_path, root)
    actual_name = _display(actual_path, root)
    return [
        f"{context}: byte mismatch ({expected_name} <> {actual_name})",
        *_diff_sample(expected, actual, expected_name, actual_name),
    ]


def _status_errors(root: Path) -> list[str]:
    # dist/ is a separate committed TypeScript build product; local npm builds
    # must not make this generator-output cleanliness check fail.
    try:
        result = run_git(
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                "docs/sdks/",
                ":(exclude)docs/sdks/typescript/dist/",
            ],
            root,
        )
    except OSError as exc:
        return [f"git status unavailable while checking docs/sdks/: {exc}"]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic").strip()
        return [f"git status failed while checking docs/sdks/: {detail}"]
    return [f"docs/sdks/ has uncommitted drift: {line}" for line in result.stdout.splitlines()]


def _run_generator(root: Path, tmp: Path, regen_cmd: list[str]) -> list[str]:
    outputs = [tmp / name for _, name in REGEN_OUTPUTS]
    command = [
        *regen_cmd,
        f"--out-ts={outputs[0]}",
        f"--out-py={outputs[1]}",
        # The generator otherwise writes the installable package beside the
        # repository; the drift leg must leave every working-tree artifact alone.
        "--out-package-py=",
    ]
    try:
        result = subprocess.run(
            command, cwd=root, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        return [f"generator unavailable ({' '.join(regen_cmd)}): {exc}"]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic").strip()
        return [f"generator failed with exit {result.returncode}: {detail}"]
    errors: list[str] = []
    for output in outputs:
        if not output.is_file():
            errors.append(f"generator did not create temporary output {output}")
    return errors


def check_regen(root: Path, tmp: Path, regen_cmd: list[str]) -> list[str]:
    """Regenerate into ``tmp`` and compare only generator-owned canonical files."""
    errors = _run_generator(root, tmp, regen_cmd)
    if errors:
        return errors
    for canonical, generated_name in REGEN_OUTPUTS:
        errors.extend(
            _compare_files(
                root / canonical,
                tmp / generated_name,
                root,
                "sdk-drift regeneration",
            )
        )
    errors.extend(_status_errors(root))
    return errors


def check_deploy(root: Path) -> tuple[list[str], bool]:
    """Sweep static copies, skipping only a genuinely absent external tree."""
    static = root / STATIC_DIR
    if not static.exists():
        return [], True
    if not static.is_dir():
        return [f"deploy sweep: static path is not a directory: {_display(static, root)}"], False

    errors: list[str] = []
    for canonical, relative_target in DEPLOY_OUTPUTS:
        source = root / canonical
        target = static / relative_target
        if not source.is_file():
            errors.append(f"deploy sweep: canonical source missing: {_display(source, root)}")
            continue
        if not target.is_file():
            errors.append(f"deploy sweep: target missing: {_display(target, root)}")
            continue
        errors.extend(
            _compare_files(source, target, root, "deploy sweep")
        )
    return errors, False


def _run_check() -> int:
    with tempfile.TemporaryDirectory(prefix="snaplink-sdk-drift-") as temporary:
        regen_errors = check_regen(ROOT, Path(temporary), REGEN_CMD)

    deploy_errors, deploy_skipped = check_deploy(ROOT)
    if regen_errors:
        print("sdk-drift: FAIL regeneration leg")
        for error in regen_errors:
            print(f"  {error}")
    if deploy_errors:
        print("sdk-drift: FAIL deploy leg")
        for error in deploy_errors:
            print(f"  {error}")
    if deploy_skipped:
        print("sdk-drift: SKIP deploy leg (static tree absent)")
    if regen_errors or deploy_errors:
        return 1
    deploy_summary = "skipped" if deploy_skipped else "3/3"
    print(f"sdk-drift: OK (regen 2/2, deploy {deploy_summary})")
    return 0


def run(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="sdk-drift",
        description="Regenerate SDK artifacts in a temporary tree and sweep deploy copies.",
    )
    parser.add_argument("action", choices=["check"], help="run both SDK drift legs")
    parsed = parser.parse_args(args)
    if parsed.action == "check":
        return _run_check()
    return 2


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
