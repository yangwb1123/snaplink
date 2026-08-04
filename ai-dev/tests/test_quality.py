"""Tests for the code organization quality scanner (ai-dev/quality.py)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

QUALITY = Path(__file__).parent.parent / "quality.py"


def _run_quality(paths: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(QUALITY)] + paths,
        capture_output=True, text=True, timeout=60,
    )


def test_clean_file_passes(tmp_path):
    good = tmp_path / "good.py"
    good.write_text(
        "def ok():\n"
        "    return 1\n"
        "\n"
        "def small(x):\n"
        "    y = 0\n"
        "    for i in range(x):\n"
        "        y += i\n"
        "    return y\n",
        encoding="utf-8",
    )
    result = _run_quality([str(good)])
    assert result.returncode == 0
    assert "quality: OK" in result.stdout


def test_long_function_reported(tmp_path):
    bad = tmp_path / "bad.py"
    lines = ["def big():"]
    lines += [f"    x{i} = {i}" for i in range(60)]
    lines += ["    return x59"]
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = _run_quality([str(bad)])
    assert result.returncode == 1
    assert "func 'big'" in result.stdout
    assert "lines > 50 budget" in result.stdout


def test_high_complexity_reported(tmp_path):
    bad = tmp_path / "cx.py"
    lines = ["def tangled(a, b, c, d):"]
    for i in range(18):
        lines.append(f"    if a{i} == {i}:")
        lines.append(f"        b{i} = c{i}")
    lines.append("    return 0")
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = _run_quality([str(bad)])
    assert result.returncode == 1
    assert "complexity 18 > 15 budget" in result.stdout


def test_test_files_get_doubled_budgets(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    long_test = tests / "test_long.py"
    lines = ["def test_scenario():", "    assert True"]
    lines += [f"    x{i} = {i}" for i in range(60)]  # 62 lines: fine for tests
    long_test.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = _run_quality([str(long_test)])
    assert result.returncode == 0


def test_syntax_error_reported(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n    pass\n", encoding="utf-8")
    result = _run_quality([str(broken)])
    assert result.returncode == 1
    assert "SYNTAX ERROR" in result.stdout
