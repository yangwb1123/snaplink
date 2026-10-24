"""Synthetic reporting regressions, not native backend or runtime acceptance."""
import contextlib
import io
import subprocess
import sys

import pytest

from checks import acceptance, coverage


@pytest.mark.parametrize("code", [0, 1, 2, -9])
@pytest.mark.parametrize("stdout", ["", "child stdout\n"])
def test_run_py_retains_both_streams_without_changing_exit(monkeypatch, code, stdout):
    calls = []

    def child(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, code, stdout, "child stderr\n")

    monkeypatch.setattr(acceptance.subprocess, "run", child)
    result = acceptance.run_py("checks.coverage", "--fixture-argument")
    assert result == (code, stdout + "child stderr\n")
    assert calls == [([sys.executable, "-m", "checks.coverage", "--fixture-argument"],
                      dict(capture_output=True, text=True, check=False,
                           cwd=str(acceptance.ROOT)))]


@pytest.mark.parametrize("failure", ["root_test", "cover_tool", "missing_total",
                                     "low_total", "target_test", "missing_target"])
def test_acceptance_prints_real_coverage_owner_failure(monkeypatch, capsys, failure):
    """Run both real Python owners; only the Go/process seams are simulated."""
    for name in ("PASS", "FAIL", "TOTAL"):
        monkeypatch.setattr(acceptance, name, 0)
    go_calls = []

    def go_result(args, root):
        assert root == acceptance.ROOT
        go_calls.append(args)
        if args[:2] == ["go", "tool"]:
            if failure == "cover_tool":
                return subprocess.CompletedProcess(args, 2, "tool detail", "tool stderr")
            text = "no aggregate row" if failure == "missing_total" else (
                "total: (statements) 0.0%" if failure == "low_total" else
                "total: (statements) 100.0%")
            return subprocess.CompletedProcess(args, 0, text, "")
        assert args[:3] == ["go", "test", "-count=1"]
        assert args[3].startswith("-coverprofile=")
        if args[-1] == "./..." and failure == "root_test":
            return subprocess.CompletedProcess(args, 3, "root detail", "root stderr")
        if args[-1] == coverage.resolve_package_path("core"):
            if failure == "target_test":
                return subprocess.CompletedProcess(args, 7, "target detail", "target stderr")
            if failure == "missing_target":
                return subprocess.CompletedProcess(args, 0, "no percentage", "")
        return subprocess.CompletedProcess(args, 0, "coverage: 100.0%", "")

    def python_result(args, **kwargs):
        if args == [sys.executable, "-m", "checks.coverage"]:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = coverage.run()
            return subprocess.CompletedProcess(args, code, output.getvalue(), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(coverage, "_run", go_result)
    monkeypatch.setattr(acceptance.subprocess, "run", python_result)
    assert acceptance.run() == 1
    out = capsys.readouterr().out
    expected = {
        "root_test": ("./... test -- command exited 3", "root detailroot stderr"),
        "cover_tool": ("coverage profile -- command exited 2", "tool detailtool stderr"),
        "missing_total": ("coverage profile did not contain a total row",),
        "low_total": ("0.0% (target 10%)",),
        "target_test": ("core -- command exited 7", "target detailtarget stderr"),
        "missing_target": ("go test output did not contain package coverage",),
    }
    assert all(text in out for text in expected[failure])
    assert "ACCEPTANCE FAILED" in out and "9/10 -- 1 failures" in out
    assert acceptance.FAIL == 1 and acceptance.TOTAL == 10
    assert go_calls[0][-1] == "./..."


def test_acceptance_does_not_print_success_output_as_failure(monkeypatch, capsys):
    for name in ("PASS", "FAIL", "TOTAL"):
        monkeypatch.setattr(acceptance, name, 0)
    monkeypatch.setattr(acceptance, "run_go", lambda args: (0, ""))
    monkeypatch.setattr(acceptance, "run_py", lambda *args: (0, "success-private-detail"))
    assert acceptance.run() == 0
    out = capsys.readouterr().out
    assert "success-private-detail" not in out
    assert "ACCEPTANCE PASSED" in out and acceptance.TOTAL == 10
