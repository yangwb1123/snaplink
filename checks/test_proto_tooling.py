"""Proto tool routing only; real lint/breaking coverage is reported separately."""
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUF = "github.com/bufbuild/buf/cmd/buf@v1.73.0"
TARGETS = [("proto-lint", "lint"), ("proto-gen", "generate"),
           ("proto-breaking", "breaking")]


@pytest.mark.parametrize("target,action", TARGETS)
def test_proto_targets_use_same_pinned_tool(target, action):
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", "GO=go", target],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert f"GOTOOLCHAIN=go1.26.9 go run {BUF} {action}" in result.stdout
    assert "@latest" not in result.stdout
    if action == "breaking":
        assert '--against "../.git#branch=main,subdir=proto"' in result.stdout


def test_proto_lint_propagates_tool_failure(tmp_path):
    # Dispatch control, not a fake proto-validator success: the tool refuses.
    tool = tmp_path / "go-refusal"
    tool.write_text("#!/bin/sh\necho 'tool refused' >&2\nexit 37\n")
    tool.chmod(0o700)
    result = subprocess.run(
        ["make", "--no-print-directory", f"GO={tool}", "proto-lint"],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "tool refused" in result.stderr
    assert "Error 37" in result.stderr
