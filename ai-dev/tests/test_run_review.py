"""Regression tests for ai-dev/ai/run-review.py.

Cover the repaired behaviors: live-run output persistence (including partial
output on failure), --all stage output chaining with explicit-value
precedence, and neutral defaults for omitted context fields.

The runner is loaded through importlib because its filename contains dashes.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

RUN_REVIEW = Path(__file__).resolve().parent.parent / "ai" / "run-review.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("run_review_under_test", RUN_REVIEW)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclass and module internals need the module registered
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def fake_agent(tmp_path):
    """A fake agent CLI that counts chained-stage markers in its prompt.

    Emitting a small deterministic value keeps chained prompts small (echoing
    the full prompt back would embed every upstream prompt into the next
    stage's output and grow the argv exponentially across --all stages). The
    count of "--- Stage NN output ---" markers verifies chaining end to end.
    """
    path = tmp_path / "fake-agent.sh"
    path.write_text(
        "#!/bin/sh\n"
        "echo \"$2\" | grep -o -- '--- Stage [0-9][0-9] output ---' | wc -l\n"
    )
    path.chmod(0o755)
    return path


class _Args:
    def __init__(self, **kwargs):
        self.agent_bin = kwargs.get("agent_bin", "")
        self.model = kwargs.get("model", "")
        self.output_dir = kwargs.get("output_dir")
        self.context_name = kwargs.get("context_name", "ctx")
        self.repo = kwargs.get("repo")


def test_chain_variables_fills_schema_placeholder():
    mod = load_runner()
    prior = {"00": "DISCOVERY TEXT"}
    variables = {"PRODUCT_DISCOVERY_OUTPUT": "(paste Stage 00 output, or 'N/A')"}
    defaults = {"PRODUCT_DISCOVERY_OUTPUT": "(paste Stage 00 output, or 'N/A')"}
    chained = mod.chain_variables(prior, "01", variables, defaults)
    assert chained["PRODUCT_DISCOVERY_OUTPUT"] == "--- Stage 00 output ---\nDISCOVERY TEXT"


def test_chain_variables_respects_explicit_value():
    mod = load_runner()
    prior = {"00": "DISCOVERY TEXT"}
    variables = {"PRODUCT_DISCOVERY_OUTPUT": "explicit context value"}
    defaults = {"PRODUCT_DISCOVERY_OUTPUT": "(paste Stage 00 output, or 'N/A')"}
    chained = mod.chain_variables(prior, "01", variables, defaults)
    assert chained == {}


def test_chain_variables_skips_missing_sources():
    mod = load_runner()
    variables = {"PRIOR_FINDINGS": "(paste Critical/High findings from Stages 01-03, or 'N/A')"}
    defaults = dict(variables)
    chained = mod.chain_variables({}, "04", variables, defaults)
    assert chained == {}


def test_context_to_vars_neutral_defaults():
    """Omitted storage/team/sprint fields must not fabricate project facts."""
    mod = load_runner()
    v03 = mod.context_to_vars({}, "03")
    assert v03["STORAGE_SUMMARY"] == ""
    v07 = mod.context_to_vars({}, "07")
    assert v07["TEAM_SIZE"] == ""
    assert v07["SPRINT_DURATION"] == ""
    v09 = mod.context_to_vars({}, "09")
    assert v09["TEAM_SIZE"] == ""


def test_run_stage_persists_output(tmp_path, fake_agent):
    mod = load_runner()
    args = _Args(agent_bin=str(fake_agent), output_dir=str(tmp_path), repo=str(tmp_path))
    rc = mod.run_stage("00", "PROMPT BODY", args)
    assert rc == 0
    out = tmp_path / "stage-00.out.md"
    assert out.exists()
    assert out.read_text(encoding="utf-8").strip() == "0"


def test_run_stage_keeps_partial_output_on_failure(tmp_path):
    agent = tmp_path / "fail-agent.sh"
    agent.write_text("#!/bin/sh\necho \"partial evidence\"\nexit 3\n")
    agent.chmod(0o755)
    mod = load_runner()
    args = _Args(agent_bin=str(agent), output_dir=str(tmp_path), repo=str(tmp_path))
    rc = mod.run_stage("00", "PROMPT BODY", args)
    assert rc == 3
    out = tmp_path / "stage-00.out.md"
    assert out.exists()
    assert "partial evidence" in out.read_text(encoding="utf-8")


def test_all_chains_stage_outputs_end_to_end(tmp_path, fake_agent):
    """--all must persist every stage and chain stage outputs downstream.

    The fake agent counts chained markers in the rendered prompt, so each
    stage-NN.out.md holds the number of upstream outputs it received: stage
    01 gets stage 00, stage 04 gets stages 01-03, stage 07 gets findings
    00-06 plus the stage 01 architecture, stage 09 gets stages 00-08.
    """
    ctx = tmp_path / "ctx.yaml"
    ctx.write_text("project: Test\nsubsystem: Chain\n", encoding="utf-8")
    out_dir = tmp_path / "reviews"
    result = subprocess.run(
        [
            sys.executable, str(RUN_REVIEW),
            "--all", "--context", str(ctx),
            "--agent-bin", str(fake_agent),
            "--output-dir", str(out_dir),
            "--repo", str(tmp_path),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    outputs = sorted(p.name for p in out_dir.iterdir())
    assert len(outputs) == 10
    assert (out_dir / "stage-00.out.md").read_text(encoding="utf-8").strip() == "0"
    assert (out_dir / "stage-01.out.md").read_text(encoding="utf-8").strip() == "1"
    assert (out_dir / "stage-02.out.md").read_text(encoding="utf-8").strip() == "1"
    assert (out_dir / "stage-03.out.md").read_text(encoding="utf-8").strip() == "1"
    assert (out_dir / "stage-04.out.md").read_text(encoding="utf-8").strip() == "3"
    assert (out_dir / "stage-06.out.md").read_text(encoding="utf-8").strip() == "4"
    assert (out_dir / "stage-07.out.md").read_text(encoding="utf-8").strip() == "8"
    assert (out_dir / "stage-09.out.md").read_text(encoding="utf-8").strip() == "9"
