"""Regression tests for ai-dev/pi-batch.py.

Cover the repaired behaviors: pi-batch.yaml resolution next to the script
(with cwd fallback and built-in defaults), post-stage command failures
failing the stage, and aggregate: true merging upstream outputs into one
combined task per template.

The runner is loaded through importlib because its filename contains dashes.
"""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PI_BATCH = Path(__file__).resolve().parent.parent / "pi-batch.py"


def load_batch():
    spec = importlib.util.spec_from_file_location("pi_batch_under_test", PI_BATCH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclass and module internals need the module registered
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def fake_agent(tmp_path):
    """A fake agent CLI that echoes its prompt argument and exits 0."""
    path = tmp_path / "fake-agent.sh"
    path.write_text("#!/bin/sh\necho \"$2\"\n")
    path.chmod(0o755)
    return path


@pytest.fixture()
def error_agent(tmp_path):
    """A fake agent that replies with a provider rate-limit error, exit 0."""
    path = tmp_path / "error-agent.sh"
    path.write_text("#!/bin/sh\necho \"Error: rate_limit_error, please retry\"\n")
    path.chmod(0o755)
    return path


def _run_import(cwd, script_path):
    code = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('m', %r)\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "sys.modules['m'] = m\n"
        "spec.loader.exec_module(m)\n"
        "print(m.AGENT_BIN, m.AGENT_DEFAULT_WORKERS)\n" % str(script_path)
    )
    return subprocess.run(
        [sys.executable, "-c", code], cwd=str(cwd), capture_output=True, text=True, timeout=60
    )


def test_config_resolved_next_to_script_beats_cwd(tmp_path):
    """The config file next to the script wins over a cwd config."""
    script_dir = tmp_path / "script"
    cwd_dir = tmp_path / "cwd"
    script_dir.mkdir()
    cwd_dir.mkdir()
    shutil.copy(PI_BATCH, script_dir / "pi-batch.py")
    (script_dir / "pi-batch.yaml").write_text(
        "agent:\n  bin: script-agent\n  default_workers: 7\n", encoding="utf-8"
    )
    (cwd_dir / "pi-batch.yaml").write_text(
        "agent:\n  bin: cwd-agent\n  default_workers: 8\n", encoding="utf-8"
    )
    result = _run_import(cwd_dir, script_dir / "pi-batch.py")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "script-agent 7"


def test_config_falls_back_to_cwd(tmp_path):
    """Without a script-adjacent config, the cwd config is used."""
    script_dir = tmp_path / "script"
    cwd_dir = tmp_path / "cwd"
    script_dir.mkdir()
    cwd_dir.mkdir()
    shutil.copy(PI_BATCH, script_dir / "pi-batch.py")
    (cwd_dir / "pi-batch.yaml").write_text(
        "agent:\n  bin: cwd-agent\n  default_workers: 5\n", encoding="utf-8"
    )
    result = _run_import(cwd_dir, script_dir / "pi-batch.py")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "cwd-agent 5"


def test_config_builtin_defaults_without_any_config(tmp_path):
    """No config anywhere -> built-in 'pi' binary and worker default."""
    script_dir = tmp_path / "script"
    cwd_dir = tmp_path / "cwd"
    script_dir.mkdir()
    cwd_dir.mkdir()
    shutil.copy(PI_BATCH, script_dir / "pi-batch.py")
    result = _run_import(cwd_dir, script_dir / "pi-batch.py")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "pi 4"


def _inputs_dir(tmp_path, names=("task1.md", "task2.md")):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name in names:
        (inputs / name).write_text(f"content of {name}", encoding="utf-8")
    return inputs


def test_command_failure_fails_stage(tmp_path, fake_agent):
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    stage = mod.Stage(name="s0", from_dir=str(inputs), commands=["exit 3"])
    results, ok = mod.execute_stage(stage, {})
    assert all(r.success for r in results)
    assert ok is False


def test_command_success_passes_stage(tmp_path, fake_agent):
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    stage = mod.Stage(name="s0", from_dir=str(inputs), commands=["true"])
    results, ok = mod.execute_stage(stage, {})
    assert all(r.success for r in results)
    assert ok is True


def test_aggregate_merges_upstream_outputs(tmp_path, fake_agent):
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    template = tmp_path / "role.md"
    template.write_text("Role prompt for {input_stem}:\n{input_content}\n", encoding="utf-8")

    stage0 = mod.Stage(name="s0", from_dir=str(inputs))
    results0, ok0 = mod.execute_stage(stage0, {})
    assert ok0 is True
    outputs = [r.task.output for r in results0 if r.success]
    assert len(outputs) == 2

    stage1 = mod.Stage(
        name="s1",
        from_outputs="s0",
        aggregate=True,
        tasks=[{"prompt_template": str(template), "output": str(tmp_path / "{input_stem}.out.md")}],
    )
    results1, ok1 = mod.execute_stage(stage1, {"s0": outputs})
    assert ok1 is True
    assert len(results1) == 1  # one combined task, not one per artifact
    assert results1[0].task.output.endswith("combined.out.md")
    assert "content of task1.md" in results1[0].task.prompt
    assert "content of task2.md" in results1[0].task.prompt


def test_fanout_default_creates_one_task_per_artifact(tmp_path, fake_agent):
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    template = tmp_path / "role.md"
    template.write_text("Role prompt for {input_stem}:\n{input_content}\n", encoding="utf-8")

    stage0 = mod.Stage(name="s0", from_dir=str(inputs))
    results0, _ = mod.execute_stage(stage0, {})
    outputs = [r.task.output for r in results0 if r.success]

    stage1 = mod.Stage(
        name="s1",
        from_outputs="s0",
        tasks=[{"prompt_template": str(template), "output": str(tmp_path / "{input_stem}.out.md")}],
    )
    results1, ok1 = mod.execute_stage(stage1, {"s0": outputs})
    assert ok1 is True
    assert len(results1) == 2  # fan-out preserved for non-aggregate stages


def test_agent_provider_error_rejects_task_and_does_not_save(tmp_path, error_agent):
    """Exit 0 with a rate-limit reply must mark the task failed and never
    write the output file."""
    mod = load_batch()
    mod.AGENT_BIN = str(error_agent)
    output = tmp_path / "result.md"
    task = mod.Task(prompt="review this", output=str(output))
    result = mod.run_task(task)
    assert result.success is False
    assert result.returncode == 0  # the process itself succeeded
    mod.save_result(task, result)
    assert not output.exists()


def test_agent_nonzero_exit_does_not_save(tmp_path):
    agent = tmp_path / "exit-agent.sh"
    agent.write_text("#!/bin/sh\necho \"partial\"\nexit 2\n")
    agent.chmod(0o755)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    output = tmp_path / "result.md"
    task = mod.Task(prompt="review this", output=str(output))
    result = mod.run_task(task)
    assert result.success is False
    mod.save_result(task, result)
    assert not output.exists()


def test_agent_legitimate_prose_is_saved(tmp_path):
    """Review prose mentioning error words must not be misclassified."""
    agent = tmp_path / "prose-agent.sh"
    agent.write_text("#!/bin/sh\necho \"timeout handling and 401 Unauthorized are findings\"\n")
    agent.chmod(0o755)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    output = tmp_path / "result.md"
    task = mod.Task(prompt="review this", output=str(output))
    result = mod.run_task(task)
    assert result.success is True
    mod.save_result(task, result)
    assert output.exists()


def test_agent_offline_output_rejects_task_and_does_not_save(tmp_path):
    """Offline/network failure replies must mark the task failed and never
    write the output file."""
    for banner in (
        "curl: (7) Failed to connect to api.example.com",
        "ConnectionError: network is unreachable",
        "requests.exceptions.ConnectionError: Max retries exceeded",
    ):
        agent = tmp_path / "offline-agent.sh"
        agent.write_text(f"#!/bin/sh\necho \"{banner}\"\n")
        agent.chmod(0o755)
        mod = load_batch()
        mod.AGENT_BIN = str(agent)
        output = tmp_path / "result.md"
        task = mod.Task(prompt="review this", output=str(output))
        result = mod.run_task(task)
        assert result.success is False
        mod.save_result(task, result)
        assert not output.exists()


def test_reuse_skips_existing_from_outputs_aggregate(tmp_path, fake_agent):
    """--reuse must skip from_outputs tasks whose output exists and keep the
    reused paths visible to downstream stages."""
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    template = tmp_path / "role.md"
    template.write_text("Role prompt for {input_stem}:\n{input_content}\n", encoding="utf-8")
    combined = tmp_path / "combined.out.md"

    stage0 = mod.Stage(name="s0", from_dir=str(inputs))
    results0, _ = mod.execute_stage(stage0, {})
    outputs0 = [r.task.output for r in results0 if r.success]
    stage1 = mod.Stage(
        name="s1",
        from_outputs="s0",
        aggregate=True,
        tasks=[{"prompt_template": str(template), "output": str(combined)}],
    )
    results1, _ = mod.execute_stage(stage1, {"s0": outputs0})
    assert len(results1) == 1
    assert combined.exists()

    # second pass with reuse: nothing reruns, downstream still sees combined
    stage_outputs2 = {}
    results0b, ok0 = mod.execute_stage(stage0, stage_outputs2, reuse=True)
    assert ok0 is True and len(results0b) == 0
    assert sorted(stage_outputs2["s0"]) == sorted(outputs0)
    results1b, ok1 = mod.execute_stage(stage1, stage_outputs2, reuse=True)
    assert ok1 is True and len(results1b) == 0
    assert stage_outputs2["s1"] == [str(combined)]


def test_reuse_skips_existing_from_outputs_fanout(tmp_path, fake_agent):
    """Non-aggregate from_outputs tasks with existing outputs are reused too."""
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    template = tmp_path / "role.md"
    template.write_text("Role prompt for {input_stem}:\n{input_content}\n", encoding="utf-8")

    stage0 = mod.Stage(name="s0", from_dir=str(inputs))
    results0, _ = mod.execute_stage(stage0, {})
    outputs0 = [r.task.output for r in results0 if r.success]
    stage1 = mod.Stage(
        name="s1",
        from_outputs="s0",
        tasks=[{"prompt_template": str(template), "output": str(tmp_path / "{input_stem}.out.md")}],
    )
    results1, _ = mod.execute_stage(stage1, {"s0": outputs0})
    assert len(results1) == 2
    assert all(Path(r.task.output).exists() for r in results1)

    stage_outputs2 = {}
    results0b, ok0 = mod.execute_stage(stage0, stage_outputs2, reuse=True)
    assert ok0 is True and len(results0b) == 0
    results1b, ok1 = mod.execute_stage(stage1, stage_outputs2, reuse=True)
    assert ok1 is True and len(results1b) == 0
    assert sorted(stage_outputs2["s1"]) == sorted(r.task.output for r in results1)


def test_pipeline_reports_failed_stage(tmp_path, fake_agent):
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    pipeline = mod.Pipeline(stages=[
        mod.Stage(name="s0", from_dir=str(inputs), commands=["exit 1"]),
    ])
    results, failed = mod.run_pipeline(pipeline)
    assert failed == ["s0"]
    assert len(results) == 2  # tasks still ran; the stage is marked failed
