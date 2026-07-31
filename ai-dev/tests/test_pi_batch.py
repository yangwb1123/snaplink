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


def _flaky_agent(tmp_path, counter, fail_times):
    """Agent that fails with a rate-limit reply for the first `fail_times`
    calls, then succeeds; each call appends to `counter`."""
    agent = tmp_path / "flaky-agent.sh"
    agent.write_text(
        "#!/bin/sh\n"
        f"echo x >> {counter}\n"
        f"if [ $(wc -l < {counter}) -le {fail_times} ]; then\n"
        "  echo 'Error: rate_limit_error'\n"
        "else\n"
        "  echo 'OK'\n"
        "fi\n"
    )
    agent.chmod(0o755)
    return agent


def test_serial_retry_recovers_after_transient_failure(tmp_path, monkeypatch):
    """A rate-limit reply is retried and the task succeeds on the next try."""
    counter = tmp_path / "counter"
    agent = _flaky_agent(tmp_path, counter, fail_times=1)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    monkeypatch.setattr(mod.time, "sleep", lambda _: None)  # no real backoff wait
    output = tmp_path / "o.md"
    results = mod.run_serial([mod.Task(prompt="x", output=str(output))], retries=2, retry_delay=0)
    assert results[0].success is True
    assert output.exists()
    assert counter.read_text(encoding="utf-8").count("x") == 2


def test_serial_retry_exhausts(tmp_path, monkeypatch):
    """A persistently failing task is retried up to the limit, then fails and
    never saves an output file."""
    counter = tmp_path / "counter"
    agent = _flaky_agent(tmp_path, counter, fail_times=999)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    monkeypatch.setattr(mod.time, "sleep", lambda _: None)
    output = tmp_path / "o.md"
    results = mod.run_serial([mod.Task(prompt="x", output=str(output))], retries=2, retry_delay=0)
    assert results[0].success is False
    assert results[0].reason
    assert not output.exists()
    assert counter.read_text(encoding="utf-8").count("x") == 3  # 1 + 2 retries


def test_task_result_carries_reason(tmp_path, fake_agent, error_agent):
    mod = load_batch()
    mod.AGENT_BIN = str(error_agent)
    failed = mod.run_task(mod.Task(prompt="x"))
    assert failed.success is False
    assert "rate" in failed.reason.lower()
    mod.AGENT_BIN = str(fake_agent)
    ok = mod.run_task(mod.Task(prompt="x"))
    assert ok.success is True
    assert ok.reason == ""


def test_max_rounds_loop_reruns_failures(tmp_path):
    """CLI --max-rounds reruns the whole batch each round and exits non-zero
    when the rounds are exhausted."""
    counter = tmp_path / "counter"
    agent = _flaky_agent(tmp_path, counter, fail_times=999)
    inputs = _inputs_dir(tmp_path)
    result = subprocess.run(
        [
            sys.executable, str(PI_BATCH),
            "--from-dir", str(inputs),
            "--agent-bin", str(agent),
            "--mode", "serial",
            "--max-rounds", "2",
            "--round-delay", "0",
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode != 0
    assert counter.read_text(encoding="utf-8").count("x") == 4  # 2 rounds x 2 tasks
    assert not (inputs / "task1.out.md").exists()


def test_loop_stops_when_all_pass(tmp_path):
    """--max-rounds 0 loops until every task passes, then exits 0."""
    counter = tmp_path / "counter"
    agent = _flaky_agent(tmp_path, counter, fail_times=2)
    inputs = _inputs_dir(tmp_path)
    result = subprocess.run(
        [
            sys.executable, str(PI_BATCH),
            "--from-dir", str(inputs),
            "--agent-bin", str(agent),
            "--mode", "serial",
            "--max-rounds", "0",
            "--round-delay", "0",
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    # round 1: 2 failures; round 2: both pass -> 4 calls total
    assert counter.read_text(encoding="utf-8").count("x") == 4
    assert (inputs / "task1.out.md").exists()


def test_reuse_filters_single_batch(tmp_path, fake_agent):
    """--reuse in single-batch mode skips tasks with existing outputs."""
    counter = tmp_path / "counter"
    agent = tmp_path / "counting-agent.sh"
    agent.write_text(f"#!/bin/sh\necho x >> {counter}\necho \"$2\"\n")
    agent.chmod(0o755)
    inputs = _inputs_dir(tmp_path)
    base = [
        sys.executable, str(PI_BATCH),
        "--from-dir", str(inputs),
        "--agent-bin", str(agent),
        "--mode", "serial",
    ]
    first = subprocess.run(base, capture_output=True, text=True, timeout=120)
    assert first.returncode == 0, first.stderr
    assert counter.read_text(encoding="utf-8").count("x") == 2
    second = subprocess.run(base + ["--reuse"], capture_output=True, text=True, timeout=120)
    assert second.returncode == 0, second.stderr
    assert "nothing to run" in second.stderr  # log line goes to stderr
    assert counter.read_text(encoding="utf-8").count("x") == 2  # agent not called again


def _recording_agent(tmp_path, args_log):
    """Agent that appends every argv element (one per line) to args_log."""
    agent = tmp_path / "record-agent.sh"
    agent.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" >> {args_log}\necho OK\n")
    agent.chmod(0o755)
    return agent


def test_shared_session_flags_sequence(tmp_path):
    """Shared mode: the first call starts the session (with --name), later
    calls continue it (session id only)."""
    args_log = tmp_path / "args.log"
    agent = _recording_agent(tmp_path, args_log)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    out = tmp_path / "o"
    tasks = [mod.Task(prompt="p1", output=str(out / "1.md")), mod.Task(prompt="p2", output=str(out / "2.md"))]
    results = mod.run_serial(tasks, session_mode="shared", session_id="sess-1", session_name="props")
    assert all(r.success for r in results)
    lines = args_log.read_text(encoding="utf-8").splitlines()
    assert lines == ["-p", "p1", "--session-id", "sess-1", "--name", "props",
                     "-p", "p2", "--session-id", "sess-1"]


def test_new_session_has_no_session_flags(tmp_path):
    """Default mode: every call is a fresh session (no session flags)."""
    args_log = tmp_path / "args.log"
    agent = _recording_agent(tmp_path, args_log)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    tasks = [mod.Task(prompt="p1", output=str(tmp_path / "1.md")), mod.Task(prompt="p2", output=str(tmp_path / "2.md"))]
    mod.run_serial(tasks)
    lines = args_log.read_text(encoding="utf-8").splitlines()
    assert "--session-id" not in lines
    assert "--name" not in lines


def test_per_stage_session_ids(tmp_path):
    """per-stage mode derives one session id per stage."""
    args_log = tmp_path / "args.log"
    agent = _recording_agent(tmp_path, args_log)
    mod = load_batch()
    mod.AGENT_BIN = str(agent)
    d1 = tmp_path / "a"
    d2 = tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    (d1 / "t.md").write_text("t1", encoding="utf-8")
    (d2 / "t.md").write_text("t2", encoding="utf-8")
    stage_a = mod.Stage(name="stage-a", from_dir=str(d1))
    stage_b = mod.Stage(name="stage-b", from_dir=str(d2))
    _, ok_a = mod.execute_stage(stage_a, {}, session_mode="per-stage", session_name="run1")
    _, ok_b = mod.execute_stage(stage_b, {}, session_mode="per-stage", session_name="run1")
    assert ok_a and ok_b
    lines = args_log.read_text(encoding="utf-8").splitlines()
    assert "run1-stage-a" in lines
    assert "run1-stage-b" in lines
    assert lines.count("--name") == 2  # each stage starts its own session


def test_shared_session_parallel_rejected(tmp_path, fake_agent):
    """Shared sessions must not run in parallel: interleaved calls would
    corrupt the conversation order."""
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    inputs = _inputs_dir(tmp_path)
    stage = mod.Stage(name="s0", from_dir=str(inputs), mode="parallel")
    results, ok = mod.execute_stage(stage, {}, session_mode="shared", session_name="x")
    assert ok is False
    assert results == []


def test_cli_shared_session_flags(tmp_path):
    """CLI --session-mode shared passes session flags to the agent."""
    args_log = tmp_path / "args.log"
    agent = _recording_agent(tmp_path, args_log)
    tasks_yaml = tmp_path / "tasks.yaml"
    tasks_yaml.write_text(
        "tasks:\n"
        f"  - prompt: t1\n    output: {tmp_path / '1.md'}\n"
        f"  - prompt: t2\n    output: {tmp_path / '2.md'}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable, str(PI_BATCH), str(tasks_yaml),
            "--agent-bin", str(agent),
            "--mode", "serial",
            "--session-mode", "shared",
            "--session-name", "proposals",
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    lines = args_log.read_text(encoding="utf-8").splitlines()
    assert "--session-id" in lines
    assert lines.count("proposals") == 3  # 1 name + 2 session-id uses


def test_cli_per_stage_requires_pipeline(tmp_path, fake_agent):
    tasks_yaml = tmp_path / "tasks.yaml"
    tasks_yaml.write_text("tasks:\n  - prompt: t1\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, str(PI_BATCH), str(tasks_yaml),
            "--agent-bin", str(fake_agent),
            "--session-mode", "per-stage",
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0
    assert "per-stage requires --pipeline" in result.stderr


def test_cli_shared_session_parallel_rejected(tmp_path, fake_agent):
    tasks_yaml = tmp_path / "tasks.yaml"
    tasks_yaml.write_text("tasks:\n  - prompt: t1\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, str(PI_BATCH), str(tasks_yaml),
            "--agent-bin", str(fake_agent),
            "--mode", "parallel",
            "--session-mode", "shared",
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0
    assert "requires --mode serial" in result.stderr


def test_validate_cmd_passes_saves_output(tmp_path, fake_agent):
    """A passing engineering gate saves the output file."""
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    output = tmp_path / "o.md"
    results = mod.run_serial([mod.Task(prompt="x", output=str(output))], validate_cmd="true")
    assert results[0].success is True
    assert output.exists()


def test_validate_cmd_failure_does_not_save(tmp_path, fake_agent):
    """A failing engineering gate rejects the result and leaves no file."""
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    output = tmp_path / "o.md"
    results = mod.run_serial([mod.Task(prompt="x", output=str(output))], validate_cmd="exit 7")
    assert results[0].success is False
    assert "validation" in results[0].reason
    assert not output.exists()


def test_validate_cmd_output_placeholder(tmp_path, fake_agent):
    """{output} is substituted with the output path before validation."""
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    output = tmp_path / "o.md"
    results = mod.run_serial([mod.Task(prompt="x", output=str(output))], validate_cmd='test -f "{output}"')
    assert results[0].success is True
    assert output.exists()


def test_validate_failure_retry_regenerates(tmp_path, fake_agent):
    """A validation failure is retried: the agent regenerates and the second
    validation passes, so the output is saved."""
    counter = tmp_path / "counter"
    mod = load_batch()
    mod.AGENT_BIN = str(fake_agent)
    output = tmp_path / "o.md"
    validate = f"echo x >> {counter}; [ $(wc -l < {counter}) -le 1 ] && exit 1 || exit 0"
    results = mod.run_serial([mod.Task(prompt="x", output=str(output))], retries=1, retry_delay=0, validate_cmd=validate)
    assert results[0].success is True
    assert output.exists()
    assert counter.read_text(encoding="utf-8").count("x") == 2


def test_cli_validate_cmd_gate(tmp_path, fake_agent):
    """CLI --validate-cmd: failing gate exits non-zero and leaves no file;
    passing gate saves."""
    inputs = _inputs_dir(tmp_path)
    base = [
        sys.executable, str(PI_BATCH),
        "--from-dir", str(inputs),
        "--agent-bin", str(fake_agent),
        "--mode", "serial",
    ]
    failing = subprocess.run(base + ["--validate-cmd", "exit 1"], capture_output=True, text=True, timeout=120)
    assert failing.returncode != 0
    assert not (inputs / "task1.out.md").exists()
    passing = subprocess.run(base + ["--validate-cmd", "true"], capture_output=True, text=True, timeout=120)
    assert passing.returncode == 0, passing.stderr
    assert (inputs / "task1.out.md").exists()


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
