"""The rehearsal driver must be explicit, owned, bounded and never touch foreign containers."""
import ast
import hashlib
import json
import socket

import pytest

from checks import migration_guard_fixture  # establishes the ops/scripts import path
from migration_guard import rehearsal_cli
from migration_guard.snapshot import GuardFailure


def test_provision_requires_sha256_image_digest(tmp_path):
    with pytest.raises(GuardFailure):
        rehearsal_cli.provision_args(dict(image='postgres:16-alpine', database='snaplink_mig_x',
                                         container='abr-x', label='l', root=tmp_path))


@pytest.mark.parametrize('database', ['snaplink_step40_tests', 'snaplink_mig_', 'SNAPLINK_MIG_X', 'snaplink_mig_x;DROP'])
def test_provision_rejects_non_dedicated_candidate_database(tmp_path, database):
    with pytest.raises(GuardFailure):
        rehearsal_cli.provision_args(dict(image='sha256:' + 'a' * 64, database=database,
                                          container='abr-x', label='l', root=tmp_path))


def test_provision_refuses_when_a_receipt_already_exists(tmp_path):
    (tmp_path / 'fixture-receipt.json').write_text('{}')
    with pytest.raises(GuardFailure):
        rehearsal_cli.provision_args(dict(image='sha256:' + 'a' * 64, database='snaplink_mig_x',
                                          container='abr-x', label='l', root=tmp_path))


def inspect_ok(**over):
    body = dict(Id='a' * 64, Name='/abr-x', Image=rehearsal_cli.IMAGE_PIN,
                Config=dict(Labels={'abr.owner': 'l'}),
                HostConfig=dict(Memory=1 << 30, MemorySwap=1 << 30, NanoCpus=2_000_000_000,
                                Tmpfs={'/var/lib/postgresql/data': 'rw,noexec,nosuid,size=768m'}),
                Mounts=[],
                NetworkSettings=dict(Ports={'5432/tcp': [dict(HostIp='127.0.0.1', HostPort='32829')]}))
    body.update(over)
    return body


def test_ownership_check_accepts_exact_owned_container():
    # docker keeps --tmpfs in HostConfig.Tmpfs; an empty Mounts list is healthy, not a defect.
    port = rehearsal_cli.verify_ownership(inspect_ok(), 'a' * 64, 'abr-x', 'l', rehearsal_cli.IMAGE_PIN)
    assert port == 32829


@pytest.mark.parametrize('mutation', [
    dict(Name='/other'), dict(Image='sha256:' + 'c' * 64), dict(Config=dict(Labels={'abr.owner': 'other'})),
    dict(HostConfig=dict(Memory=1 << 29, MemorySwap=1 << 30, NanoCpus=2_000_000_000,
                          Tmpfs={'/var/lib/postgresql/data': 'rw,noexec,nosuid,size=768m'})),
    dict(Mounts=[dict(Type='bind')]),
    dict(NetworkSettings=dict(Ports={'5432/tcp': [dict(HostIp='0.0.0.0', HostPort='32829')]})),
])
def test_ownership_check_rejects_any_deviation(mutation):
    with pytest.raises(GuardFailure):
        rehearsal_cli.verify_ownership(inspect_ok(**mutation), 'a' * 64, 'abr-x', 'l', rehearsal_cli.IMAGE_PIN)


def test_close_refuses_without_a_matching_receipt(tmp_path):
    with pytest.raises(GuardFailure):
        rehearsal_cli.close_receipt(tmp_path)
    receipt = dict(container_id='a' * 64, name='abr-x', label='l', image_id=rehearsal_cli.IMAGE_PIN,
                   database='snaplink_mig_x', port=32829)
    (tmp_path / 'fixture-receipt.json').write_text(json.dumps(receipt))
    with pytest.raises(GuardFailure):
        rehearsal_cli.close_receipt(tmp_path, inspect_body=inspect_ok(Name='/foreign'))


def test_driver_has_no_shell_execution_and_is_bounded():
    source = (rehearsal_cli.__file__ and open(rehearsal_cli.__file__).read()) or ''
    assert 'shell=True' not in source
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'run':
            assert any(k.arg == 'timeout' for k in node.keywords), 'every subprocess.run needs a timeout'


def test_run_steps_stops_after_failure_and_still_closes():
    calls = []
    steps = [("provision", lambda: calls.append("provision")),
             ("import", lambda: (_ for _ in ()).throw(RuntimeError("import failed"))),
             ("verify", lambda: calls.append("verify"))]
    out = rehearsal_cli.run_steps(steps, lambda: calls.append("close"))
    assert out["result"] == "failed"
    assert [s["step"] for s in out["steps"]] == ["provision", "import", "verify"]
    assert out["steps"][2]["result"] == "not_executed"
    assert calls == ["provision", "close"], "later steps must not run, cleanup must"


def test_run_steps_reports_cleanup_failure_separately():
    out = rehearsal_cli.run_steps([], lambda: (_ for _ in ()).throw(RuntimeError("port still open")))
    assert out["result"] == "failed"
    assert out["cleanup"] == {"step": "close", "result": "failed", "reason": "port still open"}
    assert out["failure"] is None


def test_run_steps_passes_when_all_steps_and_cleanup_succeed():
    calls = []
    out = rehearsal_cli.run_steps([("provision", lambda: calls.append("p"))], lambda: calls.append("c"))
    assert out["result"] == "passed" and calls == ["p", "c"]
    assert out["cleanup"]["result"] == "passed" and out["failure"] is None


def test_candidate_name_is_derived_and_bounded():
    assert rehearsal_cli.candidate_name("snaplink_mig_run3") == "snaplink_mig_run3_cand"
    assert rehearsal_cli.candidate_name("snaplink_mig_x" * 4).startswith("snaplink_mig_")
    with pytest.raises(GuardFailure):
        rehearsal_cli.candidate_name("not_a_candidate")


def test_initialise_candidate_writes_owned_connection_and_runs_the_initializer(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "fixture-receipt.json",
                                dict(container_id="a" * 64, name="abr-x", label="l",
                                     image_id=rehearsal_cli.IMAGE_PIN, database="snaplink_mig_run",
                                     port=32829))
    rehearsal_cli.write_private(root / "test-connection.json",
                                dict(host="127.0.0.1", port=32829, user="u", database="snaplink_mig_run",
                                     password="p", owner_token="b" * 48))
    statements, launched = [], []
    monkeypatch.setattr(rehearsal_cli, "psql", lambda connection: (["psql"], {}))
    monkeypatch.setattr(rehearsal_cli, "execute_sql", lambda argv, env, sql: statements.append(sql))
    monkeypatch.setattr(rehearsal_cli, "run_bounded",
                        lambda argv, timeout, **kw: (launched.append(argv),
                                                     type("R", (), {"returncode": 0})())[1])
    _receipt, candidate = rehearsal_cli.initialise_candidate(root, "snaplink_mig_run", "/bin/schema-init")
    assert candidate == "snaplink_mig_run_cand"
    assert any("CREATE DATABASE snaplink_mig_run_cand" in sql for sql in statements)
    assert any("migration_guard.ownership" in sql for sql in statements)
    owned = json.loads((root / "candidate-connection.json").read_text())
    assert owned["database"] == candidate and len(owned["owner_token"]) == 48
    assert launched == [["/bin/schema-init", str(root / "candidate-connection.json")]]


def test_initialise_candidate_refuses_a_root_mismatch(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "fixture-receipt.json", dict(container_id="a" * 64))
    rehearsal_cli.write_private(root / "test-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_other",
                                     password="p", owner_token="b" * 48))
    monkeypatch.setattr(rehearsal_cli, "psql", lambda connection: (["psql"], {}))
    with pytest.raises(GuardFailure):
        rehearsal_cli.initialise_candidate(root, "snaplink_mig_run", "/bin/true")


def test_import_step_requires_snapshot_digest_and_policy_template(tmp_path):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    args = type("A", (), dict(source_snapshot=str(tmp_path / "s.sqlite"), source_sha256="",
                               policy_template=""))()
    with pytest.raises(GuardFailure):
        rehearsal_cli.bind_and_import_inputs(root, args, "snaplink_mig_run_cand")


def test_policy_template_without_mappings_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    template = tmp_path / "policy.json"
    template.write_text(json.dumps({"version": 2}))
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot",
                        lambda path, sha, timeout: dict(sha256=sha))
    monkeypatch.setattr(rehearsal_cli, "inspect_target", lambda path: dict(tables={}))
    monkeypatch.setattr(rehearsal_cli, "target_shape_sha256", lambda target: "c" * 64)
    args = type("A", (), dict(source_snapshot=str(tmp_path / "s.sqlite"), source_sha256="a" * 64,
                              policy_template=str(template), base_commit="b" * 40))()
    with pytest.raises(GuardFailure):
        rehearsal_cli.bind_and_import_inputs(root, args, "snaplink_mig_run_cand")


def test_missing_or_short_base_commit_is_refused_before_import(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    template = tmp_path / "policy.json"
    template.write_text(json.dumps({"version": 2, "mappings": []}))
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot", lambda path, sha, timeout: dict(sha256=sha))
    monkeypatch.setattr(rehearsal_cli, "inspect_target", lambda path: dict(tables={}))
    for value in (None, "abc", "z" * 40):
        args = type("A", (), dict(source_snapshot=str(tmp_path / "s.sqlite"), source_sha256="a" * 64,
                                  policy_template=str(template), base_commit=value))()
        with pytest.raises(GuardFailure):
            rehearsal_cli.bind_and_import_inputs(root, args, "snaplink_mig_run_cand")


def test_sha_helper_hashes_bytes(tmp_path):
    # Guards the orchestration's digest binding, which silently broke once when
    # hashlib was not imported.
    path = tmp_path / "f"
    path.write_bytes(b"abc")
    assert rehearsal_cli._sha(path) == hashlib.sha256(b"abc").hexdigest()


def test_server_config_binds_candidate_and_disables_bootstrap(tmp_path):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=32829, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    text = rehearsal_cli.server_config(root, 18080, 18081)
    assert "snaplink_mig_run_cand" in text and "127.0.0.1:18080" in text
    assert "backend: postgres" in text and "session_backend: postgres" in text
    assert "disabled: true" in text
    assert 'listen: "127.0.0.1:18080"' in text


def test_free_port_returns_a_bindable_loopback_port():
    port = rehearsal_cli.free_port()
    assert 1 <= port <= 65535
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))


def test_smoke_fails_closed_when_config_validation_fails(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    monkeypatch.setattr(rehearsal_cli, "run_bounded",
                        lambda *a, **k: type("R", (), {"returncode": 2})())
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.smoke_candidate(root, "/bin/false-server")


def test_readpath_args_always_acknowledge_migrations(tmp_path):
    argv = rehearsal_cli.readpath_args(tmp_path / "d", tmp_path / "e", tmp_path / "r")
    assert argv[0::2] == ["-dsn-file", "-expect", "-allow-idempotent-migrations"]


def test_readpath_requires_expectations(tmp_path):
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.readpath_candidate(tmp_path, "/bin/true", None)


def test_readpath_fails_closed_on_reported_failure(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    monkeypatch.setattr(rehearsal_cli, "run_bounded",
                        lambda *a, **k: type("R", (), {"returncode": 1, "stdout": b'{"result":"failed","existing_rows_unchanged":false}'})())
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.readpath_candidate(root, "/bin/x", str(tmp_path / "e.json"))
    assert (root / "readpath-report.json").exists(), "the failing report is retained"
    assert not (root / "probe.dsn").exists(), "the private DSN file must not be left behind"


def test_replay_guard_refuses_when_the_second_import_succeeds(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    monkeypatch.setattr(rehearsal_cli, "table_counts", lambda root: {"users": 1})
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot", lambda p, s, timeout: dict(sha256=s))
    monkeypatch.setattr(rehearsal_cli, "run_import", lambda *a, **k: (0, ''))
    monkeypatch.setattr(rehearsal_cli, "psql", lambda connection: (["psql"], {}))
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64))()
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.replay_guard(root, args, "snaplink_mig_run_cand")


def test_replay_guard_passes_on_refusal_with_unchanged_counts(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    monkeypatch.setattr(rehearsal_cli, "table_counts", lambda root: {"users": 67})
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot", lambda p, s, timeout: dict(sha256=s))
    monkeypatch.setattr(rehearsal_cli, "run_import", lambda *a, **k: (1, '{"result":"failed","reason":"import_empty_target_complete_shape_preflight_failed"}'))
    monkeypatch.setattr(rehearsal_cli, "psql", lambda connection: (["psql"], {}))
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64))()
    result = rehearsal_cli.replay_guard(root, args, "snaplink_mig_run_cand")
    assert result["first_import_refused"] is True and result["counts_unchanged"] is True
    assert result["reason"].startswith("import_") and result["result"] == "passed"


def test_replay_guard_fails_when_counts_change(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    calls = []
    monkeypatch.setattr(rehearsal_cli, "table_counts",
                        lambda root: calls.append(1) or ({"users": 1} if len(calls) == 1 else {"users": 2}))
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot", lambda p, s, timeout: dict(sha256=s))
    monkeypatch.setattr(rehearsal_cli, "run_import", lambda *a, **k: (1, '{"result":"failed","reason":"import_empty_target_complete_shape_preflight_failed"}'))
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64))()
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.replay_guard(root, args, "snaplink_mig_run_cand")


def test_write_check_requires_the_sequence_to_advance(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    values = iter(["9590", "9590", "9590", "9591"])
    monkeypatch.setattr(rehearsal_cli, "psql_scalar", lambda root, sql: next(values))
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.write_check(root)
    record = json.loads((root / "write-check.json").read_text())
    assert record["result"] == "failed" and record["sequence_advanced"] is False
    assert record["candidate_mutated"] is True


def test_write_check_passes_and_declares_the_mutation(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    values = iter(["9590", "9590", "9591", "9591"])
    monkeypatch.setattr(rehearsal_cli, "psql_scalar", lambda root, sql: next(values))
    record = rehearsal_cli.write_check(root)
    assert record["result"] == "passed" and record["inserted_seq"] == 9591
    assert record["rows_after"] == record["rows_before"] + 1
    assert record["candidate_mutated"] is True and "NOT cutover" in record["scope"]


def test_scalar_int_takes_the_first_nonempty_line():
    # psql with RETURNING also prints a command tag; the scalar parser must not choke on it.
    assert rehearsal_cli.scalar_int("9591\nINSERT 0 1\n") == 9591
    assert rehearsal_cli.scalar_int("\n67\n") == 67
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.scalar_int("\n\n")


def test_write_check_is_last_because_it_mutates_the_candidate():
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64, policy_template="/p",
                               replay_guard=True, readpath="/r", readpath_expect="/e",
                               sso_server="/b", write_check=True))()
    plan = rehearsal_cli.step_plan(args)
    assert plan[-1] == "write_check"
    assert plan[:4] == ["provision", "schema_init", "import", "verify"]
    assert plan.index("readpath") < plan.index("smoke") < plan.index("write_check")

    read_only = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64, policy_template="/p",
                                   replay_guard=False, readpath=None, readpath_expect=None,
                                   sso_server=None, write_check=False))()
    assert rehearsal_cli.step_plan(read_only) == ["provision", "schema_init", "import", "verify"]


def test_smoke_records_the_validator_output_when_config_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    monkeypatch.setattr(rehearsal_cli, "run_bounded",
                        lambda *a, **k: type("R", (), {"returncode": 2, "stdout": b"", "stderr": b"bad config"})())
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.smoke_candidate(root, "/bin/x")
    record = json.loads((root / "smoke-validate-failure.json").read_text())
    assert record["exit_code"] == 2 and "bad config" in record["detail"]


def test_smoke_retries_a_rejected_preflight_with_fresh_ports(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    calls = {"validate": 0}

    def validate(argv, timeout, **kw):
        calls["validate"] += 1
        code = 2 if calls["validate"] < 3 else 0
        return type("R", (), {"returncode": code, "stdout": b"", "stderr": b"port busy" if code else b""})()

    monkeypatch.setattr(rehearsal_cli, "run_bounded", validate)
    monkeypatch.setattr(rehearsal_cli, "free_port", lambda: 30000 + calls["validate"])
    monkeypatch.setattr(rehearsal_cli, "smoke_attempt",
                        lambda root, binary: (_ for _ in ()).throw(rehearsal_cli.GuardFailure("rehearsal_smoke_config_invalid")))
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.smoke_candidate(root, "/bin/x", attempts=2)
    record = json.loads((root / "smoke-attempts.json").read_text())
    assert [a["result"] for a in record["attempts"]] == ["failed", "failed"]


def test_smoke_reports_attempt_history_on_success(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(rehearsal_cli, "smoke_attempt",
                        lambda root, binary: dict(health="ok", server_exit=0, port_closed_after_stop=True))
    facts = rehearsal_cli.smoke_candidate(root, "/bin/x")
    assert facts["health"] == "ok"
    assert json.loads((root / "smoke-attempts.json").read_text())["attempts"] == [dict(attempt=1, result="passed")]


def test_smoke_environment_is_scrubbed_of_rehearsal_variables(monkeypatch):
    monkeypatch.setenv("SSO_SERVER", "/path/to/binary")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = rehearsal_cli.smoke_env()
    assert "SSO_SERVER" not in env, "SSO_* variables become server config and corrupt the file"
    assert env.get("PATH") == "/usr/bin"


def test_native_history_tables_only_takes_migration_tables():
    report = dict(native_history_after=dict(tables=[
        dict(table="schema_migrations_clients", rows=8), dict(table="clients", rows=10)]))
    assert rehearsal_cli.native_history_tables(report) == {"schema_migrations_clients": 8}
    assert rehearsal_cli.native_history_tables(dict()) == {}


def test_native_history_drift_fails_when_rows_were_added(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "import-report.json", dict(native_history_after=dict(
        tables=[dict(table="schema_migrations_clients", rows=8)])))
    monkeypatch.setattr(rehearsal_cli, "psql_scalar", lambda root, sql: "9")
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.native_history_drift(root)
    record = json.loads((root / "native-history-drift.json").read_text())
    assert record["result"] == "failed" and record["drift"] == {"schema_migrations_clients": 1}


def test_native_history_drift_passes_when_unchanged(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "import-report.json", dict(native_history_after=dict(
        tables=[dict(table="schema_migrations_clients", rows=8)])))
    monkeypatch.setattr(rehearsal_cli, "psql_scalar", lambda root, sql: "8")
    record = rehearsal_cli.native_history_drift(root)
    assert record["result"] == "passed" and record["drift"] == {}


def determinism_fixture(tmp_path, monkeypatch, second_digest):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "import-report.json", dict(
        target_projection=dict(tables=[dict(table="clients", projected_content_sha256="a" * 64)])))
    rehearsal_cli.write_private(root / "policy.json", dict(version=2, mappings=[], target_shape_sha256="d" * 64))
    rehearsal_cli.write_private(root / "schema-contract.json", dict(version=1))

    def create(root_arg, name, schema_init, connection_name="candidate-connection.json"):
        path = root_arg / connection_name
        rehearsal_cli.write_private(path, dict(host="127.0.0.1", port=1, user="u", database=name,
                                               password="p", owner_token="c" * 48))
        return path

    def fake_import(argv):
        rehearsal_cli.write_private(root / "import-report-b.json", dict(result="passed", target_projection=dict(
            tables=[dict(table="clients", projected_content_sha256=second_digest)])))
        return 0

    monkeypatch.setattr(rehearsal_cli, "create_candidate", create)
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot", lambda p, s, timeout: dict(sha256=s))
    monkeypatch.setattr(rehearsal_cli, "_sha", lambda p: "b" * 64)
    monkeypatch.setattr(rehearsal_cli, "import_main", fake_import)
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64, schema_init="/i"))()
    return root, args


def test_determinism_step_compares_projections(tmp_path, monkeypatch):
    root, args = determinism_fixture(tmp_path, monkeypatch, "a" * 64)
    record = rehearsal_cli.determinism_check(root, args, "snaplink_mig_run_cand")
    assert record["result"] == "passed" and record["differing_tables"] == []
    intent_b = json.loads((root / "intent-b.json").read_text())
    assert intent_b["target_database"] == "snaplink_mig_run_cand_b"
    assert intent_b["target_owner_sha256"] == hashlib.sha256(("c" * 48).encode()).hexdigest()


def test_determinism_fails_on_a_differing_table(tmp_path, monkeypatch):
    root, args = determinism_fixture(tmp_path, monkeypatch, "e" * 64)
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.determinism_check(root, args, "snaplink_mig_run_cand")
    assert json.loads((root / "determinism.json").read_text())["differing_tables"] == ["clients"]


def concurrency_fixture(tmp_path, monkeypatch, codes):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "policy.json", dict(version=2, mappings=[], target_shape_sha256="d" * 64))
    rehearsal_cli.write_private(root / "schema-contract.json", dict(version=1))

    def create(root_arg, name, schema_init, connection_name="candidate-connection.json"):
        path = root_arg / connection_name
        rehearsal_cli.write_private(path, dict(host="127.0.0.1", port=1, user="u", database=name,
                                               password="p", owner_token="c" * 48))
        return path

    issued = []

    def fake_import(argv):
        issued.append(argv)
        return codes[len(issued) - 1]

    monkeypatch.setattr(rehearsal_cli, "create_candidate", create)
    monkeypatch.setattr(rehearsal_cli, "inspect_snapshot", lambda p, s, timeout: dict(sha256=s))
    monkeypatch.setattr(rehearsal_cli, "_sha", lambda p: "b" * 64)
    monkeypatch.setattr(rehearsal_cli, "import_main", fake_import)
    monkeypatch.setattr(rehearsal_cli, "table_counts",
                        lambda root_arg, connection_path=None: {"users": 67, "clients": 10})
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64, schema_init="/i"))()
    return root, args, issued


def test_concurrency_guard_accepts_one_winner(tmp_path, monkeypatch):
    root, args, issued = concurrency_fixture(tmp_path, monkeypatch, [0, 1])
    record = rehearsal_cli.concurrency_guard(root, args, "snaplink_mig_run_cand")
    assert record["result"] == "passed" and len(record["applied"]) == 1
    assert record["rows_match_single_import"] is True
    assert len(issued) == 2, "both attempts must actually be issued"


def test_concurrency_guard_fails_when_both_apply(tmp_path, monkeypatch):
    root, args, _ = concurrency_fixture(tmp_path, monkeypatch, [0, 0])
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.concurrency_guard(root, args, "snaplink_mig_run_cand")
    assert len(json.loads((root / "concurrency-guard.json").read_text())["applied"]) == 2


def test_concurrency_guard_fails_when_rows_double(tmp_path, monkeypatch):
    root, args, _ = concurrency_fixture(tmp_path, monkeypatch, [0, 1])
    calls = {"n": 0}

    def counts(root_arg, connection_path=None):
        calls["n"] += 1
        return {"users": 67} if calls["n"] == 1 else {"users": 134}

    monkeypatch.setattr(rehearsal_cli, "table_counts", counts)
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.concurrency_guard(root, args, "snaplink_mig_run_cand")


def storage_body(**over):
    body = dict(Id="a" * 64, Name="/abr-x", Image=rehearsal_cli.IMAGE_PIN,
                Config=dict(Labels={"abr.owner": "l"}),
                HostConfig=dict(Memory=1 << 30, MemorySwap=1 << 30, NanoCpus=2_000_000_000),
                Mounts=[], NetworkSettings=dict(Ports={"5432/tcp": [dict(HostIp="127.0.0.1", HostPort="32829")]}))
    body.update(over)
    return body


def test_storage_kind_defaults_to_tmpfs_and_requires_exact_layout():
    body = storage_body(HostConfig=dict(Memory=1 << 30, MemorySwap=1 << 30, NanoCpus=2_000_000_000,
                                        Tmpfs=dict(rehearsal_cli.TMPFS)))
    assert rehearsal_cli.storage_kind(body, "l") == "tmpfs"
    body["HostConfig"] = dict(body["HostConfig"], Tmpfs={"/var/lib/postgresql/data": "rw"})
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.storage_kind(body, "l")


def test_storage_kind_accepts_only_a_labelled_owned_volume(monkeypatch):
    body = storage_body(Mounts=[dict(Type="volume", Name="abr-x-data",
                                     Destination="/var/lib/postgresql/data")])
    monkeypatch.setattr(rehearsal_cli, "volume_inspect", lambda name: dict(Labels={"abr.owner": "l"}))
    assert rehearsal_cli.storage_kind(body, "l") == "volume"
    monkeypatch.setattr(rehearsal_cli, "volume_inspect", lambda name: dict(Labels={"abr.owner": "other"}))
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.storage_kind(body, "l")
    body["Mounts"] = [dict(Type="bind", Destination="/var/lib/postgresql/data")]
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.storage_kind(body, "l")


def test_provision_step_forwards_the_storage_choice(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(rehearsal_cli, "provision",
                        lambda root, container, label, database, user, **kw: seen.update(kw))
    base = dict(container="c", label="l", database="d", user="u")
    rehearsal_cli.provision_step(tmp_path, type("A", (), dict(base, durable_storage=True))())
    assert seen.get("durable") is True
    rehearsal_cli.provision_step(tmp_path, type("A", (), base)())
    assert seen.get("durable") is False


def test_auth_verdict_requires_the_full_pair():
    good = dict(login_status=200, token_status=200, admin_without_token=401, admin_with_token=200)
    assert rehearsal_cli.auth_verdict(good)["result"] == "passed"
    for broken in (dict(good, admin_with_token=403), dict(good, admin_without_token=200),
                   dict(good, login_status=401), dict(good, token_status=500)):
        assert rehearsal_cli.auth_verdict(broken)["result"] == "failed", broken
    assert rehearsal_cli.auth_verdict({"login_status": 200})["missing"], "missing facts must be reported"


def test_auth_config_enables_the_console_login_path(tmp_path):
    text = rehearsal_cli.auth_config(tmp_path, "postgres://u@h/db", 18080, tmp_path / "pw")
    for needle in ("auth_code:", "enabled: true", "admin_client_id: sso-admin-console",
                   "api_rest_enabled: true", "backend: postgres", "127.0.0.1:18080"):
        assert needle in text, needle
    assert "sso-admin-console" in text and "imported_hash_login: true" in text


def test_auth_smoke_step_is_ordered_before_the_write_check():
    args = type("A", (), dict(source_snapshot="/s", source_sha256="a" * 64, policy_template="/p",
                               replay_guard=False, concurrency_guard=False, determinism=False,
                               auth_smoke=True, drift_check=True, write_check=True,
                               readpath=None, readpath_expect=None, sso_server="/b"))()
    plan = rehearsal_cli.step_plan(args)
    assert plan.index("auth_smoke") < plan.index("write_check")
    assert plan.index("auth_smoke") < plan.index("drift_check")


def test_auth_config_can_carry_a_known_bcrypt_credential(tmp_path):
    text = rehearsal_cli.auth_config(tmp_path, "postgres://u@h/db", 18080, tmp_path / "pw", tmp_path / "admin.bcrypt")
    assert "bcrypt_hash_file" in text and "subject_id: admin" in text
    without = rehearsal_cli.auth_config(tmp_path, "postgres://u@h/db", 18080, tmp_path / "pw")
    assert "bcrypt_hash_file" not in without


def test_auth_smoke_hashes_its_password_with_sso_ctl(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    rehearsal_cli.write_private(root / "candidate-connection.json",
                                dict(host="127.0.0.1", port=1, user="u", database="snaplink_mig_run_cand",
                                     password="p", owner_token="b" * 48))
    seen = {}

    def run_bounded(argv, timeout, **kwargs):
        if argv[:2] == ["/bin/sso-ctl", "hash"]:
            seen["stdin"] = kwargs.get("stdin")
            return type("R", (), {"returncode": 0, "stdout": b"$2b$12$hash\n", "stderr": b""})()
        return type("R", (), {"returncode": 1, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(rehearsal_cli, "run_bounded", run_bounded)
    monkeypatch.setattr(rehearsal_cli, "free_port", lambda: 12345)
    args = type("A", (), dict(sso_server="/bin/sso-server", sso_ctl="/bin/sso-ctl"))()
    with pytest.raises(rehearsal_cli.GuardFailure):
        rehearsal_cli.auth_smoke(root, args)
    # the hash was produced from a generated password, and the config that was
    # written carries it; the later failure is the (absent) server binary
    assert seen.get("stdin") and seen["stdin"].startswith(b"Rehearsal-")
    assert (root / "auth-admin.bcrypt").read_bytes() == b"$2b$12$hash\n"
    assert "bcrypt_hash_file" in (root / "auth-server-config.yaml").read_text()
