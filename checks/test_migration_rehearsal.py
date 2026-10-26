"""The rehearsal driver must be explicit, owned, bounded and never touch foreign containers."""
import ast
import hashlib
import json

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
                              policy_template=str(template)))()
    with pytest.raises(GuardFailure):
        rehearsal_cli.bind_and_import_inputs(root, args, "snaplink_mig_run_cand")


def test_sha_helper_hashes_bytes(tmp_path):
    # Guards the orchestration's digest binding, which silently broke once when
    # hashlib was not imported.
    path = tmp_path / "f"
    path.write_bytes(b"abc")
    assert rehearsal_cli._sha(path) == hashlib.sha256(b"abc").hexdigest()
