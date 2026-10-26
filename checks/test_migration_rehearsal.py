"""The rehearsal driver must be explicit, owned, bounded and never touch foreign containers."""
import ast
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
