"""Post-import verification must be read-only, bounded and fail closed; the rehearsal needed it."""
import json

import pytest

from checks import migration_guard_fixture  # establishes the ops/scripts import path used by every guard test
from migration_guard import verify_cli
from migration_guard.snapshot import GuardFailure


def args(tmp_path, **over):
    report = tmp_path / 'report.json'
    values = dict(snapshot=str(tmp_path / 'source.sqlite'), snapshot_sha256='a' * 64,
                  target_connection_file=str(tmp_path / 'conn.json'),
                  conversion_policy_file=str(tmp_path / 'policy.json'),
                  report=str(report), timeout=30)
    values.update(over)
    ns = verify_cli.parser().parse_args(
        ['--snapshot', values['snapshot'], '--snapshot-sha256', values['snapshot_sha256'],
         '--target-connection-file', values['target_connection_file'],
         '--conversion-policy-file', values['conversion_policy_file'],
         '--report', values['report'], '--timeout', str(values['timeout'])])
    return ns, report


def fake(monkeypatch, content='passed', sequences='passed', seen=None):
    def snapshot(path, sha, timeout):
        if seen is not None: seen.append(('snapshot', timeout))
        return dict(sha256=sha, tables={'users': dict(rows=1)})
    def target(path):
        if seen is not None: seen.append(('target', path))
        return dict(tables={'users': dict(rows=1)})
    def policy(path):
        if seen is not None: seen.append(('policy', path))
        return dict(version=2)
    def verify_content(snapshot_path, connection_path, source, target_value, policy_value, timeout):
        return dict(result=content)
    def verify_sequences(snapshot_path, connection_path, source, target_value, policy_value, timeout):
        return dict(result=sequences, blockers=[])
    monkeypatch.setattr(verify_cli, 'inspect_snapshot', snapshot)
    monkeypatch.setattr(verify_cli, 'inspect_target', target)
    monkeypatch.setattr(verify_cli, 'load_policy', policy)
    monkeypatch.setattr(verify_cli, 'verify_content', verify_content)
    monkeypatch.setattr(verify_cli, 'verify_sequences', verify_sequences)


def test_passing_verification_writes_private_read_only_report(tmp_path, monkeypatch):
    seen = []
    fake(monkeypatch, seen=seen)
    ns, report = args(tmp_path)
    assert verify_cli.execute(ns) == 0
    body = json.loads(report.read_text())
    assert body['result'] == 'passed' and body['writes_performed'] is False
    assert body['content_result'] == 'passed' and body['sequence_result'] == 'passed'
    assert body['cutover_authorized'] is False and body['automatic_retry'] is False
    assert report.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('content,sequences', [('failed', 'passed'), ('passed', 'failed'), ('failed', 'failed')])
def test_any_failed_verification_reports_failure_and_nonzero_exit(tmp_path, monkeypatch, content, sequences):
    fake(monkeypatch, content=content, sequences=sequences)
    ns, report = args(tmp_path)
    assert verify_cli.execute(ns) == 1
    body = json.loads(report.read_text())
    assert body['result'] == 'failed' and body['writes_performed'] is False


@pytest.mark.parametrize('timeout', [0, 61, -1, True, 1.5])
def test_unbounded_or_non_integer_timeout_is_rejected(tmp_path, monkeypatch, timeout):
    fake(monkeypatch)
    ns, _ = args(tmp_path)
    ns.timeout = timeout
    with pytest.raises(GuardFailure):
        verify_cli.execute(ns)


def test_public_report_directory_is_rejected(tmp_path, monkeypatch):
    fake(monkeypatch)
    public = tmp_path / 'public'
    public.mkdir()
    public.chmod(0o755)
    ns, _ = args(tmp_path, report=str(public / 'report.json'))
    with pytest.raises(GuardFailure):
        verify_cli.execute(ns)


def test_unexpected_extra_argument_is_rejected(tmp_path):
    with pytest.raises(SystemExit):
        verify_cli.parser().parse_args(['--snapshot', 'x'])
