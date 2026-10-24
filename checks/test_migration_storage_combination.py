"""Current-base combination keeps writable admission separate from read-only modes."""
import itertools
import json
import os
import stat

import pytest

from checks.migration_policy_fixture import policy_document, policy_fixture, private_policy
from migration_guard import cli, import_cli, postgres
from migration_guard.snapshot import GuardFailure
from migration_guard.target_content import data_sql

MODES = ('--row-evidence', '--verify-target-content', '--verify-target-schema', '--verify-target-sequences')


def arguments(root, path, source):
    return ['--snapshot', str(path), '--snapshot-sha256', source['sha256'],
            '--target-connection-file', str(root/'unused.json'), '--report', str(root/'report.json')]


@pytest.mark.parametrize('pair', list(itertools.combinations(MODES, 2)))
def test_all_observation_modes_are_mutually_exclusive(tmp_path, monkeypatch, pair):
    path, source, _ = policy_fixture(tmp_path)
    monkeypatch.setattr(cli, 'inspect_snapshot', lambda *a: pytest.fail('source contacted'))
    monkeypatch.setattr(cli, 'inspect_target', lambda *a: pytest.fail('target contacted'))
    with pytest.raises(SystemExit) as error:
        cli.main(arguments(tmp_path, path, source)+list(pair))
    assert error.value.code == 2
    assert not (tmp_path/'report.json').exists()


@pytest.mark.parametrize('mode', MODES)
def test_writer_does_not_accept_readonly_flags(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(import_cli, 'execute', lambda *a: pytest.fail('writer admitted'))
    names = ('snapshot', 'snapshot-sha256', 'target-connection-file', 'conversion-policy-file',
             'schema-contract-file', 'schema-contract-sha256', 'intent-file', 'intent-sha256',
             'confirm-candidate-database', 'journal', 'report')
    argv = [value for name in names for value in ('--'+name, str(tmp_path/name))]
    with pytest.raises(SystemExit) as error:
        import_cli.main(argv+[mode])
    assert error.value.code == 2
    assert not (tmp_path/'journal').exists() and not (tmp_path/'report').exists()


@pytest.mark.parametrize('flag', ('--intent-file', '--journal', '--confirm-candidate-database'))
def test_observer_does_not_accept_writer_inputs(tmp_path, monkeypatch, flag):
    path, source, _ = policy_fixture(tmp_path)
    monkeypatch.setattr(cli, 'inspect_snapshot', lambda *a: pytest.fail('source contacted'))
    with pytest.raises(SystemExit) as error:
        cli.main(arguments(tmp_path, path, source)+[flag, 'untrusted'])
    assert error.value.code == 2


@pytest.mark.parametrize('purpose', ('verify_content', 'verify_schema', 'verify_sequences'))
def test_explicit_verification_does_not_relax_default_empty_target(tmp_path, purpose):
    from migration_guard.compare import compare
    _, source, target = policy_fixture(tmp_path)
    policy = policy_document(source, target)
    target['tables'][0]['rows'] = 1
    assert compare(source, target, policy, purpose=purpose)['result'] == 'passed'
    assert compare(source, target, policy)['result'] == 'failed'


def test_sequence_observation_never_dispatches_candidate_writer(tmp_path, monkeypatch):
    path, source, target = policy_fixture(tmp_path)
    policy = private_policy(tmp_path, policy_document(source, target))
    monkeypatch.setattr(import_cli.ImportExecution, 'run', lambda *a: pytest.fail('writer ran'))
    monkeypatch.setattr(cli, 'inspect_target', lambda *a: target)
    evidence = dict(result='passed', target_snapshot=target, blockers=[],
                    sequence_advanced_or_reset=False, cutover_authorized=False)
    monkeypatch.setattr(cli, 'verify_sequences', lambda *a: evidence)
    assert cli.main(arguments(tmp_path, path, source)+[
        '--verify-target-sequences', '--conversion-policy-file', str(policy)]) == 0
    report = json.loads((tmp_path/'report.json').read_text())
    assert report['sequence_inventory'] == evidence
    assert report['target_content_verified'] is False


def test_shared_report_is_create_only_and_fsyncs_file_then_directory(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    assert import_cli.write_report is cli.write_report
    syncs = []
    native = os.fsync
    def observe(fd):
        syncs.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        native(fd)
    monkeypatch.setattr(cli.os, 'fsync', observe)
    output = tmp_path/'report.json'
    import_cli.write_report(output, {'result': 'failed', 'cutover_authorized': False})
    original = output.read_bytes()
    assert syncs == [False, True] and output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        cli.write_report(output, {'result': 'passed'})
    assert output.read_bytes() == original
    assert not list(tmp_path.glob('.migration-preflight-*'))


def test_report_directory_sync_failure_never_becomes_empty_success(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    native = os.fsync
    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError('synthetic durability failure')
        native(fd)
    monkeypatch.setattr(cli.os, 'fsync', fail_directory)
    output = tmp_path/'report.json'
    with pytest.raises(OSError, match='durability failure'):
        cli.write_report(output, {'result': 'failed'})
    # The link may already exist: failure is not proof of removal or rollback.
    assert json.loads(output.read_text()) == {'result': 'failed'}
    assert not list(tmp_path.glob('.migration-preflight-*'))


@pytest.mark.parametrize('timeout', (True, False, 0, -1, float('nan'), float('inf'), 61, '5'))
def test_import_compatible_target_timeout_rejects_before_contact(timeout, monkeypatch):
    monkeypatch.setattr(postgres, 'connection_file', lambda *a: pytest.fail('inputs contacted'))
    with pytest.raises(GuardFailure, match='target_inspection_timeout_invalid'):
        postgres.inspect_target('unused', timeout=timeout)


def test_identity_deadline_is_forwarded_for_import_and_sequence(monkeypatch):
    calls = []
    def query(config, sql, timeout=15):
        calls.append(timeout)
        return dict(owned=True, read_only='on', database=config['database'], user=config['user'])
    monkeypatch.setattr(postgres, 'query_json', query)
    cfg = dict(database='snaplink_mig_unit', user='fixture', owner_token='a'*48)
    postgres.verify_target_identity(cfg)
    postgres.verify_target_identity(cfg, timeout=.25)
    assert calls == [15, .25]


def test_observer_transaction_default_not_replaced_by_writer_no_commit(tmp_path):
    _, _, target = policy_fixture(tmp_path)
    for table in target['tables']:
        for column in table['columns']:
            column['type_namespace'] = 'pg_catalog'
    assert data_sql(target).endswith('COMMIT;\n')
    assert 'COMMIT' not in data_sql(target, transaction_end=False)
    assert 'COMMIT' not in data_sql(target, include_metadata=True, transaction_end=False)
