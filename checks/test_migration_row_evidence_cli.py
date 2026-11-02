"""Extended inspection is explicit, fail-closed and never turns a plan into copy."""
import argparse
from contextlib import closing
import hashlib
import json
import sqlite3

import pytest

from checks.migration_policy_fixture import policy_document, policy_fixture, private_policy
from migration_guard import cli
from migration_guard.compare import compare
from migration_guard.snapshot import inspect_snapshot


def argv(tmp_path, path, source):
    return ['--snapshot',str(path),'--snapshot-sha256',source['sha256'],
            '--target-connection-file',str(tmp_path/'unused.json'),
            '--report',str(tmp_path/'report.json')]


def test_explicit_policy_required_before_any_target_contact(tmp_path, monkeypatch, capsys):
    path, source, _ = policy_fixture(tmp_path)
    monkeypatch.setattr(cli, 'inspect_target', lambda *a: pytest.fail('target must not be contacted'))
    assert cli.main(argv(tmp_path,path,source)+['--row-evidence']) == 1
    assert 'row_evidence_requires_conversion_policy' in capsys.readouterr().err
    assert not (tmp_path/'report.json').exists()


def test_default_policy_mode_does_not_run_extended_queries(tmp_path, monkeypatch):
    path, source, target = policy_fixture(tmp_path)
    policy = private_policy(tmp_path, policy_document(source,target))
    monkeypatch.setattr(cli, 'inspect_target', lambda *a: target)
    monkeypatch.setattr(cli, 'inspect_audit_sequence', lambda *a: pytest.fail('default behavior changed'))
    assert cli.main(argv(tmp_path,path,source)+['--conversion-policy-file',str(policy)]) == 0
    report = json.loads((tmp_path/'report.json').read_text())
    assert report['scope'] == 'read_only_snapshot_and_catalog_preflight'
    assert 'source_projection' not in report


def test_extended_mode_reports_unready_sequence_and_preserves_no_copy_flags(tmp_path, monkeypatch):
    path, source, target = policy_fixture(tmp_path)
    policy = private_policy(tmp_path,policy_document(source,target))
    monkeypatch.setattr(cli, 'inspect_target', lambda *a: target)
    issue = dict(code='audit_sequence_below_required_floor',table='audit_events',column='seq')
    monkeypatch.setattr(cli, 'inspect_audit_sequence', lambda path,floor: dict(result='failed',required_next_seq_floor=floor,blockers=[issue]))
    assert cli.main(argv(tmp_path,path,source)+['--conversion-policy-file',str(policy),'--row-evidence']) == 1
    report = json.loads((tmp_path/'report.json').read_text())
    assert report['audit_sequence']['required_next_seq_floor'] == 100
    assert report['blockers'] == [issue]
    assert report['source_projection']['rows'] == 9
    for flag in ('target_content_verified','cutover_authorized','audit_chain_verified','content_copied_or_target_changed'):
        assert report[flag] is False


def test_failed_shape_retains_blockers_without_extended_noop_success(tmp_path, monkeypatch):
    path, source, target = policy_fixture(tmp_path)
    policy = policy_document(source,target)
    target['tables'][0]['rows'] = 1
    report = compare(source,target,policy)
    monkeypatch.setattr(cli, 'inspect_audit_sequence', lambda *a: pytest.fail('bad shape must block'))
    cli.collect_row_evidence(argparse.Namespace(snapshot=path),report,policy)
    assert report['result'] == 'failed'
    assert report['row_evidence'] == dict(result='not_executed',reason='shape_preflight_failed')
    assert report['blockers'] == [dict(code='target_business_table_not_empty',table='audit_events')]


def test_projection_ignores_sqlite_history_never_translates_pg_metadata(tmp_path):
    from migration_guard.row_projection import project_snapshot
    path, _, target = policy_fixture(tmp_path)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE schema_migrations_audit(version INTEGER PRIMARY KEY)')
        db.execute('INSERT INTO schema_migrations_audit VALUES(999)')
    source = inspect_snapshot(path,hashlib.sha256(path.read_bytes()).hexdigest())
    result = project_snapshot(path,source,target,policy_document(source,target))
    assert result['rows'] == 9
    assert {t['table'] for t in result['tables']} == {'audit_events','permissions_resources'}
