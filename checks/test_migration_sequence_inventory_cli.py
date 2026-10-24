"""The explicit fourth mode never relaxes default import preflight or old recovery."""
import argparse
import json
import pytest
from checks.migration_policy_fixture import policy_fixture,policy_document,private_policy
from migration_guard import cli
from migration_guard.compare import compare
from migration_guard.snapshot import GuardFailure


def argv(root,path,source):
    return ['--snapshot',str(path),'--snapshot-sha256',source['sha256'],'--target-connection-file',str(root/'unused.json'),'--report',str(root/'report.json')]


def test_explicit_policy_required_before_any_contact(tmp_path,monkeypatch,capsys):
    path,source,_=policy_fixture(tmp_path)
    monkeypatch.setattr(cli,'inspect_target',lambda *a:pytest.fail('target contacted'))
    assert cli.main(argv(tmp_path,path,source)+['--verify-target-sequences'])==1
    assert 'target_sequences_requires_conversion_policy' in capsys.readouterr().err
    assert not (tmp_path/'report.json').exists()


@pytest.mark.parametrize('old',['--row-evidence','--verify-target-content','--verify-target-schema'])
def test_extended_modes_mutually_exclusive(tmp_path,old):
    path,source,_=policy_fixture(tmp_path)
    with pytest.raises(SystemExit) as exc: cli.main(argv(tmp_path,path,source)+['--verify-target-sequences',old])
    assert exc.value.code==2


def test_populated_target_allowed_only_in_explicit_verification_purpose(tmp_path):
    _,source,target=policy_fixture(tmp_path);policy=policy_document(source,target);target['tables'][0]['rows']=1
    assert compare(source,target,policy)['result']=='failed'
    assert compare(source,target,policy,purpose='verify_sequences')['result']=='passed'
    with pytest.raises(GuardFailure,match='sequence_verification_explicit_policy_required'): compare(source,target,purpose='verify_sequences')


def test_cli_failed_inventory_retains_blockers_and_no_authority(tmp_path,monkeypatch):
    path,source,target=policy_fixture(tmp_path);policy=private_policy(tmp_path,policy_document(source,target))
    monkeypatch.setattr(cli,'inspect_target',lambda *a:target)
    issue=dict(code='sequence_inventory_below_required_floor',table='audit_events',column='seq')
    evidence=dict(result='failed',blockers=[issue],target_snapshot=target,sequence_advanced_or_reset=False,writer_fencing_verified=False,cutover_authorized=False)
    monkeypatch.setattr(cli,'verify_sequences',lambda *a:evidence)
    monkeypatch.setattr(cli,'inspect_audit_sequence',lambda *a:pytest.fail('old mode contacted'))
    assert cli.main(argv(tmp_path,path,source)+['--verify-target-sequences','--conversion-policy-file',str(policy)])==1
    report=json.loads((tmp_path/'report.json').read_text())
    assert report['blockers']==[issue] and report['sequence_inventory']==evidence and report['target_content_verified'] is False


def test_bad_shape_stops_inventory_no_empty_success(tmp_path,monkeypatch):
    _,source,target=policy_fixture(tmp_path);target['tables'][0]['columns'][0]['type']='float8';policy=policy_document(source,target)
    report=compare(source,target,policy,purpose='verify_sequences')
    monkeypatch.setattr(cli,'verify_sequences',lambda *a:pytest.fail('bad shape queried'))
    cli.collect_target_sequences(argparse.Namespace(),report,policy)
    assert report['result']=='failed' and report['sequence_inventory']==dict(result='not_executed',reason='shape_preflight_failed')


def test_default_policy_does_not_query_inventory(tmp_path,monkeypatch):
    path,source,target=policy_fixture(tmp_path);policy=private_policy(tmp_path,policy_document(source,target))
    monkeypatch.setattr(cli,'inspect_target',lambda *a:target)
    monkeypatch.setattr(cli,'verify_sequences',lambda *a:pytest.fail('default changed'))
    assert cli.main(argv(tmp_path,path,source)+['--conversion-policy-file',str(policy)])==0
    assert 'sequence_inventory' not in json.loads((tmp_path/'report.json').read_text())
