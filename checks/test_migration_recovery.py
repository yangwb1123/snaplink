"""Native recovery comparisons are bounded evidence, not restore/cutover authority."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard import recovery
from migration_guard.recovery_cli import main
from migration_guard.recovery_contract import validate_checkpoint
from migration_guard.snapshot import GuardFailure
from checks.migration_recovery_fixture import fixture


def private(tmp_path,name,data):
    tmp_path.chmod(0o700);p=tmp_path/name;p.write_bytes(data);p.chmod(0o600);return p


def setup(tmp_path):
    book,_,raw=fixture()
    checkpoint=private(tmp_path,'checkpoint.json',json.dumps(book).encode())
    archive=private(tmp_path,'fixture.dump',raw)
    cfg=dict(host='127.0.0.1',port=59999,user='schema_test',database='snaplink_mig_unit_restored',password='unit-not-real',owner_token='f'*48)
    connection=private(tmp_path,'connection.json',json.dumps(cfg).encode())
    args=(checkpoint,hashlib.sha256(checkpoint.read_bytes()).hexdigest(),archive,hashlib.sha256(raw).hexdigest(),connection)
    return book,cfg,args


def test_restore_observations_and_honest_flags(tmp_path,monkeypatch):
    book,_,args=setup(tmp_path)
    monkeypatch.setattr(recovery,'observe_native',lambda *a,**k:{key:copy.deepcopy(book[key]) for key in ('content','schema','audit_sequence','target_shape_sha256')})
    report=recovery.verify_restored(*args)
    assert report['result']=='passed' and report['migration_history_rows']==1 and report['migration_history_tables']==1
    for flag in ('target_changed','restore_execution_verified','backup_snapshot_correlation_verified','writer_fencing_verified','cross_phase_atomic_snapshot','all_sequence_states_verified','production_recovery_certified','cutover_authorized','archive_consumption_provenance_verified','audit_required_floor_certified'):
        assert report[flag] is False


@pytest.mark.parametrize('field,code',[('rows','target_row_count_mismatch'),('primary_key_set_sha256','target_primary_key_set_mismatch'),('projected_content_sha256','target_projected_content_mismatch')])
def test_history_content_mutations_are_not_ignored(field,code):
    book,_,_=fixture();actual=copy.deepcopy(book);t=actual['content']['tables'][1]
    t[field]=t[field]+1 if field=='rows' else 'c'*64
    assert dict(code=code,table='schema_migrations_audit') in recovery.recovery_issues(book,actual)


@pytest.mark.parametrize('field', ['environment','index','sequence','shape'])
def test_native_recovery_mutations(field):
    book,_,_=fixture();actual=copy.deepcopy(book)
    if field=='environment': actual['schema']['environment_sha256']='c'*64
    if field=='index': actual['schema']['tables']['schema_migrations_audit']['facets']['indexes']='c'*64
    if field=='sequence': actual['audit_sequence']['state']['is_called']=False
    if field=='shape': actual['target_shape_sha256']='c'*64
    assert recovery.recovery_issues(book,actual)


@pytest.mark.parametrize('same', ['database','owner'])
def test_source_database_or_ownership_cannot_be_reused(same):
    book,_,_=fixture();config=dict(database='snaplink_mig_distinct',user='schema_test',owner_token='a'*48)
    if same=='database': config['database']=book['source_identity']['database']
    else: book['source_identity']['owner_sha256']=recovery.owner_digest(config)
    with pytest.raises(GuardFailure,match='distinct_database_and_owner'): recovery.restore_boundary(config,book)


def test_bad_checkpoint_rejects_before_contact(tmp_path,monkeypatch):
    book,cfg,args=setup(tmp_path)
    monkeypatch.setattr(recovery,'observe_native',lambda *a,**k:pytest.fail('target contacted'))
    with pytest.raises(GuardFailure,match='checkpoint_sha256_mismatch'):
        recovery.verify_restored(args[0],'0'*64,*args[2:])
    with pytest.raises(GuardFailure,match='archive_sha256_mismatch'):
        recovery.verify_restored(*args[:3],'0'*64,args[-1])


def test_cli_readonly_errors_private_reports_and_refuses_overwrite(tmp_path,monkeypatch,capsys):
    book,cfg,args=setup(tmp_path)
    monkeypatch.setattr(recovery,'observe_native',lambda *a,**k:{key:copy.deepcopy(book[key]) for key in ('content','schema','audit_sequence','target_shape_sha256')})
    report=tmp_path/'report.json'
    argv=[]
    for flag,value in zip(('--checkpoint-file','--checkpoint-sha256','--archive-file','--archive-sha256','--restored-connection-file'),args): argv.extend([flag,str(value)])
    argv.extend(['--report',str(report)])
    assert main(argv)==0 and report.stat().st_mode&0o777==0o600
    assert main(argv)==1
    output=capsys.readouterr();assert cfg['password'] not in output.out+output.err and cfg['owner_token'] not in output.out+output.err
    with pytest.raises(SystemExit) as exc: main(argv+['--restore'])
    assert exc.value.code==2
