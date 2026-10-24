"""No writable transaction admission, copy or commit without explicit complete evidence."""
import json
import time

import pytest

from checks.test_migration_import_contract import intent
from checks.test_migration_row_projection import fixture
from migration_guard.import_admission import AdmissionReader,bootstrap_import_sql
from migration_guard import import_cli
from migration_guard.import_runner import remaining
from migration_guard.snapshot import GuardFailure


def identity():
    return dict(kind='identity',database='snaplink_mig_unit',user='fixture',owned=True,
                read_only='off',isolation='repeatable read',version='synthetic guard; not engine support')


@pytest.mark.parametrize('field,value',[
    ('owned',False),('read_only','on'),('isolation','read committed'),
    ('database','snaplink_mig_other'),('user','different'),('extra',True)])
def test_writable_transaction_identity_must_be_exact_before_catalog(field,value):
    reader=AdmissionReader(dict(database='snaplink_mig_unit',user='fixture'),dict(tables=[]),{})
    frame=identity();frame[field]=value
    with pytest.raises(GuardFailure): reader.identity(frame)
    assert reader.stage=='identity'


def test_import_bootstrap_has_one_transaction_exclusive_locks_and_no_destructive_data_sql(tmp_path):
    _,_,target,_=fixture(tmp_path)
    script=bootstrap_import_sql(dict(owner_token='a'*48),target)
    assert script.count('BEGIN ISOLATION LEVEL')==1
    assert 'ACCESS EXCLUSIVE MODE' in script and 'migration_guard.ownership' in script
    assert 'pg_advisory_xact_lock' in script and 'search_path=pg_catalog,public' in script
    for word in ('COMMIT','TRUNCATE','CASCADE','setval','nextval','COPY'):
        assert word not in script


def test_extra_public_sequence_never_becomes_untracked_success():
    reader=AdmissionReader({},dict(tables=[]),{})
    reader.stage='sequences';reader.sequence=dict(name='audit_events_seq_seq')
    with pytest.raises(GuardFailure): reader.accept(dict(kind='public_sequences',names=['audit_events_seq_seq','extra']),None)
    assert reader.stage=='sequences'


def test_expired_whole_window_never_runs_another_phase():
    with pytest.raises(GuardFailure,match='whole_window'): remaining(time.monotonic()-1)


def test_cli_missing_intent_cannot_query_target_or_create_report(tmp_path,monkeypatch,capsys):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(import_cli,'inspect_target',lambda *a,**k:pytest.fail('must not contact target'))
    args=[]
    for name in ['snapshot','snapshot-sha256','target-connection-file','conversion-policy-file','schema-contract-file','schema-contract-sha256','intent-file','intent-sha256','confirm-candidate-database','journal','report']:
        args+=['--'+name,str(tmp_path/(name+'.json')) if name!='intent-sha256' else '1'*64]
    assert import_cli.main(args)==1
    assert not (tmp_path/'report.json').exists() and not (tmp_path/'journal.json').exists()
    assert 'failed' in capsys.readouterr().err


def test_report_or_journal_overwrite_rejects_before_any_input_load(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    path=tmp_path/'report.json';path.write_text('original')
    monkeypatch.setattr(import_cli,'collect_inputs',lambda *a:pytest.fail('must not load inputs or contact target'))
    args=type('Args',(),dict(report=path,journal=tmp_path/'journal.jsonl'))()
    with pytest.raises(GuardFailure): import_cli.execute(args)
    assert path.read_text()=='original' and not (tmp_path/'journal.jsonl').exists()
