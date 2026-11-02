"""No recovery-only path may hide migration histories, PKs, RLS or partial replies."""
import copy
from pathlib import Path
import sys
import time
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard.snapshot import GuardFailure
from migration_guard.sequence import inspect_audit_sequence
from migration_guard.recovery_observe import RecoveryContentReader, RecoverySchemaReader, native_tables, observe_native, read_frames
from migration_guard.target_content import bootstrap_sql, data_sql
from checks.migration_recovery_fixture import fixture


def frame(target):
    return dict(kind='catalog',tables=[{k:v for k,v in t.items() if k not in ('metadata_only','rows')} for t in target['tables']])


def test_metadata_is_explicitly_opt_in():
    book,target,_=fixture();config=dict(owner_token='0'*48)
    assert 'schema_migrations_audit' not in bootstrap_sql(config,target)
    assert 'schema_migrations_audit' in bootstrap_sql(config,target,include_metadata=True)
    assert 'schema_migrations_audit' not in data_sql(target)
    assert 'schema_migrations_audit' in data_sql(target,include_metadata=True)
    assert all(t['rows'] is None for t in native_tables(frame(target),book['target_shape_sha256']))


@pytest.mark.parametrize('change', ['rls','partition','namespace','pk','duplicate_pk','shape'])
def test_recovery_history_visibility_and_shape_reject(change):
    book,target,_=fixture();f=frame(target);t=f['tables'][1]
    if change=='rls': t['rls_enabled']=True
    if change=='partition': t['relkind']='p'
    if change=='namespace': t['columns'][0]['type_namespace']='public'
    if change=='pk': t['columns'][-1]['pk_order']=0
    if change=='duplicate_pk': t['columns'][0]['pk_order']=1
    if change=='shape': t['columns'][0]['not_null']=False
    with pytest.raises(GuardFailure): native_tables(f,book['target_shape_sha256'])


class Stream:
    def __init__(self): self.commands=[]
    def send(self,sql,final=False): self.commands.append((sql,final))


def test_all_history_frames_and_counts_are_real():
    _,target,_=fixture();reader=RecoveryContentReader({},target,time.monotonic()+60);reader.target={};stream=Stream()
    reader.catalog(frame(target),stream)
    assert reader.names==['audit_events','schema_migrations_audit'] and reader.target['migration_history_counts_tracked'] is True
    reader.start(dict(kind='table_start',table='audit_events'))
    reader.row(dict(kind='row',values=[['text','a'],['integer','7']]))
    reader.end(dict(kind='table_end',table='audit_events'))
    with pytest.raises(GuardFailure,match='completion_missing'): reader.accept(dict(kind='complete',read_only='on',isolation='repeatable read'),stream)
    reader.start(dict(kind='table_start',table='schema_migrations_audit'))
    reader.row(dict(kind='row',values=[['integer','9007199254740993'],['text','unit migration'],['integer','1']]))
    reader.end(dict(kind='table_end',table='schema_migrations_audit'))
    reader.accept(dict(kind='complete',read_only='on',isolation='repeatable read'),stream)
    assert reader.rows==2 and reader.target['tables'][1]['rows']==1 and reader.stage=='complete'


def test_schema_reader_includes_history():
    _,target,_=fixture();reader=RecoverySchemaReader({},target);reader.target={};stream=Stream()
    reader.catalog(frame(target),stream)
    assert reader.names==['audit_events','schema_migrations_audit']
    assert not any(t['metadata_only'] for t in reader.target['tables'])
    assert 'schema_migrations_audit' in stream.commands[0][0]


@pytest.mark.parametrize('timeout', [True,0,-1,61,float('nan'),float('inf'),'60'])
def test_invalid_timeout_before_contact(timeout):
    with pytest.raises(GuardFailure,match='timeout_invalid'): observe_native('/missing-private-connection',timeout)
    with pytest.raises(GuardFailure,match='timeout_invalid'): inspect_audit_sequence('/missing-private-connection',1,timeout)
