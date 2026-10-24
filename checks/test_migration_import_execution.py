"""Bounded writer pipe, transaction gating and durable attempt regression controls."""
from contextlib import closing
import json
import os
import sys
import time

import pytest

from checks.test_migration_row_projection import fixture
from checks.test_migration_import_contract import intent
from migration_guard import import_stream
from migration_guard.import_copy import copy_chunks
from migration_guard.import_content import ImportContentReader,verify_import_content
from migration_guard.import_intent import bind_intent
from migration_guard.import_journal import ImportJournal
from migration_guard.import_runner import ImportExecution
from migration_guard.snapshot import GuardFailure
from migration_guard.conversion_policy import digest,target_shape_sha256
from migration_guard.row_projection import project_snapshot
from migration_guard.target_content import data_sql


def test_intent_binds_entire_operation_not_just_present_file(tmp_path):
    path,source,target,policy=fixture(tmp_path)
    cfg=dict(database='snaplink_mig_unit',owner_token='a'*48)
    data=intent(cfg)
    data.update(source_sha256=source['sha256'],policy_sha256=digest(policy),target_shape_sha256=target_shape_sha256(target))
    bind_intent(data,cfg,source,policy,'3'*64,target_shape_sha256(target),cfg['database'])
    for name in ['source_sha256','policy_sha256','schema_contract_sha256','target_owner_sha256','target_shape_sha256']:
        wrong=dict(data,**{name:'0'*64})
        with pytest.raises(GuardFailure): bind_intent(wrong,cfg,source,policy,'3'*64,target_shape_sha256(target),cfg['database'])
    with pytest.raises(GuardFailure): bind_intent(data,cfg,source,policy,'3'*64,target_shape_sha256(target),'snaplink_mig_other')


def test_copy_all_columns_rows_and_source_budget_fail_closed(tmp_path,monkeypatch):
    path,source,target,policy=fixture(tmp_path)
    chunks=list(copy_chunks(path,source,target,policy['mappings'],sorted(t['table'] for t in target['tables']),time.monotonic()+2))
    assert sum(chunk.startswith(b'COPY ') for chunk in chunks)==3
    assert sum(chunk==b'\\.\n' for chunk in chunks)==3
    assert chunks[-1].startswith(b"SELECT json_build_object('kind','copied')")
    import migration_guard.import_copy as module
    monkeypatch.setattr(module,'MAX_COPY_ROW',1)
    with pytest.raises(GuardFailure,match='budget'):
        list(copy_chunks(path,source,target,policy['mappings'],sorted(t['table'] for t in target['tables']),time.monotonic()+2))
    with pytest.raises(GuardFailure,match='coverage'):
        list(copy_chunks(path,source,target,policy['mappings'],[],time.monotonic()+2))


def test_durable_journal_is_exclusive_private_and_never_overwritten(tmp_path):
    tmp_path.chmod(0o700)
    path=tmp_path/'attempt.jsonl'
    with closing(ImportJournal(path,'1'*64,'2'*64)) as journal:
        journal.append('commit_requested')
        journal.append('failed_reconcile_before_replay',commit_outcome='unknown')
    before=path.read_bytes()
    assert path.stat().st_mode & 0o777==0o600
    assert [json.loads(line)['phase'] for line in before.splitlines()]==['prepared','commit_requested','failed_reconcile_before_replay']
    with pytest.raises(FileExistsError): ImportJournal(path,'1'*64,'2'*64)
    assert path.read_bytes()==before


def test_writer_transport_incremental_input_and_owned_timeout(monkeypatch):
    cfg=dict(database='snaplink_mig_unit')
    def command(config):
        return [sys.executable,'-c',"import sys,json;data=sys.stdin.buffer.read();print(json.dumps({'kind':'complete','bytes':len(data)}))"],os.environ.copy()
    monkeypatch.setattr(import_stream,'psql_command',command)
    with closing(import_stream.ImportStream(cfg,2)) as stream:
        stream.queue(iter([b'a'*65536,b'b'*65536]),final=True)
        assert list(stream)==[dict(kind='complete',bytes=131072)]
        assert stream.child.returncode==0 and len(stream.pending)==0
    monkeypatch.setattr(import_stream,'psql_command',lambda config:([sys.executable,'-c','import time;time.sleep(5)'],os.environ.copy()))
    with closing(import_stream.ImportStream(cfg,.1)) as stream:
        stream.send('SELECT 1;',final=True)
        with pytest.raises(GuardFailure,match='timeout'): list(stream)
    assert stream.child.poll() is not None and stream.closed


@pytest.mark.parametrize('case',['input','stderr','exit','truncated'])
def test_writer_transport_rejects_budgets_or_incomplete_exit(monkeypatch,case):
    code={'input':'import sys;sys.stdin.read()',
          'stderr':"import sys;sys.stderr.write('synthetic-private-password'+('x'*8193));sys.stderr.flush()",
          'exit':"import sys;sys.stderr.write('synthetic-private-password');sys.exit(3)",
          'truncated':"import sys;sys.stdin.read();sys.stdout.write('{\\\"kind\\\":\\\"unterminated\\\"}')"}[case]
    monkeypatch.setattr(import_stream,'psql_command',lambda config:([sys.executable,'-c',code],os.environ.copy()))
    with closing(import_stream.ImportStream({},2)) as stream:
        with pytest.raises(GuardFailure) as error:
            if case=='input': stream.send('x'*4097,final=True)
            else:
                stream.send('SELECT 1;',final=True)
                list(stream)
        assert 'synthetic-private-password' not in str(error.value)
    assert stream.child.poll() is not None


def test_shared_data_query_keeps_old_commit_and_new_explicit_no_commit(tmp_path):
    _,_,target,_=fixture(tmp_path)
    for table in target['tables']:
        for column in table['columns']:
            column['type_namespace']='pg_catalog'
    assert data_sql(target).endswith('COMMIT;\n')
    assert 'COMMIT' not in data_sql(target,transaction_end=False)


def test_import_content_never_accepts_readonly_or_incomplete_completion(tmp_path):
    _,_,target,_=fixture(tmp_path)
    reader=ImportContentReader({},target,time.monotonic()+2)
    with pytest.raises(GuardFailure): reader.accept(dict(kind='complete',read_only='off',isolation='repeatable read'),None)
    reader.tables=[{}]*len(reader.names)
    with pytest.raises(GuardFailure): reader.accept(dict(kind='complete',read_only='on',isolation='repeatable read'),None)


def test_unverified_restart_cannot_send_commit_or_persist_success():
    class Journal:
        def append(self,*a,**kw): pytest.fail('must not persist commit request')
    class Stream:
        def send(self,*a,**kw): pytest.fail('must not request COMMIT')
    execution=ImportExecution.__new__(ImportExecution)
    execution.inputs={'floor':100};execution.journal=Journal()
    for frame in [dict(kind='restart',last_value=99,is_called=False),dict(kind='restart',last_value=100,is_called=True),dict(kind='restart',last_value=100,is_called=False,extra=True)]:
        with pytest.raises(GuardFailure): execution.request_commit(frame,Stream())


def test_commit_ack_alone_without_normal_process_exit_is_not_success():
    execution=ImportExecution.__new__(ImportExecution)
    execution.stage='commit';execution.deadline=time.monotonic()+2
    execution.journal=type('Journal',(),{'attempt':'synthetic-attempt'})()
    execution.accept(dict(kind='committed',attempt='synthetic-attempt'),None)
    assert execution.commit_ack and execution.stage=='complete'
    with pytest.raises(GuardFailure): execution.accept(dict(kind='committed',attempt='synthetic-attempt'),None)
