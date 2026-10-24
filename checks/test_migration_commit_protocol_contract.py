"""Commit protocol keeps deadline, recheck/journal/send order and honest partial state."""
import ast
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from checks.test_migration_input_contract import conservative_complexity
from checks.test_migration_sequence_evidence import descriptor
from migration_guard import import_runner as runner
from migration_guard.snapshot import GuardFailure, MAX_ROWS

FUNCTIONS = [n for n in ast.walk(ast.parse(Path(runner.__file__).read_text())) if isinstance(n, ast.FunctionDef)]
RESTART = dict(kind='restart', last_value=100, is_called=False)
ACK = dict(kind='committed', attempt='synthetic-attempt')


class Stream:
    def __init__(self, fail=False): self.commands, self.queues, self.fail = [], [], fail
    def send(self, text, final=False):
        self.commands.append((text,final))
        if self.fail: raise GuardFailure('synthetic_send_failure')
    def queue(self, value, final=False): self.queues.append((value,final))


class Journal:
    def __init__(self, fail=None): self.attempt, self.events, self.fail = 'synthetic-attempt', [], fail
    def append(self, phase, **fields):
        self.events.append((phase,fields))
        if self.fail == phase: raise OSError('synthetic_journal_failure')


class Projection:
    def evidence(self, metadata): return dict(rows=1 if metadata else 17,tables=[],algorithm='synthetic-projection')


def execution(stage='foreign_keys'):
    item = runner.ImportExecution.__new__(runner.ImportExecution)
    item.args = SimpleNamespace(snapshot='synthetic-source')
    item.inputs = dict(floor=100,expected=dict(rows=17),config=dict(database='snaplink_mig_unit',user='fixture',owner_token='0'*48),target=dict(tables=[dict(table='audit_events')]))
    item.journal, item.deadline, item.stage = Journal(), 10, stage
    item.admission = SimpleNamespace(stage='identity',target=item.inputs['target'],sequence=descriptor(),expected_fks=[],fk_rows=[],scanned=0)
    item.baseline, item.actual, item.restart = Projection(), Projection(), None
    item.commit_requested, item.commit_ack = False, False
    return item


@pytest.fixture(autouse=True)
def clock(monkeypatch): monkeypatch.setattr(runner,'time',SimpleNamespace(monotonic=lambda:9))


@pytest.mark.parametrize('node',FUNCTIONS,ids=[n.name+'-'+str(n.lineno) for n in FUNCTIONS])
def test_commit_owner_complexity(node):
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


@pytest.mark.parametrize('stage',['admission','baseline','copy','content','foreign_keys','restart','commit','complete','unknown'])
def test_deadline_precedes_kind_read_and_all_handlers(stage):
    item, stream = execution(stage), Stream(); item.deadline = 9
    class Unreadable(dict):
        def get(self,*args): pytest.fail('frame read before whole-window check')
    with pytest.raises(GuardFailure,match='import_whole_window_exceeded'): item.accept(Unreadable(),stream)
    assert item.stage == stage and not item.commit_requested and not item.commit_ack
    assert not stream.commands and not stream.queues and not item.journal.events


@pytest.mark.parametrize('stage',['copy','foreign_keys','restart','commit','complete','unknown'])
@pytest.mark.parametrize('frame',[{},dict(kind=None),dict(kind=[]),dict(kind='unknown'),dict(ACK,extra=True)])
def test_unknown_frames_keep_state_and_no_commit(stage,frame):
    item, stream = execution(stage), Stream()
    with pytest.raises(GuardFailure) as error: item.accept(copy.deepcopy(frame),stream)
    assert str(error.value) == 'import_frame_order_or_coverage_invalid'
    assert item.stage == stage and item.restart is None and not item.commit_requested and not item.commit_ack
    assert not item.journal.events and not stream.commands and not stream.queues


@pytest.mark.parametrize('stage,method',[('admission','start_baseline'),('baseline','copy'),('content','verify')])
@pytest.mark.parametrize('completed',[False,True])
def test_reader_completion_dispatch_preserves_order(monkeypatch,stage,method,completed):
    item, stream, calls = execution(stage), Stream(), []
    class Reader:
        stage = 'reading'
        def accept(self,frame,pipe):
            calls.append(('reader',frame,pipe))
            if completed: self.stage = 'complete'
    owned = Reader(); setattr(item,{'admission':'admission','baseline':'baseline','content':'actual'}[stage],owned)
    monkeypatch.setattr(item,method,lambda pipe:calls.append((method,pipe)))
    frame = dict(kind='synthetic-reader-frame')
    assert item.accept(frame,stream) is None
    assert calls[0] == ('reader',frame,stream)
    assert calls[1:] == ([(method,stream)] if completed else []) and not item.journal.events


def test_exact_copied_marker_assigns_actual_reader_before_content_stage(monkeypatch):
    item, stream, calls = execution('copy'), Stream(), []
    actual = Projection()
    def begin(*args): calls.append(args); return actual
    monkeypatch.setattr(runner,'begin_content',begin)
    assert item.accept(dict(kind='copied'),stream) is None
    assert calls == [(stream,item.inputs['config'],item.admission.target,item.deadline)]
    assert item.actual is actual and item.stage == 'content' and not item.journal.events
    item.stage = 'copy'
    with pytest.raises(GuardFailure,match='import_frame_order_or_coverage_invalid'):
        item.accept(dict(kind='copied',extra=True),stream)
    def fail(*args): raise GuardFailure('synthetic_begin_failure')
    monkeypatch.setattr(runner,'begin_content',fail)
    with pytest.raises(GuardFailure,match='synthetic_begin_failure'): item.accept(dict(kind='copied'),stream)
    assert item.stage == 'copy' and item.actual is actual


@pytest.mark.parametrize('scanned,reason',[(2,None),(MAX_ROWS+1,'schema_foreign_key_count_or_budget_invalid')])
def test_postcopy_fk_validation_uses_existing_schema_reader(scanned,reason):
    item, stream = execution(), Stream()
    item.admission.expected_fks = [('children',dict(name='fk_parent',validated=True))]
    frame = dict(kind='foreign_key',table='children',constraint='fk_parent',scanned_rows=scanned,violations=0,validated=True)
    if reason:
        with pytest.raises(GuardFailure,match=reason): item.accept(frame,stream)
        assert not item.admission.fk_rows and item.admission.scanned == 0
    else:
        assert item.accept(frame,stream) is None and item.admission.scanned == 2
        assert item.admission.fk_rows == [{k:v for k,v in frame.items() if k != 'kind'}]
    assert item.stage == 'foreign_keys' and not item.journal.events and not stream.commands


def test_fk_total_budget_failure_keeps_counter_and_blocks_restart(monkeypatch):
    item, stream = execution(), Stream(); item.admission.scanned = MAX_ROWS
    item.admission.expected_fks = [('children',dict(name='fk_parent',validated=True))]
    monkeypatch.setattr(item,'recheck_inputs',lambda:pytest.fail('unverified FK reached recheck'))
    with pytest.raises(GuardFailure,match='schema_foreign_key_total_row_budget_exceeded'):
        item.accept(dict(kind='foreign_key',table='children',constraint='fk_parent',scanned_rows=1,violations=0,validated=True),stream)
    assert item.admission.scanned == MAX_ROWS+1 and not item.admission.fk_rows
    with pytest.raises(GuardFailure,match='import_postcopy_foreign_key_validation_failed'):
        item.accept(dict(kind='verified'),stream)
    assert not item.journal.events and not stream.commands


@pytest.mark.parametrize('rows',[[],[dict(table='children',constraint='fk_parent',scanned_rows=2,violations=1,validated=True)],[dict(table='children',constraint='fk_parent',scanned_rows=2,violations=0,validated=False)]])
def test_missing_or_blocked_fk_precedes_input_recheck_journal_and_restart(monkeypatch,rows):
    item, stream = execution(), Stream(); item.admission.fk_rows = copy.deepcopy(rows)
    item.admission.expected_fks = [('children',dict(name='fk_parent',validated=True))]
    monkeypatch.setattr(item,'recheck_inputs',lambda:pytest.fail('FK failure passed'))
    with pytest.raises(GuardFailure,match='import_postcopy_foreign_key_validation_failed'): item.accept(dict(kind='verified'),stream)
    assert item.admission.fk_rows == rows and item.stage == 'foreign_keys'
    assert not item.journal.events and not stream.commands


@pytest.mark.parametrize('send_failure',[False,True])
def test_verified_marker_rechecks_then_journals_then_sends_restart(monkeypatch,send_failure):
    item, stream, calls = execution(), Stream(send_failure), []
    monkeypatch.setattr(item,'recheck_inputs',lambda:calls.append('rechecked'))
    if send_failure:
        with pytest.raises(GuardFailure,match='synthetic_send_failure'): item.accept(dict(kind='verified'),stream)
    else: assert item.accept(dict(kind='verified'),stream) is None
    assert calls == ['rechecked'] and item.journal.events == [('verified_uncommitted',dict(rows=17))]
    assert stream.commands[0][0].startswith('ALTER SEQUENCE public."audit_events_seq_seq" RESTART WITH 100;\n')
    assert stream.commands[0][1] is False and 'COMMIT' not in stream.commands[0][0]
    assert item.stage == ('foreign_keys' if send_failure else 'restart') and not item.commit_requested


@pytest.mark.parametrize('change', [{'last_value':99},{'is_called':True},{'is_called':0},{'extra':True}])
def test_restart_rejection_precedes_evidence_rechecks_and_commit(monkeypatch,change):
    item, stream = execution('restart'), Stream()
    monkeypatch.setattr(item,'recheck_inputs',lambda:pytest.fail('bad restart reached recheck'))
    frame = dict(RESTART,**change)
    with pytest.raises(GuardFailure,match='import_transactional_sequence_restart_not_verified'): item.accept(frame,stream)
    assert item.restart is None and item.stage == 'restart' and not item.commit_requested
    assert not stream.commands and not item.journal.events


@pytest.mark.parametrize('last,floor',[(100.0,100),(True,1)])
def test_equal_numeric_restart_still_reaches_strict_sequence_state_validator(monkeypatch,last,floor):
    item, stream = execution('restart'), Stream(); item.inputs['floor'] = floor
    monkeypatch.setattr(item,'recheck_inputs',lambda:pytest.fail('bad sequence state reached recheck'))
    with pytest.raises(GuardFailure,match='audit_sequence_state_invalid'):
        item.accept(dict(RESTART,last_value=last),stream)
    assert item.restart is None and not item.journal.events and not stream.commands


@pytest.mark.parametrize('failure',['none','recheck','journal','send'])
def test_commit_request_retains_exact_partial_flags_and_durable_order(monkeypatch,failure):
    item, stream, calls = execution('restart'), Stream(failure=='send'), []
    def recheck():
        calls.append('rechecked')
        if failure == 'recheck': raise GuardFailure('synthetic_recheck_failure')
    monkeypatch.setattr(item,'recheck_inputs',recheck)
    if failure == 'journal': item.journal.fail = 'commit_requested'
    frame = copy.deepcopy(RESTART)
    if failure == 'none': assert item.accept(frame,stream) is None
    else:
        expected = OSError if failure == 'journal' else GuardFailure
        with pytest.raises(expected): item.accept(frame,stream)
    assert frame == RESTART and item.restart['state'] == {'last_value':100,'is_called':False}
    assert calls == ['rechecked'] and item.commit_ack is False
    assert item.commit_requested is (failure in ('none','send'))
    assert item.stage == ('commit' if failure == 'none' else 'restart')
    assert item.journal.events == ([] if failure == 'recheck' else [('commit_requested',{})])
    if failure in ('none','send'):
        assert stream.commands == [("COMMIT;\nSELECT json_build_object('kind','committed','attempt','synthetic-attempt')::jsonb;\n",True)]
    else: assert not stream.commands


@pytest.mark.parametrize('change',[{'attempt':'other'},{'attempt':None},{'extra':True},{'kind':'complete'}])
def test_bad_ack_never_claims_success_or_clears_commit_ambiguity(change):
    item, stream = execution('commit'), Stream(); item.commit_requested = True
    with pytest.raises(GuardFailure,match='import_frame_order_or_coverage_invalid'): item.accept(dict(ACK,**change),stream)
    assert item.commit_requested and not item.commit_ack and item.stage == 'commit'
    assert not item.journal.events and not stream.commands


def test_exact_ack_changes_only_ack_and_stage_not_durable_success():
    item, stream = execution('commit'), Stream(); item.commit_requested = True
    frame = copy.deepcopy(ACK)
    assert item.accept(frame,stream) is None and frame == ACK
    assert item.commit_ack and item.commit_requested and item.stage == 'complete'
    assert not item.journal.events and not stream.commands
    with pytest.raises(GuardFailure,match='import_frame_order_or_coverage_invalid'): item.accept(ACK,stream)
    assert item.commit_ack and item.stage == 'complete'


@pytest.mark.parametrize('failure',['source','connection','policy','contract','intent',None])
def test_private_input_recheck_first_failure_order(monkeypatch,failure):
    item, calls = execution(), []
    item.args = SimpleNamespace(snapshot='source',target_connection_file='cfg',conversion_policy_file='policy',schema_contract_file='contract',schema_contract_sha256='1'*64,intent_file='intent',intent_sha256='2'*64)
    item.inputs.update(source=dict(sha256='3'*64),policy=dict(version=1),contract=dict(version=1),intent=dict(version=1))
    def source(*args):
        calls.append('source')
        if failure == 'source': raise GuardFailure('snapshot_sha256_mismatch')
    monkeypatch.setattr(runner,'verify_snapshot',source)
    def loader(label,value):
        def load(*args): calls.append(label); return {} if label == failure else value
        return load
    for label,name,key in [('connection','connection_file','config'),('policy','load_policy','policy'),('contract','load_contract','contract'),('intent','load_intent','intent')]:
        monkeypatch.setattr(runner,name,loader(label,item.inputs[key]))
    if failure:
        reason = 'snapshot_sha256_mismatch' if failure == 'source' else 'import_'+failure+'_changed'
        with pytest.raises(GuardFailure,match=reason): item.recheck_inputs()
    else: assert item.recheck_inputs() is None
    order = ['source','connection','policy','contract','intent']
    assert calls == (order[:order.index(failure)+1] if failure else order)


@pytest.mark.parametrize('failure',['none','missing_ack','child_after_ack','deadline_after_ack','journal_after_ack'])
def test_run_needs_ack_child_completion_deadline_and_durable_success(monkeypatch,failure):
    item, calls = execution('commit'), []; item.commit_requested = True
    item.restart = dict(state={'last_value':100,'is_called':False})
    class Child(Stream):
        def __init__(self,*args): super().__init__(); calls.append('opened')
        def __iter__(self):
            if failure != 'missing_ack': yield copy.deepcopy(ACK)
            if failure == 'child_after_ack': raise GuardFailure('target_content_query_failed_diagnostics_withheld')
        def close(self): calls.append('closed')
    monkeypatch.setattr(runner,'ImportStream',Child)
    if failure == 'deadline_after_ack':
        values = iter([9,9,10]); monkeypatch.setattr(runner,'time',SimpleNamespace(monotonic=lambda:next(values)))
    if failure == 'journal_after_ack': item.journal.fail = 'committed_acknowledged'
    if failure == 'none':
        report = item.run()
        assert report['result'] == 'passed' and report['normal_process_exit'] and report['commit_acknowledged']
        assert report['rollback_verified'] is False and report['automatic_retry'] is False and report['cutover_authorized'] is False
    else:
        with pytest.raises(OSError if failure == 'journal_after_ack' else GuardFailure): item.run()
    assert calls == ['opened','closed'] and item.commit_requested
    assert item.commit_ack is (failure != 'missing_ack')
    assert item.journal.events == ([('committed_acknowledged',{})] if failure in ('none','journal_after_ack') else [])
