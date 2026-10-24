"""Candidate FK/sequence admission preserves order, partial state and no writer grant."""
import ast
import copy
from pathlib import Path

import pytest

from checks.test_migration_input_contract import conservative_complexity
from checks.test_migration_row_projection import fixture
from checks.test_migration_sequence_evidence import descriptor
from checks.test_migration_target_schema import fake_frames
from migration_guard import import_admission as admission
from migration_guard.conversion_policy import target_shape_sha256
from migration_guard.schema_contract import schema_fingerprint
from migration_guard.schema_records import environment_evidence
from migration_guard.snapshot import GuardFailure, MAX_ROWS

CONFIG = dict(database='snaplink_mig_test', user='schema_test', owner_token='0'*48)
FUNCTIONS = [n for n in ast.walk(ast.parse(Path(admission.__file__).read_text())) if isinstance(n, ast.FunctionDef)]
PUBLIC = dict(kind='public_sequences', names=['audit_events_seq_seq'])


class Stream:
    def __init__(self, fail=False): self.commands, self.fail = [], fail
    def send(self, text, final=False):
        self.commands.append((text, final))
        if self.fail: raise GuardFailure('synthetic_send_failure')


def reader(stage='foreign_keys'):
    item = admission.AdmissionReader.__new__(admission.AdmissionReader)
    item.config, item.shape, item.contract = copy.deepcopy(CONFIG), '0'*64, {}
    item.stage, item.target = stage, None
    item.names, item.facets, item.expected_fks, item.fk_rows = [], {}, [], []
    item.environment, item.scanned, item.sequence = None, 0, None
    return item


def admission_fixture(root):
    _, source, target, _ = fixture(root)
    for table in target['tables']:
        for column in table['columns']: column['type_namespace'] = 'pg_catalog'
    frames = list(fake_frames(target))[:-1]
    frames[0]['read_only'] = 'off'
    sequences = next(frame for frame in frames if frame.get('facet') == 'sequences')
    next(table for table in sequences['tables'] if table['table'] == 'audit_events')['records'] = [dict(
        column='seq', schema='public', name='audit_events_seq_seq', dependency='a',
        type_schema='pg_catalog', type='int8', start=1, increment=1, minimum=1,
        maximum=9223372036854775807, cache=1, cycle=False)]
    tables = [dict(table=table['table'], facets={packet['facet']: schema_fingerprint(table['table'], packet['facet'],
        next(t for t in packet['tables'] if t['table'] == table['table'])['records'])
        for packet in frames if packet['kind'] == 'facet'}) for table in target['tables']]
    contract = dict(version=1, algorithm='pg_native_schema_facets_v1', source_sha256=source['sha256'],
        target_shape_sha256=target_shape_sha256(target), schema_source=dict(base_commit='a'*40, combination_sha256='b'*64),
        environment_sha256=environment_evidence(frames[2]['value']), tables=tables)
    frames.extend([dict(kind='sequence_descriptor', value=descriptor()), copy.deepcopy(PUBLIC)])
    return admission.AdmissionReader(copy.deepcopy(CONFIG), target, contract), frames


@pytest.mark.parametrize('node', FUNCTIONS, ids=[n.name+'-'+str(n.lineno) for n in FUNCTIONS])
def test_admission_owner_complexity(node):
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


@pytest.mark.parametrize('stage', ['identity','catalog','environment','facets','foreign_keys','sequences','complete','unknown'])
@pytest.mark.parametrize('frame', [{}, dict(kind=None), dict(kind=[]), dict(kind='unknown'), dict(PUBLIC, extra=True)])
def test_unadmitted_frames_do_not_advance_or_send(stage, frame):
    item, stream = reader(stage), Stream(); before = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure) as error: item.accept(copy.deepcopy(frame), stream)
    assert str(error.value) == 'import_admission_frame_order_or_coverage_invalid'
    assert item.__dict__ == before and not stream.commands


def test_fk_is_checked_before_descriptor_and_public_inventory():
    item, stream = reader(), Stream()
    item.expected_fks = [('children', dict(name='fk_parent', validated=True))]
    before = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure, match='import_declared_foreign_key_validation_failed'):
        item.accept(dict(kind='sequence_descriptor', value=None), stream)
    assert item.__dict__ == before and not stream.commands
    frame = dict(kind='foreign_key', table='children', constraint='fk_parent', scanned_rows=2, violations=0, validated=True)
    assert item.accept(frame, stream) is None and item.scanned == 2
    assert item.stage == 'foreign_keys' and not stream.commands and 'kind' not in item.fk_rows[0]
    meta = descriptor(); item.accept(dict(kind='sequence_descriptor', value=meta), stream)
    assert item.sequence is meta and item.stage == 'sequences' and len(stream.commands) == 1
    assert stream.commands[0][1] is False and "c.relkind='S'" in stream.commands[0][0]
    assert 'COMMIT' not in stream.commands[0][0] and 'nextval' not in stream.commands[0][0]
    item.accept(PUBLIC, stream)
    assert item.stage == 'complete' and len(stream.commands) == 1


@pytest.mark.parametrize('violations,validated', [(1,True),(0,False),(1,False)])
def test_fk_blockers_precede_invalid_descriptor(violations, validated):
    item, stream = reader(), Stream()
    item.expected_fks = [('children', dict(name='fk_parent', validated=validated))]
    item.accept(dict(kind='foreign_key', table='children', constraint='fk_parent', scanned_rows=2, violations=violations, validated=validated), stream)
    before = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure, match='import_declared_foreign_key_validation_failed'):
        item.accept(dict(kind='sequence_descriptor', value=None), stream)
    assert item.__dict__ == before and not stream.commands


@pytest.mark.parametrize('change,reason', [
    ({'extra':True}, 'schema_foreign_key_frame_invalid'),
    ({'constraint':'other'}, 'schema_foreign_key_frame_order_or_state_invalid'),
    ({'validated':1}, 'schema_foreign_key_frame_order_or_state_invalid'),
    ({'scanned_rows':True}, 'schema_foreign_key_count_or_budget_invalid'),
    ({'scanned_rows':MAX_ROWS+1}, 'schema_foreign_key_count_or_budget_invalid'),
    ({'violations':3}, 'schema_foreign_key_count_or_budget_invalid')])
def test_fk_failure_reasons_keep_prevalidation_state(change, reason):
    item, stream = reader(), Stream()
    item.expected_fks = [('children', dict(name='fk_parent', validated=True))]
    frame = dict(kind='foreign_key', table='children', constraint='fk_parent', scanned_rows=2, violations=0, validated=True)
    frame.update(change); before = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure) as error: item.accept(frame, stream)
    assert str(error.value) == reason and item.__dict__ == before and not stream.commands


def test_total_fk_budget_retains_actual_counter_without_appending_result():
    item, stream = reader(), Stream(); item.scanned = MAX_ROWS
    item.expected_fks = [('children', dict(name='fk_parent', validated=True))]
    with pytest.raises(GuardFailure, match='schema_foreign_key_total_row_budget_exceeded'):
        item.accept(dict(kind='foreign_key', table='children', constraint='fk_parent', scanned_rows=1, violations=0, validated=True), stream)
    assert item.scanned == MAX_ROWS+1 and not item.fk_rows and item.stage == 'foreign_keys'
    assert item.sequence is None and not stream.commands


@pytest.mark.parametrize('value,reason', [
    (None,'audit_sequence_required'), ({},'audit_sequence_descriptor_fields_invalid'),
    (dict(descriptor(),increment=True),'audit_sequence_shape_or_configuration_unsupported'),
    (dict(descriptor(),type='int4'),'audit_sequence_shape_or_configuration_unsupported'),
    (dict(descriptor(),name='unsafe;name'),'unsupported_schema_identifier')])
def test_descriptor_failure_never_admits_inventory(value, reason):
    item, stream = reader(), Stream(); before = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure) as error: item.accept(dict(kind='sequence_descriptor', value=value), stream)
    assert str(error.value) == reason and item.__dict__ == before and not stream.commands


@pytest.mark.parametrize('frame', [dict(kind='sequence_descriptor'),dict(kind='sequence_descriptor',value=None,extra=True)])
def test_descriptor_envelope_precedes_fk_or_value_checks(frame):
    item, stream = reader(), Stream()
    item.expected_fks = [('children', dict(name='fk_parent',validated=True))]
    with pytest.raises(GuardFailure, match='import_admission_frame_order_or_coverage_invalid'): item.accept(frame,stream)
    assert item.sequence is None and item.stage == 'foreign_keys' and not stream.commands


def test_send_failure_keeps_validated_descriptor_alias_but_does_not_advance():
    item, stream, meta = reader(), Stream(fail=True), descriptor()
    with pytest.raises(GuardFailure, match='synthetic_send_failure'):
        item.accept(dict(kind='sequence_descriptor',value=meta), stream)
    assert item.sequence is meta and item.stage == 'foreign_keys'
    assert len(stream.commands) == 1 and stream.commands[0][1] is False


@pytest.mark.parametrize('names', [None,[],['other'],['audit_events_seq_seq','other'],['other','audit_events_seq_seq'],['audit_events_seq_seq']*2,'audit_events_seq_seq',('audit_events_seq_seq',)])
def test_public_sequence_coverage_is_exact_ordered_list(names):
    item, stream = reader('sequences'), Stream(); item.sequence = descriptor()
    before = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure, match='import_other_public_sequences_unsupported'):
        item.accept(dict(kind='public_sequences',names=names), stream)
    assert item.__dict__ == before and not stream.commands


def test_completion_is_admission_only_and_rejects_following_frames():
    item, stream = reader('sequences'), Stream(); item.sequence = descriptor()
    frame = copy.deepcopy(PUBLIC); item.accept(frame, stream)
    assert frame == PUBLIC and item.stage == 'complete' and not stream.commands
    for next_frame in [PUBLIC,dict(kind='copied'),dict(kind='committed',attempt='untrusted')]:
        with pytest.raises(GuardFailure, match='import_admission_frame_order_or_coverage_invalid'):
            item.accept(next_frame,stream)
    assert item.stage == 'complete' and not stream.commands and not hasattr(item,'commit_ack')


def test_environment_envelope_and_value_precede_advancement():
    item, stream = reader('environment'), Stream()
    with pytest.raises(GuardFailure, match='import_admission_frame_order_or_coverage_invalid'):
        item.accept(dict(kind='environment',value=None,extra=True),stream)
    with pytest.raises(GuardFailure, match='schema_wire_record_fields_invalid'):
        item.accept(dict(kind='environment',value=None),stream)
    assert item.environment is None and item.stage == 'environment' and not stream.commands


def test_full_admission_keeps_inventory_sql_and_no_commit_copy_or_restart(tmp_path):
    item, frames = admission_fixture(tmp_path); stream = Stream(); before = copy.deepcopy(frames)
    for frame in frames: assert item.accept(frame,stream) is None
    assert frames == before and item.stage == 'complete' and item.sequence is frames[-2]['value']
    assert item.order() == sorted(item.names) and item.scanned == 0 and not item.fk_rows
    assert len(stream.commands) == 3 and all(final is False for _,final in stream.commands)
    text = '\n'.join(sql for sql,_ in stream.commands)
    assert 'sequence_descriptor' in text and 'public_sequences' in text
    assert all(phrase not in text for phrase in ['COMMIT;', 'COPY public.', 'ALTER SEQUENCE ', 'setval('])


def test_last_facet_send_failure_retains_complete_facets_without_reset(tmp_path):
    item, frames = admission_fixture(tmp_path); stream = Stream()
    for frame in frames[:-3]: item.accept(frame,stream)
    prior_stage = item.stage; failing = Stream(fail=True)
    with pytest.raises(GuardFailure, match='synthetic_send_failure'): item.accept(frames[-3],failing)
    assert prior_stage == item.stage == 'facets' and len(item.facets) == 6
    assert item.sequence is None and len(failing.commands) == 1
