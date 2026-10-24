"""Read-only schema frame order/completion is not child-exit or writer authority."""
import ast
import copy
from pathlib import Path

import pytest

from checks.test_migration_input_contract import conservative_complexity
from checks.test_migration_target_schema import setup
from migration_guard import target_schema as schema
from migration_guard.recovery_observe import RecoverySchemaReader, read_frames
from migration_guard.snapshot import GuardFailure, MAX_ROWS

CLASSES = (schema.SchemaReader, RecoverySchemaReader)
FUNCTIONS = [n for n in ast.walk(ast.parse(Path(schema.__file__).read_text())) if isinstance(n, ast.FunctionDef)]
CONFIG = dict(database='snaplink_mig_test', user='schema_test', owner_token='0'*48)
IDENTITY = dict(kind='identity', database='snaplink_mig_test', user='schema_test', owned=True,
    read_only='on', isolation='repeatable read', version='16 synthetic')
ENVIRONMENT = dict(kind='environment', value=dict(server_version_num=160014,encoding='UTF8',collate='C',ctype='C',provider='c',icu_locale=None,recorded_version=None,actual_version=None))
COMPLETE = dict(kind='complete', read_only='on', isolation='repeatable read')


class Stream:
    def __init__(self): self.commands = []
    def send(self, text, final=False): self.commands.append((text, final))


def reader(cls):
    if cls is schema.SchemaReader: return cls(copy.deepcopy(CONFIG), {}, None)
    return cls(copy.deepcopy(CONFIG), dict(tables=[]))


@pytest.mark.parametrize('node', FUNCTIONS, ids=[n.name+'-'+str(n.lineno) for n in FUNCTIONS])
def test_schema_reader_owner_complexity(node):
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


@pytest.mark.parametrize('cls', CLASSES)
def test_identity_is_validated_before_count_scope_and_stage_change(cls):
    item, stream = reader(cls), Stream()
    frame = copy.deepcopy(IDENTITY); prior = copy.deepcopy(frame)
    assert item.accept(frame, stream) is None and frame == prior
    assert item.stage == 'catalog' and stream.commands == []
    assert item.target['counts_tracked_for_business_tables_only'] is False
    assert item.target['table_counts_not_collected_in_schema_snapshot'] is True
    item = reader(cls); frame['owned'] = False
    with pytest.raises(GuardFailure, match='target_content_ownership_or_snapshot_not_verified'):
        item.accept(frame, stream)
    assert item.stage == 'identity' and item.target is None and not stream.commands


@pytest.mark.parametrize('cls', CLASSES)
@pytest.mark.parametrize('stage', ['identity','catalog','environment','facets','foreign_keys','complete','unknown'])
@pytest.mark.parametrize('frame', [{}, dict(kind='unknown'), dict(kind=None), dict(kind=[]), dict(COMPLETE, extra=True)])
def test_unadmitted_frames_preserve_reader_state_and_never_send(cls, stage, frame):
    item, stream = reader(cls), Stream(); item.stage = stage
    prior = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure) as error: item.accept(copy.deepcopy(frame), stream)
    assert str(error.value) == 'schema_frame_order_or_coverage_invalid'
    assert item.__dict__ == prior and not stream.commands


@pytest.mark.parametrize('cls', CLASSES)
@pytest.mark.parametrize('value', ['off', None, True, 1, 'ON'])
def test_completion_rejects_read_write_or_noncanonical_flags(cls, value):
    item, stream = reader(cls), Stream(); item.stage = 'foreign_keys'
    with pytest.raises(GuardFailure, match='schema_completion_or_snapshot_invalid'):
        item.accept(dict(COMPLETE, read_only=value), stream)
    assert item.stage == 'foreign_keys' and not stream.commands
    with pytest.raises(GuardFailure, match='schema_completion_missing'): item.evidence()


@pytest.mark.parametrize('cls', CLASSES)
@pytest.mark.parametrize('value', ['read committed', 'serializable', '', None, True])
def test_completion_requires_exact_repeatable_read(cls, value):
    item, stream = reader(cls), Stream(); item.stage = 'foreign_keys'
    with pytest.raises(GuardFailure, match='schema_completion_or_snapshot_invalid'):
        item.accept(dict(COMPLETE, isolation=value), stream)
    assert item.stage == 'foreign_keys' and not stream.commands


@pytest.mark.parametrize('cls', CLASSES)
def test_missing_expected_fk_blocks_completion_without_state_reset(cls):
    item, stream = reader(cls), Stream(); item.stage = 'foreign_keys'
    item.expected_fks = [('children',dict(name='fk_parent',validated=True))]
    prior = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure, match='schema_completion_or_snapshot_invalid'): item.accept(COMPLETE, stream)
    assert item.__dict__ == prior and not stream.commands


@pytest.mark.parametrize('cls', CLASSES)
@pytest.mark.parametrize('validated', [False, True])
def test_fk_then_completion_preserves_actual_evidence_and_no_authority(cls, validated):
    item, stream = reader(cls), Stream(); item.stage = 'foreign_keys'
    item.expected_fks = [('children',dict(name='fk_parent',validated=validated))]
    frame = dict(kind='foreign_key', table='children',constraint='fk_parent',scanned_rows=2,violations=1,validated=validated)
    prior = copy.deepcopy(frame)
    assert item.accept(frame, stream) is None and frame == prior
    assert item.scanned == 2 and item.stage == 'foreign_keys'
    assert item.accept(COMPLETE, stream) is None and item.stage == 'complete' and not stream.commands
    result = item.evidence()
    assert result['declared_foreign_keys']['result'] == 'failed'
    assert result['declared_foreign_keys']['checks'][0]['validated'] is validated
    for key in ('writer_fencing_verified','full_ddl_certified','cutover_authorized','all_sequence_states_verified','all_business_relationships_verified','schema_baseline_provenance_verified'):
        assert result[key] is False
    with pytest.raises(GuardFailure, match='schema_frame_order_or_coverage_invalid'): item.accept(COMPLETE, stream)


@pytest.mark.parametrize('cls', CLASSES)
@pytest.mark.parametrize('change,reason', [
    ({'extra':True},'schema_foreign_key_frame_invalid'),
    ({'table':'other'},'schema_foreign_key_frame_order_or_state_invalid'),
    ({'validated':1},'schema_foreign_key_frame_order_or_state_invalid'),
    ({'scanned_rows':True},'schema_foreign_key_count_or_budget_invalid'),
    ({'scanned_rows':MAX_ROWS+1},'schema_foreign_key_count_or_budget_invalid'),
    ({'violations':3},'schema_foreign_key_count_or_budget_invalid'),
])
def test_fk_frame_reasons_and_prevalidation_state_unchanged(cls, change, reason):
    item, stream = reader(cls), Stream(); item.stage = 'foreign_keys'
    item.expected_fks = [('children',dict(name='fk_parent',validated=True))]
    frame = dict(kind='foreign_key',table='children',constraint='fk_parent',scanned_rows=2,violations=0,validated=True)
    frame.update(change); prior = copy.deepcopy(item.__dict__)
    with pytest.raises(GuardFailure) as error: item.accept(frame, stream)
    assert str(error.value) == reason and item.__dict__ == prior and not stream.commands


@pytest.mark.parametrize('cls', CLASSES)
def test_total_fk_budget_failure_retains_real_partial_counter(cls):
    item, stream = reader(cls), Stream(); item.stage = 'foreign_keys'
    item.expected_fks = [('children',dict(name='fk_parent',validated=True))]; item.scanned = MAX_ROWS
    with pytest.raises(GuardFailure, match='schema_foreign_key_total_row_budget_exceeded'):
        item.accept(dict(kind='foreign_key',table='children',constraint='fk_parent',scanned_rows=1,violations=0,validated=True),stream)
    assert item.scanned == MAX_ROWS+1 and not item.fk_rows and item.stage == 'foreign_keys'
    with pytest.raises(GuardFailure, match='schema_completion_or_snapshot_invalid'): item.accept(COMPLETE,stream)


@pytest.mark.parametrize('cls', CLASSES)
def test_environment_envelope_before_value_and_hash_before_stage(cls):
    item, stream = reader(cls), Stream(); item.stage = 'environment'
    with pytest.raises(GuardFailure, match='schema_frame_order_or_coverage_invalid'):
        item.accept(dict(kind='environment',value=None,extra=True),stream)
    assert item.environment is None and item.stage == 'environment'
    with pytest.raises(GuardFailure, match='schema_wire_record_fields_invalid'):
        item.accept(dict(kind='environment',value=None),stream)
    assert item.environment is None and item.stage == 'environment'
    frame = copy.deepcopy(ENVIRONMENT)
    assert item.accept(frame,stream) is None
    assert len(item.environment) == 64 and item.stage == 'facets' and not stream.commands
    assert frame == ENVIRONMENT


def test_full_schema_transcript_sends_readonly_inventory_and_final_commit(tmp_path, monkeypatch):
    args = setup(tmp_path,monkeypatch)
    report = schema.verify_schema(*args[:6])
    assert report['result'] == 'passed' and report['read_only'] is True
    assert report['declared_foreign_keys']['result'] == 'not_executed'
    assert report['declared_foreign_keys']['reason'] == 'no_declared_foreign_keys'
    assert len(args[-1]) == 3
    assert 'REPEATABLE READ READ ONLY' in args[-1][0][0]
    assert 'ACCESS SHARE' in args[-1][0][0]
    assert args[-1][-1][1] is True and args[-1][-1][0].endswith('COMMIT;\n')
    assert 'nextval' not in '\n'.join(text for text,_ in args[-1]).lower()


@pytest.mark.parametrize('failure,reason', [('truncate','schema_completion_missing'),('after_complete','schema_frame_order_or_coverage_invalid'),('writable','schema_completion_or_snapshot_invalid')])
def test_bad_full_transcript_cannot_produce_evidence(tmp_path,monkeypatch,failure,reason):
    def mutate(frames):
        if failure == 'truncate': frames.pop()
        if failure == 'after_complete': frames.append(dict(kind='complete',read_only='on',isolation='repeatable read'))
        if failure == 'writable': frames[-1]['read_only'] = 'off'
    args = setup(tmp_path,monkeypatch,mutate)
    with pytest.raises(GuardFailure) as error: schema.verify_schema(*args[:6])
    assert str(error.value) == reason


def test_recovery_complete_frame_does_not_override_child_failure(monkeypatch):
    import time
    from migration_guard import recovery_observe as recovery
    class FailedChild(Stream):
        def __init__(self,*args,**kwargs): super().__init__()
        def __iter__(self):
            yield dict(COMPLETE)
            raise GuardFailure('target_content_query_failed_diagnostics_withheld')
        def close(self): pass
    monkeypatch.setattr(recovery,'PsqlStream',FailedChild)
    monkeypatch.setattr(recovery,'psql_command',lambda unused: ('synthetic-psql',{}))
    item = reader(RecoverySchemaReader); item.stage = 'foreign_keys'
    with pytest.raises(GuardFailure, match='target_content_query_failed_diagnostics_withheld'):
        read_frames(item,CONFIG,dict(tables=[]),time.monotonic()+30)
    assert item.stage == 'complete'  # Actual partial fact, never published as success.
