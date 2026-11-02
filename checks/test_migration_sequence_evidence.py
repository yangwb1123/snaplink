"""No nextval/setval, guessed ownership, exhausted range or stale sequence pass."""
import json

import pytest

from checks.migration_guard_fixture import connection_config, private_config
from migration_guard.snapshot import GuardFailure
from migration_guard import sequence as seq


def descriptor():
    return dict(schema='public', name='audit_events_seq_seq', type='int8',
                start=1, increment=1, min=1, max=9223372036854775807,
                cache=1, cycle=False, owned_by_column=True, default_matches=True,
                default_dependents=1, column_identity='')


@pytest.mark.parametrize('called,last,next_value', [(False,1,1),(True,1,2),(False,9591,9591),(True,9590,9591)])
def test_readonly_next_candidate_is_exact_without_advancing(called, last, next_value):
    evidence = seq.sequence_evidence(descriptor(), dict(last_value=last,is_called=called), 9591)
    assert evidence['next_candidate'] == next_value
    assert evidence['result'] == ('passed' if next_value >= 9591 else 'failed')
    assert evidence['blockers'] == ([] if next_value >= 9591 else [dict(code='audit_sequence_below_required_floor',table='audit_events',column='seq')])
    assert not evidence['sequence_advanced_or_reset']
    assert not evidence['writer_fencing_verified']


@pytest.mark.parametrize('key,value', [
    ('schema','other'), ('name','unsafe;name'), ('type','int4'), ('increment',-1),
    ('increment',2), ('min',0), ('max',99), ('cache',2), ('cycle',True),
    ('owned_by_column',False), ('default_matches',False), ('default_dependents',2),
    ('column_identity','a'), ('start',0), ('start',True)])
def test_noncanonical_owned_serial_configuration_rejects(key, value):
    meta = descriptor()
    meta[key] = value
    with pytest.raises(GuardFailure):
        seq.sequence_evidence(meta, dict(last_value=1,is_called=False), 1)


@pytest.mark.parametrize('state,floor', [
    ({'last_value':0,'is_called':False},1), ({'last_value':True,'is_called':False},1),
    ({'last_value':1,'is_called':0},1), ({'last_value':9223372036854775807,'is_called':True},1),
    ({'last_value':1,'is_called':False},True), ({'last_value':1,'is_called':False},0)])
def test_unknown_invalid_or_exhausted_state_does_not_become_zero(state, floor):
    with pytest.raises(GuardFailure):
        seq.sequence_evidence(descriptor(), state, floor)


def test_null_catalog_and_wrong_owner_reject_before_state_read(tmp_path, monkeypatch):
    path = private_config(tmp_path, connection_config())
    monkeypatch.setattr(seq, 'verify_target_identity', lambda config: (_ for _ in ()).throw(GuardFailure('wrong_owner')))
    monkeypatch.setattr(seq, 'query_json', lambda *args: pytest.fail('must reject before querying sequence'))
    with pytest.raises(GuardFailure, match='wrong_owner'):
        seq.inspect_audit_sequence(path, 1)


def test_read_sequence_never_calls_mutating_functions_and_rechecks_state(tmp_path, monkeypatch):
    path = private_config(tmp_path, connection_config())
    calls = []
    monkeypatch.setattr(seq, 'verify_target_identity', lambda config: {'owned':True,'read_only':'on'})
    def query(config, sql, timeout=15):
        calls.append(sql)
        assert 'nextval(' not in sql.lower() and 'setval(' not in sql.lower()
        if 'pg_sequence' in sql:
            return descriptor()
        return dict(last_value=1,is_called=False)
    monkeypatch.setattr(seq, 'query_json', query)
    result = seq.inspect_audit_sequence(path, 1)
    assert result['result'] == 'passed' and len(calls) == 4
    assert result['stable_between_reads'] and not result['cross_query_atomic_snapshot']
    assert 'synthetic-private-password' not in json.dumps(result)


def test_missing_sequence_is_json_null_not_an_empty_psql_field(tmp_path, monkeypatch):
    assert "coalesce((SELECT" in seq.SEQUENCE_SQL
    assert "'null'::json" in seq.SEQUENCE_SQL
    path = private_config(tmp_path,connection_config())
    monkeypatch.setattr(seq,'verify_target_identity',lambda config: {'owned':True,'read_only':'on'})
    monkeypatch.setattr(seq,'query_json',lambda *a: None)
    with pytest.raises(GuardFailure,match='audit_sequence_required'):
        seq.inspect_audit_sequence(path,1)


def test_changed_sequence_rejects_instead_of_claiming_atomic_snapshot(tmp_path, monkeypatch):
    path = private_config(tmp_path, connection_config())
    monkeypatch.setattr(seq, 'verify_target_identity', lambda config: {'owned':True,'read_only':'on'})
    states = iter([dict(last_value=1,is_called=False),dict(last_value=1,is_called=True)])
    monkeypatch.setattr(seq, 'query_json', lambda config,sql,timeout=15: descriptor() if 'pg_sequence' in sql else next(states))
    with pytest.raises(GuardFailure, match='changed'):
        seq.inspect_audit_sequence(path, 1)
