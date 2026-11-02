"""Exact PostgreSQL scalar wire values, not JSON number coercion or rendering."""
import pytest

from checks.migration_guard_fixture import sample_snapshot
from migration_guard.snapshot import GuardFailure
from migration_guard import target_codec as codec


@pytest.mark.parametrize('kind,cell,value', [
    ('int8',['integer','9007199254740993'],9007199254740993),
    ('int2',['integer','-32768'],-32768),('int4',['integer','0'],0),
    ('float8',['real','3ff0000000000001'],1.0000000000000002),
    ('float8',['real','8000000000000000'],-0.0),
    ('text',['text','e\u0301 😀 '],'e\u0301 😀 '),('text',['text',''],''),
    ('bytea',['blob','410042'],b'A\x00B'),('bytea',['blob',''],b''),
    ('bytea',['null'],None)])
def test_values_do_not_round_normalize_trim_or_collapse_null(kind, cell, value):
    assert codec.decode_cell(cell,dict(type=kind,not_null=False)) == value


@pytest.mark.parametrize('kind,cell', [
    ('int8',['integer',9007199254740993]),('int8',['integer','01']),
    ('int8',['integer','-0']),('int8',['integer','9223372036854775808']),
    ('int2',['integer','32768']),('int4',['integer','2147483648']),
    ('text',['integer','1']),('bytea',['text','41']),('bytea',['blob','0']),
    ('bytea',['blob','GG']),('float8',['real','7ff0000000000000']),
    ('float8',['real','7ff8000000000000']),('float8',['real','1']),
    ('text',['text',False]),('text',['null','']),('jsonb',['text','{}'])])
def test_bad_nonfinite_unknown_or_lossy_values_fail(kind, cell):
    with pytest.raises(GuardFailure):
        codec.decode_cell(cell,dict(type=kind,not_null=False))


def test_null_constraints_and_namespace_spoof_are_not_bypassed():
    with pytest.raises(GuardFailure):
        codec.decode_cell(['null'],dict(type='text',not_null=True))
    with pytest.raises(GuardFailure):
        codec.column_expression(dict(name='id',type='int8',type_namespace='public'))
    for kind in ('text','int2','int4','int8','bytea','float8'):
        sql = codec.column_expression(dict(name='id',type=kind,type_namespace='pg_catalog'))
        assert '"id"' in sql and 'CASE WHEN' in sql
    assert 'float8send' in codec.column_expression(dict(name='ratio',type='float8',type_namespace='pg_catalog'))
    assert 'CASE WHEN' not in codec.column_expression(dict(name='id',type='text',type_namespace='pg_catalog',not_null=True))
