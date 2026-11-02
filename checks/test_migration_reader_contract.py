"""Lossless scalar/catalog contracts; readable validation is not migration authority."""
import ast
import copy
from pathlib import Path
import struct

import pytest

from checks.test_migration_input_contract import conservative_complexity
from migration_guard import target_codec as codec, target_content as content
from migration_guard.snapshot import GuardFailure

OWNERS = (codec, content)
FUNCTIONS = [(module, node) for module in OWNERS
             for node in ast.walk(ast.parse(Path(module.__file__).read_text()))
             if isinstance(node, ast.FunctionDef)]


@pytest.mark.parametrize('module,node', FUNCTIONS, ids=[m.__name__+'.'+n.name for m, n in FUNCTIONS])
def test_reader_owner_complexity(module, node):
    # Unchanged Step24/27 supplementary metric; committed Go gates remain authoritative.
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


@pytest.mark.parametrize('kind,lo,hi', [('int2', -32768, 32767),
    ('int4', -2147483648, 2147483647), ('int8', -9223372036854775808, 9223372036854775807)])
def test_native_integer_endpoints_and_adjacent_rejections(kind, lo, hi):
    column = dict(type=kind, not_null=False)
    for number in (lo, -1, 0, 1, hi):
        result = codec.decode_cell(['integer', str(number)], column)
        assert type(result) is int and result == number
    for number in (lo-1, hi+1):
        with pytest.raises(GuardFailure) as error:
            codec.decode_cell(['integer', str(number)], column)
        assert str(error.value) == 'target_content_integer_out_of_range'


@pytest.mark.parametrize('value', ['', '+1', '-0', '00', '01', '-01', ' 1', '1 ',
    '1\n', '1.0', '1e0', '١', '１', '−1', '1'*21, '\x001'])
def test_integer_grammar_rejection_reason(value):
    with pytest.raises(GuardFailure) as error:
        codec.decode_cell(['integer', value], dict(type='int8', not_null=False))
    assert str(error.value) == 'invalid_target_content_integer'


@pytest.mark.parametrize('bits', ['0000000000000000', '8000000000000000',
    '0000000000000001', '8000000000000001', '3ff0000000000001',
    '7fefffffffffffff', 'ffefffffffffffff'])
def test_binary64_bits_are_preserved_not_only_numeric_equality(bits):
    value = codec.decode_cell(['real', bits], dict(type='float8', not_null=False))
    assert type(value) is float and struct.pack('!d', value).hex() == bits


@pytest.mark.parametrize('kind,cell,reason', [
    ('int8', None, 'invalid_target_content_cell'),
    ('int8', ('integer', '1'), 'invalid_target_content_cell'),
    ('int8', ['integer', True], 'invalid_target_content_cell'),
    ('int8', ['text', '01'], 'invalid_target_content_cell'),
    ('int8', ['integer', '1', 'extra'], 'invalid_target_content_cell'),
    ('text', ['null', 'extra'], 'invalid_target_content_cell'),
    ('text', [], 'invalid_target_content_cell'),
    ('jsonb', ['null'], 'invalid_target_content_cell'),
    ('bytea', ['blob', 'A0'], 'invalid_target_content_hex'),
    ('bytea', ['blob', '0'], 'invalid_target_content_hex'),
    ('bytea', ['blob', '00\n'], 'invalid_target_content_hex'),
    ('float8', ['real', 'GG'], 'invalid_target_content_hex'),
    ('float8', ['real', '0'], 'invalid_target_content_hex'),
    ('float8', ['real', ''], 'invalid_target_content_float'),
    ('float8', ['real', '00'], 'invalid_target_content_float'),
    ('float8', ['real', '7ff0000000000000'], 'nonfinite_target_content_float'),
    ('float8', ['real', 'fff0000000000000'], 'nonfinite_target_content_float'),
    ('float8', ['real', '7ff8000000000001'], 'nonfinite_target_content_float'),
])
def test_scalar_rejections_keep_exact_reason_and_precedence(kind, cell, reason):
    with pytest.raises(GuardFailure) as error:
        codec.decode_cell(cell, dict(type=kind, not_null=True))
    assert str(error.value) == reason


@pytest.mark.parametrize('kind', ('text', 'bytea', 'int2', 'int4', 'int8', 'float8'))
def test_null_is_not_empty_or_a_nullable_constraint_bypass(kind):
    assert codec.decode_cell(['null'], dict(type=kind, not_null=False)) is None
    with pytest.raises(GuardFailure) as error:
        codec.decode_cell(['null'], dict(type=kind, not_null=True))
    assert str(error.value) == 'target_content_null_constraint_failed'


@pytest.mark.parametrize('value', ['', 'é', 'e\u0301', '😀 ', 'trailing  ',
    '{  "n":9007199254740993, "null":null }\n', 'quote"\\N\n'])
def test_text_is_untouched_including_stored_json(value):
    assert codec.decode_cell(['text', value], dict(type='text', not_null=False)) == value


def test_invalid_unicode_retains_strict_encode_failure():
    with pytest.raises(UnicodeEncodeError):
        codec.decode_cell(['text', '\ud800'], dict(type='text', not_null=False))


def table(name='items', **updates):
    return dict(table=name, columns=[dict(name='id', type='text', type_namespace='pg_catalog',
                not_null=True, pk_order=1)], relkind='r', rls_enabled=False, force_rls=False, **updates)


@pytest.mark.parametrize('items,reason', [(None, 'target_content_catalog_budget_or_format_invalid'),
    ((), 'target_content_catalog_budget_or_format_invalid'),
    ([], 'target_content_catalog_budget_or_format_invalid'),
    ([table()]*101, 'target_content_catalog_budget_or_format_invalid'),
    ([None], 'target_content_catalog_format_invalid'),
    ([dict(table(), extra=True)], 'target_content_catalog_format_invalid'),
    ([dict(table(), table='Bad')], 'unsupported_schema_identifier'),
    ([dict(table(), columns=[])], 'target_content_column_budget_or_duplicate_table'),
    ([dict(table(), columns=())], 'target_content_column_budget_or_duplicate_table'),
    ([dict(table(), columns=[{}]*81)], 'target_content_column_budget_or_duplicate_table'),
    ([table(), dict(table(), relkind='p')], 'target_content_column_budget_or_duplicate_table'),
    ([dict(table(), relkind='p', columns=[{}])], 'target_content_visibility_or_relation_unsupported'),
    ([dict(table(), rls_enabled=True)], 'target_content_visibility_or_relation_unsupported'),
    ([dict(table(), rls_enabled=0)], 'target_content_visibility_or_relation_unsupported'),
    ([dict(table(), force_rls=0)], 'target_content_visibility_or_relation_unsupported'),
    ([dict(table(), force_rls=True)], 'target_content_visibility_or_relation_unsupported'),
    ([dict(table(), columns=[{}])], 'target_content_column_format_invalid'),
    ([dict(table(), columns=[None])], 'target_content_column_format_invalid'),
])
def test_catalog_rejections_are_ordered_and_never_empty_success(items, reason):
    with pytest.raises(GuardFailure) as error:
        content.catalog_tables(items)
    assert str(error.value) == reason


@pytest.mark.parametrize('field,value,reason', [
    ('name', 'Bad', 'unsupported_schema_identifier'),
    ('name', None, 'unsupported_schema_identifier'),
    ('type', None, 'target_content_column_shape_invalid'),
    ('type_namespace', 1, 'target_content_column_shape_invalid'),
    ('not_null', 1, 'target_content_column_shape_invalid'),
    ('not_null', None, 'target_content_column_shape_invalid'),
    ('pk_order', True, 'target_content_column_shape_invalid'),
    ('pk_order', -1, 'target_content_column_shape_invalid'),
    ('pk_order', 81, 'target_content_column_shape_invalid'),
    ('pk_order', 1.0, 'target_content_column_shape_invalid'),
    ('type', 'numeric', 'unsupported_target_content_column_type'),
    ('type_namespace', 'public', 'unsupported_target_content_column_type'),
])
def test_column_shape_precedes_native_type_admission(field, value, reason):
    item = table()
    item['columns'][0][field] = value
    with pytest.raises(GuardFailure) as error:
        content.catalog_tables([item])
    assert str(error.value) == reason


def test_duplicate_column_precedes_type_admission():
    item = table()
    item['columns'].append(dict(item['columns'][0], type='numeric'))
    with pytest.raises(GuardFailure) as error:
        content.catalog_tables([item])
    assert str(error.value) == 'target_content_column_shape_invalid'


@pytest.mark.parametrize('count', (1, 80))
def test_column_budget_endpoints_and_native_shapes(count):
    item = table()
    item['columns'] = [dict(name='c'+str(i), type='int8', type_namespace='pg_catalog',
                            not_null=True, pk_order=i+1) for i in range(count)]
    result = content.catalog_tables([item])
    assert result == [dict(item, rows=None, metadata_only=False)]
    assert result[0]['columns'] is item['columns']


def test_catalog_table_budget_order_and_input_objects_are_preserved():
    items = [table('t'+str(i)) for i in range(100)]
    original = copy.deepcopy(items)
    result = content.catalog_tables(items)
    assert [t['table'] for t in result] == [t['table'] for t in items]
    assert items == original and all('rows' not in t and 'metadata_only' not in t for t in items)
    assert all(out['columns'] is inp['columns'] for out, inp in zip(result, items))
    assert all(t['rows'] is None and t['metadata_only'] is False for t in result)


def test_known_metadata_seam_stays_separate_from_business_and_recovery():
    item = table('schema_migrations_audit')
    item.update(relkind='p', rls_enabled=True, force_rls=True)
    item['columns'][0].update(type='opaque_history_type', type_namespace='public')
    assert content.catalog_tables([item]) == [dict(item, rows=None, metadata_only=True)]
    item['table'] = 'schema_migrations_unrecognized'
    with pytest.raises(GuardFailure, match='target_content_visibility_or_relation_unsupported'):
        content.catalog_tables([item])
    item['table'] = 'schema_migrations_audit'
    item['columns'][0]['pk_order'] = False
    with pytest.raises(GuardFailure, match='target_content_column_shape_invalid'):
        content.catalog_tables([item])


def test_invalid_locked_catalog_never_dispatches_a_data_script():
    reader = content.TargetReader({}, {}, {}, float('inf'))
    frame = dict(kind='catalog', tables=[dict(table(), rls_enabled=True)])
    class Stream:
        def send(self, *args, **kwargs):
            pytest.fail('data sent before locked catalog validation')
    with pytest.raises(GuardFailure, match='target_content_visibility_or_relation_unsupported'):
        reader.catalog(frame, Stream())
    assert reader.stage == 'identity' and reader.target is None
