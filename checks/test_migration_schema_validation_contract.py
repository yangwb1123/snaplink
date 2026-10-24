"""Native schema validation preserves facts/order; no inferred relationships or authority."""
import ast
import copy
import itertools
from pathlib import Path

import pytest

from checks.test_migration_input_contract import conservative_complexity
from checks.test_migration_schema_contract import document
from checks.test_migration_declared_fk import fk, shapes
from migration_guard import schema_contract as contract, schema_records as records, declared_fk as declared
from migration_guard.snapshot import GuardFailure

OWNERS = (contract, records, declared)
FUNCTIONS = [(module, node) for module in OWNERS
             for node in ast.walk(ast.parse(Path(module.__file__).read_text()))
             if isinstance(node, ast.FunctionDef)]


@pytest.mark.parametrize('module,node', FUNCTIONS, ids=[m.__name__+'.'+n.name for m, n in FUNCTIONS])
def test_schema_validation_owner_complexity(module, node):
    # Same supplementary AST metric, not the committed Go cyclomatic authority.
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


def set_path(value, path, replacement):
    for key in path[:-1]: value = value[key]
    value[path[-1]] = replacement


@pytest.mark.parametrize('path,value,reason', [
    (('extra',), True, 'schema_contract_fields_or_version_invalid'),
    (('version',), True, 'schema_contract_fields_or_version_invalid'),
    (('version',), False, 'schema_contract_fields_or_version_invalid'),
    (('version',), 1.0, 'schema_contract_fields_or_version_invalid'),
    (('version',), '1', 'schema_contract_fields_or_version_invalid'),
    (('algorithm',), 'unknown', 'schema_contract_fields_or_version_invalid'),
    (('source_sha256',), 'A'*64, 'schema_contract_digest_required'),
    (('target_shape_sha256',), None, 'schema_contract_digest_required'),
    (('environment_sha256',), '0'*65, 'schema_contract_digest_required'),
    (('schema_source',), None, 'schema_contract_provenance_required'),
    (('schema_source',), {}, 'schema_contract_provenance_required'),
    (('schema_source', 'base_commit'), 'HEAD', 'schema_contract_digest_required'),
    (('schema_source', 'combination_sha256'), True, 'schema_contract_digest_required'),
    (('tables',), None, 'schema_contract_table_budget_or_format_invalid'),
    (('tables',), (), 'schema_contract_table_budget_or_format_invalid'),
    (('tables',), [], 'schema_contract_table_budget_or_format_invalid'),
    (('tables',), [{}]*101, 'schema_contract_table_budget_or_format_invalid'),
    (('tables',), [None], 'schema_contract_table_fields_invalid'),
    (('tables',), [{}], 'schema_contract_table_fields_invalid'),
    (('tables', 0, 'table'), 'Bad', 'unsupported_schema_identifier'),
    (('tables', 0, 'facets'), {}, 'schema_contract_duplicate_table_or_facets_invalid'),
    (('tables', 0, 'facets', 'columns'), '', 'schema_contract_digest_required'),
])
def test_contract_exact_rejection_reason(path, value, reason):
    data = document()
    set_path(data, path, value)
    with pytest.raises(GuardFailure) as error: contract.validate_contract(data)
    assert str(error.value) == reason


@pytest.mark.parametrize('first,second,reason', [
    ((('version',), True), (('source_sha256',), ''), 'schema_contract_fields_or_version_invalid'),
    ((('source_sha256',), ''), (('schema_source',), {}), 'schema_contract_digest_required'),
    ((('environment_sha256',), ''), (('tables',), []), 'schema_contract_digest_required'),
    ((('schema_source', 'base_commit'), ''), (('tables',), []), 'schema_contract_digest_required'),
    ((('tables', 0, 'table'), 'Bad'), (('tables', 0, 'facets'), {}), 'unsupported_schema_identifier'),
])
def test_contract_first_failure_precedence(first, second, reason):
    data = document()
    for path, value in (first, second): set_path(data, path, value)
    with pytest.raises(GuardFailure) as error: contract.validate_contract(data)
    assert str(error.value) == reason


@pytest.mark.parametrize('count', (1, 100))
def test_contract_alias_and_order_preserved_at_table_budget_endpoints(count):
    data = document()
    data['tables'] = [dict(table='t'+str(i), facets=copy.deepcopy(data['tables'][0]['facets'])) for i in reversed(range(count))]
    prior = copy.deepcopy(data)
    assert contract.validate_contract(data) is data and data == prior
    assert data['tables'][0]['table'] == 't'+str(count-1)


def test_duplicate_contract_table_precedes_its_bad_facet_digest():
    data = document()
    data['tables'].append(copy.deepcopy(data['tables'][0]))
    data['tables'][1]['facets']['columns'] = ''
    with pytest.raises(GuardFailure, match='schema_contract_duplicate_table_or_facets_invalid'):
        contract.validate_contract(data)


def native_record(facet):
    defaults = dict(s='x', i=0, b=False, n=None, l=None)
    value = {key: defaults[kind] for key, kind in records.FIELDS[facet].items()}
    if facet == 'columns':
        value.update(name='id', position=1, type_schema='pg_catalog', type='text', identity='', generated='')
    if facet == 'constraints':
        value.update(name='fk_parent', type='f', parent_schema='public', parent_table='parents',
            match_type='s', on_update='a', on_delete='a', child_columns=['id'], parent_columns=['id'], equality_operators=['pg_catalog.='])
    if facet == 'indexes': value.update(name='idx_id', method='btree', valid=True, ready=True, live=True, key_columns=1, all_columns=1)
    if facet == 'collations': value.update(column='id', schema='pg_catalog', name='default', provider='c', deterministic=True)
    if facet == 'sequences': value.update(column='seq', schema='public', name='audit_seq', dependency='a', type_schema='pg_catalog', type='int8', start=1, increment=1, minimum=1, maximum=9223372036854775807, cache=1)
    if facet == 'hazards': value.update(persistence='p', access_method='heap')
    return value


@pytest.mark.parametrize('facet', tuple(records.FIELDS))
def test_each_native_facet_returns_original_records_without_mutation(facet):
    value = [native_record(facet)]
    prior = copy.deepcopy(value)
    assert records.validate_records(facet, value) is value and value == prior


@pytest.mark.parametrize('facet,value', [('columns', []), ('columns', [{}]*81),
    ('hazards', []), ('hazards', [{}, {}]), ('constraints', [{}]*257),
    ('columns', None), ('indexes', ())])
def test_record_budget_precedes_grammar(facet, value):
    with pytest.raises(GuardFailure, match='schema_facet_record_budget_or_coverage_invalid'):
        records.validate_records(facet, value)


@pytest.mark.parametrize('facet,field,value,reason', [
    ('columns', 'extra', True, 'schema_wire_record_fields_invalid'),
    ('columns', 'not_null', 1, 'schema_wire_record_type_or_budget_invalid'),
    ('columns', 'position', True, 'schema_wire_record_type_or_budget_invalid'),
    ('columns', 'position', 1 << 63, 'schema_wire_record_type_or_budget_invalid'),
    ('columns', 'type', 'x'*4097, 'schema_wire_record_type_or_budget_invalid'),
    ('columns', 'type', '\ud800', 'schema_wire_utf8_invalid'),
    ('columns', 'name', 'Bad', 'unsupported_schema_identifier'),
    ('columns', 'type_schema', 'public', 'schema_column_type_identity_or_generated_unsupported'),
    ('columns', 'identity', 'a', 'schema_column_type_identity_or_generated_unsupported'),
    ('columns', 'generated', 's', 'schema_column_type_identity_or_generated_unsupported'),
    ('indexes', 'valid', False, 'schema_index_not_ready_or_valid'),
    ('indexes', 'ready', False, 'schema_index_not_ready_or_valid'),
    ('indexes', 'live', False, 'schema_index_not_ready_or_valid'),
    ('indexes', 'options', ['x']*257, 'schema_wire_record_type_or_budget_invalid'),
    ('indexes', 'options', [None], 'schema_wire_record_type_or_budget_invalid'),
    ('hazards', 'persistence', 'u', 'schema_relation_behavior_unsupported'),
    ('hazards', 'access_method', 'other', 'schema_relation_behavior_unsupported'),
    ('hazards', 'user_triggers', 1, 'schema_relation_behavior_unsupported'),
    ('hazards', 'rules', 1, 'schema_relation_behavior_unsupported'),
    ('hazards', 'inheritance_edges', 1, 'schema_relation_behavior_unsupported'),
    ('hazards', 'policies', 1, 'schema_relation_behavior_unsupported'),
    ('collations', 'actual_version', '', 'schema_collation_version_drift'),
])
def test_wire_grammar_names_and_native_support_reasons(facet, field, value, reason):
    record = native_record(facet); record[field] = value
    with pytest.raises(GuardFailure) as error: records.validate_records(facet, [record])
    assert str(error.value) == reason


@pytest.mark.parametrize('facet', ('columns', 'constraints', 'indexes', 'collations', 'sequences'))
def test_duplicate_record_name_precedes_unsupported_semantics(facet):
    first, second = native_record(facet), native_record(facet)
    if facet == 'columns': second['identity'] = 'a'
    if facet == 'indexes': second['valid'] = False
    if facet == 'collations': second['actual_version'] = 'changed'
    with pytest.raises(GuardFailure, match='schema_facet_duplicate_record'):
        records.validate_records(facet, [first, second])


def test_grammar_precedes_name_and_native_support():
    record = native_record('columns')
    record.update(name='Bad', not_null=1, identity='a')
    with pytest.raises(GuardFailure, match='schema_wire_record_type_or_budget_invalid'):
        records.validate_records('columns', [record])
    record['not_null'] = True
    with pytest.raises(GuardFailure, match='unsupported_schema_identifier'):
        records.validate_records('columns', [record])


@pytest.mark.parametrize('facet,count', [('columns', 80), ('constraints', 256), ('indexes', 256), ('collations', 256), ('sequences', 256)])
def test_exact_facet_record_budget_endpoints(facet, count):
    key = 'column' if facet in ('collations', 'sequences') else 'name'
    data = [dict(native_record(facet), **{key:'c'+str(i)}) for i in range(count)]
    assert records.validate_records(facet, data) is data


def test_scalar_utf8_byte_budget_is_not_character_count():
    value = native_record('columns')
    value['default_expression'] = 'é'*2048
    assert records.validate_records('columns', [value]) == [value]
    value['default_expression'] += 'é'
    with pytest.raises(GuardFailure, match='schema_wire_record_type_or_budget_invalid'):
        records.validate_records('columns', [value])


def test_unknown_low_level_empty_facet_does_not_bypass_public_frame_guard():
    value = []
    assert records.validate_records('unknown', value) is value
    with pytest.raises(KeyError): records.validate_records('unknown', [{}])
    with pytest.raises(GuardFailure, match='schema_facet_frame_fields_or_coverage_invalid'):
        records.facet_evidence(dict(kind='facet', facet='unknown', tables=[]), [])


@pytest.mark.parametrize('match,delete,update', list(itertools.product(('s', 'f'), ('a', 'r', 'c', 'n', 'd'), ('a', 'r', 'c', 'n', 'd'))))
def test_all_existing_match_action_combinations_remain_supported(match, delete, update):
    value = fk(); value.update(match_type=match, on_delete=delete, on_update=update)
    prior = copy.deepcopy(value)
    assert declared.validate_foreign_key('children', value, shapes()) is None and value == prior
    sql = declared.foreign_key_sql('children', value)
    assert 'public."parents"' in sql and 'OPERATOR(pg_catalog.=)' in sql
    assert ('IS NULL' in sql) is (match == 'f')


@pytest.mark.parametrize('field,value,reason', [
    ('parent_schema', 'other', 'declared_fk_parent_scope_unsupported'),
    ('parent_table', 'missing', 'declared_fk_parent_scope_unsupported'),
    ('child_columns', (), 'declared_fk_column_arity_unsupported'),
    ('child_columns', [], 'declared_fk_column_arity_unsupported'),
    ('parent_columns', ['id'], 'declared_fk_column_arity_unsupported'),
    ('child_columns', ['id', 'id'], 'declared_fk_duplicate_columns'),
    ('parent_columns', ['id', 'id'], 'declared_fk_duplicate_columns'),
    ('child_columns', ['missing', 'id'], 'declared_fk_columns_missing'),
    ('equality_operators', ['public.=', 'pg_catalog.='], 'declared_fk_operator_or_match_unsupported'),
    ('match_type', 'p', 'declared_fk_operator_or_match_unsupported'),
    ('on_delete', 'unknown', 'declared_fk_action_unsupported'),
    ('on_update', 'unknown', 'declared_fk_action_unsupported'),
    ('name', 'Bad', 'unsupported_schema_identifier'),
])
def test_fk_scoped_columns_operators_actions_and_name_reasons(field, value, reason):
    record = fk(); record[field] = value
    with pytest.raises(GuardFailure) as error: declared.validate_foreign_key('children', record, shapes())
    assert str(error.value) == reason


def test_fk_first_failure_order_and_short_circuit_mapping_access():
    value = fk()
    value.update(parent_schema='other', child_columns=[], equality_operators=[], on_delete='unknown', name='Bad')
    with pytest.raises(GuardFailure, match='declared_fk_parent_scope_unsupported'):
        declared.validate_foreign_key('children', value, shapes())
    value['parent_schema'] = 'public'
    with pytest.raises(GuardFailure, match='declared_fk_column_arity_unsupported'):
        declared.validate_foreign_key('children', value, shapes())
    value['child_columns'] = ['tenant', 'id']
    with pytest.raises(GuardFailure, match='declared_fk_operator_or_match_unsupported'):
        declared.validate_foreign_key('children', value, shapes())
    value['equality_operators'] = ['pg_catalog.=']*2
    value.pop('on_update')
    with pytest.raises(GuardFailure, match='declared_fk_action_unsupported'):
        declared.validate_foreign_key('children', value, shapes())


def test_absent_and_not_valid_fk_evidence_never_certifies_business_relations():
    absent = declared.relationship_evidence([])
    assert absent['result'] == 'not_executed' and absent['reason'] == 'no_declared_foreign_keys'
    for validated, violations in itertools.product((False, True), (0, 1)):
        result = declared.relationship_evidence([dict(table='children', constraint='tenant_parent', validated=validated, scanned_rows=2, violations=violations)])
        assert result['result'] == ('passed' if validated and not violations else 'failed')
        assert result['all_business_relationships_verified'] is False
        expected = ([] if not violations else ['target_declared_fk_violations']) + ([] if validated else ['target_declared_fk_not_validated'])
        assert [b['code'] for b in result['blockers']] == expected
