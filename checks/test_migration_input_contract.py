"""Refactor-only guards: admission ordering and shape evidence never authorize writes."""
import ast
import copy
import inspect
import itertools
from pathlib import Path
from types import SimpleNamespace

import pytest

from checks.migration_policy_fixture import policy_document, policy_fixture
from migration_guard import cli, compare as comparison, conversion_policy as policy
from migration_guard.snapshot import GuardFailure

MODULES = (cli, comparison, policy)
MODE_NAMES = ('row_evidence', 'verify_target_content', 'verify_target_schema', 'verify_target_sequences')
POLICY_REASONS = ('row_evidence_requires_conversion_policy', 'target_content_requires_conversion_policy',
                  'target_schema_requires_conversion_policy', 'target_sequences_requires_conversion_policy')
MODE_CASES = list(itertools.product((False, True), repeat=4))


def conservative_complexity(node):
    nodes = list(ast.walk(node))
    branches = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.IfExp, ast.comprehension)
    return 1 + sum(isinstance(n, branches) for n in nodes) + sum(len(n.values)-1 for n in nodes if isinstance(n, ast.BoolOp))


FUNCTIONS = [(module, node.name) for module in MODULES
             for node in ast.parse(Path(module.__file__).read_text()).body if isinstance(node, ast.FunctionDef)]


@pytest.mark.parametrize('module,name', FUNCTIONS, ids=[m.__name__+'.'+n for m, n in FUNCTIONS])
def test_input_owner_complexity(module, name):
    # Supplementary AST metric, not the committed Go cyclomatic/release authority.
    node = ast.parse(inspect.getsource(getattr(module, name))).body[0]
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


def dependency_reason(flags, has_policy, contract_file, contract_digest):
    if not has_policy:
        for enabled, reason in reversed(list(zip(flags, POLICY_REASONS))):
            if enabled:
                return reason
    if flags[2] and (contract_file is None or contract_digest is None):
        return 'target_schema_requires_pinned_contract'
    if not flags[2] and (contract_file is not None or contract_digest is not None):
        return 'schema_contract_requires_schema_mode'
    return None


@pytest.mark.parametrize('flags', MODE_CASES)
@pytest.mark.parametrize('has_policy', (False, True))
@pytest.mark.parametrize('contract_file,contract_digest', ((None, None), ('contract', None), (None, 'digest'), ('contract', 'digest')))
def test_mode_dependencies_before_load_and_original_priority(monkeypatch, flags, has_policy, contract_file, contract_digest):
    args = SimpleNamespace(**dict(zip(MODE_NAMES, flags)), conversion_policy_file='policy' if has_policy else None,
                           schema_contract_file=contract_file, schema_contract_sha256=contract_digest)
    calls = []
    policy_value, contract_value = object(), object()
    def load_policy(path):
        calls.append(('policy', path))
        return policy_value
    def load_contract(path, digest):
        calls.append(('contract', path, digest))
        return contract_value
    monkeypatch.setattr(cli, 'load_policy', load_policy)
    monkeypatch.setattr(cli, 'load_contract', load_contract)
    reason = dependency_reason(flags, has_policy, contract_file, contract_digest)
    if reason:
        with pytest.raises(GuardFailure) as error:
            cli.mode_inputs(args)
        assert str(error.value) == reason and calls == []
        return
    assert cli.mode_inputs(args) == (policy_value if has_policy else None, contract_value if flags[2] else None)
    expected = [('policy', 'policy')] if has_policy else []
    if flags[2]:
        expected.append(('contract', contract_file, contract_digest))
    assert calls == expected


def test_empty_paths_are_not_absence_and_policy_load_failure_stops_contract(monkeypatch):
    args = SimpleNamespace(**dict.fromkeys(MODE_NAMES, False), conversion_policy_file='', schema_contract_file='', schema_contract_sha256='')
    args.verify_target_schema = True
    calls = []
    def fail_policy(path):
        calls.append(path)
        raise GuardFailure('synthetic_invalid_private_policy')
    monkeypatch.setattr(cli, 'load_policy', fail_policy)
    monkeypatch.setattr(cli, 'load_contract', lambda *a: pytest.fail('contract contacted after invalid policy'))
    with pytest.raises(GuardFailure, match='synthetic_invalid_private_policy'):
        cli.mode_inputs(args)
    assert calls == ['']


PURPOSES = (
    ('preflight', 'read_only_snapshot_and_catalog_preflight', {}),
    ('verify_content', 'read_only_shape_for_content_verification', dict(target_content_verified=False, content_verification_required=True)),
    ('verify_schema', 'read_only_shape_for_schema_verification', dict(target_content_verified=False, target_schema_contract_matched=False, schema_verification_required=True)),
    ('verify_sequences', 'read_only_shape_for_sequence_inventory', dict(target_content_verified=False, sequence_inventory_verification_required=True)),
)


@pytest.mark.parametrize('purpose,scope,extra', PURPOSES)
def test_shape_report_exact_fields_and_metadata_order(tmp_path, purpose, scope, extra):
    _, source, target = policy_fixture(tmp_path)
    source['tables'].extend(dict(table=name, metadata_only=True) for name in ('schema_migrations_z', 'schema_migrations_a'))
    target['tables'].append(dict(table='schema_migrations_pg', metadata_only=True, columns=[], rows=1))
    document = policy_document(source, target)
    report = comparison.compare(source, target, document, purpose=purpose)
    expected = dict(result='passed', scope=scope, source_business_tables=2, source_business_rows=9,
                    target_business_tables=2, blockers=[], source=source, target=target,
                    source_metadata_tables=['schema_migrations_z', 'schema_migrations_a'],
                    source_schema_history_must_not_overwrite_postgres_history=True,
                    runtime_semantics_certified=False, audit_chain_verified=False,
                    content_copied_or_target_changed=False, cutover_authorized=False,
                    missing_empty_tables_are_not_exempt=True,
                    future_range_collation_defaults_indexes_fk_and_topology_require_separate_acceptance=True,
                    conversion_plan=policy.conversion_plan(source, target, document), **extra)
    assert report == expected and report['source'] is source and report['target'] is target


@pytest.mark.parametrize('purpose,reason', (('bogus', 'unsupported_comparison_purpose'),
    ('verify_content', 'content_verification_explicit_policy_required'), ('verify_schema', 'schema_verification_explicit_policy_required'),
    ('verify_sequences', 'sequence_verification_explicit_policy_required')))
def test_purpose_rejects_before_planning_or_accessing_catalog(monkeypatch, purpose, reason):
    monkeypatch.setattr(comparison, 'conversion_plan', lambda *a: pytest.fail('planner contacted'))
    with pytest.raises(GuardFailure) as error:
        comparison.compare({}, {}, None, purpose=purpose)
    assert str(error.value) == reason


def test_blocker_order_and_empty_target_admission_are_not_changed(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    source['tables'].append(dict(source['tables'][0], table='absent'))
    target['tables'].append(dict(target['tables'][0], table='unexpected'))
    target['tables'][0]['rows'] = 1
    document = policy_document(source, target)
    expected = [dict(code='source_business_table_missing_in_target', table='absent'),
                dict(code='target_only_business_table_requires_policy', table='unexpected'),
                dict(code='target_business_table_not_empty', table='audit_events')]
    assert comparison.compare(source, target, document)['blockers'] == expected
    for purpose, _, _ in PURPOSES[1:]:
        report = comparison.compare(source, target, document, purpose=purpose)
        assert report['blockers'] == expected[:2] and report['result'] == 'failed'
        assert report['target_content_verified'] is False and report['cutover_authorized'] is False


@pytest.mark.parametrize('version', (True, False, 0, 2, '1', 1.0, None))
def test_document_version_is_exact_integer(tmp_path, version):
    _, source, target = policy_fixture(tmp_path)
    document = policy_document(source, target)
    document['version'] = version
    with pytest.raises(GuardFailure, match='unsupported_conversion_policy_version'):
        policy.validate_document(document)


@pytest.mark.parametrize('mappings,reason', (
    (None, 'bounded_nonempty_mapping_list_required'), ((), 'bounded_nonempty_mapping_list_required'),
    ([], 'bounded_nonempty_mapping_list_required'), ([{}, {}, {}], 'bounded_nonempty_mapping_list_required'),
    ([{}], 'unknown_or_missing_mapping_field'), ([None], 'unknown_or_missing_mapping_field'),
    ([dict(table=[], column='seq', mode='sqlite_rowid_int8_v1')], 'mapping_fields_must_be_strings'),
    ([dict(table='audit_events', column='seq', mode='unsupported')], 'unsupported_or_duplicate_mapping'),
    ([dict(table='audit_events', column='seq', mode='sqlite_rowid_int8_v1')]*2, 'unsupported_or_duplicate_mapping'),
))
def test_mapping_entry_rejections_and_order(tmp_path, mappings, reason):
    _, source, target = policy_fixture(tmp_path)
    document = policy_document(source, target)
    document['mappings'] = mappings
    with pytest.raises(GuardFailure) as error:
        policy.validate_document(document)
    assert str(error.value) == reason


def test_document_checks_precede_entries_and_preserve_object(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    document = policy_document(source, target)
    assert policy.validate_document(document) is document
    bad = dict(document, mappings=[None], source_sha256='A'*64)
    with pytest.raises(GuardFailure, match='conversion_policy_digest_required'):
        policy.validate_document(bad)
    bad['version'] = True
    with pytest.raises(GuardFailure, match='unsupported_conversion_policy_version'):
        policy.validate_document(bad)
    bad['unknown'] = True
    with pytest.raises(GuardFailure, match='unknown_or_missing_policy_field'):
        policy.validate_document(bad)


def test_audit_native_shape_rejections_precede_proof(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    left, right = source['tables'][0], target['tables'][0]
    left['audit_rowid'] = {}
    left['columns'][0]['pk_order'] = 0
    left['columns'].append(dict(name='seq'))
    right['columns'][-1]['type'] = 'int4'
    with pytest.raises(GuardFailure, match='seq_target_shape_invalid'):
        policy.audit_plan(left, right)
    right['columns'][-1]['type'] = 'int8'
    with pytest.raises(GuardFailure, match='source_seq_cannot_be_replaced'):
        policy.audit_plan(left, right)
    left['columns'].pop()
    with pytest.raises(GuardFailure, match='audit_source_id_shape_invalid'):
        policy.audit_plan(left, right)
    left['columns'][0]['pk_order'] = 1
    with pytest.raises(GuardFailure, match='source_rowid_evidence_required'):
        policy.audit_plan(left, right)


@pytest.mark.parametrize('low,high', ((True, 99), (7, False), ('7', 99), (7, 99.0), (0, 99), (7, 6), (7, policy.MAX_INT8)))
def test_audit_floor_rejects_nonnative_nonpositive_and_exhausted_rowids(tmp_path, low, high):
    _, source, target = policy_fixture(tmp_path)
    source['tables'][0]['audit_rowid'].update(min=low, max=high)
    with pytest.raises(GuardFailure, match='source_rowid_range_unsupported'):
        policy.audit_plan(source['tables'][0], target['tables'][0])


@pytest.mark.parametrize('rows,low,high,floor', ((0, None, None, 1), (3, 7, 99, 100), (3, 7, policy.MAX_INT8-1, policy.MAX_INT8)))
def test_exact_audit_floor_and_false_mutation_claims(tmp_path, rows, low, high, floor):
    _, source, target = policy_fixture(tmp_path)
    left = copy.deepcopy(source['tables'][0])
    left['rows'] = rows
    left['audit_rowid'].update(rows=rows, min=low, max=high)
    result = policy.audit_plan(left, target['tables'][0])
    assert result == dict(table='audit_events', column='seq', mode='sqlite_rowid_int8_v1', rows=rows,
                          source_rowid_min=low, source_rowid_max=high, rowid_and_id_sha256=left['audit_rowid']['rowid_and_id_sha256'],
                          required_next_seq_floor=floor, sequence_reset_executed=False, historical_fields_rewritten=False)
    if rows == 0:
        left['audit_rowid']['max'] = 0
        with pytest.raises(GuardFailure, match='empty_source_rowid_evidence_invalid'):
            policy.audit_plan(left, target['tables'][0])
