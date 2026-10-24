"""Finite TEMP-only client projection for an explicitly pinned read-only observer."""
import hashlib

from .client_policy_defaults import client_default_values
from .compare import business_tables, compare
from .snapshot import GuardFailure, identifier


def column_names(table):
    columns = table.get('columns', [])
    if not isinstance(columns, list) or not 1 <= len(columns) <= 80:
        raise GuardFailure('client_read_projection_columns_invalid')
    names = [column.get('name') for column in columns]
    for name in names:
        identifier(name)
        if len(name) > 63:
            raise GuardFailure('client_read_projection_columns_invalid')
    if len(set(names)) != len(names):
        raise GuardFailure('client_read_projection_columns_invalid')
    return sorted(names)


def client_read_projection(source, target, policy):
    report = compare(source, target, policy, purpose='verify_content')
    if report['result'] != 'passed':
        raise GuardFailure('client_read_projection_complete_shape_required')
    if policy['version'] != 2:
        raise GuardFailure('client_read_projection_explicit_v2_required')
    left, right = business_tables(source).get('clients'), business_tables(target).get('clients')
    if left is None or right is None:
        raise GuardFailure('client_read_projection_clients_required')
    defaults = client_default_values(left, right, report['conversion_plan']['mappings'])
    if not defaults:
        raise GuardFailure('client_read_projection_selected_zeros_required')
    original, columns = column_names(left), column_names(right)
    if set(original) | set(defaults) != set(columns) or set(original) & set(defaults):
        raise GuardFailure('client_read_projection_coverage_invalid')
    expressions = [('0 AS ' if name in defaults else '') + identifier(name) for name in columns]
    sql = 'CREATE TEMP VIEW "clients" AS SELECT ' + ','.join(expressions) + ' FROM main."clients";'
    if len(sql.encode()) > 16 << 10:
        raise GuardFailure('client_read_projection_sql_budget_exceeded')
    return dict(version=1, algorithm='readonly_sqlite_client_view_v1',
                source_sha256=source['sha256'], target_shape_sha256=policy['target_shape_sha256'],
                policy_content_sha256=report['conversion_plan']['policy_content_sha256'],
                source_columns=original, view_columns=columns, zero_columns=sorted(defaults),
                sql=sql, sql_sha256=hashlib.sha256(sql.encode()).hexdigest(),
                main_source_modified=False, historical_policy_inferred=False,
                target_schema_or_runtime_certified=False, import_or_cutover_authorized=False)
