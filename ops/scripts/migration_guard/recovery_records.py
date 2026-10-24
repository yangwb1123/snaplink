"""Strict bounded native-PG checkpoint records; no inferred recovery facts."""
from .conversion_policy import SHAPE_FIELDS
from .row_digest import ALGORITHM
from .schema_contract import digest_required
from .schema_sql import FACETS
from .sequence import sequence_evidence
from .snapshot import GuardFailure, MAX_ROWS, MAX_SCAN_BYTES, identifier


def integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise GuardFailure('recovery_checkpoint_count_or_budget_invalid')


def column_shape(columns, keys):
    if not isinstance(columns, list) or not 1 <= len(columns) <= 80:
        raise GuardFailure('recovery_checkpoint_columns_invalid')
    names, positions = [], []
    for column in columns:
        if not isinstance(column, dict) or set(column) != set(SHAPE_FIELDS):
            raise GuardFailure('recovery_checkpoint_column_fields_invalid')
        identifier(column['name'])
        if column['type'] not in ('text','int2','int4','int8','float8','bytea') or type(column['not_null']) is not bool:
            raise GuardFailure('recovery_checkpoint_column_type_invalid')
        integer(column['pk_order'], 80)
        names.append(column['name'])
        if column['pk_order']:
            positions.append((column['pk_order'], column['name']))
    positions.sort()
    if names != sorted(set(names)) or not positions or [p for p,n in positions] != list(range(1,len(positions)+1)) or keys != [n for p,n in positions]:
        raise GuardFailure('recovery_checkpoint_columns_or_primary_keys_invalid')


def content_records(data):
    if not isinstance(data, dict) or set(data) != {'algorithm','tables','rows','scanned_bytes'} or data['algorithm'] != ALGORITHM:
        raise GuardFailure('recovery_checkpoint_content_fields_invalid')
    if not isinstance(data['tables'], list) or not 1 <= len(data['tables']) <= 100:
        raise GuardFailure('recovery_checkpoint_table_budget_invalid')
    rows, scanned, names = 0, 0, []
    for table in data['tables']:
        fields = {'table','rows','scanned_bytes','projected_columns','primary_key_columns','primary_key_set_sha256','projected_content_sha256'}
        if not isinstance(table, dict) or set(table) != fields:
            raise GuardFailure('recovery_checkpoint_table_fields_invalid')
        identifier(table['table'])
        column_shape(table['projected_columns'], table['primary_key_columns'])
        integer(table['rows'], MAX_ROWS)
        integer(table['scanned_bytes'], MAX_SCAN_BYTES)
        digest_required(table['primary_key_set_sha256'])
        digest_required(table['projected_content_sha256'])
        rows, scanned = rows + table['rows'], scanned + table['scanned_bytes']
        names.append(table['table'])
    integer(data['rows'], MAX_ROWS)
    integer(data['scanned_bytes'], MAX_SCAN_BYTES)
    if names != sorted(set(names)) or (rows,scanned) != (data['rows'],data['scanned_bytes']):
        raise GuardFailure('recovery_checkpoint_coverage_or_totals_invalid')
    return set(names)


def schema_records(data, names):
    if not isinstance(data, dict) or set(data) != {'environment_sha256','tables'}:
        raise GuardFailure('recovery_checkpoint_schema_fields_invalid')
    digest_required(data['environment_sha256'])
    if not isinstance(data['tables'], dict) or set(data['tables']) != names:
        raise GuardFailure('recovery_checkpoint_schema_coverage_invalid')
    for name, table in data['tables'].items():
        if not isinstance(table, dict) or set(table) != {'facets','counts'}:
            raise GuardFailure('recovery_checkpoint_schema_table_invalid')
        if not isinstance(table['facets'], dict) or not isinstance(table['counts'], dict) or set(table['facets']) != set(FACETS) or set(table['counts']) != set(FACETS):
            raise GuardFailure('recovery_checkpoint_facets_invalid')
        for facet in FACETS:
            digest_required(table['facets'][facet])
            integer(table['counts'][facet], 256)
        if table['counts']['sequences'] != int(name == 'audit_events'):
            raise GuardFailure('recovery_other_sequences_unsupported')
    if 'audit_events' not in names:
        raise GuardFailure('recovery_audit_table_required')


def audit_records(data):
    if not isinstance(data, dict) or set(data) != {'descriptor','state'}:
        raise GuardFailure('recovery_checkpoint_audit_fields_invalid')
    sequence_evidence(data['descriptor'], data['state'], 1)
