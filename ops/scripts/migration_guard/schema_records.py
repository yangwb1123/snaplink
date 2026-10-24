"""Strict bounded wire record grammar and supported-native-schema guardrails."""
from .schema_contract import schema_fingerprint
from .schema_sql import FACETS
from .snapshot import GuardFailure, identifier

FIELDS = {
 "columns": dict(name='s',position='i',type_schema='s',type='s',typmod='i',not_null='b',identity='s',generated='s',default_expression='n',collation_schema='n',collation='n'),
 "constraints": dict(name='s',type='s',definition='s',validated='b',deferrable='b',initially_deferred='b',parent_schema='n',parent_table='n',match_type='s',on_update='s',on_delete='s',child_columns='l',parent_columns='l',equality_operators='l'),
 "indexes": dict(name='s',method='s',unique_index='b',primary_index='b',valid='b',ready='b',live='b',nulls_not_distinct='b',key_columns='i',all_columns='i',definition='s',predicate='n',expressions='n',opclasses='l',options='l'),
 "collations": dict(column='s',schema='s',name='s',provider='s',deterministic='b',encoding='i',collate='n',ctype='n',icu_locale='n',recorded_version='n',actual_version='n'),
 "sequences": dict(column='s',schema='s',name='s',dependency='s',type_schema='s',type='s',start='i',increment='i',maximum='i',minimum='i',cache='i',cycle='b'),
 "hazards": dict(persistence='s',access_method='s',options='l',user_triggers='i',rules='i',inheritance_edges='i',policies='i',dropped_columns='i'),
}
ENVIRONMENT = dict(server_version_num='i',encoding='s',collate='s',ctype='s',provider='s',icu_locale='n',recorded_version='n',actual_version='n')


def scalar(value, kind):
    if kind in ('s', 'n'):
        return (kind == 'n' and value is None) or (isinstance(value, str) and len(value.encode('utf-8', errors='strict')) <= 4096)
    if kind == 'i':
        return type(value) is int and -(1 << 63) <= value < (1 << 63)
    if kind == 'b':
        return type(value) is bool
    return value is None or (isinstance(value, list) and len(value) <= 256 and all(scalar(v, 's') for v in value))


def record_fields(record, fields):
    if not isinstance(record, dict) or set(record) != set(fields):
        raise GuardFailure("schema_wire_record_fields_invalid")
    try:
        if not all(scalar(record[key], kind) for key, kind in fields.items()):
            raise GuardFailure("schema_wire_record_type_or_budget_invalid")
    except UnicodeError as exc:
        raise GuardFailure("schema_wire_utf8_invalid") from exc


def validate_record_name(facet, record, names):
    key = record['column'] if facet in ('collations', 'sequences') else record.get('name')
    if key is not None:
        identifier(key)
        if key in names:
            raise GuardFailure("schema_facet_duplicate_record")
        names.add(key)


def validate_record_support(facet, record):
    if facet == 'columns' and (record['type_schema'] != 'pg_catalog' or record['identity'] or record['generated']):
        raise GuardFailure("schema_column_type_identity_or_generated_unsupported")
    if facet == 'indexes' and not all(record[k] is True for k in ('valid', 'ready', 'live')):
        raise GuardFailure("schema_index_not_ready_or_valid")
    if facet == 'hazards' and (record['persistence'] != 'p' or record['access_method'] != 'heap' or any(record[k] for k in ('user_triggers', 'rules', 'inheritance_edges', 'policies'))):
        raise GuardFailure("schema_relation_behavior_unsupported")
    if facet == 'collations' and record['recorded_version'] != record['actual_version']:
        raise GuardFailure("schema_collation_version_drift")


def validate_records(facet, records):
    if not isinstance(records, list) or len(records) > 256 or (facet == 'hazards' and len(records) != 1) or (facet == 'columns' and not 1 <= len(records) <= 80):
        raise GuardFailure("schema_facet_record_budget_or_coverage_invalid")
    names = set()
    for record in records:
        record_fields(record, FIELDS[facet])
        validate_record_name(facet, record, names)
        validate_record_support(facet, record)
    return records


def environment_evidence(value):
    record_fields(value, ENVIRONMENT)
    if value['server_version_num'] // 10000 not in (15, 16) or value['encoding'] != 'UTF8':
        raise GuardFailure("schema_environment_version_or_encoding_unsupported")
    if value['recorded_version'] != value['actual_version']:
        raise GuardFailure("schema_database_collation_version_drift")
    return schema_fingerprint('', 'environment', [value])


def facet_evidence(frame, names):
    if set(frame) != {'kind', 'facet', 'tables'} or not isinstance(frame['facet'], str) or frame['facet'] not in FACETS or not isinstance(frame['tables'], list) or len(frame['tables']) != len(names):
        raise GuardFailure("schema_facet_frame_fields_or_coverage_invalid")
    result = {}
    for table in frame['tables']:
        if not isinstance(table, dict) or set(table) != {'table', 'records'} or not isinstance(table['table'], str) or table['table'] not in names or table['table'] in result:
            raise GuardFailure("schema_facet_table_coverage_invalid")
        records = validate_records(frame['facet'], table['records'])
        result[table['table']] = dict(sha256=schema_fingerprint(table['table'], frame['facet'], records), records=records)
    return result
