"""Explicit new client policies; zero is not inferred historical authorization."""
from .snapshot import GuardFailure

CLIENT_MODE = 'client_policy_zero_v1'
CLIENT_COLUMNS = {'allow_passwordless_only': 'int4', 'consent_refresh_interval': 'int8', 'skip_consent': 'int4'}
CLIENT_MODES = {('clients', column): CLIENT_MODE for column in CLIENT_COLUMNS}


def policy_version(document):
    version, entries = document['version'], document['mappings']
    if type(version) is int and version == 1:
        return 1
    if (type(version) is int and version == 2 and isinstance(entries, list) and 1 <= len(entries) <= 5
            and any(isinstance(entry, dict) and entry.get('mode') == CLIENT_MODE for entry in entries)):
        return 2
    raise GuardFailure('unsupported_conversion_policy_version')


def client_policy_plan(source, target, column):
    if source['table'] != 'clients' or target['table'] != 'clients' or column not in CLIENT_COLUMNS:
        raise GuardFailure('client_policy_mapping_unsupported')
    if any(c['name'] == column for c in source['columns']):
        raise GuardFailure('client_policy_source_column_present')
    value = next((c for c in target['columns'] if c['name'] == column), {})
    shape = tuple(value.get(k) for k in ('type', 'type_namespace', 'not_null', 'pk_order'))
    if (shape != (CLIENT_COLUMNS[column], 'pg_catalog', True, 0) or type(value.get('pk_order')) is not int
            or value.get('not_null') is not True or value.get('canonical_zero_default') is not True):
        raise GuardFailure('client_policy_target_shape_invalid')
    return dict(table='clients', column=column, mode=CLIENT_MODE, rows=source['rows'], value=0,
                origin='explicit_new_client_policy_default', source_column_present=False,
                canonical_zero_default_verified=True, historical_fields_rewritten=False, inferred_from_attributes=False)


def client_default_values(source, target, mappings):
    result = {}
    for entry in mappings:
        if entry['mode'] != CLIENT_MODE or entry['table'] != source['table']:
            continue
        plan = client_policy_plan(source, target, entry['column'])
        if entry['column'] in result:
            raise GuardFailure('unsupported_or_duplicate_mapping')
        if 'value' in entry and (type(entry['value']) is not int or entry['value'] != 0):
            raise GuardFailure('client_policy_literal_invalid')
        result[entry['column']] = plan['value']
    return result


def validate_client_defaults(source, target, mappings):
    selected = [entry for entry in mappings if entry['mode'] == CLIENT_MODE]
    if not selected:
        return
    if len(selected) > 3 or any(entry['table'] != 'clients' for entry in selected):
        raise GuardFailure('client_policy_mapping_unsupported')
    left = next((t for t in source['tables'] if t['table'] == 'clients' and not t['metadata_only']), None)
    right = next((t for t in target['tables'] if t['table'] == 'clients' and not t['metadata_only']), None)
    if left is None or right is None:
        raise GuardFailure('mapping_source_and_target_table_required')
    client_default_values(left, right, selected)
