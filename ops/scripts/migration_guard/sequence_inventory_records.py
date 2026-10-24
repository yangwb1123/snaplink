"""Supported positive canonical serials only; inventory completeness is not fencing."""
import re
from .snapshot import GuardFailure, MAX_ROWS, identifier

MAXIMA = dict(int2=32767,int4=2147483647,int8=9223372036854775807)
FIELDS = {'oid','schema','name','type_namespace','type','start','increment','minimum','maximum','cache','cycle','owner_count','table_schema','table','column','dependency','relation_oid','relkind','rls_enabled','force_rls','column_type_namespace','column_type','not_null','column_identity','default_matches','default_dependents','other_dependents','other_dependencies'}


def descriptor_shape(data, target):
    if not isinstance(data,dict) or set(data)!=FIELDS:
        raise GuardFailure('sequence_inventory_descriptor_fields_invalid')
    for key in ('schema','name','table_schema','table','column'):
        identifier(data[key])
    if not isinstance(data['type'],str) or data['type'] not in MAXIMA:
        raise GuardFailure('sequence_inventory_type_unsupported')
    expected=dict(schema='public',type_namespace='pg_catalog',start=1,increment=1,minimum=1,maximum=MAXIMA[data['type']],cache=1,cycle=False,owner_count=1,
        table_schema='public',dependency='a',relkind='r',rls_enabled=False,force_rls=False,column_type_namespace='pg_catalog',column_type=data['type'],
        not_null=True,column_identity='',default_matches=True,default_dependents=1,other_dependents=0,other_dependencies=0)
    if any(type(data[k]) is not type(v) or data[k]!=v for k,v in expected.items()):
        raise GuardFailure('sequence_inventory_configuration_or_dependency_unsupported')
    if any(type(data[k]) is not int or not 1 <= data[k] <= 4294967295 for k in ('oid','relation_oid')):
        raise GuardFailure('sequence_inventory_catalog_identity_invalid')
    validate_locked_owner(data,target)
    if data['table']=='audit_events' and data['column']=='seq' and data['type']!='int8':
        raise GuardFailure('sequence_inventory_audit_bigserial_required')
    return data


def validate_locked_owner(data,target):
    table=next((t for t in target['tables'] if t['table']==data['table']),None)
    column=next((c for c in table['columns'] if c['name']==data['column']),None) if table else None
    if table is None or column is None:
        raise GuardFailure('sequence_inventory_owner_not_in_locked_catalog')
    table_fields=dict(relkind='r',rls_enabled=False,force_rls=False)
    column_fields=dict(type_namespace='pg_catalog',type=data['type'],not_null=True)
    for actual,fields in ((table,table_fields),(column,column_fields)):
        if any(type(actual[k]) is not type(v) or actual[k]!=v for k,v in fields.items()):
            raise GuardFailure('sequence_inventory_owner_not_in_locked_catalog')


def validate_inventory(items, target):
    if not isinstance(items,list) or not 1 <= len(items) <= 100:
        raise GuardFailure('sequence_inventory_empty_or_budget_invalid')
    names,oids,owners=[],set(),set()
    for item in items:
        descriptor_shape(item,target)
        names.append((item['schema'],item['name']))
        owner=(item['table'],item['column'])
        if item['oid'] in oids or owner in owners:
            raise GuardFailure('sequence_inventory_duplicate_identity_or_owner')
        oids.add(item['oid']);owners.add(owner)
    if names!=sorted(set(names)):
        raise GuardFailure('sequence_inventory_duplicate_or_order_invalid')
    if ('audit_events','seq') not in owners:
        raise GuardFailure('sequence_inventory_audit_bigserial_required')
    return items


def decimal(value, minimum, maximum):
    if not isinstance(value,str) or len(value)>20 or not re.fullmatch(r'0|-?[1-9][0-9]*',value):
        raise GuardFailure('sequence_inventory_exact_integer_required')
    number=int(value)
    if not minimum <= number <= maximum:
        raise GuardFailure('sequence_inventory_integer_outside_range')
    return number


def validate_state(data, descriptor):
    if not isinstance(data,dict) or set(data)!={'last_value','is_called'} or type(data['is_called']) is not bool:
        raise GuardFailure('sequence_inventory_state_invalid')
    return dict(last_value=decimal(data['last_value'],1,descriptor['maximum']),is_called=data['is_called'])


def column_bounds(data, descriptor):
    if not isinstance(data,dict) or set(data)!={'rows','nulls','minimum','maximum'}:
        raise GuardFailure('sequence_inventory_bounds_fields_invalid')
    if type(data['rows']) is not int or not 0 <= data['rows'] <= MAX_ROWS or type(data['nulls']) is not int or data['nulls']!=0:
        raise GuardFailure('sequence_inventory_bounds_count_or_budget_invalid')
    if data['rows']==0:
        if data['minimum'] is not None or data['maximum'] is not None:
            raise GuardFailure('sequence_inventory_empty_bounds_invalid')
        return dict(data)
    minimum=decimal(data['minimum'],1,descriptor['maximum']);maximum=decimal(data['maximum'],minimum,descriptor['maximum'])
    return dict(data,minimum=minimum,maximum=maximum)


def floor_evidence(descriptor, state, bounds, audit_floor):
    if type(audit_floor) is not int or not 1 <= audit_floor <= MAXIMA['int8']:
        raise GuardFailure('sequence_inventory_source_audit_floor_invalid')
    state=validate_state(state,descriptor);bounds=column_bounds(bounds,descriptor)
    source_floor=audit_floor if (descriptor['table'],descriptor['column'])==('audit_events','seq') else 1
    observed_floor=1 if bounds['maximum'] is None else bounds['maximum']+1
    required=max(source_floor,observed_floor);candidate=state['last_value']+int(state['is_called'])
    issues=[]
    if candidate>descriptor['maximum'] or required>descriptor['maximum']:
        issues.append(dict(code='sequence_inventory_exhausted',table=descriptor['table'],column=descriptor['column']))
    elif candidate<required:
        issues.append(dict(code='sequence_inventory_below_required_floor',table=descriptor['table'],column=descriptor['column']))
    return dict(result='failed' if issues else 'passed',blockers=issues,
                descriptor={k:v for k,v in descriptor.items() if k not in ('oid','relation_oid')},state=state,owner_column_bounds=bounds,
                next_candidate=candidate,source_required_floor=source_floor,required_next_floor=required)
