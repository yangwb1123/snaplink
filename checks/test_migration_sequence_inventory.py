"""Read-only complete supported sequence inventory and data-derived next floors."""
import copy
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard.snapshot import GuardFailure
from migration_guard.sequence_inventory_records import validate_inventory, floor_evidence


def descriptor(kind='int8',name='audit_events_seq_seq',table='audit_events',column='seq',oid=100):
    maximum={'int2':32767,'int4':2147483647,'int8':9223372036854775807}[kind]
    return dict(oid=oid,schema='public',name=name,type_namespace='pg_catalog',type=kind,start=1,increment=1,minimum=1,maximum=maximum,cache=1,cycle=False,
        owner_count=1,table_schema='public',table=table,column=column,dependency='a',relation_oid=200,relkind='r',rls_enabled=False,force_rls=False,
        column_type_namespace='pg_catalog',column_type=kind,not_null=True,column_identity='',default_matches=True,default_dependents=1,other_dependents=0,other_dependencies=0)


def target_for(items):
    tables={}
    for d in items:
        t=tables.setdefault(d['table'],dict(table=d['table'],relkind='r',rls_enabled=False,force_rls=False,metadata_only=False,columns=[]))
        t['columns'].append(dict(name=d['column'],type=d['type'],type_namespace='pg_catalog',not_null=True,pk_order=0))
    return dict(tables=list(tables.values()))


def bounds(rows=0,minimum=None,maximum=None):
    return dict(rows=rows,nulls=0,minimum=None if minimum is None else str(minimum),maximum=None if maximum is None else str(maximum))


def test_fresh_audit_still_blocks_retained_source_floor():
    d=descriptor()
    assert validate_inventory([d],target_for([d]))==[d]
    evidence=floor_evidence(d,dict(last_value='1',is_called=False),bounds(),9591)
    assert evidence['result']=='failed' and evidence['next_candidate']==1 and evidence['required_next_floor']==9591


def test_existing_target_rows_raise_floor_independent_of_source():
    d=descriptor()
    evidence=floor_evidence(d,dict(last_value='7',is_called=True),bounds(1,100,100),1)
    assert evidence['result']=='failed' and evidence['required_next_floor']==101


@pytest.mark.parametrize('kind',['int2','int4','int8'])
@pytest.mark.parametrize('last,called,maximum',[(1,False,None),(1,True,1),(7,True,7),(9007199254740993,True,9007199254740993)])
def test_supported_typed_serial_floors(kind,last,called,maximum):
    d=descriptor(kind,name='other_seq',table='business_state',column='counter')
    if last>d['maximum']:
        with pytest.raises(GuardFailure):
            floor_evidence(d,dict(last_value=str(last),is_called=called),bounds(),1)
        return
    result=floor_evidence(d,dict(last_value=str(last),is_called=called),bounds() if maximum is None else bounds(1,maximum,maximum),1)
    assert result['result']=='passed' and result['next_candidate']==last+int(called)
    assert result['required_next_floor']==1 if maximum is None else result['required_next_floor']==maximum+1


@pytest.mark.parametrize('field,value',[
    ('schema','other'),('schema','pg_catalog'),('schema','information_schema'),('type_namespace','other'),('type','numeric'),('type',[]),('start',2),('increment',2),('increment',-1),('minimum',0),('maximum',100),('cache',2),('cycle',True),
    ('owner_count',0),('owner_count',2),('table_schema','other'),('dependency','i'),('dependency','n'),('relkind','p'),('rls_enabled',True),('force_rls',True),
    ('column_type_namespace','spoof'),('column_type','text'),('not_null',False),('column_identity','a'),('default_matches',False),('default_dependents',0),('default_dependents',2),
    ('other_dependents',1),('other_dependencies',1),('oid',True),('oid',0),('relation_oid',1.0),('cache',True),('owner_count',1.0),('cycle',0),('name',"evil';select 1"),('column',None)])
def test_unsupported_descriptor_rejected(field,value):
    d=descriptor();target=target_for([d]);d[field]=value
    with pytest.raises(GuardFailure): validate_inventory([d],target)


@pytest.mark.parametrize('items',[None,[],[None],list(range(101))])
def test_incomplete_or_unbounded_inventory_rejected(items):
    with pytest.raises(GuardFailure): validate_inventory(items,target_for([descriptor()]))


def test_inventory_coverage_duplicates_order_and_missing_audit_reject():
    d=descriptor();other=descriptor('int4','z_seq','business_state','counter',101);target=target_for([d,other])
    assert len(validate_inventory([d,other],target))==2
    for items in ([other],[other,d],[d,d],[d,dict(other,oid=d['oid'])],[d,dict(other,table=d['table'],column=d['column'])],[dict(d,unknown=True)],[dict(d,table='absent')]):
        with pytest.raises(GuardFailure): validate_inventory(items,target)


@pytest.mark.parametrize('state',[None,{},dict(last_value='1',is_called=1),dict(last_value=1,is_called=False),dict(last_value='01',is_called=False),dict(last_value='-0',is_called=False),dict(last_value='0',is_called=False),dict(last_value='9223372036854775808',is_called=True)])
def test_bad_state_rejects(state):
    with pytest.raises(GuardFailure): floor_evidence(descriptor(),state,bounds(),1)


@pytest.mark.parametrize('data',[None,{},bounds(True),bounds(200001),dict(rows=1,nulls=1,minimum=None,maximum=None),bounds(0,1,1),bounds(1,None,None),bounds(1,0,1),bounds(1,3,2),bounds(1,1,9223372036854775808),dict(rows=1,nulls=False,minimum='1',maximum='1')])
def test_bad_counts_or_bounds_reject(data):
    with pytest.raises(GuardFailure): floor_evidence(descriptor(),dict(last_value='1',is_called=False),data,1)


@pytest.mark.parametrize('kind',['int2','int4','int8'])
@pytest.mark.parametrize('called',[False,True])
def test_exhaustion_is_explicit_and_never_wraps(kind,called):
    d=descriptor(kind,table='business_state',column='counter')
    result=floor_evidence(d,dict(last_value=str(d['maximum']),is_called=called),bounds(1,d['maximum'],d['maximum']),1)
    assert result['result']=='failed' and result['blockers'][0]['code']=='sequence_inventory_exhausted'


@pytest.mark.parametrize('floor',[True,0,-1,1.0,None,9223372036854775808])
def test_invalid_source_floor_rejects(floor):
    with pytest.raises(GuardFailure): floor_evidence(descriptor(),dict(last_value='1',is_called=False),bounds(),floor)
