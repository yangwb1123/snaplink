"""Admission, frame ordering, complete subprocess observations and drift rechecks."""
import copy
import time
import pytest
from checks.test_migration_sequence_inventory import descriptor,target_for,bounds
from checks.migration_policy_fixture import policy_fixture,policy_document
from migration_guard import sequence_inventory as mod
from migration_guard.snapshot import GuardFailure


class Stream:
    def __init__(self): self.sent=[]
    def send(self,sql,final=False): self.sent.append((sql,final))


def reader(tmp_path):
    _,source,target=policy_fixture(tmp_path)
    config=dict(database='owned',user='role',owner_token='0'*48)
    r=mod.SequenceReader(config,source,policy_document(source,target),100);s=Stream()
    r.accept(dict(kind='identity',database='owned',user='role',owned=True,read_only='on',isolation='repeatable read',version='fixture'),s)
    items=[]
    for table in target['tables']:
        columns=[dict({k:c[k] for k in ('name','type','not_null','pk_order')},type_namespace='pg_catalog') for c in table['columns']]
        t=dict(table=table['table'],columns=columns,relkind='r',rls_enabled=False,force_rls=False)
        items.append(t)
    r.accept(dict(kind='catalog',tables=items),s)
    return r,s


def state(d,last='1',called=False):
    return dict(kind='sequence_state',sequence=d['name'],oid=str(d['oid']),last_value=last,is_called=called)


def test_catalog_inventory_precede_any_state_or_bounds_read(tmp_path):
    r,s=reader(tmp_path)
    assert r.stage=='inventory' and len(s.sent)==1 and 'sequence_inventory' in s.sent[0][0] and 'last_value' not in s.sent[0][0]
    d=descriptor();r.accept(dict(kind='sequence_inventory',items=[d]),s)
    assert r.stage=='observations' and s.sent[-1][1] is True and 'last_value' in s.sent[-1][0]
    r.accept(state(d),s);r.accept(dict(kind='sequence_bounds',sequence=d['name'],**bounds()),s)
    r.accept(dict(kind='complete',read_only='on',isolation='repeatable read'),s)
    assert r.stage=='complete' and r.evidence[0]['required_next_floor']==100
    assert next(t for t in r.target['tables'] if t['table']=='permissions_resources')['rows'] is None
    assert r.target['counts_tracked_for_sequence_owner_tables_only'] is True


@pytest.mark.parametrize('mutation',['schema','cache','default_matches','owner_count'])
def test_unsupported_inventory_sends_no_state_queries(tmp_path,mutation):
    r,s=reader(tmp_path);d=descriptor();d[mutation]={'schema':'outside','cache':2,'default_matches':False,'owner_count':0}[mutation]
    with pytest.raises(GuardFailure): r.accept(dict(kind='sequence_inventory',items=[d]),s)
    assert len(s.sent)==1


@pytest.mark.parametrize('bad',[None,{},dict(kind='complete',read_only='on',isolation='repeatable read'),dict(kind='sequence_state',sequence='wrong',oid='100',last_value='1',is_called=False),dict(kind='sequence_bounds',sequence='audit_events_seq_seq',**bounds())])
def test_bad_or_incomplete_first_observation_rejects(tmp_path,bad):
    r,s=reader(tmp_path);r.accept(dict(kind='sequence_inventory',items=[descriptor()]),s)
    with pytest.raises(GuardFailure): r.accept(bad,s)


@pytest.mark.parametrize('complete',[dict(kind='complete',read_only='off',isolation='repeatable read'),dict(kind='complete',read_only='on',isolation='read committed'),dict(kind='complete',read_only='on',isolation='repeatable read',extra=True)])
def test_false_snapshot_completion_rejects(tmp_path,complete):
    r,s=reader(tmp_path);d=descriptor();r.accept(dict(kind='sequence_inventory',items=[d]),s)
    r.accept(state(d),s);r.accept(dict(kind='sequence_bounds',sequence=d['name'],**bounds()),s)
    with pytest.raises(GuardFailure): r.accept(complete,s)


@pytest.mark.parametrize('timeout',[True,False,0,-1,61,float('nan'),float('inf'),'60',None])
def test_invalid_windows_reject_before_target_contact(monkeypatch,timeout):
    monkeypatch.setattr(mod,'connection_file',lambda *a:pytest.fail('target contact'))
    with pytest.raises(GuardFailure,match='sequence_inventory_timeout_invalid'):
        mod.verify_sequences(None,None,None,None,None,timeout)


@pytest.mark.parametrize('drift',['oid','state','catalog_boolean_alias'])
def test_recheck_detects_catalog_or_state_drift(tmp_path,monkeypatch,drift):
    r,s=reader(tmp_path);d=descriptor();r.accept(dict(kind='sequence_inventory',items=[d]),s)
    r.accept(state(d),s);r.accept(dict(kind='sequence_bounds',sequence=d['name'],**bounds()),s)
    monkeypatch.setattr(mod,'verify_target_identity',lambda *a:None)
    def query(config,sql,timeout):
        if sql==mod.INVENTORY_SQL:
            fresh=copy.deepcopy(r.items)
            if drift=='oid': fresh[0]['oid']+=1
            if drift=='catalog_boolean_alias': fresh[0]['cycle']=0
            return fresh
        return dict(sequence=d['name'],oid=str(d['oid']),last_value='2' if drift=='state' else '1',is_called=False)
    monkeypatch.setattr(mod,'query_json',query)
    with pytest.raises(GuardFailure): mod.recheck(r.config,r,time.monotonic()+60)


def test_recheck_identity_receives_remaining_deadline(tmp_path,monkeypatch):
    r,s=reader(tmp_path);r.accept(dict(kind='sequence_inventory',items=[descriptor()]),s)
    calls=[]
    monkeypatch.setattr(mod,'verify_target_identity',lambda config,timeout:calls.append(timeout))
    monkeypatch.setattr(mod,'query_json',lambda *a:[])  # Complete catalog cannot become an empty PASS.
    with pytest.raises(GuardFailure): mod.recheck(r.config,r,time.monotonic()+0.5)
    assert 0<calls[0]<=0.5


@pytest.mark.parametrize('failure',['missing_completion','child_nonzero_after_complete'])
def test_complete_frames_and_successful_exit_both_required(tmp_path,monkeypatch,failure):
    from migration_guard.conversion_policy import target_shape_sha256
    path,source,target=policy_fixture(tmp_path);config=dict(database='owned',user='role',owner_token='0'*48)
    policy=policy_document(source,target);tables=[]
    for table in target['tables']:
        columns=[dict({k:c[k] for k in ('name','type','not_null','pk_order')},type_namespace='pg_catalog') for c in table['columns']]
        tables.append(dict(table=table['table'],columns=columns,relkind='r',rls_enabled=False,force_rls=False))
    class Fake:
        def __init__(self,*a,**kw): self.sent=[]
        def send(self,*a,**kw): self.sent.append(a)
        def close(self): pass
        def __iter__(self):
            yield dict(kind='identity',database='owned',user='role',owned=True,read_only='on',isolation='repeatable read',version='fixture')
            yield dict(kind='catalog',tables=tables)
            yield dict(kind='sequence_inventory',items=[descriptor()])
            yield state(descriptor())
            yield dict(kind='sequence_bounds',sequence=descriptor()['name'],**bounds())
            if failure=='child_nonzero_after_complete':
                yield dict(kind='complete',read_only='on',isolation='repeatable read')
                raise GuardFailure('target_content_query_failed_diagnostics_withheld')
    monkeypatch.setattr(mod,'connection_file',lambda *a:config)
    monkeypatch.setattr(mod,'psql_command',lambda *a:([],{}))
    monkeypatch.setattr(mod,'PsqlStream',Fake)
    monkeypatch.setattr(mod,'recheck',lambda *a:pytest.fail('incomplete child accepted'))
    with pytest.raises(GuardFailure): mod.verify_sequences(path,None,source,target,policy)


def test_same_table_owner_counts_must_match_and_total_remains_bounded():
    r=mod.SequenceReader({},None,None,1);a=descriptor();b=descriptor(name='z_seq',column='other',oid=101)
    r.items=[a,b];r.target=target_for([a,b]);r.target['tables'][0]['rows']=None;r.stage='observations';s=Stream()
    r.accept(state(a),s);r.accept(dict(kind='sequence_bounds',sequence=a['name'],**bounds(1,1,1)),s)
    r.accept(state(b),s)
    with pytest.raises(GuardFailure,match='sequence_inventory_owner_table_count_drift'):
        r.accept(dict(kind='sequence_bounds',sequence=b['name'],**bounds(2,1,1)),s)
    r=mod.SequenceReader({},None,None,1);r.items=[a,b];r.target=target_for([a,b]);r.target['tables'][0]['rows']=None;r.stage='observations'
    r.accept(state(a),s);r.accept(dict(kind='sequence_bounds',sequence=a['name'],**bounds(200000,1,1)),s);r.accept(state(b),s)
    with pytest.raises(GuardFailure,match='sequence_inventory_total_scan_budget_exceeded'):
        r.accept(dict(kind='sequence_bounds',sequence=b['name'],**bounds(200000,1,1)),s)


def test_sequence_inventory_implementation_stays_within_function_complexity_budget():
    import ast
    from pathlib import Path
    for name in ('sequence_inventory.py','sequence_inventory_records.py','sequence_inventory_sql.py'):
        path=Path(mod.__file__).with_name(name)
        tree=ast.parse(path.read_text())
        assert len(path.read_text().splitlines())<=500
        for function in (n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef)):
            assert function.end_lineno-function.lineno+1<=50
            complexity=1
            for node in ast.walk(function):
                if isinstance(node,(ast.If,ast.For,ast.While,ast.IfExp,ast.comprehension,ast.ExceptHandler)):
                    complexity+=1
                elif isinstance(node,ast.BoolOp):
                    complexity+=len(node.values)-1
            assert complexity<=15,(name,function.name,complexity)
