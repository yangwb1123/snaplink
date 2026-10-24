"""Native facets are explicit expectations, not self-approved candidate schema."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from checks.test_migration_row_projection import fixture
from checks.migration_guard_fixture import private_config, connection_config
from checks.test_migration_schema_contract import private_contract
from migration_guard import target_schema as schema
from migration_guard.schema_contract import schema_fingerprint
from migration_guard.schema_records import environment_evidence, validate_records
from migration_guard.schema_sql import FACETS
from migration_guard.source_relations import source_foreign_keys
from migration_guard.snapshot import GuardFailure


def column(c,pos):
    return dict(name=c['name'],position=pos,type_schema='pg_catalog',type=c['type'],typmod=-1,
        not_null=c['not_null'],identity='',generated='',default_expression=None,collation_schema=None,collation=None)


def fake_frames(target):
    yield dict(kind='identity',database='snaplink_mig_test',user='schema_test',owned=True,read_only='on',isolation='repeatable read',version='16 synthetic')
    yield dict(kind='catalog',tables=[dict(table=t['table'],relkind='r',rls_enabled=False,force_rls=False,
        columns=[{k:c[k] for k in ('name','type','type_namespace','not_null','pk_order')} for c in t['columns']]) for t in target['tables']])
    yield dict(kind='environment',value=dict(server_version_num=160014,encoding='UTF8',collate='C',ctype='C',provider='c',icu_locale=None,recorded_version=None,actual_version=None))
    for facet in FACETS:
        tables=[]
        for table in target['tables']:
            records=[]
            if facet=='columns': records=[column(c,pos) for pos,c in enumerate(table['columns'],1)]
            if facet=='hazards': records=[dict(persistence='p',access_method='heap',options=None,user_triggers=0,rules=0,inheritance_edges=0,policies=0,dropped_columns=0)]
            tables.append(dict(table=table['table'],records=records))
        yield dict(kind='facet',facet=facet,tables=tables)
    yield dict(kind='complete',read_only='on',isolation='repeatable read')


def setup(root,monkeypatch,mutate=None):
    path,source,target,policy=fixture(root)
    for table in target['tables']:
        for c in table['columns']: c['type_namespace']='pg_catalog'
    connection=private_config(root,dict(connection_config(),database='snaplink_mig_test',user='schema_test'));frames=list(fake_frames(target))
    fingerprints={t['table']:{f:schema_fingerprint(t['table'],f,next(g for g in packet['tables'] if g['table']==t['table'])['records'])
        for f,packet in [(p['facet'],p) for p in frames if p['kind']=='facet']} for t in target['tables']}
    contract=dict(version=1,algorithm='pg_native_schema_facets_v1',source_sha256=source['sha256'],target_shape_sha256=policy['target_shape_sha256'],
        schema_source=dict(base_commit='a'*40,combination_sha256='b'*64),environment_sha256=environment_evidence(frames[2]['value']),
        tables=[dict(table=t,facets=facets) for t,facets in fingerprints.items()])
    if mutate: mutate(frames)
    scripts=[]
    class Fake:
        def __init__(self,*args,**kwargs): pass
        def send(self,text,final=False): scripts.append((text,final))
        def __iter__(self): return iter(frames)
        def close(self): pass
    monkeypatch.setattr(schema,'PsqlStream',Fake)
    return path,connection,source,target,policy,contract,scripts


def test_all_facets_checked_without_content_or_relationship_claim(tmp_path,monkeypatch):
    args=setup(tmp_path,monkeypatch)
    result=schema.verify_schema(*args[:6])
    assert result['result']=='passed' and result['target_schema_contract_matched']
    assert result['declared_foreign_keys']['result']=='not_executed'
    assert all(result[k] is False for k in ['full_ddl_certified','all_business_relationships_verified','target_content_verified','writer_fencing_verified','cutover_authorized','schema_baseline_provenance_verified'])
    assert all(t['rows'] is None for t in result['target_snapshot']['tables'])
    assert result['target_snapshot']['table_counts_not_collected_in_schema_snapshot']
    assert len(args[-1])==3 and args[-1][-1][1]
    assert 'default_expression' not in json.dumps(result)
    assert source_foreign_keys(args[0],args[2])['result']=='not_executed'


@pytest.mark.parametrize('failure',['default','environment','hazard_options','sequence'])
def test_facet_or_environment_mismatch_is_not_shape_pass(tmp_path,monkeypatch,failure):
    def mutate(data):
        if failure=='environment': data[2]['value']['ctype']='different'
        if failure=='default': data[3]['tables'][0]['records'][0]['default_expression']="'do-not-expose-default'::text"
        if failure=='hazard_options': data[-2]['tables'][0]['records'][0]['options']=['fillfactor=70']
        if failure=='sequence':
            next(p for p in data if p.get('facet')=='sequences')['tables'][0]['records']=[dict(column='seq',schema='public',name='audit_seq',dependency='a',type_schema='pg_catalog',type='int8',start=1,increment=1,minimum=1,maximum=9223372036854775807,cache=1,cycle=False)]
    args=setup(tmp_path,monkeypatch,mutate);report=schema.verify_schema(*args[:6])
    assert report['result']=='failed' and not report['target_schema_contract_matched']
    assert 'do-not-expose-default' not in json.dumps(report)


@pytest.mark.parametrize('failure',['truncate','extra','duplicate','bad_bool','rls','order','namespace','trigger','collation_version'])
def test_bad_native_stream_fails_closed(tmp_path,monkeypatch,failure):
    def mutate(data):
        if failure=='truncate': data.pop()
        if failure=='extra': data.append(dict(kind='extra'))
        if failure=='duplicate': data[3]['tables'][0]['records']*=2
        if failure=='bad_bool': data[3]['tables'][0]['records'][0]['not_null']=1
        if failure=='rls': data[1]['tables'][0]['rls_enabled']=True
        if failure=='order': data[3],data[4]=data[4],data[3]
        if failure=='namespace': data[3]['tables'][0]['records'][0]['type_schema']='hostile'
        if failure=='trigger': data[-2]['tables'][0]['records'][0]['user_triggers']=1
        if failure=='collation_version': data[2]['value']['actual_version']='unrecorded'
    args=setup(tmp_path,monkeypatch,mutate)
    with pytest.raises(GuardFailure): schema.verify_schema(*args[:6])


def test_cli_schema_keeps_content_unknown_and_sequence_gate(tmp_path,monkeypatch):
    from migration_guard import cli
    args=setup(tmp_path,monkeypatch)
    policy=tmp_path/'policy.json';policy.write_text(json.dumps(args[4]));policy.chmod(0o600)
    contract,sha=private_contract(tmp_path,args[5])
    monkeypatch.setattr(cli,'inspect_target',lambda *unused: args[3])
    monkeypatch.setattr(cli,'inspect_audit_sequence',lambda *unused: dict(result='failed',blockers=[dict(code='audit_sequence_below_required_floor')]))
    argv=['--snapshot',str(args[0]),'--snapshot-sha256',args[2]['sha256'],'--target-connection-file',str(args[1]),
          '--report',str(tmp_path/'report.json'),'--conversion-policy-file',str(policy),
          '--verify-target-schema','--schema-contract-file',str(contract),'--schema-contract-sha256',sha]
    assert cli.main(argv)==1
    report=json.loads((tmp_path/'report.json').read_text())
    assert report['schema_verification']['result']=='passed' and report['target_schema_contract_matched']
    assert report['target_content_verified'] is False and report['cutover_authorized'] is False
    assert report['source_declared_foreign_keys']['result']=='not_executed'
    assert len(report['blockers'])==1


def test_late_source_sha_change_is_rejected(tmp_path,monkeypatch):
    args=setup(tmp_path,monkeypatch)
    def tampered(*unused,**kwargs):
        args[0].write_bytes(args[0].read_bytes()+b'x')
        return dict(target_snapshot=args[3],environment_sha256=args[5]['environment_sha256'],
            tables={t['table']:dict(facets=t['facets']) for t in args[5]['tables']},declared_foreign_keys=dict(blockers=[]))
    monkeypatch.setattr(schema,'inspect_native_schema',tampered)
    with pytest.raises(GuardFailure,match='snapshot_sha256_mismatch'): schema.verify_schema(*args[:6])


def test_contract_binding_and_cli_precontact_constraints(tmp_path,monkeypatch,capsys):
    from migration_guard import cli
    args=setup(tmp_path,monkeypatch)
    contract=copy.deepcopy(args[5]);contract['source_sha256']='0'*64
    with pytest.raises(GuardFailure,match='source_or_shape'): schema.verify_schema(*args[:5],contract)
    monkeypatch.setattr(cli,'inspect_target',lambda *args: pytest.fail('must reject before target contact'))
    argv=['--snapshot',str(args[0]),'--snapshot-sha256',args[2]['sha256'],'--target-connection-file',str(args[1]),'--report',str(tmp_path/'report.json'),'--verify-target-schema']
    assert cli.main(argv)==1 and 'target_schema_requires_conversion_policy' in capsys.readouterr().err
    policy=tmp_path/'policy.json';policy.write_text(json.dumps(args[4]));policy.chmod(0o600)
    assert cli.main(argv+['--conversion-policy-file',str(policy)])==1
    assert 'target_schema_requires_pinned_contract' in capsys.readouterr().err
    path,sha=private_contract(tmp_path,args[5])
    assert cli.main(argv+['--conversion-policy-file',str(policy),'--schema-contract-file',str(path),'--schema-contract-sha256','0'*64])==1
    assert 'schema_contract_sha256_mismatch' in capsys.readouterr().err
    with pytest.raises(SystemExit) as error: cli.main(argv+['--verify-target-content'])
    assert error.value.code==2
