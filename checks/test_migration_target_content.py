"""Complete content/PK comparison is explicit; malformed evidence never passes."""
from contextlib import closing
import json
import sqlite3

import pytest

from checks.test_migration_row_projection import fixture
from checks.migration_guard_fixture import connection_config,private_config
from migration_guard.snapshot import GuardFailure,canonical
from migration_guard.compare import compare
from migration_guard import row_projection
from migration_guard import target_content as content


def frames(path,source,target):
    yield dict(kind='identity',database='snaplink_mig_synthetic',user='fixture',owned=True,
               read_only='on',isolation='repeatable read',version='synthetic transport, not an engine')
    yield dict(kind='catalog',tables=[dict(table=t['table'],relkind='r',rls_enabled=False,force_rls=False,columns=[
        {key:c[key] for key in ('name','type','type_namespace','not_null','pk_order')}
        for c in t['columns']]) for t in target['tables']])
    with closing(sqlite3.connect(path)) as db:
        for table in sorted(target['tables'],key=lambda t:t['table']):
            if table['metadata_only']:
                continue
            yield dict(kind='table_start',table=table['table'])
            src=next(t for t in source['tables'] if t['table']==table['table'])
            columns=sorted(table['columns'],key=lambda c:c['name'])
            for row in row_projection.projected_rows(db,src,table,[
                dict(table='audit_events',column='seq',mode='sqlite_rowid_int8_v1'),
                dict(table='permissions_resources',column='dispatch_key',mode='text_utf8_bytea_v1')]):
                yield dict(kind='row',values=[canonical(row[c['name']]) for c in columns])
            yield dict(kind='table_end',table=table['table'])
    yield dict(kind='complete',read_only='on',isolation='repeatable read')


def setup(root,monkeypatch,mutate=lambda data:data):
    path,source,target,policy=fixture(root)
    for table in target['tables']:
        for col in table['columns']:
            col['type_namespace']='pg_catalog'
    connection=private_config(root,connection_config())
    data=list(frames(path,source,target))
    scripts=[]
    class Stream:
        def __init__(self,*args,**kwargs): pass
        def send(self,script,final=False): scripts.append(script)
        def __iter__(self): return iter(mutate(data))
        def close(self): pass
    monkeypatch.setattr(content,'PsqlStream',Stream)
    return path,connection,source,target,policy,scripts


def test_explicit_content_mode_accepts_rows_without_weakening_preflight(tmp_path,monkeypatch):
    path,conn,source,target,policy,scripts=setup(tmp_path,monkeypatch)
    target['tables'][0]['rows']=3
    assert compare(source,target,policy)['result']=='failed'
    report=content.verify_content(path,conn,source,target,policy)
    assert report['result']=='passed' and report['target_content_verified']
    assert report['target_projection']['rows']==12
    assert report['target_projection']['tables']==report['source_projection']['tables']
    assert not report['cutover_authorized'] and not report['writer_fencing_verified']
    assert 'synthetic-private-value' not in json.dumps(report)
    assert 'REPEATABLE READ READ ONLY' in scripts[0]
    assert 'public."business_state"' in scripts[1]
    assert all('::jsonb' in statement for sql in scripts for statement in sql.split(';') if statement.strip().startswith('SELECT json_build_object'))


@pytest.mark.parametrize('change,expected', [
    ('value','target_projected_content_mismatch'),('key','target_primary_key_set_mismatch'),
    ('missing','target_row_count_mismatch'),('extra','target_row_count_mismatch')])
def test_same_counts_cannot_hide_changed_value_or_pk(tmp_path,monkeypatch,change,expected):
    def mutate(data):
        indexes=[i for i,f in enumerate(data) if f['kind']=='row']
        first=indexes[0]
        if change=='missing': data.pop(first)
        elif change=='extra':
            row=json.loads(json.dumps(data[first]))
            row['values'][1]=['text','extra-audit-id']
            data.insert(first,row)
        else:
            row=data[first]['values']
            row[1 if change=='key' else 0]=['text','corrupt-value']
        return data
    args=setup(tmp_path,monkeypatch,mutate)
    report=content.verify_content(*args[:5])
    assert report['result']=='failed' and not report['target_content_verified']
    assert expected in {b['code'] for b in report['blockers']}


@pytest.mark.parametrize('failure',['owner','isolation','missing_table','shape','duplicate','null_pk','truncated','extra_frame','rls','partition','bad_kind'])
def test_incomplete_wrong_or_ambiguous_stream_fails_closed(tmp_path,monkeypatch,failure):
    def mutate(data):
        if failure=='owner': data[0]['owned']=False
        elif failure=='isolation': data[0]['isolation']='read committed'
        elif failure=='missing_table': data[1]['tables']=data[1]['tables'][:-1]
        elif failure=='shape': data[1]['tables'][0]['columns'][0]['type']='bytea'
        elif failure=='truncated': data.pop()
        elif failure=='extra_frame': data.append(dict(kind='unexpected'))
        elif failure=='rls': data[1]['tables'][0]['rls_enabled']=True
        elif failure=='partition': data[1]['tables'][0]['relkind']='p'
        elif failure=='bad_kind': data[-1]['kind']=[]
        else:
            index=next(i for i,f in enumerate(data) if f['kind']=='row')
            if failure=='duplicate': data.insert(index,data[index])
            else: data[index]['values'][1]=['null']
        return data
    args=setup(tmp_path,monkeypatch,mutate)
    with pytest.raises(GuardFailure): content.verify_content(*args[:5])


@pytest.mark.parametrize('budget',['rows','bytes','window'])
def test_target_projection_budget_is_closed(tmp_path,monkeypatch,budget):
    args=setup(tmp_path,monkeypatch)
    if budget=='rows': monkeypatch.setattr(content,'MAX_ROWS',1)
    if budget=='bytes': monkeypatch.setattr(content,'MAX_SCAN_BYTES',1)
    with pytest.raises(GuardFailure,match='budget|window'):
        content.verify_content(*args[:5],timeout=0 if budget=='window' else 60)


def test_cli_content_verification_is_explicit_and_preserves_no_cutover_claim(tmp_path,monkeypatch):
    from migration_guard import cli
    from checks.migration_policy_fixture import private_policy
    path,conn,source,target,policy,_=setup(tmp_path,monkeypatch)
    target['tables'][0]['rows']=3
    monkeypatch.setattr(cli,'inspect_target',lambda *args: target)
    monkeypatch.setattr(cli,'inspect_audit_sequence',lambda connection,floor: dict(result='passed',blockers=[],required_next_seq_floor=floor))
    policy_path=private_policy(tmp_path,policy)
    argv=['--snapshot',str(path),'--snapshot-sha256',source['sha256'],
          '--target-connection-file',str(conn),'--report',str(tmp_path/'report.json'),
          '--conversion-policy-file',str(policy_path),'--verify-target-content']
    assert cli.main(argv)==0
    report=json.loads((tmp_path/'report.json').read_text())
    assert report['target_content_verified'] and report['target']['counts_tracked_for_business_tables_only']
    assert report['audit_sequence']['required_next_seq_floor']==100
    for flag in ('cutover_authorized','audit_chain_verified','content_copied_or_target_changed','runtime_semantics_certified'):
        assert report[flag] is False


def test_cli_content_policy_required_before_any_target_contact(tmp_path,monkeypatch,capsys):
    from migration_guard import cli
    path,source,target,policy=fixture(tmp_path)
    monkeypatch.setattr(cli,'inspect_target',lambda *args: pytest.fail('must not contact target'))
    argv=['--snapshot',str(path),'--snapshot-sha256',source['sha256'],
          '--target-connection-file','unused','--report',str(tmp_path/'report.json'),'--verify-target-content']
    assert cli.main(argv)==1
    assert 'target_content_requires_conversion_policy' in capsys.readouterr().err
    with pytest.raises(SystemExit) as error: cli.main(argv+['--row-evidence'])
    assert error.value.code==2


def test_missing_policy_or_unknown_purpose_cannot_be_shape_only_success(tmp_path):
    path,source,target,policy=fixture(tmp_path)
    with pytest.raises(GuardFailure):
        compare(source,target,policy,purpose='typo')
    with pytest.raises(GuardFailure):
        row_projection.project_snapshot(path,source,target,None,purpose='verify_content')
