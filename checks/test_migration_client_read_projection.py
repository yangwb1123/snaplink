"""Only explicit pinned client policy projection may shadow an immutable source."""
from contextlib import closing
import copy
import hashlib
import importlib
import sqlite3

import pytest

from checks.migration_client_policy_fixture import ATTRIBUTES,COLUMNS,client_table,fixture,repin
from migration_guard.snapshot import GuardFailure


def projection(source,target,policy):
    return importlib.import_module('migration_guard.client_read_projection').client_read_projection(source,target,policy)


def test_manifest_and_temp_view_preserve_full_source_and_literal_origins(tmp_path):
    path,source,target,policy=fixture(tmp_path);before=path.read_bytes()
    result=projection(source,target,policy)
    assert result['version']==1 and result['algorithm']=='readonly_sqlite_client_view_v1'
    assert result['source_sha256']==source['sha256'] and result['target_shape_sha256']==policy['target_shape_sha256']
    assert result['source_columns']==['attributes','id','note']
    assert result['view_columns']==sorted(['attributes','id','note',*COLUMNS])
    assert result['zero_columns']==list(COLUMNS)
    assert result['sql'].startswith('CREATE TEMP VIEW "clients" AS SELECT ') and result['sql'].endswith(' FROM main."clients";')
    assert result['sql_sha256']==hashlib.sha256(result['sql'].encode()).hexdigest()
    assert result['main_source_modified'] is False and result['historical_policy_inferred'] is False
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
        db.execute('PRAGMA temp_store=MEMORY');db.execute(result['sql']);db.execute('PRAGMA query_only=ON')
        rows=db.execute('SELECT id,attributes,note,skip_consent,consent_refresh_interval,allow_passwordless_only FROM clients ORDER BY id').fetchall()
        assert rows==[('client-a',ATTRIBUTES,None,0,0,0),('client-b ','','',0,0,0)]
        assert [r[1] for r in db.execute('PRAGMA main.table_info(clients)')]==['id','attributes','note']
        assert db.execute('SELECT count(*) FROM sqlite_temp_master WHERE name="clients"').fetchone()[0]==1
        with pytest.raises(sqlite3.OperationalError):db.execute('UPDATE main.clients SET note="forbidden"')
    assert path.read_bytes()==before
    assert not any(path.with_name(path.name+suffix).exists() for suffix in ('-wal','-shm','-journal'))


@pytest.mark.parametrize('change', ['v1','unknown_mode','unknown_column','source_sha','shape_sha','false_default','nullable','pk','literal','duplicate','target_only','missing_clients','unknown_identifier'])
def test_unbound_or_unapproved_projection_fails_closed(tmp_path,change):
    _,source,target,policy=fixture(tmp_path)
    if change=='v1':policy['version']=1;policy['mappings']=policy['mappings'][:2]
    if change=='unknown_mode':policy['mappings'][-1]['mode']='arbitrary_default'
    if change=='unknown_column':policy['mappings'][-1]['column']='active'
    if change=='source_sha':policy['source_sha256']='0'*64
    if change=='shape_sha':policy['target_shape_sha256']='0'*64
    if change=='false_default':client_table(target)['columns'][-1]['canonical_zero_default']=False
    if change=='nullable':client_table(target)['columns'][-1]['not_null']=False;repin(policy,source,target)
    if change=='pk':client_table(target)['columns'][-1]['pk_order']=2;repin(policy,source,target)
    if change=='literal':policy['mappings'][-1]['value']=0
    if change=='duplicate':policy['mappings'][-1]=copy.deepcopy(policy['mappings'][-2])
    if change=='target_only':client_table(target)['columns'].append(dict(name='unapproved',type='int4',not_null=True,pk_order=0));repin(policy,source,target)
    if change=='missing_clients':source['tables']=[t for t in source['tables'] if t['table']!='clients']
    if change=='unknown_identifier':
        for snapshot in (source,target):client_table(snapshot)['columns'][0]['name']='id";DROP TABLE clients;--'
        repin(policy,source,target)
    with pytest.raises(GuardFailure):projection(source,target,policy)


def test_present_source_policy_is_not_replaced_by_zero(tmp_path):
    from migration_guard.snapshot import inspect_snapshot
    path,_,target,policy=fixture(tmp_path)
    with closing(sqlite3.connect(path)) as db,db:db.execute('ALTER TABLE clients ADD COLUMN skip_consent INTEGER NOT NULL DEFAULT 1')
    source=inspect_snapshot(path,hashlib.sha256(path.read_bytes()).hexdigest());repin(policy,source,target)
    with pytest.raises(GuardFailure,match='source_column_present'):projection(source,target,policy)
    policy['mappings']=[m for m in policy['mappings'] if m['column']!='skip_consent']
    result=projection(source,target,policy)
    assert result['zero_columns']==['allow_passwordless_only','consent_refresh_interval']
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
        db.execute(result['sql']);db.execute('PRAGMA query_only=ON')
        assert db.execute('SELECT skip_consent,consent_refresh_interval FROM clients').fetchall()==[(1,0),(1,0)]
