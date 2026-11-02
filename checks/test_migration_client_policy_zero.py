"""Explicit new-policy defaults are opt-in, exact, pinned and fully projected."""
from contextlib import closing
import copy
import hashlib
import json
import sqlite3
import time

import pytest

from checks.migration_client_policy_fixture import ATTRIBUTES,COLUMNS,MODE,client_table,fixture,repin
from migration_guard.compare import compare
from migration_guard.conversion_policy import conversion_plan,validate_document
from migration_guard.import_copy import copy_chunks
from migration_guard.row_projection import projected_rows,project_snapshot
from migration_guard.snapshot import GuardFailure,inspect_snapshot


def test_old_policy_retains_three_exact_rejections(tmp_path):
    path,source,target,policy=fixture(tmp_path)
    before=path.read_bytes();policy['version']=1;policy['mappings']=policy['mappings'][:2]
    report=compare(source,target,policy)
    assert report['result']=='failed'
    assert report['blockers']==[dict(code='target_only_column_requires_explicit_policy',table='clients',column=n) for n in COLUMNS]
    assert path.read_bytes()==before


def test_explicit_zero_plan_has_new_origin_not_historical_or_attribute_authority(tmp_path):
    path,source,target,policy=fixture(tmp_path);before=path.read_bytes()
    report=compare(source,target,policy)
    assert report['result']=='passed' and not report['blockers'] and not report['cutover_authorized']
    mappings=[m for m in report['conversion_plan']['mappings'] if m['table']=='clients']
    assert [m['column'] for m in mappings]==list(COLUMNS)
    assert all(m['mode']==MODE and type(m['value']) is int and m['value']==0 and m['rows']==2 for m in mappings)
    assert all(m['origin']=='explicit_new_client_policy_default' and not m['historical_fields_rewritten'] and not m['inferred_from_attributes'] for m in mappings)
    with closing(sqlite3.connect(path)) as db:
        rows=list(projected_rows(db,client_table(source),client_table(target),report['conversion_plan']['mappings']))
    assert rows[0]['attributes']==ATTRIBUTES and rows[0]['note'] is None
    assert rows[1]['id']=='client-b ' and rows[1]['attributes']==rows[1]['note']==''
    assert all(type(row[n]) is int and row[n]==0 for row in rows for n in COLUMNS)
    assert path.read_bytes()==before


@pytest.mark.parametrize('selected', [('skip_consent',),('consent_refresh_interval',),('allow_passwordless_only',),('skip_consent','allow_passwordless_only')])
def test_partial_selection_does_not_authorize_other_columns(tmp_path,selected):
    _,source,target,policy=fixture(tmp_path)
    policy['mappings']=[m for m in policy['mappings'] if m['table']!='clients' or m['column'] in selected]
    report=compare(source,target,policy)
    assert report['result']=='failed'
    assert [b['column'] for b in report['blockers']]==[n for n in COLUMNS if n not in selected]


@pytest.mark.parametrize('column', list(COLUMNS))
@pytest.mark.parametrize('change', ['type','nullable','pk','namespace','missing_flag','false_flag','integer_flag','null_flag'])
def test_exact_native_target_shape_and_zero_flag_required(tmp_path,column,change):
    _,source,target,policy=fixture(tmp_path)
    value=next(c for c in client_table(target)['columns'] if c['name']==column)
    if change=='type':value['type']='int8' if COLUMNS[column]=='int4' else 'int4'
    if change=='nullable':value['not_null']=False
    if change=='pk':value['pk_order']=2
    if change=='namespace':value['type_namespace']='untrusted'
    if change=='missing_flag':value.pop('canonical_zero_default')
    if change=='false_flag':value['canonical_zero_default']=False
    if change=='integer_flag':value['canonical_zero_default']=1
    if change=='null_flag':value['canonical_zero_default']=None
    repin(policy,source,target)
    with pytest.raises(GuardFailure,match='client_policy_target_shape_invalid'):compare(source,target,policy)


@pytest.mark.parametrize('column', list(COLUMNS))
def test_existing_source_policy_is_never_overwritten(tmp_path,column):
    path,_,target,policy=fixture(tmp_path)
    with closing(sqlite3.connect(path)) as db,db:db.execute('ALTER TABLE clients ADD COLUMN "'+column+'" INTEGER NOT NULL DEFAULT 1')
    source=inspect_snapshot(path,hashlib.sha256(path.read_bytes()).hexdigest());repin(policy,source,target)
    with pytest.raises(GuardFailure,match='client_policy_source_column_present'):compare(source,target,policy)


@pytest.mark.parametrize('change', ['v1','legacy_only_v2','unknown_version','literal_field','wrong_mode','wrong_table','wrong_column','duplicate','over_budget'])
def test_new_version_and_closed_mapping_grammar(tmp_path,change):
    _,source,target,policy=fixture(tmp_path)
    if change=='v1':policy['version']=1
    if change=='legacy_only_v2':policy['mappings']=policy['mappings'][:2]
    if change=='unknown_version':policy['version']=3
    if change=='literal_field':policy['mappings'][-1]['value']=0
    if change=='wrong_mode':policy['mappings'][-1]['mode']=MODE.upper()
    if change=='wrong_table':policy['mappings'][-1]['table']='users'
    if change=='wrong_column':policy['mappings'][-1]['column']='active'
    if change=='duplicate':policy['mappings'][-1]=copy.deepcopy(policy['mappings'][-2])
    if change=='over_budget':policy['mappings'].append(dict(table='clients',column='unapproved',mode=MODE))
    with pytest.raises(GuardFailure):validate_document(policy)


def test_new_policy_keeps_sha_pins_and_nonempty_admission(tmp_path):
    _,source,target,policy=fixture(tmp_path)
    changed=copy.deepcopy(source);changed['sha256']='0'*64
    with pytest.raises(GuardFailure,match='policy_source_digest_mismatch'):compare(changed,target,policy)
    changed=copy.deepcopy(target);client_table(changed)['columns'][0]['not_null']=False
    with pytest.raises(GuardFailure,match='policy_target_shape_mismatch'):compare(source,changed,policy)
    client_table(target)['rows']=1
    assert compare(source,target,policy)['blockers']==[dict(code='target_business_table_not_empty',table='clients')]
    assert compare(source,target,policy,purpose='verify_content')['result']=='passed'


def test_full_projection_and_copy_include_literals_and_preserve_source(tmp_path):
    path,source,target,policy=fixture(tmp_path);before=path.read_bytes()
    evidence=project_snapshot(path,source,target,policy)
    assert evidence['rows']==11 and len(evidence['tables'])==3 and not evidence['copied']
    assert ATTRIBUTES not in json.dumps(evidence) and not evidence['target_content_verified']
    columns=next(t for t in evidence['tables'] if t['table']=='clients')['projected_columns']
    assert set(c['name'] for c in columns)=={'id','attributes','note',*COLUMNS}
    plan=conversion_plan(source,target,policy)
    chunks=list(copy_chunks(path,source,target,plan['mappings'],['audit_events','clients','permissions_resources'],time.monotonic()+3))
    header=b'COPY public."clients"("allow_passwordless_only","attributes","consent_refresh_interval","id","note","skip_consent") FROM STDIN;\n'
    start=chunks.index(header);rows=chunks[start+1:start+3]
    assert rows==[('0\t'+ATTRIBUTES+'\t0\tclient-a\t\\N\t0\n').encode(),b'0\t\t0\tclient-b \t\t0\n']
    assert chunks[-1].startswith(b"SELECT json_build_object('kind','copied')") and path.read_bytes()==before


@pytest.mark.parametrize('value', [True,None,1,'0',0.0])
def test_tampered_plan_literal_never_overwrites_or_serializes(tmp_path,value):
    path,source,target,policy=fixture(tmp_path)
    plan=conversion_plan(source,target,policy)
    next(m for m in plan['mappings'] if m['table']=='clients')['value']=value
    with closing(sqlite3.connect(path)) as db:
        with pytest.raises(GuardFailure,match='client_policy_literal_invalid'):
            list(projected_rows(db,client_table(source),client_table(target),plan['mappings']))


def test_copy_revalidates_new_defaults_before_any_header(tmp_path):
    path,source,target,policy=fixture(tmp_path);plan=conversion_plan(source,target,policy)
    client_table(target)['columns'][-1]['canonical_zero_default']=False
    chunks=copy_chunks(path,source,target,plan['mappings'],['audit_events','clients','permissions_resources'],time.monotonic()+3)
    with pytest.raises(GuardFailure,match='client_policy_target_shape_invalid'):next(chunks)
