"""Native catalog grammar and locked reader/writer seams; no simulated engine claims."""
import copy
import time
from types import SimpleNamespace

import pytest

from checks.migration_client_policy_fixture import COLUMNS,client_table,fixture
from migration_guard.conversion_policy import conversion_plan
from migration_guard.import_runner import ImportExecution
from migration_guard.postgres import CATALOG_SQL
from migration_guard.snapshot import GuardFailure
from migration_guard.target_content import TargetReader,catalog_tables


def catalog(target,flag=True):
    tables=[]
    for table in target['tables']:
        columns=[]
        for original in table['columns']:
            column={k:original[k] for k in ('name','type','type_namespace','not_null','pk_order')}
            if flag:column['canonical_zero_default']=original.get('canonical_zero_default',False)
            columns.append(column)
        tables.append(dict(table=table['table'],columns=columns,relkind='r',rls_enabled=False,force_rls=False))
    return tables


def test_native_catalog_classifies_only_constant_non_generated_defaults():
    assert "'canonical_zero_default'" in CATALOG_SQL
    assert "a.attidentity=''" in CATALOG_SQL and "a.attgenerated=''" in CATALOG_SQL
    assert "pg_get_expr(ad.adbin,ad.adrelid)='0'" in CATALOG_SQL
    assert 'LEFT JOIN pg_attrdef ad' in CATALOG_SQL
    assert "'default_expression'" not in CATALOG_SQL


@pytest.mark.parametrize('flag', [True,False])
def test_legacy_and_additive_catalog_grammars_remain_readable(tmp_path,flag):
    _,_,target,_=fixture(tmp_path)
    result=catalog_tables(catalog(target,flag))
    assert len(result)==3
    assert all(('canonical_zero_default' in c)==flag for t in result for c in t['columns'])


@pytest.mark.parametrize('value', [None,0,1,'true',[],{}])
def test_catalog_default_flag_requires_an_actual_boolean(tmp_path,value):
    _,_,target,_=fixture(tmp_path);data=catalog(target)
    data[-1]['columns'][-1]['canonical_zero_default']=value
    with pytest.raises(GuardFailure,match='target_content_column_default_invalid'):catalog_tables(data)


def test_unknown_catalog_fields_are_not_default_evidence(tmp_path):
    _,_,target,_=fixture(tmp_path);data=catalog(target)
    data[-1]['columns'][-1]['default_expression']='private-expression-must-not-be-reported'
    with pytest.raises(GuardFailure,match='target_content_column_format_invalid'):catalog_tables(data)


def test_locked_reader_rejects_lost_default_evidence_before_row_query(tmp_path):
    _,source,target,policy=fixture(tmp_path)
    reader=TargetReader({},source,policy,time.monotonic()+3)
    data=catalog(target);data[-1]['columns'][-1]['canonical_zero_default']=False
    class Stream:
        def send(self,*args,**kwargs):pytest.fail('row query emitted for unapproved locked default')
    with pytest.raises(GuardFailure,match='client_policy_target_shape_invalid'):
        reader.catalog(dict(kind='catalog',tables=data),Stream())


@pytest.mark.parametrize('change', ['flag','namespace','type'])
def test_locked_writer_revalidates_before_copy_journal_or_queue(tmp_path,change):
    _,source,target,policy=fixture(tmp_path);plan=conversion_plan(source,target,policy)
    locked=copy.deepcopy(target);column=client_table(locked)['columns'][-1]
    if change=='flag':column['canonical_zero_default']=False
    if change=='namespace':column['type_namespace']='unsafe'
    if change=='type':column['type']='int8'
    execution=ImportExecution.__new__(ImportExecution)
    execution.inputs=dict(source=source,plan=plan)
    execution.admission=SimpleNamespace(target=locked)
    execution.baseline=SimpleNamespace(evidence=lambda _:dict(tables=[dict(rows=0)]))
    class Journal:
        def append(self,*args,**kwargs):pytest.fail('COPY attempt persisted before locked default authorization')
    class Stream:
        def queue(self,*args,**kwargs):pytest.fail('COPY queued with unapproved locked default')
    execution.journal=Journal()
    with pytest.raises(GuardFailure,match='client_policy_target_shape_invalid'):execution.copy(Stream())


def test_reader_compares_new_values_in_complete_content_digest(tmp_path):
    from contextlib import closing
    import sqlite3
    from migration_guard.row_projection import projected_rows,project_snapshot
    from migration_guard.row_digest import TableDigest
    from migration_guard.target_content import comparison_issues
    path,source,target,policy=fixture(tmp_path)
    expected=project_snapshot(path,source,target,policy)
    shape=client_table(target);digest=TableDigest(shape,time.monotonic()+3,200000,128<<20)
    with closing(sqlite3.connect(path)) as db:
        rows=list(projected_rows(db,client_table(source),shape,policy['mappings']))
    rows[0]['skip_consent']=1
    for row in rows:digest.add(row)
    actual=copy.deepcopy(expected)
    actual['tables']=[digest.finish() if t['table']=='clients' else t for t in actual['tables']]
    assert comparison_issues(expected,actual)==[dict(code='target_projected_content_mismatch',table='clients')]
