"""Declared FK semantics: composite keys, MATCH SIMPLE/FULL and no empty proof."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard.snapshot import GuardFailure
from migration_guard.declared_fk import foreign_key_sql, validate_foreign_key, relationship_evidence


def fk():
    return dict(name='tenant_parent',type='f',definition='FOREIGN KEY (tenant,id) REFERENCES parents(tenant,id)',
        validated=True,deferrable=False,initially_deferred=False,parent_schema='public',parent_table='parents',
        match_type='s',on_update='a',on_delete='a',child_columns=['tenant','id'],parent_columns=['tenant','id'],
        equality_operators=['pg_catalog.=','pg_catalog.='])


def shapes():
    return {name:dict(table=name,columns=[dict(name='tenant'),dict(name='id')]) for name in ['children','parents']}


def test_composite_simple_and_full_semantics_are_explicit():
    value=fk();validate_foreign_key('children',value,shapes())
    sql=foreign_key_sql('children',value)
    assert 'public."children"' in sql and 'public."parents"' in sql and sql.count('OPERATOR(pg_catalog.=)')==2
    assert '"tenant" IS NOT NULL AND c."id" IS NOT NULL' in sql
    value['match_type']='f';sql=foreign_key_sql('children',value)
    assert 'IS NULL' in sql and 'NOT (' in sql
    assert 'nextval(' not in sql and 'setval(' not in sql


@pytest.mark.parametrize('failure',['schema','parent','column','arity','operator','partial','duplicate','bad_action'])
def test_unsupported_foreign_key_cannot_guess(failure):
    value=fk()
    if failure=='schema': value['parent_schema']='outside'
    if failure=='parent': value['parent_table']='missing'
    if failure=='column': value['child_columns'][0]='missing'
    if failure=='arity': value['parent_columns'].pop()
    if failure=='operator': value['equality_operators'][0]='hostile.='
    if failure=='partial': value['match_type']='p'
    if failure=='duplicate': value['child_columns']=['id','id']
    if failure=='bad_action': value['on_delete']='unknown'
    with pytest.raises(GuardFailure): validate_foreign_key('children',value,shapes())


def test_zero_declarations_is_missing_relationship_proof_and_orphans_block():
    absent=relationship_evidence([])
    assert absent['result']=='not_executed' and absent['reason']=='no_declared_foreign_keys'
    assert absent['all_business_relationships_verified'] is False
    rows=[dict(table='children',constraint='tenant_parent',violations=2,validated=False)]
    result=relationship_evidence(rows)
    assert result['result']=='failed' and len(result['blockers'])==2
    assert {x['code'] for x in result['blockers']}=={'target_declared_fk_violations','target_declared_fk_not_validated'}
    good=relationship_evidence([dict(rows[0],violations=0,validated=True)])
    assert good['result']=='passed' and not good['all_business_relationships_verified']
