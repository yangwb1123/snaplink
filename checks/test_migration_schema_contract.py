"""Pinned private native schema contract is evidence, never release authority."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard.snapshot import GuardFailure
from migration_guard.schema_contract import load_contract, schema_fingerprint, validate_contract
from migration_guard.schema_sql import FACETS


def document():
    return dict(version=1,algorithm='pg_native_schema_facets_v1',source_sha256='1'*64,target_shape_sha256='2'*64,
        schema_source=dict(base_commit='a'*40,combination_sha256='3'*64),environment_sha256='4'*64,
        tables=[dict(table='audit_events',facets={key:'5'*64 for key in FACETS})])


def private_contract(root,data):
    root.chmod(0o700);path=root/'contract.json'
    path.write_text(json.dumps(data));path.chmod(0o600)
    return path,hashlib.sha256(path.read_bytes()).hexdigest()


def test_pinned_contract_and_order_independent_fingerprint(tmp_path):
    doc=document();path,sha=private_contract(tmp_path,doc)
    assert load_contract(path,sha)==doc
    assert schema_fingerprint('x','columns',[dict(a=1,b=None),dict(a=2,b='')])==schema_fingerprint('x','columns',[dict(b='',a=2),dict(b=None,a=1)])
    assert schema_fingerprint('x','columns',[dict(a=1)])!=schema_fingerprint('x','columns',[dict(a=True)])
    assert schema_fingerprint('x','columns',[dict(a=None)])!=schema_fingerprint('x','columns',[dict(a='')])


@pytest.mark.parametrize('failure',['unknown','missing','version','bool','algorithm','sha','provenance','empty','duplicate','facet','unknown_table'])
def test_bad_contract_rejects(failure):
    doc=document()
    if failure=='unknown': doc['approve_cutover']=True
    if failure=='missing': doc.pop('source_sha256')
    if failure=='version': doc['version']=2
    if failure=='bool': doc['version']=True
    if failure=='algorithm': doc['algorithm']='anything'
    if failure=='sha': doc['environment_sha256']='0'
    if failure=='provenance': doc['schema_source']['base_commit']='HEAD'
    if failure=='empty': doc['tables']=[]
    if failure=='duplicate': doc['tables']*=2
    if failure=='facet': doc['tables'][0]['facets'].pop('indexes')
    if failure=='unknown_table': doc['tables'][0]['table']='MixedCase'
    with pytest.raises(GuardFailure): validate_contract(doc)


@pytest.mark.parametrize('failure',['sha','mode','duplicate','budget'])
def test_private_hash_duplicate_and_budget_contract_fail(tmp_path,failure):
    path,sha=private_contract(tmp_path,document())
    if failure=='sha': sha='0'*64
    if failure=='mode': path.chmod(0o644)
    if failure=='duplicate':
        path.write_text('{"version":1,"version":1}');sha=hashlib.sha256(path.read_bytes()).hexdigest()
    if failure=='budget':
        path.write_bytes(b' '*((256<<10)+1));sha=hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(GuardFailure): load_contract(path,sha)
