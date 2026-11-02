"""Exact checkpoint grammar/binding, not archive or production recovery approval."""
import ast
import copy
import hashlib
import itertools
import json
from pathlib import Path

import pytest

from checks.migration_recovery_fixture import fixture
from checks.test_migration_input_contract import conservative_complexity
from migration_guard import recovery_contract as contract
from migration_guard.snapshot import GuardFailure

FUNCTIONS = [n for n in ast.walk(ast.parse(Path(contract.__file__).read_text())) if isinstance(n,ast.FunctionDef)]


@pytest.mark.parametrize('node',FUNCTIONS,ids=[n.name for n in FUNCTIONS])
def test_checkpoint_owner_complexity(node):
    assert conservative_complexity(node) <= 15
    assert node.end_lineno-node.lineno+1 <= 50


def set_path(data,path,value):
    for key in path[:-1]: data=data[key]
    data[path[-1]]=value


@pytest.mark.parametrize('path,value,reason',[
    (('restore_authorized',),True,'recovery_checkpoint_fields_or_version_invalid'),
    (('version',),True,'recovery_checkpoint_fields_or_version_invalid'),
    (('version',),1.0,'recovery_checkpoint_fields_or_version_invalid'),
    (('version',),'1','recovery_checkpoint_fields_or_version_invalid'),
    (('algorithm',),'unknown','recovery_checkpoint_fields_or_version_invalid'),
    (('archive',),None,'recovery_checkpoint_archive_invalid'),
    (('archive',),{},'recovery_checkpoint_archive_invalid'),
    (('archive','bytes'),True,'recovery_checkpoint_archive_invalid'),
    (('archive','bytes'),5.0,'recovery_checkpoint_archive_invalid'),
    (('archive','bytes'),4,'recovery_checkpoint_archive_invalid'),
    (('archive','bytes'),(64<<20)+1,'recovery_checkpoint_archive_invalid'),
    (('archive','sha256'),'A'*64,'schema_contract_digest_required'),
    (('target_shape_sha256',),'0'*63,'schema_contract_digest_required'),
    (('source_identity',),None,'recovery_checkpoint_identity_invalid'),
    (('source_identity',),{},'recovery_checkpoint_identity_invalid'),
    (('source_identity','database'),'production','recovery_checkpoint_identity_invalid'),
    (('source_identity','database'),'snaplink_mig_','recovery_checkpoint_identity_invalid'),
    (('source_identity','database'),'snaplink_mig_'+('a'*33),'recovery_checkpoint_identity_invalid'),
    (('source_identity','database'),'snaplink_mig_Upper','recovery_checkpoint_identity_invalid'),
    (('source_identity','user'),None,'recovery_checkpoint_identity_invalid'),
    (('source_identity','user'),'','recovery_checkpoint_identity_invalid'),
    (('source_identity','user'),'u'*257,'recovery_checkpoint_identity_invalid'),
    (('source_identity','user'),'u\x00name','recovery_checkpoint_identity_invalid'),
    (('source_identity','owner_sha256'),True,'schema_contract_digest_required'),
    (('content',),None,'recovery_checkpoint_content_fields_invalid'),
    (('content','tables'),[],'recovery_checkpoint_table_budget_invalid'),
    (('content','rows'),True,'recovery_checkpoint_count_or_budget_invalid'),
    (('content','rows'),3,'recovery_checkpoint_coverage_or_totals_invalid'),
    (('target_shape_sha256',),'0'*64,'recovery_checkpoint_shape_content_mismatch'),
    (('schema',),None,'recovery_checkpoint_schema_fields_invalid'),
    (('schema','tables'),{},'recovery_checkpoint_schema_coverage_invalid'),
    (('audit_sequence',),None,'recovery_checkpoint_audit_fields_invalid'),
    (('audit_sequence','state','is_called'),1,'audit_sequence_state_invalid'),
])
def test_document_rejection_class_reason_and_no_input_mutation(path,value,reason):
    data,_,_=fixture(); set_path(data,path,value); prior=copy.deepcopy(data)
    with pytest.raises(GuardFailure) as error: contract.validate_checkpoint(data)
    assert str(error.value)==reason and data==prior


@pytest.mark.parametrize('archive_bytes',[5,64<<20])
@pytest.mark.parametrize('database',['snaplink_mig_a','snaplink_mig_'+('a'*32)])
@pytest.mark.parametrize('user',['u','u'*256,'😀'*256,' e\u0301  ','\ud800'])
def test_exact_archive_and_identity_limits_preserve_document_alias(archive_bytes,database,user):
    data,_,_=fixture(); data['archive']['bytes']=archive_bytes
    data['source_identity'].update(database=database,user=user)
    aliases=(data['archive'],data['source_identity'],data['content']['tables'],data['schema']['tables'],data['audit_sequence'])
    prior=copy.deepcopy(data); result=contract.validate_checkpoint(data)
    assert result is data and result==prior
    assert all(left is right for left,right in zip(aliases,(result['archive'],result['source_identity'],result['content']['tables'],result['schema']['tables'],result['audit_sequence'])))


@pytest.mark.parametrize('first,second,reason',[
    ((('version',),True),(('archive',),None),'recovery_checkpoint_fields_or_version_invalid'),
    ((('archive','bytes'),4),(('archive','sha256'),None),'recovery_checkpoint_archive_invalid'),
    ((('archive','sha256'),None),(('source_identity',),None),'schema_contract_digest_required'),
    ((('target_shape_sha256',),None),(('source_identity','database'),'production'),'schema_contract_digest_required'),
    ((('source_identity','database'),'production'),(('source_identity','owner_sha256'),None),'recovery_checkpoint_identity_invalid'),
    ((('source_identity','user'),'u\x00'),(('content',),None),'recovery_checkpoint_identity_invalid'),
    ((('source_identity','owner_sha256'),None),(('content',),None),'schema_contract_digest_required'),
    ((('content','rows'),True),(('schema',),None),'recovery_checkpoint_count_or_budget_invalid'),
    ((('target_shape_sha256',),'0'*64),(('schema',),None),'recovery_checkpoint_shape_content_mismatch'),
    ((('schema',),None),(('audit_sequence',),None),'recovery_checkpoint_schema_fields_invalid'),
])
def test_first_failure_order_is_unchanged(first,second,reason):
    data,_,_=fixture()
    for path,value in (first,second): set_path(data,path,value)
    with pytest.raises(GuardFailure) as error: contract.validate_checkpoint(data)
    assert str(error.value)==reason


def test_pinned_load_exact_object_and_no_archive_file_or_native_contact(tmp_path,monkeypatch):
    from migration_guard import recovery_observe
    monkeypatch.setattr(recovery_observe,'observe_native',lambda *a,**k:pytest.fail('validator cannot contact target'))
    data,_,_=fixture(); raw=json.dumps(data,ensure_ascii=False).encode()
    path=tmp_path/'checkpoint.json'; path.write_bytes(raw); path.chmod(0o600); tmp_path.chmod(0o700)
    loaded=contract.load_checkpoint(path,hashlib.sha256(raw).hexdigest())
    assert loaded==data and path.read_bytes()==raw
    assert list(tmp_path.iterdir())==[path]


@pytest.mark.parametrize('raw,reason',[
    (b'{','recovery_checkpoint_json_invalid'),
    (b'{"version":1,"version":1}','recovery_checkpoint_json_invalid'),
    (b'\xff','recovery_checkpoint_json_invalid'),
    (b'[]','recovery_checkpoint_fields_or_version_invalid'),
])
def test_private_pinned_json_rejects_without_fallback(tmp_path,raw,reason):
    path=tmp_path/'checkpoint.json'; path.write_bytes(raw); path.chmod(0o600); tmp_path.chmod(0o700)
    with pytest.raises(GuardFailure) as error: contract.load_checkpoint(path,hashlib.sha256(raw).hexdigest())
    assert str(error.value)==reason and path.read_bytes()==raw


def test_stale_pin_precedes_document_validation(tmp_path):
    path=tmp_path/'checkpoint.json'; path.write_bytes(b'{}'); path.chmod(0o600); tmp_path.chmod(0o700)
    with pytest.raises(GuardFailure,match='recovery_checkpoint_sha256_mismatch'):
        contract.load_checkpoint(path,'0'*64)


def test_archive_prefix_acceptance_is_not_full_format_or_restore_proof(tmp_path):
    raw=b'PGDMP-not-a-real-archive-only-prefix-witness'
    path=tmp_path/'prefix.bin'; path.write_bytes(raw); path.chmod(0o600); tmp_path.chmod(0o700)
    evidence=contract.archive_evidence(path,hashlib.sha256(raw).hexdigest())
    assert evidence==dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
    assert set(evidence)=={'sha256','bytes'}  # Never fabricate a format/provenance/restore verdict.


@pytest.mark.parametrize('bad',['private_mode','hardlink','symlink','oversize'])
def test_checkpoint_load_retains_private_and_budget_boundaries(tmp_path,bad):
    import os
    raw=b'{}' if bad!='oversize' else b' '*(256<<10)+b'{}'
    path=tmp_path/'checkpoint.json'; path.write_bytes(raw); path.chmod(0o600); tmp_path.chmod(0o700)
    if bad=='private_mode': path.chmod(0o644)
    if bad=='hardlink': os.link(path,tmp_path/'second.json')
    if bad=='symlink': alias=tmp_path/'alias.json'; alias.symlink_to(path); path=alias
    with pytest.raises(GuardFailure): contract.load_checkpoint(path,hashlib.sha256(raw).hexdigest())
