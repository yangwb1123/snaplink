"""Fail-closed candidate-only intent and exact COPY scalar regression controls."""
import hashlib
import json
import time

import pytest

from checks.migration_guard_fixture import sample_snapshot  # sets tooling import path
from migration_guard.import_intent import load_intent, validate_intent
from migration_guard.import_copy import copy_cell, dependency_order
from migration_guard.snapshot import GuardFailure


def intent(config=None):
    config = config or dict(database='snaplink_mig_unit', owner_token='a'*48)
    return dict(version=1, scope='owned_candidate_import_v1', source_sha256='1'*64,
                policy_sha256='2'*64, schema_contract_sha256='3'*64,
                target_shape_sha256='4'*64, target_database=config['database'],
                target_owner_sha256=hashlib.sha256(config['owner_token'].encode()).hexdigest(),
                expires_at=int(time.time())+600, candidate_exclusive=True,
                source_is_final_cutover_snapshot=False, historical_audit_chain_certified=False,
                sequence_mode='pg_transactional_restart_v1')


def test_candidate_intent_requires_explicit_private_sha(tmp_path):
    tmp_path.chmod(0o700)
    path=tmp_path/'intent.json'
    raw=json.dumps(intent()).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    assert load_intent(path,hashlib.sha256(raw).hexdigest()) == intent()
    with pytest.raises(GuardFailure): load_intent(path,'0'*64)
    path.chmod(0o644)
    with pytest.raises(GuardFailure): load_intent(path,hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize('field,value',[
    ('version',True),('scope','production'),('expires_at',0),('expires_at',True),
    ('expires_at',int(time.time())+7200),('candidate_exclusive',False),
    ('source_is_final_cutover_snapshot',True),('historical_audit_chain_certified',True),
    ('sequence_mode','setval'),('target_database','snaplink'),('policy_sha256',''),
    ('extra','ignored')])
def test_candidate_intent_rejects_unknown_authority_and_invalid_fields(field,value):
    data=intent(); data[field]=value
    with pytest.raises(GuardFailure): validate_intent(data)


def test_duplicate_intent_fields_fail_before_any_target_contact(tmp_path):
    tmp_path.chmod(0o700)
    path=tmp_path/'intent.json'
    raw=json.dumps(intent()).replace('"version": 1','"version": 1, "version": 1').encode()
    path.write_bytes(raw); path.chmod(0o600)
    with pytest.raises(GuardFailure): load_intent(path,hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize('value,expected',[
    (None,r'\N'),('', ''),('\\N',r'\\N'),('\\.',r'\\.'),
    ('x\ny\r\tz\\',r'x\ny\r\tz\\'),('é e\u0301 😀 ','é e\u0301 😀 '),
    (9007199254740993,'9007199254740993'),(-9223372036854775808,'-9223372036854775808'),
    (-0.0,'-0.0'),(b'\x00\xff',r'\\x00ff'),(b'',r'\\x')])
def test_copy_preserves_scalar_identity_and_prevents_psql_control(value,expected):
    assert copy_cell(value)==expected
    assert '\n' not in copy_cell(value) and '\r' not in copy_cell(value)


@pytest.mark.parametrize('value',[True,False,float('nan'),float('inf'),'\x00',{},[]])
def test_copy_rejects_unsupported_values(value):
    with pytest.raises(GuardFailure): copy_cell(value)


def test_copy_dependency_order_parent_first_and_cycles_fail():
    assert dependency_order(['children','parents','independent'], [('children','parents')]) == ['independent','parents','children']
    for edges in [[('a','a')],[('a','b'),('b','a')],[('a','missing')]]:
        with pytest.raises(GuardFailure): dependency_order(['a','b'],edges)
