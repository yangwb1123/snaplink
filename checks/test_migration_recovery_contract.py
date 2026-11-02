"""Pinned recovery input rejects before any target query; archive is evidence, not SQL authority."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops/scripts'))
from migration_guard.snapshot import GuardFailure
from migration_guard.recovery_contract import archive_evidence, load_checkpoint, validate_checkpoint
from checks.migration_recovery_fixture import fixture


def private(tmp_path, name, data):
    tmp_path.chmod(0o700)
    p = tmp_path / name
    p.write_bytes(data)
    p.chmod(0o600)
    return p


def test_archive_exact_hash_and_bounds(tmp_path):
    data = b'PGDMP' + bytes(range(32))
    p = private(tmp_path, 'fixture.dump', data)
    assert archive_evidence(p, hashlib.sha256(data).hexdigest()) == dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    with pytest.raises(GuardFailure, match='recovery_archive_sha256_mismatch'):
        archive_evidence(p, 'a'*64)


@pytest.mark.parametrize('data', [b'', b'PGD', b'CREATE TABLE secret;', b'not a backup'])
def test_archive_is_not_plain_sql(tmp_path, data):
    p = private(tmp_path, 'invalid.dump', data)
    with pytest.raises(GuardFailure, match='recovery_custom_archive_required'):
        archive_evidence(p, hashlib.sha256(data).hexdigest())


@pytest.mark.parametrize('data', [b'{', b'[]', b'{"version":1,"version":1}', b'{"version":true}'])
def test_bad_pinned_checkpoint(tmp_path, data):
    p = private(tmp_path, 'checkpoint.json', data)
    with pytest.raises(GuardFailure):
        load_checkpoint(p, hashlib.sha256(data).hexdigest())


def test_stale_pin_rejects_before_validation(tmp_path):
    p = private(tmp_path, 'checkpoint.json', b'{}')
    with pytest.raises(GuardFailure, match='recovery_checkpoint_sha256_mismatch'):
        load_checkpoint(p, '0'*64)


@pytest.mark.parametrize('case', ['unknown','bool_version','large_archive','invalid_digest','identity','unknown_identity','missing_table','duplicate_table','totals','bool_count','large_count','columns','keys','shape','missing_facet','unknown_facet','other_sequence','called','state','identity_column'])
def test_strict_checkpoint_records(case):
    book,_,_=fixture()
    assert validate_checkpoint(book) == book
    t=book['content']['tables'][0]
    if case=='unknown': book['restore_authorized']=True
    elif case=='bool_version': book['version']=True
    elif case=='large_archive': book['archive']['bytes']=65<<20
    elif case=='invalid_digest': book['archive']['sha256']='A'*64
    elif case=='identity': book['source_identity']['database']='production'
    elif case=='unknown_identity': book['source_identity']['password']='forbidden'
    elif case=='missing_table': book['content']['tables'].pop()
    elif case=='duplicate_table': book['content']['tables'].append(copy.deepcopy(t))
    elif case=='totals': book['content']['rows']+=1
    elif case=='bool_count': t['rows']=True
    elif case=='large_count': t['rows']=200001
    elif case=='columns': t['projected_columns'][0]['not_null']=1
    elif case=='keys': t['primary_key_columns']=['seq']
    elif case=='shape': book['target_shape_sha256']='c'*64
    elif case=='missing_facet': book['schema']['tables']['audit_events']['facets'].pop('hazards')
    elif case=='unknown_facet': book['schema']['tables']['audit_events']['counts']['functions']=1
    elif case=='other_sequence': book['schema']['tables']['schema_migrations_audit']['counts']['sequences']=1
    elif case=='called': book['audit_sequence']['state']['is_called']=1
    elif case=='state': book['audit_sequence']['state']['last_value']=True
    elif case=='identity_column': book['audit_sequence']['descriptor']['column_identity']='a'
    with pytest.raises(GuardFailure): validate_checkpoint(book)


@pytest.mark.parametrize('case',['public_mode','symlink','hardlink','parent','budget'])
def test_private_archive_boundaries(tmp_path,monkeypatch,case):
    from migration_guard import recovery_contract
    raw=b'PGDMP'+b'unit-only'*4
    p=private(tmp_path,'fixture.dump',raw)
    if case=='public_mode': p.chmod(0o644)
    elif case=='symlink': q=tmp_path/'link';q.symlink_to(p);p=q
    elif case=='hardlink': __import__('os').link(p,tmp_path/'second-link')
    elif case=='parent': tmp_path.chmod(0o755)
    elif case=='budget': monkeypatch.setattr(recovery_contract,'MAX_ARCHIVE_BYTES',len(raw)-1)
    with pytest.raises(GuardFailure): archive_evidence(p,hashlib.sha256(raw).hexdigest())
