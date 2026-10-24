"""Projected facts are bounded, typed, PK-sorted, private and never copied."""
from contextlib import closing
import hashlib
import json
import sqlite3

import pytest

from checks.migration_policy_fixture import policy_document, policy_fixture
from migration_guard.snapshot import GuardFailure, inspect_snapshot
from migration_guard import row_projection as projection


def fixture(root):
    path, _, target = policy_fixture(root)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE business_state(tenant TEXT, id TEXT COLLATE NOCASE, quantity INTEGER NOT NULL, note TEXT, payload BLOB, PRIMARY KEY(tenant,id))')
        db.executemany('INSERT INTO business_state VALUES(?,?,?,?,?)', [
            ('tenant-a', 'a', 9007199254740993, None, b'\x00\xff'),
            ('tenant-a', 'B', 0, '', b''),
            ('tenant-b', 'a ', -7, 'synthetic-private-value', None)])
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    table = next(t for t in source['tables'] if t['table'] == 'business_state')
    columns = [dict(name=c['name'], type={'TEXT':'text','INTEGER':'int8','BLOB':'bytea'}[c['type']],
                    not_null=c['not_null'] or bool(c['pk_order']), pk_order=c['pk_order']) for c in table['columns']]
    target['tables'].append(dict(table='business_state', rows=0, metadata_only=False, columns=columns))
    return path, source, target, policy_document(source, target)


def facts(tmp_path):
    path, source, target, policy = fixture(tmp_path)
    return projection.project_snapshot(path, source, target, policy)


def test_projection_covers_all_tables_without_row_values_or_copy_claim(tmp_path):
    evidence = facts(tmp_path)
    assert evidence['algorithm'] == 'pk_sorted_typed_projection_v1'
    assert evidence['rows'] == 12 and len(evidence['tables']) == 3
    assert evidence['read_only'] and not evidence['target_content_verified']
    assert not evidence['copied'] and not evidence['audit_chain_verified']
    assert 'synthetic-private-value' not in json.dumps(evidence)
    assert 'stored-not-recomputed' not in json.dumps(evidence)
    for table in evidence['tables']:
        assert len(table['projected_content_sha256']) == len(table['primary_key_set_sha256']) == 64


def test_pk_order_and_target_column_order_are_driver_independent(tmp_path):
    path, source, target, policy = fixture(tmp_path)
    before = projection.project_snapshot(path, source, target, policy)
    target['tables'].reverse()
    for table in target['tables']:
        table['columns'].reverse()
    assert projection.project_snapshot(path, source, target, policy) == before
    bucket = next(t for t in before['tables'] if t['table'] == 'business_state')
    assert bucket['primary_key_columns'] == ['tenant', 'id']


def test_mapping_is_exact_rowid_and_utf8_not_order_or_normalization(tmp_path):
    path, source, target = policy_fixture(tmp_path)
    policy = policy_document(source, target)
    with closing(sqlite3.connect(path)) as db:
        audit = next(t for t in source['tables'] if t['table'] == 'audit_events')
        shape = next(t for t in target['tables'] if t['table'] == 'audit_events')
        rows = list(projection.projected_rows(db, audit, shape, policy['mappings']))
        assert {r['id']:r['seq'] for r in rows} == {'z':7,'a':13,'b':99}
        resource = next(t for t in source['tables'] if t['table'] == 'permissions_resources')
        shape = next(t for t in target['tables'] if t['table'] == 'permissions_resources')
        rows = list(projection.projected_rows(db, resource, shape, policy['mappings']))
        assert {r['id']:r['dispatch_key'] for r in rows} == {
            '0':b'', '1':b'A\x00B', '2':'é'.encode(), '3':'e\u0301'.encode(),
            '4':'😀 '.encode(), '5':'quote"\\N\n'.encode()}


@pytest.mark.parametrize('failure', ['policy', 'nonempty', 'column', 'sha'])
def test_projection_has_no_unapproved_shape_or_stale_input_fallback(tmp_path, failure):
    path, source, target, policy = fixture(tmp_path)
    if failure == 'policy':
        policy = None
    elif failure == 'nonempty':
        target['tables'][0]['rows'] = 1
    elif failure == 'column':
        target['tables'][0]['columns'].pop()
    else:
        source['sha256'] = policy['source_sha256'] = 'a'*64
    with pytest.raises(GuardFailure):
        projection.project_snapshot(path, source, target, policy)


@pytest.mark.parametrize('budget', ['rows', 'bytes', 'time'])
def test_projection_budget_is_closed_without_partial_digest(tmp_path, monkeypatch, budget):
    path, source, target, policy = fixture(tmp_path)
    if budget == 'rows':
        monkeypatch.setattr(projection, 'MAX_ROWS', 1)
    elif budget == 'bytes':
        monkeypatch.setattr(projection, 'MAX_SCAN_BYTES', 1)
    with pytest.raises(GuardFailure, match='budget|window'):
        projection.project_snapshot(path, source, target, policy, timeout=0 if budget == 'time' else 60)


def test_nullable_dispatch_is_null_not_empty_bytes(tmp_path):
    path, _, target = policy_fixture(tmp_path)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('ALTER TABLE permissions_resources RENAME TO old_resources')
        db.execute('CREATE TABLE permissions_resources(id TEXT PRIMARY KEY,dispatch_key TEXT)')
        db.execute('INSERT INTO permissions_resources SELECT * FROM old_resources')
        db.execute("INSERT INTO permissions_resources VALUES('nullable',NULL)")
        db.execute('DROP TABLE old_resources')
    source = inspect_snapshot(path,hashlib.sha256(path.read_bytes()).hexdigest())
    shape = next(t for t in target['tables'] if t['table']=='permissions_resources')
    next(c for c in shape['columns'] if c['name']=='dispatch_key')['not_null'] = False
    policy = policy_document(source,target)
    evidence = projection.project_snapshot(path,source,target,policy)
    assert evidence['rows'] == 10
    table = next(t for t in source['tables'] if t['table']=='permissions_resources')
    with closing(sqlite3.connect(path)) as db:
        rows = {r['id']:r['dispatch_key'] for r in projection.projected_rows(db,table,shape,policy['mappings'])}
    assert rows['nullable'] is None and rows['0'] == b'' and rows['1'] == b'A\x00B'


def test_low_level_duplicate_and_missing_pk_are_closed(tmp_path):
    path, source, target, policy = fixture(tmp_path)
    table = next(t for t in source['tables'] if t['table']=='business_state')
    shape = next(t for t in target['tables'] if t['table']=='business_state')
    for c in shape['columns']:
        c['pk_order'] = 1 if c['name']=='tenant' else 0
    with closing(sqlite3.connect(path)) as db:
        with pytest.raises(GuardFailure,match='duplicate_primary_key'):
            projection.project_table(db,table,shape,policy['mappings'],float('inf'))
        for c in shape['columns']:
            c['pk_order'] = 0
        with pytest.raises(GuardFailure,match='primary_key_required'):
            projection.project_table(db,table,shape,policy['mappings'],float('inf'))


def test_content_digest_independently_preserves_all_audit_fields(tmp_path):
    path, source, target = policy_fixture(tmp_path)
    evidence = projection.project_snapshot(path, source, target, policy_document(source, target))
    audit = next(t for t in evidence['tables'] if t['table'] == 'audit_events')
    expected = {'a':(100,'','',13),'z':(100,None,None,7),'b':(-5,'stored-not-recomputed','unchanged',99)}
    def frame(digest, value):
        digest.update(len(value).to_bytes(8,'big'))
        digest.update(value)
    def encode(values):
        return json.dumps(values,ensure_ascii=False,separators=(',',':')).encode()
    digest = hashlib.sha256()
    frame(digest,json.dumps(['pk_sorted_typed_projection_v1','audit_events',audit['projected_columns']],sort_keys=True,separators=(',',':')).encode())
    for event_id in sorted(expected):
        timestamp,stored_hash,prev,seq = expected[event_id]
        fields = {'id':['text',event_id],'ts_unix_ns':['integer',str(timestamp)],
                  'hash':['null'] if stored_hash is None else ['text',stored_hash],
                  'prev_hash':['null'] if prev is None else ['text',prev],'seq':['integer',str(seq)]}
        frame(digest,encode([['text',event_id]]))
        frame(digest,hashlib.sha256(encode([fields[c['name']] for c in audit['projected_columns']])).digest())
    assert digest.hexdigest() == audit['projected_content_sha256']


def test_changed_source_is_rejected_after_scan(tmp_path, monkeypatch):
    path, source, target, policy = fixture(tmp_path)
    original = projection.project_table
    def changed(*args):
        result = original(*args)
        with closing(sqlite3.connect(path)) as writer, writer:
            writer.execute("UPDATE business_state SET note='tampered-after-scan'")
        return result
    monkeypatch.setattr(projection, 'project_table', changed)
    with pytest.raises(GuardFailure, match='sha256_mismatch'):
        projection.project_snapshot(path,source,target,policy)


def test_source_row_count_is_rechecked_from_actual_rows(tmp_path):
    path, source, target, policy = fixture(tmp_path)
    next(t for t in source['tables'] if t['table']=='business_state')['rows'] = 5
    with pytest.raises(GuardFailure,match='row_count_mismatch'):
        projection.project_snapshot(path,source,target,policy)


def test_row_leaf_is_unambiguous_and_never_rounds_int64():
    keys = [projection.encode_values(v) for v in [
        (None,), ('',), (b'',), (0,), ('0',), (9007199254740993,),
        (9007199254740992,), ('é',), ('e\u0301',), ('k',), ('k ',), ('a','bc'), ('ab','c')]]
    assert len(set(keys)) == len(keys)
    assert b'9007199254740993' in keys[5]
    with pytest.raises(GuardFailure):
        projection.encode_values((False,))
