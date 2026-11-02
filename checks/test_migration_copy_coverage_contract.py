"""Exact lazy COPY input/coverage contract, not writer authority or rollback proof."""
import ast
import copy
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import time

import pytest

from checks.test_migration_input_contract import conservative_complexity
from checks.test_migration_row_projection import fixture
from migration_guard import import_copy as owner
from migration_guard.snapshot import GuardFailure

FUNCTIONS=[n for n in ast.walk(ast.parse(Path(owner.__file__).read_text())) if isinstance(n,ast.FunctionDef)]


@pytest.mark.parametrize('node',FUNCTIONS,ids=[n.name for n in FUNCTIONS])
def test_copy_owner_complexity(node):
    assert conservative_complexity(node)<=15 and node.end_lineno-node.lineno+1<=50


def run_fixture(root,monkeypatch,rows=None):
    path,source,target,policy=fixture(root)
    order=[t['table'] for t in target['tables'] if not t['metadata_only']]
    if rows is not None:
        def projected(db,left,right,mappings):
            if left['table']=='audit_events': yield from rows
        monkeypatch.setattr(owner,'projected_rows',projected)
        for table in source['tables']:
            if not table['metadata_only']: table['rows']=len(rows) if table['table']=='audit_events' else 0
    return path,source,target,policy,order


def chunks(data,deadline=None):
    path,source,target,policy,order=data
    return owner.copy_chunks(path,source,target,policy['mappings'],order,deadline if deadline is not None else time.monotonic()+30)


@pytest.mark.parametrize('failure',['missing','extra','duplicate','right_missing','left_missing','metadata_only'])
def test_coverage_rejects_before_connection_or_output(tmp_path,monkeypatch,failure):
    path,source,target,policy,order=run_fixture(tmp_path,monkeypatch)
    if failure=='missing': order.pop()
    elif failure=='extra': order.append('unknown')
    elif failure=='duplicate': order.append(order[0])
    elif failure=='right_missing': target['tables'].pop()
    elif failure=='left_missing': source['tables'].pop()
    else: source['tables'][0]['metadata_only']=True
    monkeypatch.setattr(owner.sqlite3,'connect',lambda *a,**k:pytest.fail('coverage rejects before SQLite opening'))
    gen=owner.copy_chunks(path,source,target,policy['mappings'],order,time.monotonic()+30)
    with pytest.raises(GuardFailure,match='^import_copy_table_coverage_invalid$'): next(gen)
    assert gen.gi_frame is None


@pytest.mark.parametrize('order',[
    ['audit_events','business_state','permissions_resources'],
    ['permissions_resources','business_state','audit_events'],
    ['business_state','audit_events','permissions_resources'],
])
@pytest.mark.parametrize('reverse_columns',[True,False])
def test_order_columns_exact_markers_and_source_unchanged(tmp_path,monkeypatch,order,reverse_columns):
    data=list(run_fixture(tmp_path,monkeypatch)); data[-1]=order
    if reverse_columns:
        for table in data[2]['tables']: table['columns'].reverse()
    prior=copy.deepcopy(data[1:]); source_bytes=data[0].read_bytes()
    parts=list(chunks(data)); headers=[p for p in parts if p.startswith(b'COPY ')]
    assert headers==[('COPY public."'+name+'"('+','.join('"'+c+'"' for c in sorted(col['name'] for col in next(t for t in data[2]['tables'] if t['table']==name)['columns']))+') FROM STDIN;\n').encode() for name in order]
    assert parts.count(b'\\.\n')==3 and parts[-1]==b"SELECT json_build_object('kind','copied')::jsonb;\n"
    assert any(b'9007199254740993' in p for p in parts)
    assert data[1:]==prior and data[0].read_bytes()==source_bytes


@pytest.mark.parametrize('value',[
    None,'','\\N','\\.','\\copy public.x FROM STDIN;',"x\ny\r\tz\b\f\v\\",'e\u0301 😀  ',
    b'',b'\x00\xff',9007199254740993,-9223372036854775808,-0.0,1.0000000000000002,5e-324,
])
def test_cell_bytes_not_reinterpreted_as_psql_or_rounded(tmp_path,monkeypatch,value):
    row=dict(id='x',hash=value,prev_hash=None,seq=7,ts_unix_ns=9007199254740993)
    data=run_fixture(tmp_path,monkeypatch,[row]); gen=chunks(data)
    assert next(gen).startswith(b'COPY public."audit_events"(')
    expected=('\t'.join(owner.copy_cell(row[c]) for c in sorted(row))+'\n').encode()
    assert next(gen)==expected
    assert b'\r' not in expected[:-1] and b'\n' not in expected[:-1]
    gen.close(); assert gen.gi_frame is None


@pytest.mark.parametrize('value,exception,reason',[
    (True,GuardFailure,'import_copy_scalar_unsupported'),
    (False,GuardFailure,'import_copy_scalar_unsupported'),
    (float('nan'),GuardFailure,'import_copy_nonfinite_float'),
    (float('inf'),GuardFailure,'import_copy_nonfinite_float'),
    ('x\x00',GuardFailure,'import_copy_text_nul_unsupported'),
    ({},GuardFailure,'import_copy_scalar_unsupported'),
    ('\ud800',UnicodeEncodeError,None),
])
def test_bad_scalar_preserves_exception_and_never_emits_row(tmp_path,monkeypatch,value,exception,reason):
    data=run_fixture(tmp_path,monkeypatch,[dict(id='x',hash=value,prev_hash=None,seq=7,ts_unix_ns=1)])
    gen=chunks(data); next(gen)
    with pytest.raises(exception) as error: next(gen)
    if reason: assert str(error.value)==reason
    assert gen.gi_frame is None


@pytest.mark.parametrize('budget',['row','total_rows','total_bytes','deadline'])
def test_partial_budget_failure_keeps_header_but_no_row_or_success(tmp_path,monkeypatch,budget):
    data=run_fixture(tmp_path,monkeypatch,[dict(id='x',hash='',prev_hash=None,seq=7,ts_unix_ns=1)])
    if budget=='row': monkeypatch.setattr(owner,'MAX_COPY_ROW',0)
    if budget=='total_rows': monkeypatch.setattr(owner,'MAX_ROWS',0)
    if budget=='total_bytes': monkeypatch.setattr(owner,'MAX_SCAN_BYTES',0)
    gen=chunks(data,time.monotonic()-1 if budget=='deadline' else None)
    assert next(gen).startswith(b'COPY ')
    with pytest.raises(GuardFailure,match='^import_copy_budget_or_window_exceeded$'): next(gen)


@pytest.mark.parametrize('budget',['row','total_rows','total_bytes'])
def test_exact_inclusive_budget_has_no_off_by_one(tmp_path,monkeypatch,budget):
    row=dict(id='x',hash='',prev_hash=None,seq=7,ts_unix_ns=1)
    data=run_fixture(tmp_path,monkeypatch,[row]); raw=('\t'.join(owner.copy_cell(row[c]) for c in sorted(row))+'\n').encode()
    monkeypatch.setattr(owner,{'row':'MAX_COPY_ROW','total_rows':'MAX_ROWS','total_bytes':'MAX_SCAN_BYTES'}[budget],1 if budget=='total_rows' else len(raw))
    assert list(chunks(data))[-1]==b"SELECT json_build_object('kind','copied')::jsonb;\n"


def test_lazy_snapshot_precedes_bad_coverage_and_connection(tmp_path,monkeypatch):
    data=run_fixture(tmp_path,monkeypatch); data[1]['sha256']='0'*64; data[-1].clear()
    calls=[]; original=owner.verify_snapshot
    def verify(*args): calls.append(args[1]); return original(*args)
    monkeypatch.setattr(owner,'verify_snapshot',verify)
    monkeypatch.setattr(owner.sqlite3,'connect',lambda *a,**k:pytest.fail('no connection before admission'))
    gen=chunks(data); assert calls==[]
    with pytest.raises(GuardFailure,match='^snapshot_sha256_mismatch$'): next(gen)
    assert calls==['0'*64]


@pytest.mark.parametrize('after_header',[True,False])
def test_cancel_closes_only_owned_sqlite_and_skips_final_source_marker(tmp_path,monkeypatch,after_header):
    data=run_fixture(tmp_path,monkeypatch); original=owner.sqlite3.connect; handles=[]; verifies=[]; verify=owner.verify_snapshot
    class Tracked:
        def __init__(self,*args,**kwargs): self.db=original(*args,**kwargs); self.closed=False; handles.append(self)
        def __getattr__(self,name): return getattr(self.db,name)
        def close(self): self.closed=True; self.db.close()
    monkeypatch.setattr(owner.sqlite3,'connect',Tracked)
    monkeypatch.setattr(owner,'verify_snapshot',lambda *a:(verifies.append(a[1]),verify(*a))[1])
    gen=chunks(data); next(gen)
    if not after_header: next(gen)
    locals_=gen.gi_frame.f_locals
    assert locals_['rows']==(0 if after_header else 1)
    assert all(locals_['left'][t['table']] is t for t in data[1]['tables'] if not t['metadata_only'])
    gen.close(); assert handles[0].closed and len(verifies)==1 and gen.gi_frame is None


def test_final_source_change_rejects_after_terminators_without_success(tmp_path,monkeypatch):
    data=run_fixture(tmp_path,monkeypatch); gen=chunks(data); parts=[]
    while parts.count(b'\\.\n')<3: parts.append(next(gen))
    with closing(sqlite3.connect(data[0])) as writer,writer:
        writer.execute("UPDATE business_state SET note='synthetic-changed-after-scan'")
    with pytest.raises(GuardFailure,match='^snapshot_sha256_mismatch$'): next(gen)
    assert not any(p.startswith(b'SELECT ') for p in parts)


def test_metadata_excluded_and_last_duplicate_table_object_preserved(tmp_path,monkeypatch):
    data=run_fixture(tmp_path,monkeypatch,[])
    data[1]['tables'].append(dict(table='ignored_history',metadata_only=True))
    data[2]['tables'].append(dict(table='different_ignored_history',metadata_only=True))
    last=dict(data[1]['tables'][0]); data[1]['tables'].append(last)
    right=dict(data[2]['tables'][0]); data[2]['tables'].append(right)
    seen=[]
    def project(db,left,target,mappings): seen.append((left,target)); return iter([])
    monkeypatch.setattr(owner,'projected_rows',project)
    list(chunks(data)); assert seen[0][0] is last and seen[0][1] is right
