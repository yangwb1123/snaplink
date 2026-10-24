"""Exact bounded COPY text from the SHA-verified immutable SQLite projection."""
from contextlib import closing
import math
import sqlite3
import time
from urllib.parse import quote

from .row_projection import projected_rows
from .client_policy_defaults import validate_client_defaults
from .snapshot import GuardFailure, MAX_ROWS, MAX_SCAN_BYTES, identifier, verify_snapshot

MAX_COPY_ROW = 2 << 20


def copy_cell(value):
    if value is None:
        return r'\N'
    if isinstance(value,bool) or not isinstance(value,(str,bytes,int,float)):
        raise GuardFailure('import_copy_scalar_unsupported')
    if isinstance(value,float) and not math.isfinite(value):
        raise GuardFailure('import_copy_nonfinite_float')
    text = ('\\x'+value.hex()) if isinstance(value,bytes) else str(value)
    if '\x00' in text:
        raise GuardFailure('import_copy_text_nul_unsupported')
    return text.replace('\\','\\\\').replace('\n',r'\n').replace('\r',r'\r').replace('\t',r'\t').replace('\b',r'\b').replace('\f',r'\f').replace('\v',r'\v')


def dependency_order(names, edges):
    remaining={name:set() for name in names}
    for child,parent in edges:
        if child not in remaining or parent not in remaining or child == parent:
            raise GuardFailure('import_foreign_key_dependency_unsupported')
        remaining[child].add(parent)
    ordered=[]
    while remaining:
        ready=sorted(name for name,parents in remaining.items() if not parents)
        if not ready:
            raise GuardFailure('import_foreign_key_cycle_unsupported')
        ordered.extend(ready)
        for name in ready:
            del remaining[name]
        for parents in remaining.values():
            parents.difference_update(ready)
    return ordered


def copy_table_shapes(source, target, order):
    left={t['table']:t for t in source['tables'] if not t['metadata_only']}
    right={t['table']:t for t in target['tables'] if not t['metadata_only']}
    if set(order) != set(left) or len(order) != len(left) or set(left) != set(right):
        raise GuardFailure('import_copy_table_coverage_invalid')
    return left,right


def copy_chunks(path, source, target, mappings, order, deadline):
    path,before=verify_snapshot(path,source['sha256'])
    left,right=copy_table_shapes(source,target,order)
    validate_client_defaults(source,target,mappings)
    uri='file:'+quote(str(path),safe='/')+'?mode=ro&immutable=1'
    rows,scanned=0,0
    with closing(sqlite3.connect(uri,uri=True,timeout=3)) as db:
        db.execute('PRAGMA query_only=ON')
        db.set_progress_handler(lambda:int(time.monotonic() >= deadline),5000)
        for name in order:
            columns=sorted(c['name'] for c in right[name]['columns'])
            yield ('COPY public.'+identifier(name)+'('+','.join(identifier(c) for c in columns)+') FROM STDIN;\n').encode()
            count=0
            for row in projected_rows(db,left[name],right[name],mappings):
                data=('\t'.join(copy_cell(row[c]) for c in columns)+'\n').encode('utf-8',errors='strict')
                count,rows,scanned=count+1,rows+1,scanned+len(data)
                if len(data)>MAX_COPY_ROW or rows>MAX_ROWS or scanned>MAX_SCAN_BYTES or time.monotonic() >= deadline:
                    raise GuardFailure('import_copy_budget_or_window_exceeded')
                yield data
            if count != left[name]['rows']:
                raise GuardFailure('import_copy_source_count_changed')
            yield b'\\.\n'
    verify_snapshot(path,before)
    yield b"SELECT json_build_object('kind','copied')::jsonb;\n"
