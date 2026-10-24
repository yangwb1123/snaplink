"""Synthetic unit-only recovery checkpoint, never a real archive/import fixture."""
import hashlib
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard.conversion_policy import target_shape_sha256
from migration_guard.recovery_contract import ALGORITHM
from migration_guard.row_digest import ALGORITHM as CONTENT, TableDigest
from migration_guard.schema_sql import FACETS
from migration_guard.sequence import MAX_INT8


def fixture():
    descriptor=dict(schema='public',name='audit_events_seq_seq',type='int8',start=1,increment=1,min=1,max=MAX_INT8,cache=1,cycle=False,owned_by_column=True,default_matches=True,default_dependents=1,column_identity='')
    shapes=[];tables=[];schema={}
    for name,columns,row in [('audit_events',[('id','text',1),('seq','int8',0)],dict(id='unit-a',seq=7)),
                             ('schema_migrations_audit',[('applied_at','int8',0),('name','text',0),('version','int4',1)],dict(applied_at=9007199254740993,name='unit migration',version=1))]:
        shape=dict(table=name,columns=[dict(name=n,type=t,type_namespace='pg_catalog',not_null=True,pk_order=p) for n,t,p in columns],metadata_only=name.startswith('schema_migrations_'),relkind='r',rls_enabled=False,force_rls=False)
        shapes.append(shape)
        digest=TableDigest(shape,time.monotonic()+60,200000,128<<20);digest.add(row);tables.append(digest.finish())
        schema[name]=dict(facets={k:'a'*64 for k in FACETS},counts={k:(int(name=='audit_events') if k=='sequences' else 1) for k in FACETS})
    raw=b'PGDMP-unit-only-not-real-archive'
    book=dict(version=1,algorithm=ALGORITHM,archive=dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw)),
              source_identity=dict(database='snaplink_mig_unit_source',user='schema_test',owner_sha256='0'*64),
              target_shape_sha256=target_shape_sha256(dict(tables=shapes)),
              content=dict(algorithm=CONTENT,tables=tables,rows=sum(t['rows'] for t in tables),scanned_bytes=sum(t['scanned_bytes'] for t in tables)),
              schema=dict(environment_sha256='b'*64,tables=schema),audit_sequence=dict(descriptor=descriptor,state=dict(last_value=7,is_called=True)))
    return book,dict(tables=shapes),raw
