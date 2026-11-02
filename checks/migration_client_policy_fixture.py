"""Older client rows with explicitly new zero policies, never inferred attributes."""
from contextlib import closing
import hashlib
import sqlite3

from checks.migration_policy_fixture import policy_document, policy_fixture
from migration_guard.conversion_policy import target_shape_sha256
from migration_guard.snapshot import inspect_snapshot

MODE = 'client_policy_zero_v1'
COLUMNS = {'allow_passwordless_only': 'int4', 'consent_refresh_interval': 'int8', 'skip_consent': 'int4'}
ATTRIBUTES = '{"_snaplink_client_skip_consent":"true","skip_consent":"true","locale":"zh-CN"}'


def fixture(root):
    path, _, target = policy_fixture(root)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE clients(id TEXT PRIMARY KEY, attributes TEXT, note TEXT)')
        db.executemany('INSERT INTO clients VALUES(?,?,?)', [('client-a', ATTRIBUTES, None), ('client-b ', '', '')])
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    columns = [dict(name=n, type='text', not_null=n=='id', pk_order=int(n=='id'), type_namespace='pg_catalog') for n in ('id', 'attributes', 'note')]
    columns += [dict(name=n, type=t, not_null=True, pk_order=0, type_namespace='pg_catalog', canonical_zero_default=True) for n,t in COLUMNS.items()]
    target['tables'].append(dict(table='clients', columns=columns, metadata_only=False, rows=0))
    for table in target['tables']:
        for column in table['columns']:column.setdefault('type_namespace', 'pg_catalog')
    policy = policy_document(source, target)
    policy['version'] = 2
    policy['mappings'] += [dict(table='clients', column=n, mode=MODE) for n in COLUMNS]
    return path, source, target, policy


def repin(policy, source, target):
    policy.update(source_sha256=source['sha256'], target_shape_sha256=target_shape_sha256(target))


def client_table(snapshot):
    return next(t for t in snapshot['tables'] if t['table']=='clients')
