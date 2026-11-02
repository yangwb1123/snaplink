"""SQLite declared FK inventory only: absence never proves business relationships."""
from contextlib import closing
import sqlite3
import time
from urllib.parse import quote

from .snapshot import GuardFailure, identifier, verify_snapshot


def source_foreign_keys(path, source, timeout=60):
    path, digest = verify_snapshot(path, source['sha256'])
    deadline = time.monotonic() + timeout
    records = []
    uri = 'file:' + quote(str(path), safe='/') + '?mode=ro&immutable=1'
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.execute('PRAGMA query_only=ON')
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        for table in source['tables']:
            if table['metadata_only']:
                continue
            rows = list(db.execute('PRAGMA foreign_key_list(' + identifier(table['table']) + ')'))
            if len(rows) > 256:
                raise GuardFailure('source_declared_fk_budget_exceeded')
            for row in rows:
                records.append(dict(table=table['table'],constraint_id=row[0],position=row[1],parent_table=row[2],
                                    child_column=row[3],parent_column=row[4],on_update=row[5],on_delete=row[6],match=row[7]))
                if len(records) > 256:
                    raise GuardFailure('source_declared_fk_total_budget_exceeded')
        if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise GuardFailure('source_foreign_key_check_failed')
    verify_snapshot(path, digest)
    if time.monotonic() >= deadline:
        raise GuardFailure('source_declared_fk_window_exceeded')
    return dict(result='passed' if records else 'not_executed',reason=None if records else 'no_declared_foreign_keys',
                source_sha256=digest,declared_foreign_keys=len({(r['table'],r['constraint_id']) for r in records}),
                column_links=records,read_only=True,all_business_relationships_verified=False,
                scope='SQLite declared foreign keys only; no inferred business references')
