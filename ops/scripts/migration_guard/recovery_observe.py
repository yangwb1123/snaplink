"""Read native PG public business and migration-history tables; not SQLite conversion."""
from contextlib import closing
import math
import time

from .content_stream import PsqlStream
from .conversion_policy import target_shape_sha256
from .postgres import CATALOG_SQL, connection_file, psql_command, query_json, verify_target_identity
from .row_digest import ALGORITHM
from .sequence import inspect_audit_sequence
from .snapshot import GuardFailure
from .target_codec import column_expression
from .target_content import TargetReader, bootstrap_sql, catalog_tables, data_sql
from .target_schema import SchemaReader
from .schema_sql import inventory_sql


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise GuardFailure('recovery_observation_window_exceeded')
    return value


def native_tables(frame, expected_shape):
    if set(frame) != {'kind','tables'}:
        raise GuardFailure('recovery_catalog_frame_invalid')
    tables = catalog_tables(frame['tables'])
    for table in tables:
        if table['relkind'] != 'r' or table['rls_enabled'] is not False or table['force_rls'] is not False:
            raise GuardFailure('recovery_metadata_visibility_or_relation_unsupported')
        for column in table['columns']:
            column_expression(column)
        positions = sorted(c['pk_order'] for c in table['columns'] if c['pk_order'])
        if not positions or positions != list(range(1,len(positions)+1)):
            raise GuardFailure('recovery_primary_key_required_or_invalid')
    if target_shape_sha256(dict(tables=tables)) != expected_shape:
        raise GuardFailure('recovery_locked_shape_mismatch')
    return tables


class RecoveryContentReader(TargetReader):
    def __init__(self, config, target, deadline):
        super().__init__(config, {}, None, deadline)
        self.expected_shape = target_shape_sha256(target)

    def catalog(self, frame, stream):
        self.target['tables'] = native_tables(frame, self.expected_shape)
        self.target['counts_tracked_for_business_tables_only'] = False
        self.target['migration_history_counts_tracked'] = True
        self.names = sorted(t['table'] for t in self.target['tables'])
        stream.send(data_sql(self.target, include_metadata=True), final=True)
        self.stage = 'tables'


class RecoverySchemaReader(SchemaReader):
    def __init__(self, config, target):
        super().__init__(config, {}, None)
        self.expected_shape = target_shape_sha256(target)

    def catalog(self, frame, stream):
        self.target['tables'] = native_tables(frame, self.expected_shape)
        # SchemaReader's FK resolver must cover history too, not silently drop those tables.
        for table in self.target['tables']:
            table['metadata_only'] = False
        self.names = sorted(t['table'] for t in self.target['tables'])
        stream.send(inventory_sql(self.names))
        self.stage = 'environment'


def read_frames(reader, config, target, deadline):
    with closing(PsqlStream(*psql_command(config), timeout=remaining(deadline))) as stream:
        stream.send(bootstrap_sql(config, target, include_metadata=True))
        for frame in stream:
            remaining(deadline)
            reader.accept(frame, stream)
    if reader.stage != 'complete':
        raise GuardFailure('recovery_complete_observation_required')


def observe_native(path, timeout=60):
    if isinstance(timeout, bool) or not isinstance(timeout, (int,float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise GuardFailure('recovery_observation_timeout_invalid')
    deadline = time.monotonic() + timeout
    config = connection_file(path)
    verify_target_identity(config)
    items = query_json(config, CATALOG_SQL, min(15, remaining(deadline)))
    target = dict(tables=catalog_tables(items))
    shape = target_shape_sha256(target)
    native_tables(dict(kind='catalog',tables=items), shape)
    content = RecoveryContentReader(config, target, deadline)
    read_frames(content, config, target, deadline)
    schema = RecoverySchemaReader(config, target)
    read_frames(schema, config, target, deadline)
    audit = inspect_audit_sequence(path, 1, timeout=remaining(deadline))
    sequences = query_json(config,"SELECT coalesce(json_agg(c.relname ORDER BY c.relname),'[]'::json) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S';",min(15,remaining(deadline)))
    if sequences != [audit['descriptor']['name']]:
        raise GuardFailure('recovery_other_sequences_unsupported')
    remaining(deadline)
    if connection_file(path) != config:
        raise GuardFailure('recovery_connection_changed')
    ddl = schema.evidence()
    if ddl['declared_foreign_keys']['blockers']:
        raise GuardFailure('recovery_declared_foreign_key_validation_failed')
    return dict(target_shape_sha256=shape,content=dict(algorithm=ALGORITHM,tables=content.tables,rows=content.rows,scanned_bytes=content.scanned),
                schema={k:ddl[k] for k in ('environment_sha256','tables')},audit_sequence={k:audit[k] for k in ('descriptor','state')},
                declared_foreign_keys=ddl['declared_foreign_keys'])
