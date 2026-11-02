"""One read-only locked MVCC observation of supported DDL facets and declared FKs."""
from contextlib import closing
import time

from .conversion_policy import target_shape_sha256
from .declared_fk import foreign_key_sql, relationship_evidence, validate_foreign_key
from .postgres import connection_file, psql_command
from .content_stream import PsqlStream
from .schema_contract import schema_issues, validate_contract
from .schema_records import environment_evidence, facet_evidence
from .schema_sql import FACETS, inventory_sql
from .snapshot import GuardFailure, MAX_ROWS, verify_snapshot
from .target_content import bootstrap_sql, snapshot_catalog, snapshot_identity


class SchemaReader:
    def __init__(self, config, source, policy):
        self.config, self.source, self.policy = config, source, policy
        self.stage, self.target = 'identity', None
        self.names, self.facets, self.expected_fks, self.fk_rows = [], {}, [], []
        self.environment, self.scanned = None, 0

    def catalog(self, frame, stream):
        self.target['tables'] = snapshot_catalog(frame, self.source, self.policy, 'verify_schema')
        self.names = sorted(t['table'] for t in self.target['tables'] if not t['metadata_only'])
        stream.send(inventory_sql(self.names))
        self.stage = 'environment'

    def facet(self, frame, stream):
        if frame.get('facet') != list(FACETS)[len(self.facets)]:
            raise GuardFailure('schema_facet_order_invalid')
        self.facets[frame['facet']] = facet_evidence(frame, self.names)
        if len(self.facets) != len(FACETS):
            return
        shapes = {t['table']: t for t in self.target['tables'] if not t['metadata_only']}
        for name in self.names:
            for record in self.facets['constraints'][name]['records']:
                if record['type'] != 'f':
                    continue
                validate_foreign_key(name, record, shapes)
                self.expected_fks.append((name, record))
                if len(self.expected_fks) > 100:
                    raise GuardFailure('schema_total_foreign_key_budget_exceeded')
        sql = '\n'.join(foreign_key_sql(name, record) for name, record in self.expected_fks)
        sql += "\nSELECT json_build_object('kind','complete','read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'))::jsonb;\nCOMMIT;\n"
        stream.send(sql, final=True)
        self.stage = 'foreign_keys'

    def foreign_key(self, frame):
        if set(frame) != {'kind','table','constraint','scanned_rows','violations','validated'} or len(self.fk_rows) >= len(self.expected_fks):
            raise GuardFailure('schema_foreign_key_frame_invalid')
        table, record = self.expected_fks[len(self.fk_rows)]
        if frame['table'] != table or frame['constraint'] != record['name'] or frame['validated'] is not record['validated']:
            raise GuardFailure('schema_foreign_key_frame_order_or_state_invalid')
        if type(frame['scanned_rows']) is not int or type(frame['violations']) is not int or not 0 <= frame['violations'] <= frame['scanned_rows'] <= MAX_ROWS:
            raise GuardFailure('schema_foreign_key_count_or_budget_invalid')
        self.scanned += frame['scanned_rows']
        if self.scanned > MAX_ROWS:
            raise GuardFailure('schema_foreign_key_total_row_budget_exceeded')
        self.fk_rows.append({key:value for key,value in frame.items() if key != 'kind'})

    def identity(self, frame):
        self.target, self.stage = snapshot_identity(frame, self.config), 'catalog'
        self.target.update(counts_tracked_for_business_tables_only=False,table_counts_not_collected_in_schema_snapshot=True)

    def environment_frame(self, frame):
        self.environment, self.stage = environment_evidence(frame['value']), 'facets'

    def complete(self, frame):
        if len(self.fk_rows) != len(self.expected_fks) or frame['read_only'] != 'on' or frame['isolation'] != 'repeatable read':
            raise GuardFailure('schema_completion_or_snapshot_invalid')
        self.stage = 'complete'

    def accept(self, frame, stream):
        kind = frame.get('kind')
        if self.stage == 'identity' and kind == 'identity':
            self.identity(frame)
        elif self.stage == 'catalog' and kind == 'catalog':
            self.catalog(frame, stream)
        elif self.stage == 'environment' and kind == 'environment' and set(frame) == {'kind','value'}:
            self.environment_frame(frame)
        elif self.stage == 'facets' and kind == 'facet':
            self.facet(frame, stream)
        elif self.stage == 'foreign_keys' and kind == 'foreign_key':
            self.foreign_key(frame)
        elif self.stage == 'foreign_keys' and kind == 'complete' and set(frame) == {'kind','read_only','isolation'}:
            self.complete(frame)
        else:
            raise GuardFailure('schema_frame_order_or_coverage_invalid')

    def evidence(self):
        if self.stage != 'complete':
            raise GuardFailure('schema_completion_missing')
        tables = {name:dict(facets={facet:self.facets[facet][name]['sha256'] for facet in FACETS},
                            counts={facet:len(self.facets[facet][name]['records']) for facet in FACETS}) for name in self.names}
        return dict(environment_sha256=self.environment,tables=tables,declared_foreign_keys=relationship_evidence(self.fk_rows),
                    target_snapshot=self.target,read_only=True,raw_ddl_or_row_values_in_report=False,
                    writer_fencing_verified=False,all_business_relationships_verified=False,
                    full_ddl_certified=False,all_sequence_states_verified=False,cutover_authorized=False,
                    schema_baseline_provenance_verified=False,scope='supported native DDL facets and declared FKs only')


def inspect_native_schema(connection_path, source, target, policy, timeout=60):
    config = connection_file(connection_path)
    reader = SchemaReader(config, source, policy)
    with closing(PsqlStream(*psql_command(config), timeout=timeout)) as stream:
        stream.send(bootstrap_sql(config, target))
        for frame in stream:
            reader.accept(frame, stream)
    return reader.evidence()


def verify_schema(snapshot, connection_path, source, target, policy, contract, timeout=60):
    validate_contract(contract)
    if contract['source_sha256'] != source['sha256'] or contract['target_shape_sha256'] != target_shape_sha256(target):
        raise GuardFailure('schema_contract_source_or_shape_mismatch')
    verify_snapshot(snapshot, source['sha256'])
    deadline = time.monotonic() + timeout
    observed = inspect_native_schema(connection_path, source, target, policy, timeout=timeout)
    if target_shape_sha256(observed['target_snapshot']) != contract['target_shape_sha256']:
        raise GuardFailure('schema_contract_locked_shape_mismatch')
    blockers = schema_issues(contract, observed) + observed['declared_foreign_keys']['blockers']
    verify_snapshot(snapshot, source['sha256'])
    if time.monotonic() >= deadline:
        raise GuardFailure('schema_verification_window_exceeded')
    matched = not schema_issues(contract, observed)
    return dict(observed,result='failed' if blockers else 'passed',blockers=blockers,
                target_schema_contract_matched=matched,target_content_verified=False,
                expected_schema_source=contract['schema_source'],content_copied_or_target_changed=False)
