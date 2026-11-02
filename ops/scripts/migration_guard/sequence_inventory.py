"""Complete supported user-sequence catalog/state/next-floor evidence, never calibration."""
from contextlib import closing
import math
import time

from .compare import compare
from .content_stream import PsqlStream
from .postgres import connection_file,psql_command,query_json,verify_target_identity
from .sequence_inventory_records import floor_evidence,validate_inventory,validate_state
from .sequence_inventory_sql import INVENTORY_SQL,inventory_frame_sql,scan_sql,state_sql
from .snapshot import GuardFailure,MAX_ROWS,verify_snapshot
from .target_content import bootstrap_sql,snapshot_catalog,snapshot_identity


def remaining(deadline):
    value=deadline-time.monotonic()
    if value<=0:
        raise GuardFailure('sequence_inventory_inspection_window_exceeded')
    return value


class SequenceReader:
    def __init__(self,config,source,policy,audit_floor):
        self.config,self.source,self.policy,self.audit_floor=config,source,policy,audit_floor
        self.stage,self.target,self.items,self.evidence='identity',None,[],[]
        self.pending,self.scanned=None,0

    def catalog(self,frame,stream):
        self.target['tables']=snapshot_catalog(frame,self.source,self.policy,'verify_sequences')
        self.target.update(counts_tracked_for_business_tables_only=False,counts_tracked_for_sequence_owner_tables_only=True)
        stream.send(inventory_frame_sql())
        self.stage='inventory'

    def inventory(self,frame,stream):
        if set(frame)!={'kind','items'}:
            raise GuardFailure('sequence_inventory_frame_invalid')
        self.items=validate_inventory(frame['items'],self.target)
        stream.send(scan_sql(self.items),final=True)
        self.stage='observations'

    def observation(self,frame):
        if len(self.evidence)>=len(self.items):
            raise GuardFailure('sequence_inventory_extra_observation')
        descriptor=self.items[len(self.evidence)]
        if frame.get('sequence')!=descriptor['name']:
            raise GuardFailure('sequence_inventory_observation_order_invalid')
        if self.pending is None:
            if set(frame)!={'kind','sequence','oid','last_value','is_called'} or frame['kind']!='sequence_state' or frame['oid']!=str(descriptor['oid']):
                raise GuardFailure('sequence_inventory_state_frame_invalid')
            self.pending={k:frame[k] for k in ('last_value','is_called')}
            return
        if set(frame)!={'kind','sequence','rows','nulls','minimum','maximum'} or frame['kind']!='sequence_bounds':
            raise GuardFailure('sequence_inventory_bounds_frame_invalid')
        bounds={k:frame[k] for k in ('rows','nulls','minimum','maximum')}
        evidence=floor_evidence(descriptor,self.pending,bounds,self.audit_floor)
        self.scanned+=bounds['rows']
        if self.scanned>MAX_ROWS:
            raise GuardFailure('sequence_inventory_total_scan_budget_exceeded')
        table=next(t for t in self.target['tables'] if t['table']==descriptor['table'])
        if table['rows'] is not None and table['rows']!=bounds['rows']:
            raise GuardFailure('sequence_inventory_owner_table_count_drift')
        table['rows']=bounds['rows']
        self.evidence.append(evidence);self.pending=None

    def identity(self,frame,stream):
        self.target,self.stage=snapshot_identity(frame,self.config),'catalog'

    def complete(self,frame):
        if set(frame)!={'kind','read_only','isolation'} or frame['kind']!='complete':
            raise GuardFailure('sequence_inventory_frame_order_invalid')
        if self.pending is not None or len(self.evidence)!=len(self.items) or frame['read_only']!='on' or frame['isolation']!='repeatable read':
            raise GuardFailure('sequence_inventory_completion_or_snapshot_invalid')
        self.stage='complete'

    def accept(self,frame,stream):
        if not isinstance(frame,dict) or not isinstance(frame.get('kind'),str):
            raise GuardFailure('sequence_inventory_frame_invalid')
        kind=frame['kind']
        handlers={('identity','identity'):self.identity,('catalog','catalog'):self.catalog,('inventory','sequence_inventory'):self.inventory}
        handler=handlers.get((self.stage,kind))
        if handler is not None:
            handler(frame,stream)
        elif self.stage!='observations':
            raise GuardFailure('sequence_inventory_frame_order_invalid')
        elif kind in ('sequence_state','sequence_bounds'):
            self.observation(frame)
        else:
            self.complete(frame)


def recheck(config,reader,deadline):
    verify_target_identity(config,min(15,remaining(deadline)))
    def query(sql): return query_json(config,sql,min(15,remaining(deadline)))
    if validate_inventory(query(INVENTORY_SQL),reader.target)!=reader.items:
        raise GuardFailure('sequence_inventory_changed_during_inspection')
    for descriptor,evidence in zip(reader.items,reader.evidence):
        expected=dict(sequence=descriptor['name'],oid=str(descriptor['oid']),last_value=str(evidence['state']['last_value']),is_called=evidence['state']['is_called'])
        actual=query(state_sql(descriptor,framed=False))
        if not isinstance(actual,dict) or actual!=expected:
            raise GuardFailure('sequence_inventory_changed_during_inspection')
        validate_state({k:actual[k] for k in ('last_value','is_called')},descriptor)
    if validate_inventory(query(INVENTORY_SQL),reader.target)!=reader.items:
        raise GuardFailure('sequence_inventory_changed_during_inspection')


def verify_sequences(snapshot,connection_path,source,target,policy,timeout=60):
    if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or not 0<timeout<=60:
        raise GuardFailure('sequence_inventory_timeout_invalid')
    deadline=time.monotonic()+timeout
    report=compare(source,target,policy,purpose='verify_sequences')
    if report['result']!='passed':
        raise GuardFailure('sequence_inventory_shape_preflight_failed')
    audit=next((m for m in report['conversion_plan']['mappings'] if m['table']=='audit_events'),None)
    if audit is None:
        raise GuardFailure('sequence_inventory_audit_mapping_required')
    verify_snapshot(snapshot,source['sha256'])
    config=connection_file(connection_path);reader=SequenceReader(config,source,policy,audit['required_next_seq_floor'])
    with closing(PsqlStream(*psql_command(config),timeout=remaining(deadline))) as stream:
        stream.send(bootstrap_sql(config,target,include_metadata=True))
        for frame in stream:
            remaining(deadline);reader.accept(frame,stream)
    if reader.stage!='complete':
        raise GuardFailure('sequence_inventory_completion_missing')
    recheck(config,reader,deadline)
    if connection_file(connection_path)!=config:
        raise GuardFailure('sequence_inventory_connection_changed')
    verify_snapshot(snapshot,source['sha256']);remaining(deadline)
    issues=[issue for e in reader.evidence for issue in e['blockers']]
    return dict(result='failed' if issues else 'passed',blockers=issues,sequences=reader.evidence,sequence_count=len(reader.items),target_snapshot=reader.target,
        scope='all database sequences in every schema enumerated; supported public canonical positive serials and observed floors only',
        supported_inventory_complete=True,supported_sequence_states_observed=True,stable_between_reads=True,owner_column_rows_scanned=reader.scanned,
        read_only=True,raw_rows_ddl_credentials_in_report=False,sequence_advanced_or_reset=False,
        sequence_state_in_mvcc_snapshot=False,cross_query_atomic_snapshot=False,writer_fencing_verified=False,all_sequence_states_verified=False,
        target_content_verified=False,full_ddl_certified=False,audit_chain_verified=False,production_recovery_certified=False,cutover_authorized=False)
