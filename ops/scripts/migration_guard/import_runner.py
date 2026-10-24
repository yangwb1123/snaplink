"""One-shot owned-candidate import: verify before COMMIT; never retry uncertain writes."""
from contextlib import closing
import time

from .declared_fk import foreign_key_sql, relationship_evidence
from .import_admission import AdmissionReader, bootstrap_import_sql
from .import_content import begin_content, verify_import_content
from .import_copy import copy_chunks
from .import_intent import load_intent
from .import_stream import ImportStream
from .postgres import connection_file
from .conversion_policy import load_policy
from .client_policy_defaults import validate_client_defaults
from .schema_contract import load_contract
from .sequence import sequence_evidence
from .snapshot import GuardFailure, identifier, verify_snapshot
from .target_schema import SchemaReader


def remaining(deadline):
    value=deadline-time.monotonic()
    if value<=0:
        raise GuardFailure('import_whole_window_exceeded')
    return value


class ImportExecution:
    def __init__(self,args,inputs,journal,deadline):
        self.args,self.inputs,self.journal,self.deadline=args,inputs,journal,deadline
        self.admission=AdmissionReader(inputs['config'],inputs['target'],inputs['contract'])
        self.stage='admission'
        self.baseline,self.actual,self.restart=None,None,None
        self.commit_requested,self.commit_ack=False,False

    def start_baseline(self,stream):
        self.baseline=begin_content(stream,self.inputs['config'],self.admission.target,self.deadline)
        self.stage='baseline'

    def copy(self,stream):
        if any(t['rows'] for t in self.baseline.evidence(False)['tables']):
            raise GuardFailure('import_locked_target_not_empty')
        validate_client_defaults(self.inputs['source'],self.admission.target,self.inputs['plan']['mappings'])
        self.journal.append('copy_started')
        stream.queue(copy_chunks(self.args.snapshot,self.inputs['source'],self.admission.target,
                                  self.inputs['plan']['mappings'],self.admission.order(),self.deadline))
        self.stage='copy'

    def verify(self,stream):
        verify_import_content(self.inputs['expected'],self.baseline,self.actual)
        self.admission.fk_rows=[]
        self.admission.scanned=0
        sql='\n'.join(foreign_key_sql(name,record) for name,record in self.admission.expected_fks)
        stream.send(sql+"\nSELECT json_build_object('kind','verified')::jsonb;\n")
        self.stage='foreign_keys'

    def recheck_inputs(self):
        verify_snapshot(self.args.snapshot,self.inputs['source']['sha256'])
        if connection_file(self.args.target_connection_file)!=self.inputs['config']:
            raise GuardFailure('import_connection_changed')
        if load_policy(self.args.conversion_policy_file)!=self.inputs['policy']:
            raise GuardFailure('import_policy_changed')
        if load_contract(self.args.schema_contract_file,self.args.schema_contract_sha256)!=self.inputs['contract']:
            raise GuardFailure('import_contract_changed')
        if load_intent(self.args.intent_file,self.args.intent_sha256)!=self.inputs['intent']:
            raise GuardFailure('import_intent_changed')
        remaining(self.deadline)

    def restart_sequence(self,stream):
        if len(self.admission.fk_rows)!=len(self.admission.expected_fks) or relationship_evidence(self.admission.fk_rows)['blockers']:
            raise GuardFailure('import_postcopy_foreign_key_validation_failed')
        self.recheck_inputs()
        self.journal.append('verified_uncommitted',rows=self.actual.evidence(False)['rows'])
        floor=self.inputs['floor']
        sequence='public.'+identifier(self.admission.sequence['name'])
        stream.send('ALTER SEQUENCE '+sequence+' RESTART WITH '+str(floor)+';\n'
                    "SELECT json_build_object('kind','restart','last_value',last_value,'is_called',is_called)::jsonb FROM "+sequence+';\n')
        self.stage='restart'

    def request_commit(self,frame,stream):
        if set(frame)!={'kind','last_value','is_called'} or frame['last_value']!=self.inputs['floor'] or frame['is_called'] is not False:
            raise GuardFailure('import_transactional_sequence_restart_not_verified')
        state={k:frame[k] for k in ('last_value','is_called')}
        self.restart=sequence_evidence(self.admission.sequence,state,self.inputs['floor'])
        self.recheck_inputs()
        self.journal.append('commit_requested')  # Persist ambiguity before sending COMMIT.
        self.commit_requested=True
        stream.send("COMMIT;\nSELECT json_build_object('kind','committed','attempt','"+self.journal.attempt+"')::jsonb;\n",final=True)
        self.stage='commit'

    def accept(self,frame,stream):
        remaining(self.deadline)
        kind=frame.get('kind')
        if self.stage=='admission':
            self.admission.accept(frame,stream)
            if self.admission.stage=='complete': self.start_baseline(stream)
        elif self.stage=='baseline':
            self.baseline.accept(frame,stream)
            if self.baseline.stage=='complete': self.copy(stream)
        elif self.stage=='copy' and frame=={'kind':'copied'}:
            self.actual=begin_content(stream,self.inputs['config'],self.admission.target,self.deadline)
            self.stage='content'
        elif self.stage=='content':
            self.actual.accept(frame,stream)
            if self.actual.stage=='complete': self.verify(stream)
        else:
            self.accept_commit_protocol(frame,stream,kind)

    def accept_commit_protocol(self,frame,stream,kind):
        if self.stage=='foreign_keys' and kind=='foreign_key':
            SchemaReader.foreign_key(self.admission,frame)
        elif self.stage=='foreign_keys' and frame=={'kind':'verified'}:
            self.restart_sequence(stream)
        elif self.stage=='restart' and kind=='restart':
            self.request_commit(frame,stream)
        elif self.stage=='commit' and frame==dict(kind='committed',attempt=self.journal.attempt):
            self.commit_ack,self.stage=True,'complete'
        else:
            raise GuardFailure('import_frame_order_or_coverage_invalid')

    def run(self):
        with closing(ImportStream(self.inputs['config'],remaining(self.deadline))) as stream:
            stream.send(bootstrap_import_sql(self.inputs['config'],self.inputs['target']))
            for frame in stream:
                self.accept(frame,stream)
        if self.stage!='complete' or not self.commit_ack:
            raise GuardFailure('import_commit_ack_or_normal_exit_missing')
        remaining(self.deadline)
        self.journal.append('committed_acknowledged')
        return dict(result='passed',scope='owned_candidate_transactional_import_only',
                    source_projection=self.inputs['expected'],target_projection=self.actual.evidence(False),
                    native_history_before=self.baseline.evidence(True),native_history_after=self.actual.evidence(True),
                    declared_foreign_keys=relationship_evidence(self.admission.fk_rows),
                    sequence_descriptor=self.admission.sequence,sequence_restart_state=self.restart['state'],
                    sequence_restart_mode='transactional ALTER SEQUENCE RESTART; never setval/nextval',
                    target_content_verified_before_commit=True,native_migration_history_unchanged=True,
                    commit_acknowledged=True,normal_process_exit=True,target_changed=True,
                    rollback_verified=False,raw_rows_or_credentials_in_report=False,
                    whole_execution_window_seconds=60,automatic_retry=False,
                    lock_scope='ACCESS EXCLUSIVE existing public tables and ownership marker; cooperative advisory lock',
                    exclusive_admin_or_global_ddl_fencing_verified=False,candidate_exclusivity_is_caller_claim=True,
                    production_migration_certified=False,cutover_authorized=False,historical_audit_chain_verified=False)
