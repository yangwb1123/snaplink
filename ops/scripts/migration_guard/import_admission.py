"""In-transaction catalog/schema admission under exclusive candidate table locks."""
from .conversion_policy import target_shape_sha256
from .declared_fk import foreign_key_sql, relationship_evidence, validate_foreign_key
from .import_copy import dependency_order
from .postgres import CATALOG_SQL
from .recovery_observe import native_tables
from .schema_contract import schema_issues
from .schema_records import environment_evidence, facet_evidence
from .schema_sql import FACETS, inventory_sql
from .sequence import SEQUENCE_SQL, validate_descriptor
from .snapshot import GuardFailure, MAX_ROWS, identifier
from .target_schema import SchemaReader


def bootstrap_import_sql(config,target):
    locks=','.join('public.'+identifier(t['table']) for t in sorted(target['tables'],key=lambda t:t['table']))
    return ("\\set VERBOSITY sqlstate\nBEGIN ISOLATION LEVEL REPEATABLE READ;\n"
            "SET LOCAL search_path=pg_catalog,public;\nSET LOCAL standard_conforming_strings=on;\n"
            "DO $$BEGIN PERFORM pg_advisory_xact_lock(72415217631521); END$$;\n"
            "LOCK TABLE migration_guard.ownership,"+locks+" IN ACCESS EXCLUSIVE MODE;\n"
            "SELECT json_build_object('kind','identity','database',current_database(),'user',current_user,"
            "'owned',(SELECT count(*)=1 AND bool_and(token='"+config['owner_token']+"') FROM migration_guard.ownership),"
            "'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),'version',version())::jsonb;\n"
            "SELECT json_build_object('kind','catalog','tables',("+CATALOG_SQL.strip().removesuffix(';')+"))::jsonb;\n")


class AdmissionReader:
    def __init__(self,config,target,contract):
        self.config,self.shape,self.contract=config,target_shape_sha256(target),contract
        self.stage,self.target='identity',None
        self.names,self.facets,self.expected_fks,self.fk_rows=[],{},[],[]
        self.environment,self.scanned,self.sequence=None,0,None

    def identity(self,frame):
        fields={'kind','database','user','owned','read_only','isolation','version'}
        if set(frame)!=fields or frame['owned'] is not True or frame['read_only']!='off' or frame['isolation']!='repeatable read':
            raise GuardFailure('import_ownership_or_transaction_not_verified')
        if frame['database']!=self.config['database'] or frame['user']!=self.config['user']:
            raise GuardFailure('import_database_or_role_mismatch')
        self.target=dict(identity={k:v for k,v in frame.items() if k!='kind'})
        self.stage='catalog'

    def catalog(self,frame,stream):
        self.target['tables']=native_tables(frame,self.shape)
        self.names=sorted(t['table'] for t in self.target['tables'])
        stream.send(inventory_sql(self.names))
        self.stage='environment'

    def finish_facets(self,stream):
        shapes={t['table']:t for t in self.target['tables']}
        for name in self.names:
            for record in self.facets['constraints'][name]['records']:
                if record['type']=='f':
                    validate_foreign_key(name,record,shapes)
                    self.expected_fks.append((name,record))
        if len(self.expected_fks)>100:
            raise GuardFailure('import_foreign_key_budget_exceeded')
        if schema_issues(self.contract,self.business_schema()):
            raise GuardFailure('import_pinned_schema_mismatch')
        for name in self.names:
            sequences=self.facets['sequences'][name]['records']
            if len(sequences)!=int(name=='audit_events'):
                raise GuardFailure('import_other_sequences_unsupported')
        sql='\n'.join(foreign_key_sql(name,record) for name,record in self.expected_fks)
        sql+="\nSELECT json_build_object('kind','sequence_descriptor','value',("+SEQUENCE_SQL.strip().removesuffix(';')+"))::jsonb;\n"
        stream.send(sql)
        self.stage='foreign_keys'

    def business_schema(self):
        names=[t['table'] for t in self.target['tables'] if not t['metadata_only']]
        return dict(environment_sha256=self.environment,tables={name:dict(facets={facet:self.facets[facet][name]['sha256'] for facet in FACETS}) for name in names})

    def accept(self,frame,stream):
        kind=frame.get('kind')
        if self.stage=='identity' and kind=='identity':
            self.identity(frame)
        elif self.stage=='catalog' and kind=='catalog':
            self.catalog(frame,stream)
        elif self.stage=='environment' and kind=='environment' and set(frame)=={'kind','value'}:
            self.environment,self.stage=environment_evidence(frame['value']),'facets'
        elif self.stage=='facets' and kind=='facet' and frame.get('facet')==list(FACETS)[len(self.facets)]:
            self.facets[frame['facet']]=facet_evidence(frame,self.names)
            if len(self.facets)==len(FACETS):
                self.finish_facets(stream)
        else:
            self.accept_sequence_admission(frame,stream,kind)

    def accept_sequence_admission(self,frame,stream,kind):
        if self.stage=='foreign_keys' and kind=='foreign_key':
            SchemaReader.foreign_key(self,frame)
        elif self.stage=='foreign_keys' and kind=='sequence_descriptor' and set(frame)=={'kind','value'}:
            if len(self.fk_rows)!=len(self.expected_fks) or relationship_evidence(self.fk_rows)['blockers']:
                raise GuardFailure('import_declared_foreign_key_validation_failed')
            self.sequence=validate_descriptor(frame['value'])
            stream.send("SELECT json_build_object('kind','public_sequences','names',coalesce(json_agg(c.relname ORDER BY c.relname),'[]'::json))::jsonb FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S';\n")
            self.stage='sequences'
        elif self.stage=='sequences' and set(frame)=={'kind','names'} and kind=='public_sequences':
            if frame['names'] != [self.sequence['name']]:
                raise GuardFailure('import_other_public_sequences_unsupported')
            self.stage='complete'
        else:
            raise GuardFailure('import_admission_frame_order_or_coverage_invalid')

    def order(self):
        names=[t['table'] for t in self.target['tables'] if not t['metadata_only']]
        edges=[(name,record['parent_table']) for name,record in self.expected_fks if name in names]
        return dependency_order(names,edges)
