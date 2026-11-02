"""Reuse exact typed digests inside the open import transaction, including histories."""
from .row_digest import ALGORITHM
from .snapshot import GuardFailure
from .target_content import TargetReader, comparison_issues, data_sql


class ImportContentReader(TargetReader):
    def __init__(self,config,target,deadline):
        super().__init__(config,{},None,deadline)
        self.target,self.stage=target,'tables'
        self.names=sorted(t['table'] for t in target['tables'])

    def accept(self,frame,stream):
        if frame.get('kind')=='complete':
            if set(frame)!={'kind','read_only','isolation'} or self.digest is not None or len(self.tables)!=len(self.names):
                raise GuardFailure('import_content_completion_missing')
            if frame['read_only']!='off' or frame['isolation']!='repeatable read':
                raise GuardFailure('import_content_transaction_not_verified')
            self.stage='complete'
            return
        super().accept(frame,stream)

    def evidence(self,metadata):
        names={t['table'] for t in self.target['tables'] if t['metadata_only']==metadata}
        tables=[t for t in self.tables if t['table'] in names]
        return dict(algorithm=ALGORITHM,tables=tables,rows=sum(t['rows'] for t in tables),scanned_bytes=sum(t['scanned_bytes'] for t in tables))


def begin_content(stream,config,target,deadline):
    reader=ImportContentReader(config,target,deadline)
    stream.send(data_sql(target,include_metadata=True,transaction_end=False))
    return reader


def verify_import_content(expected,baseline,actual):
    issues=comparison_issues(expected,actual.evidence(False))
    issues+=comparison_issues(baseline.evidence(True),actual.evidence(True))
    if issues:
        raise GuardFailure('import_content_or_native_history_mismatch')
