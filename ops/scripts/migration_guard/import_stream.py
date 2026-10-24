"""Writer-only bounded incremental pipe input; existing read-only transport unchanged."""
import os

from .content_stream import MAX_SCRIPT_BYTES, PsqlStream
from .postgres import psql_command
from .snapshot import GuardFailure, MAX_SCAN_BYTES


class ImportStream(PsqlStream):
    def __init__(self,config,timeout):
        argv,env=psql_command(config)
        env['PGOPTIONS']='-c default_transaction_read_only=off -c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=15000'
        super().__init__(argv,env,timeout=timeout)
        self.chunks=None
        self.script_bytes,self.copy_bytes=0,0

    def send(self,script,final=False):
        data=script.encode('utf-8',errors='strict')
        self.script_bytes+=len(data)
        if self.script_bytes>MAX_SCRIPT_BYTES or any(len(s)>4096 for s in data.split(b';')):
            raise GuardFailure('import_query_input_budget_exceeded')
        self.queue(iter([data]),final)

    def queue(self,chunks,final=False):
        if self.final or self.closed or self.chunks is not None or self.pending:
            raise GuardFailure('import_input_pending_or_closed')
        self.chunks,self.final=iter(chunks),final
        self.ready.register(self.child.stdin,2,'input')

    def fill_pending(self):
        try:
            data=next(self.chunks)
        except StopIteration:
            self.chunks=None
            self.ready.unregister(self.child.stdin)
            if self.final:
                self.child.stdin.close()
            return
        if not isinstance(data,bytes) or len(data)>2<<20:
            raise GuardFailure('import_copy_frame_budget_or_type_invalid')
        self.copy_bytes+=len(data)
        if self.copy_bytes>MAX_SCAN_BYTES:
            raise GuardFailure('import_total_input_budget_exceeded')
        self.pending.extend(data)

    def write_pending(self):
        if not self.pending:
            self.fill_pending()
        if not self.pending:
            return
        try:
            sent=os.write(self.child.stdin.fileno(),self.pending[:65536])
        except BrokenPipeError as exc:
            raise GuardFailure('import_query_failed_diagnostics_withheld') from exc
        del self.pending[:sent]
        if not self.pending:
            self.fill_pending()

    def close(self):
        if self.chunks is not None and hasattr(self.chunks,'close'):
            self.chunks.close()
        self.chunks=None
        super().close()
