"""Exclusive local durable attempt journal; no replay or rollback inference."""
import json
import os
from pathlib import Path
import secrets

from .snapshot import GuardFailure


class ImportJournal:
    def __init__(self,path,source_sha,intent_sha):
        path=Path(path).absolute()
        parent=path.parent
        if parent.is_symlink() or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode & 0o777 != 0o700:
            raise GuardFailure('import_private_journal_directory_required')
        self.fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.attempt=secrets.token_hex(24)
        self.events=0
        try:
            self.append('prepared',source_sha256=source_sha,intent_sha256=intent_sha)
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        except BaseException:
            self.close()
            raise

    def append(self,phase,**facts):
        if self.events>=16:
            raise GuardFailure('import_journal_event_budget_exceeded')
        data=(json.dumps(dict(attempt=self.attempt,phase=phase,**facts),sort_keys=True)+'\n').encode()
        view=memoryview(data)
        while view:
            count=os.write(self.fd,view)
            if not count:
                raise GuardFailure('import_journal_persist_failed')
            view=view[count:]
        os.fsync(self.fd)
        self.events+=1

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd=None
