"""Bounded full-duplex owned process; no SQL/row/secret diagnostic disclosure."""
from contextlib import closing
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops/scripts'))
from migration_guard.snapshot import GuardFailure
from migration_guard.content_stream import PsqlStream


def stream(code,timeout=2):
    return PsqlStream([sys.executable,'-u','-c',code],os.environ.copy(),timeout=timeout)


def test_normal_packets_and_normal_process_exit_are_required():
    with closing(stream("import sys;sys.stdin.read();print('{\"kind\":\"complete\"}')")) as child:
        child.send('SELECT 1;\n',final=True)
        assert list(child)==[dict(kind='complete')]
    with closing(stream("import sys;sys.stdin.read();print('{\"kind\":\"complete\"}');sys.exit(3)")) as child:
        child.send('SELECT 1;\n',final=True)
        with pytest.raises(GuardFailure,match='diagnostics_withheld'):
            list(child)


@pytest.mark.parametrize('code', [
    "import sys;sys.stdin.read();print('not-json synthetic-private-value')",
    "import sys;sys.stdin.read();print('{\"kind\":1,\"kind\":2}')",
    "import sys;sys.stdin.read();print('[]')",
    "import sys;sys.stdin.read();sys.stdout.write('{\"kind\":\"row\"}')",
    "import sys;sys.stdin.read();sys.stderr.write('synthetic-private-password');sys.exit(1)",
    "import sys;sys.stdin.read();sys.stdout.buffer.write(b'x'*((2<<20)+1))",
    "import sys;sys.stdin.read();sys.stderr.buffer.write(b'x'*((8<<10)+1))"])
def test_invalid_truncated_or_excessive_frames_are_closed(code):
    with closing(stream(code)) as child:
        child.send('SELECT 1;\n',final=True)
        with pytest.raises(GuardFailure) as error:
            list(child)
        assert 'synthetic-private' not in str(error.value)
    assert child.child.poll() is not None


def test_wall_input_and_total_output_budgets_fail(monkeypatch):
    with closing(stream('import time;time.sleep(5)',timeout=.1)) as child:
        child.send('SELECT 1;\n',final=True)
        with pytest.raises(GuardFailure,match='timeout'): list(child)
    with closing(stream('import sys;sys.stdin.read()')) as child:
        with pytest.raises(GuardFailure,match='input_budget'): child.send('x'*4097+'\n')
    import migration_guard.content_stream as transport
    monkeypatch.setattr(transport,'MAX_WIRE_BYTES',len(b'{"kind":"complete"}\n')-1)
    with closing(stream("import sys;sys.stdin.read();print('{\"kind\":\"complete\"}')")) as child:
        child.send('SELECT 1;\n',final=True)
        with pytest.raises(GuardFailure,match='output_budget'): list(child)


def test_send_after_identity_can_continue_without_pipe_deadlock():
    code="import sys;sys.stdin.readline();print('{\"kind\":\"identity\"}',flush=True);body=sys.stdin.read();print('{\"kind\":\"complete\"}',flush=True)"
    with closing(stream(code)) as child:
        child.send('SELECT 1;\n')
        packets=iter(child)
        assert next(packets)==dict(kind='identity')
        child.send(('SELECT 1;\n'*4000)+'COMMIT;\n',final=True)
        assert list(packets)==[dict(kind='complete')]
