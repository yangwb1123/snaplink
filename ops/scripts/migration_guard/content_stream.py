"""Bounded full-duplex JSON-line transport, owning only its psql subprocess."""
import json
import os
import selectors
import subprocess
import time

from .snapshot import GuardFailure, MAX_SCAN_BYTES

MAX_WIRE_BYTES = MAX_SCAN_BYTES
MAX_FRAME_BYTES = 2 << 20
MAX_SCRIPT_BYTES = 64 << 10


def unique_frame(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardFailure("invalid_target_content_frame")
        result[key] = value
    return result


class PsqlStream:
    def __init__(self, argv, env, timeout=60):
        self.deadline = time.monotonic() + timeout
        self.child = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ready = selectors.DefaultSelector()
        self.pending, self.buffer = bytearray(), bytearray()
        self.input_bytes, self.output_bytes, self.error_bytes = 0, 0, 0
        self.final, self.closed = False, False
        os.set_blocking(self.child.stdin.fileno(), False)
        self.ready.register(self.child.stdout, selectors.EVENT_READ, "output")
        self.ready.register(self.child.stderr, selectors.EVENT_READ, "error")

    def send(self, script, final=False):
        data = script.encode("utf-8", errors="strict")
        if self.final or self.closed:
            raise GuardFailure("target_content_input_already_closed")
        self.input_bytes += len(data)
        if self.input_bytes > MAX_SCRIPT_BYTES or any(len(statement) > 4096 for statement in data.split(b";")):
            raise GuardFailure("target_content_query_input_budget_exceeded")
        if not self.pending:
            self.ready.register(self.child.stdin, selectors.EVENT_WRITE, "input")
        self.pending.extend(data)
        self.final = final

    def write_pending(self):
        try:
            sent = os.write(self.child.stdin.fileno(), self.pending[:65536])
        except BrokenPipeError as exc:
            raise GuardFailure("target_content_query_failed_diagnostics_withheld") from exc
        del self.pending[:sent]
        if not self.pending:
            self.ready.unregister(self.child.stdin)
            if self.final:
                self.child.stdin.close()

    def read_ready(self, event):
        chunk = os.read(event.fileobj.fileno(), 65536)
        if not chunk:
            self.ready.unregister(event.fileobj)
            return
        if event.data == "error":
            self.error_bytes += len(chunk)
            if self.error_bytes > 8 << 10:
                raise GuardFailure("target_content_query_output_budget_exceeded")
            return
        self.output_bytes += len(chunk)
        if self.output_bytes > MAX_WIRE_BYTES:
            raise GuardFailure("target_content_query_output_budget_exceeded")
        self.buffer.extend(chunk)

    def packets(self):
        while b"\n" in self.buffer:
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            if not line or len(line) > MAX_FRAME_BYTES:
                raise GuardFailure("target_content_frame_budget_or_format_invalid")
            try:
                value = json.loads(line.decode("utf-8", errors="strict"), object_pairs_hook=unique_frame)
            except (ValueError, UnicodeError) as exc:
                raise GuardFailure("invalid_target_content_frame") from exc
            if not isinstance(value, dict):
                raise GuardFailure("invalid_target_content_frame")
            yield value
        if len(self.buffer) > MAX_FRAME_BYTES:
            raise GuardFailure("target_content_query_output_budget_exceeded")

    def __iter__(self):
        while self.ready.get_map():
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise GuardFailure("target_content_query_timeout")
            for event, _ in self.ready.select(min(remaining, .2)):
                if event.data == "input":
                    self.write_pending()
                else:
                    self.read_ready(event)
                    yield from self.packets()
        try:
            code = self.child.wait(timeout=max(.001, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise GuardFailure("target_content_query_timeout") from exc
        if code:
            raise GuardFailure("target_content_query_failed_diagnostics_withheld")
        if self.buffer or not self.final:
            raise GuardFailure("target_content_query_truncated")

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.child.poll() is None:
            self.child.kill()
            self.child.wait(timeout=5)
        self.ready.close()
        for pipe in (self.child.stdin, self.child.stdout, self.child.stderr):
            pipe.close()
