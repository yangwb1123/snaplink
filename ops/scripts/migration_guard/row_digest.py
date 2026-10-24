"""Shared exact typed, PK-ordered digest contract for source and target readers."""
import hashlib
import json
import time

from .conversion_policy import SHAPE_FIELDS
from .snapshot import GuardFailure, canonical

ALGORITHM = "pk_sorted_typed_projection_v1"


def encode_values(values):
    if any(isinstance(v, bool) for v in values):
        raise GuardFailure("unsupported_projection_boolean_storage")
    return json.dumps([canonical(v) for v in values], ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8", errors="strict")


def append_bytes(digest, data):
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)


class TableDigest:
    def __init__(self, table, deadline, max_rows, max_bytes):
        self.table, self.deadline = table["table"], deadline
        self.columns = sorted(table["columns"], key=lambda c: c["name"])
        self.keys = sorted((c for c in self.columns if c["pk_order"]), key=lambda c: c["pk_order"])
        if not self.keys:
            raise GuardFailure("projection_primary_key_required")
        self.entries, self.scanned = {}, 0
        self.max_rows, self.max_bytes = max_rows, max_bytes

    def check_window(self):
        if time.monotonic() >= self.deadline:
            raise GuardFailure("projection_scan_window_exceeded")

    def add(self, row):
        self.check_window()
        if set(row) != {c["name"] for c in self.columns}:
            raise GuardFailure("projection_column_coverage_mismatch")
        key_values = [row[c["name"]] for c in self.keys]
        if any(v is None for v in key_values):
            raise GuardFailure("projection_null_primary_key")
        key = encode_values(key_values)
        body = encode_values([row[c["name"]] for c in self.columns])
        self.scanned += len(key) + len(body)
        if key in self.entries:
            raise GuardFailure("projection_duplicate_primary_key")
        self.entries[key] = hashlib.sha256(body).digest()
        if len(self.entries) > self.max_rows or self.scanned > self.max_bytes:
            raise GuardFailure("projection_scan_budget_exceeded")

    def finish(self):
        self.check_window()
        shape = [{field: c[field] for field in SHAPE_FIELDS} for c in self.columns]
        content, primary = hashlib.sha256(), hashlib.sha256()
        append_bytes(content, json.dumps([ALGORITHM, self.table, shape], sort_keys=True, separators=(",", ":")).encode())
        append_bytes(primary, encode_values([c["name"] for c in self.keys]))
        for key in sorted(self.entries):
            append_bytes(primary, key)
            append_bytes(content, key)
            append_bytes(content, self.entries[key])
        self.check_window()
        return dict(table=self.table, rows=len(self.entries), scanned_bytes=self.scanned,
                    projected_columns=shape, primary_key_columns=[c["name"] for c in self.keys],
                    primary_key_set_sha256=primary.hexdigest(), projected_content_sha256=content.hexdigest())
