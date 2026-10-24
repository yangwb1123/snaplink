"""Bounded, non-mutating inspection of a private SHA-pinned SQLite backup."""
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import time
from urllib.parse import quote

MAX_SNAPSHOT_BYTES = 64 << 20
MAX_ROWS = 200_000
MAX_SCAN_BYTES = 128 << 20
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")
METADATA_TABLES = {"schema_migrations_" + ns for ns in (
    "account_lockout", "audit", "auth_codes", "clients", "password_credentials",
    "permissions", "refresh_tokens", "revocations", "sessions", "users")}


class GuardFailure(ValueError):
    """A closed precondition failure, never a permission to fall back or copy."""


def private_file(path, limit):
    path = Path(path).absolute()
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        raise GuardFailure("private_regular_owned_file_required")
    if st.st_mode & 0o777 != 0o600 or st.st_size > limit:
        raise GuardFailure("private_file_mode_or_budget_invalid")
    if path.parent.is_symlink() or path.parent.stat().st_uid != os.getuid() or path.parent.stat().st_mode & 0o777 != 0o700:
        raise GuardFailure("private_parent_directory_required")
    return path


def identifier(name):
    if not isinstance(name, str) or not IDENTIFIER.fullmatch(name):
        raise GuardFailure("unsupported_schema_identifier")
    return '"' + name + '"'


def canonical(value):
    if value is None:
        return ["null"]
    if isinstance(value, int):
        return ["integer", str(value)]
    if isinstance(value, float) and math.isfinite(value):
        return ["real", struct.pack("!d", value).hex()]
    if isinstance(value, str):
        return ["text", value]
    if isinstance(value, bytes):
        return ["blob", value.hex()]
    raise GuardFailure("unsupported_or_nonfinite_source_value")


def digest_row(digest, values):
    encoded = json.dumps([canonical(v) for v in values], ensure_ascii=False,
                         separators=(",", ":")).encode()
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return len(encoded)


def audit_rowid_evidence(db, summaries):
    if any(c["name"].lower() in {"rowid", "_rowid_", "oid"} for c in summaries):
        return {"available": False, "reason": "hidden_rowid_shadowed"}
    try:
        db.execute("SELECT _rowid_ FROM audit_events LIMIT 0")
    except sqlite3.OperationalError as exc:
        if str(exc) != "no such column: _rowid_":
            raise
        return {"available": False, "reason": "without_rowid"}
    if not any(c["name"] == "id" for c in summaries):
        return {"available": False, "reason": "audit_id_missing"}
    digest, count, scanned, low, high = hashlib.sha256(), 0, 0, None, None
    for rowid, event_id in db.execute('SELECT _rowid_,id FROM audit_events ORDER BY _rowid_'):
        scanned += digest_row(digest, (rowid, event_id))
        count += 1
        if count > MAX_ROWS or scanned > MAX_SCAN_BYTES:
            raise GuardFailure("source_mapping_scan_budget_exceeded")
        low, high = rowid if low is None else low, rowid
    return {"available": True, "rows": count, "min": low, "max": high,
            "rowid_and_id_sha256": digest.hexdigest()}


def dispatch_byte_evidence(db, summaries):
    if not {"id", "dispatch_key"}.issubset(c["name"] for c in summaries):
        return {"valid_storage": False, "reason": "dispatch_column_missing"}
    digest, count, scanned, total, nulls = hashlib.sha256(), 0, 0, 0, 0
    for resource_id, key in db.execute('SELECT id,dispatch_key FROM permissions_resources ORDER BY id'):
        if key is not None and not isinstance(key, str):
            return {"valid_storage": False, "reason": "dispatch_not_text_or_null"}
        raw = None if key is None else key.encode("utf-8", errors="strict")
        scanned += digest_row(digest, (resource_id, raw))
        total += 0 if raw is None else len(raw)
        nulls += int(raw is None)
        count += 1
        if count > MAX_ROWS or scanned > MAX_SCAN_BYTES:
            raise GuardFailure("source_mapping_scan_budget_exceeded")
    return {"valid_storage": True, "rows": count, "null_rows": nulls,
            "utf8_bytes": total, "id_and_bytes_sha256": digest.hexdigest()}


def column_stats(values, summaries):
    for value, item in zip(values, summaries):
        kind = canonical(value)[0]
        item["storage_classes"][kind] = item["storage_classes"].get(kind, 0) + 1
        if kind == "integer":
            item["min_integer"] = min(value, item.get("min_integer", value))
            item["max_integer"] = max(value, item.get("max_integer", value))
        if kind == "text":
            item["contains_nul"] = item.get("contains_nul", False) or "\x00" in value


def table_inventory(db, name):
    quoted = identifier(name)
    columns = list(db.execute("PRAGMA table_xinfo(" + quoted + ")"))
    if not columns or len(columns) > 80 or any(row[6] for row in columns):
        raise GuardFailure("hidden_or_oversized_source_columns")
    summaries = [{"name": row[1], "type": row[2], "not_null": bool(row[3]),
                  "pk_order": row[5], "storage_classes": {}} for row in columns]
    for col in summaries:
        identifier(col["name"])
    projection = ",".join(identifier(col["name"]) for col in summaries)
    order = ",".join(identifier(col["name"]) for col in sorted(summaries, key=lambda c: c["pk_order"]) if col["pk_order"])
    if not order:
        raise GuardFailure("source_primary_key_required")
    digest = hashlib.sha256()
    count, scanned = 0, 0
    for row in db.execute("SELECT " + projection + " FROM " + quoted + " ORDER BY " + order):
        count, scanned = count + 1, scanned + digest_row(digest, row)
        if count > MAX_ROWS or scanned > MAX_SCAN_BYTES:
            raise GuardFailure("source_table_scan_budget_exceeded")
        column_stats(row, summaries)
    ddl = db.execute("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", (name,)).fetchone()[0]
    table = {"table": name, "rows": count, "columns": summaries,
             "typed_content_sha256": digest.hexdigest(), "ddl_sha256": hashlib.sha256(ddl.encode()).hexdigest(),
             "metadata_only": name in METADATA_TABLES}
    if name == "audit_events":
        table["audit_rowid"] = audit_rowid_evidence(db, summaries)
    if name == "permissions_resources":
        table["dispatch_bytes"] = dispatch_byte_evidence(db, summaries)
    return table


def verify_snapshot(path, expected_sha256):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise GuardFailure("snapshot_sha256_required")
    path = private_file(path, MAX_SNAPSHOT_BYTES)
    if any(Path(str(path) + tail).exists() for tail in ("-wal", "-shm", "-journal")):
        raise GuardFailure("snapshot_has_unaccounted_journal")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    if before != expected_sha256:
        raise GuardFailure("snapshot_sha256_mismatch")
    return path, before


def inspect_snapshot(path, expected_sha256, timeout=60):
    path, before = verify_snapshot(path, expected_sha256)
    deadline = time.monotonic() + timeout
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 5000)
        if [row[0] for row in db.execute("PRAGMA quick_check")] != ["ok"]:
            raise GuardFailure("source_integrity_failed")
        if list(db.execute("PRAGMA foreign_key_check")):
            raise GuardFailure("source_foreign_key_check_failed")
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        if len(names) > 100:
            raise GuardFailure("source_table_budget_exceeded")
        tables = [table_inventory(db, name) for name in names]
        if time.monotonic() >= deadline or sum(t["rows"] for t in tables) > MAX_ROWS:
            raise GuardFailure("source_scan_window_or_total_row_budget_exceeded")
    if hashlib.sha256(path.read_bytes()).hexdigest() != before:
        raise GuardFailure("snapshot_changed_during_inspection")
    return {"sha256": before, "bytes": path.stat().st_size, "tables": tables,
            "read_only": True, "copied": False, "schema_history_is_snapshot_evidence_not_pg_history": True}
