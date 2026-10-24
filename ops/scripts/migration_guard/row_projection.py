"""Expected mapped content, not target-content verification or an import API."""
from contextlib import closing
import sqlite3
import time
from urllib.parse import quote

from .compare import compare
from .client_policy_defaults import client_default_values
from .row_digest import ALGORITHM, TableDigest, encode_values
from .snapshot import (GuardFailure, MAX_ROWS, MAX_SCAN_BYTES,
                       identifier, verify_snapshot)


def projected_rows(db, source, target, mappings):
    names = [c["name"] for c in source["columns"]]
    selected = {(m["table"], m["column"]): m["mode"] for m in mappings}
    audit = selected.get((source["table"], "seq")) == "sqlite_rowid_int8_v1"
    dispatch = selected.get((source["table"], "dispatch_key")) == "text_utf8_bytea_v1"
    defaults = client_default_values(source, target, mappings)
    columns = ",".join(identifier(name) for name in names)
    sql = "SELECT " + columns + (",_rowid_" if audit else "") + " FROM " + identifier(source["table"])
    for values in db.execute(sql):
        row = dict(zip(names, values))
        if audit:
            row["seq"] = values[-1]
        if dispatch and row["dispatch_key"] is not None:
            if not isinstance(row["dispatch_key"], str):
                raise GuardFailure("source_dispatch_storage_invalid")
            row["dispatch_key"] = row["dispatch_key"].encode("utf-8", errors="strict")
        row.update(defaults)
        if set(row) != {c["name"] for c in target["columns"]}:
            raise GuardFailure("projection_column_coverage_mismatch")
        yield row


def project_table(db, source, target, mappings, deadline):
    digest = TableDigest(target, deadline, MAX_ROWS, MAX_SCAN_BYTES)
    for row in projected_rows(db, source, target, mappings):
        digest.add(row)
    evidence = digest.finish()
    if evidence["rows"] != source["rows"]:
        raise GuardFailure("projection_source_row_count_mismatch")
    return evidence


def project_snapshot(path, source, target, policy, timeout=60, *, purpose="preflight"):
    deadline = time.monotonic() + timeout
    if policy is None:
        raise GuardFailure("projection_explicit_policy_required")
    preflight = compare(source, target, policy, purpose=purpose)
    if preflight["result"] != "passed":
        raise GuardFailure("projection_shape_preflight_failed")
    path, before = verify_snapshot(path, source["sha256"])
    left = {t["table"]: t for t in source["tables"] if not t["metadata_only"]}
    right = {t["table"]: t for t in target["tables"] if not t["metadata_only"]}
    mappings = preflight["conversion_plan"]["mappings"]
    tables, rows, scanned = [], 0, 0
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.execute("PRAGMA query_only=ON")
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 5000)
        for name in sorted(left):
            table = project_table(db, left[name], right[name], mappings, deadline)
            rows, scanned = rows + table["rows"], scanned + table["scanned_bytes"]
            if rows > MAX_ROWS or scanned > MAX_SCAN_BYTES:
                raise GuardFailure("projection_total_scan_budget_exceeded")
            tables.append(table)
    verify_snapshot(path, before)
    if time.monotonic() >= deadline:
        raise GuardFailure("projection_scan_window_exceeded")
    return dict(algorithm=ALGORITHM, source_sha256=before, rows=rows, scanned_bytes=scanned,
                policy_content_sha256=preflight["conversion_plan"]["policy_content_sha256"],
                tables=tables, read_only=True, copied=False, target_content_verified=False,
                audit_chain_verified=False, order="encoded typed primary key bytes; no database collation")
