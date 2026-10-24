"""Synthetic order/key fixtures; no deployed IDs, hashes or permissions."""
from contextlib import closing
import hashlib
import json
import sqlite3

from checks.migration_guard_fixture import sample_target
from migration_guard.snapshot import inspect_snapshot


KEYS = ["", "A\x00B", "é", "e\u0301", "😀 ", "quote\"\\N\n"]


def policy_fixture(root):
    root.chmod(0o700)
    path = root / "source.sqlite"
    with closing(sqlite3.connect(path)) as db:
        with db:
            db.execute("CREATE TABLE audit_events(id TEXT PRIMARY KEY,ts_unix_ns INTEGER NOT NULL,hash TEXT,prev_hash TEXT)")
            db.executemany("INSERT INTO audit_events(rowid,id,ts_unix_ns,hash,prev_hash) VALUES(?,?,?,?,?)", [
                (13, "a", 100, "", ""), (7, "z", 100, None, None),
                (99, "b", -5, "stored-not-recomputed", "unchanged")])
            db.execute("CREATE TABLE permissions_resources(id TEXT PRIMARY KEY,dispatch_key TEXT NOT NULL)")
            db.executemany("INSERT INTO permissions_resources VALUES(?,?)", [
                (str(i), key) for i, key in enumerate(KEYS)])
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    source = inspect_snapshot(path, digest)
    target = sample_target(source)
    audit, resources = target["tables"]
    audit["columns"].append(dict(name="seq", type="int8", not_null=True, pk_order=0))
    resources["columns"][1]["type"] = "bytea"
    return path, source, target


def policy_document(source, target):
    from migration_guard.conversion_policy import target_shape_sha256
    return dict(version=1, source_sha256=source["sha256"],
                target_shape_sha256=target_shape_sha256(target), mappings=[
        dict(table="audit_events", column="seq", mode="sqlite_rowid_int8_v1"),
        dict(table="permissions_resources", column="dispatch_key", mode="text_utf8_bytea_v1")])


def private_policy(root, document):
    path = root / "policy.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return path
