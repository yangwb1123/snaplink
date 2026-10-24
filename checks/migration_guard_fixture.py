"""Synthetic fixtures only; never contain deployed credentials or row values."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops/scripts"))
from migration_guard.snapshot import inspect_snapshot


def sample_snapshot(root):
    root.chmod(0o700)
    path = root / "source.sqlite"
    with closing(sqlite3.connect(path)) as db:
        with db:
            db.execute("CREATE TABLE buckets(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, quota INTEGER NOT NULL, note TEXT, payload BLOB)")
            db.executemany("INSERT INTO buckets VALUES(?,?,?,?,?)", [
                ("é😀", "tenant-a", 9007199254740993, None, b"\x00\xff"),
                ("key ", "tenant-b", 0, "", b""),
                ("key", "tenant-a", -7, 'quote"\n\\.\n\\N', None)])
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, digest, inspect_snapshot(path, digest)


def sample_target(source):
    target = json.loads(json.dumps(source))
    for table in target["tables"]:
        table["rows"] = 0
        for column in table["columns"]:
            column["type"] = {"TEXT": "text", "INTEGER": "int8", "BLOB": "bytea"}[column["type"]]
            column["not_null"] = column["not_null"] or column["pk_order"] > 0
    target["read_only"] = True
    return target


def connection_config():
    return {"host": "127.0.0.1", "port": 12345, "user": "fixture", "password": "synthetic-private-password",
            "database": "snaplink_mig_synthetic", "owner_token": "a" * 48}


def private_config(root, data):
    root.chmod(0o700)
    path = root / "connection.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path
