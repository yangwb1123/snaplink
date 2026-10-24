"""Byte-pinned readonly inspection, exact scalar classes, and closed budgets."""
import hashlib
import sqlite3

import pytest

from checks.migration_guard_fixture import sample_snapshot
from migration_guard import snapshot
from migration_guard.snapshot import GuardFailure, canonical, inspect_snapshot


def test_source_digest_and_scalar_classes_are_exact(tmp_path):
    path, digest, source = sample_snapshot(tmp_path)
    assert source["sha256"] == digest
    assert source["read_only"] and not source["copied"]
    columns = {c["name"]: c for c in source["tables"][0]["columns"]}
    assert columns["quota"]["max_integer"] == 9007199254740993
    assert columns["quota"]["min_integer"] == -7
    assert columns["note"]["storage_classes"] == {"text": 2, "null": 1}
    assert columns["payload"]["storage_classes"] == {"blob": 2, "null": 1}
    assert canonical(None) != canonical("") != canonical(b"")
    assert canonical(0) != canonical(0.0)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert not any(tmp_path.glob("source.sqlite-*"))


def test_bad_sha_journal_and_modes_reject(tmp_path):
    path, digest, _ = sample_snapshot(tmp_path)
    with pytest.raises(GuardFailure, match="snapshot_sha256_mismatch"):
        inspect_snapshot(path, "0" * 64)
    with pytest.raises(GuardFailure, match="snapshot_sha256_required"):
        inspect_snapshot(path, "")
    journal = tmp_path / "source.sqlite-wal"
    journal.write_bytes(b"synthetic journal")
    with pytest.raises(GuardFailure, match="unaccounted_journal"):
        inspect_snapshot(path, digest)
    journal.unlink()
    path.chmod(0o644)
    with pytest.raises(GuardFailure, match="file_mode"):
        inspect_snapshot(path, digest)


def test_symlink_and_hardlink_reject(tmp_path):
    path, digest, _ = sample_snapshot(tmp_path)
    link = tmp_path / "linked.sqlite"
    link.symlink_to(path)
    with pytest.raises(GuardFailure, match="regular_owned"):
        inspect_snapshot(link, digest)
    import os
    os.link(path, tmp_path / "hard.sqlite")
    with pytest.raises(GuardFailure, match="regular_owned"):
        inspect_snapshot(path, digest)


def test_scan_budget_and_missing_pk_reject(tmp_path, monkeypatch):
    path, digest, _ = sample_snapshot(tmp_path)
    monkeypatch.setattr(snapshot, "MAX_ROWS", 1)
    with pytest.raises(GuardFailure, match="scan_budget"):
        inspect_snapshot(path, digest)
    monkeypatch.setattr(snapshot, "MAX_ROWS", 200000)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unkeyed(value TEXT)")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(GuardFailure, match="primary_key_required"):
        inspect_snapshot(path, digest)


def test_unknown_metadata_prefix_is_not_exempt(tmp_path):
    path, _, _ = sample_snapshot(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE schema_migrations_secret_business(id INTEGER PRIMARY KEY)")
        db.execute("INSERT INTO schema_migrations_secret_business VALUES (7)")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    source = inspect_snapshot(path, digest)
    table = next(t for t in source["tables"] if t["table"] == "schema_migrations_secret_business")
    assert table["rows"] == 1 and not table["metadata_only"]


def test_inspection_closes_owned_connection_on_success_and_rejection(tmp_path, monkeypatch):
    path, digest, _ = sample_snapshot(tmp_path)
    original, closes = sqlite3.connect, []
    class Tracked(sqlite3.Connection):
        def close(self):
            closes.append(True)
            return super().close()
    def connect(*args, **kwargs):
        return original(*args, factory=Tracked, **kwargs)
    monkeypatch.setattr(sqlite3, "connect", connect)
    inspect_snapshot(path, digest)
    assert len(closes) == 1
    monkeypatch.setattr(snapshot, "MAX_ROWS", 1)
    with pytest.raises(GuardFailure, match="scan_budget"):
        inspect_snapshot(path, digest)
    assert len(closes) == 2


def test_nul_real_and_nonfinite_are_not_coerced(tmp_path):
    path, _, _ = sample_snapshot(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE buckets SET note=? WHERE id=?", ("nul\x00value", "key"))
        db.execute("CREATE TABLE scalars(id INTEGER PRIMARY KEY, value REAL)")
        db.execute("INSERT INTO scalars VALUES(1,0.125)")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    source = inspect_snapshot(path, digest)
    note = next(c for c in source["tables"][0]["columns"] if c["name"] == "note")
    assert note["contains_nul"]
    assert source["tables"][1]["columns"][1]["storage_classes"] == {"real": 1}
    with pytest.raises(GuardFailure, match="nonfinite"):
        canonical(float("inf"))
