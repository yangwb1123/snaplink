"""Real private SQLite scans; no timestamp sorting, JSON normalization or filling."""
import hashlib
import json
import sqlite3

import pytest

from checks.migration_policy_fixture import KEYS, policy_document, policy_fixture, private_policy
from migration_guard import cli, snapshot
from migration_guard.compare import compare
from migration_guard.snapshot import GuardFailure, inspect_snapshot


def independent_digest(rows):
    digest = hashlib.sha256()
    for row in rows:
        raw = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode()
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def test_order_is_hidden_rowid_not_id_timestamp_or_row_number(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    proof = source["tables"][0]["audit_rowid"]
    expected = [[["integer", str(i)], ["text", key]] for i, key in [(7, "z"), (13, "a"), (99, "b")]]
    assert proof["rowid_and_id_sha256"] == independent_digest(expected)
    dispatch = source["tables"][1]["dispatch_bytes"]
    expected = [[["text", str(i)], ["blob", key.encode("utf-8").hex()]] for i, key in enumerate(KEYS)]
    assert dispatch["id_and_bytes_sha256"] == independent_digest(expected)
    assert KEYS[2].encode() != KEYS[3].encode()
    assert compare(source, target, policy_document(source, target))["result"] == "passed"


@pytest.mark.parametrize("variant", ["WITHOUT ROWID", "shadow"])
def test_unavailable_or_shadowed_rowid_never_gets_synthetic_sequence(tmp_path, variant):
    path, _, target = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE audit_events")
        extra = ", rowid INTEGER" if variant == "shadow" else ""
        suffix = " WITHOUT ROWID" if variant == "WITHOUT ROWID" else ""
        db.execute("CREATE TABLE audit_events(id TEXT PRIMARY KEY,ts_unix_ns INTEGER NOT NULL,hash TEXT,prev_hash TEXT"+extra+")"+suffix)
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    assert source["tables"][0]["audit_rowid"]["available"] is False
    with pytest.raises(GuardFailure, match="rowid_evidence"):
        compare(source, target, policy_document(source, target))


def test_empty_audit_proves_no_maximum_and_separate_next_seq_floor(tmp_path):
    path, _, target = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM audit_events")
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    plan = compare(source, target, policy_document(source, target))["conversion_plan"]["mappings"][0]
    assert plan["source_rowid_min"] is None and plan["source_rowid_max"] is None
    assert plan["rows"] == 0 and plan["required_next_seq_floor"] == 1
    assert not plan["sequence_reset_executed"]


def test_null_dispatch_is_not_empty_bytes_or_a_notnull_waiver(tmp_path):
    path, _, target = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE permissions_resources")
        db.execute("CREATE TABLE permissions_resources(id TEXT PRIMARY KEY,dispatch_key TEXT)")
        db.executemany("INSERT INTO permissions_resources VALUES(?,?)", [("null", None), ("empty", "")])
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    report = compare(source, target, policy_document(source, target))
    assert report["result"] == "failed"
    assert {b["code"] for b in report["blockers"]} == {"source_null_rejected_by_target"}
    plan = report["conversion_plan"]["mappings"][1]
    assert plan["null_rows"] == 1 and plan["utf8_bytes"] == 0


def test_invalid_utf8_text_cannot_be_replacement_decoded(tmp_path):
    path, _, _ = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE permissions_resources SET dispatch_key=CAST(x'80' AS TEXT) WHERE id='1'")
    with pytest.raises(sqlite3.Error):
        inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_supplemental_scan_budgets_are_not_relaxed(tmp_path, monkeypatch):
    path, _, _ = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        monkeypatch.setattr(snapshot, "MAX_ROWS", 1)
        with pytest.raises(GuardFailure, match="mapping_scan_budget"):
            snapshot.audit_rowid_evidence(db, [{"name": "id"}])
        with pytest.raises(GuardFailure, match="mapping_scan_budget"):
            snapshot.dispatch_byte_evidence(db, [{"name": "id"}, {"name": "dispatch_key"}])


def test_cli_policy_is_explicit_and_bad_contract_never_writes_report(tmp_path, monkeypatch, capsys):
    path, source, target = policy_fixture(tmp_path)
    policy = private_policy(tmp_path, policy_document(source, target))
    monkeypatch.setattr(cli, "inspect_target", lambda _: target)
    args = ["--snapshot", str(path), "--snapshot-sha256", source["sha256"],
            "--target-connection-file", "not-a-real-fixture", "--report", str(tmp_path/"report.json")]
    assert cli.main(args+["--conversion-policy-file", str(policy)]) == 0
    assert json.loads((tmp_path/"report.json").read_text())["conversion_plan"]["apply_supported"] is False
    bad = json.loads(policy.read_text())
    bad["approved"] = True
    policy.write_text(json.dumps(bad))
    args[-1] = str(tmp_path/"never-created.json")
    assert cli.main(args+["--conversion-policy-file", str(policy)]) == 1
    assert not (tmp_path/"never-created.json").exists()
    assert "unknown_or_missing_policy_field" in capsys.readouterr().err
