"""Explicit scalar mapping evidence never grants copy, chain or cutover authority."""
import copy
import hashlib
import json
import sqlite3

import pytest

from checks.migration_policy_fixture import KEYS, policy_document, policy_fixture, private_policy
from migration_guard.compare import compare
from migration_guard.snapshot import GuardFailure, inspect_snapshot


def test_mapping_is_opt_in_byte_exact_and_not_migration_authority(tmp_path):
    from migration_guard.conversion_policy import load_policy
    path, source, target = policy_fixture(tmp_path)
    before = path.read_bytes()
    assert {i["code"] for i in compare(source, target)["blockers"]} == {
        "target_only_column_requires_explicit_policy", "unapproved_column_type_mapping",
        "postgres_text_cannot_preserve_nul"}
    policy = load_policy(private_policy(tmp_path, policy_document(source, target)))
    report = compare(source, target, policy)
    assert report["result"] == "passed" and not report["blockers"]
    audit, dispatch = report["conversion_plan"]["mappings"]
    assert audit["source_rowid_min"] == 7 and audit["source_rowid_max"] == 99
    assert audit["required_next_seq_floor"] == 100
    assert not audit["sequence_reset_executed"]
    assert dispatch["utf8_bytes"] == sum(len(k.encode("utf-8")) for k in KEYS)
    assert dispatch["rows"] == len(KEYS)
    assert not report["content_copied_or_target_changed"]
    assert not report["audit_chain_verified"] and not report["cutover_authorized"]
    assert path.read_bytes() == before


def test_one_mapping_does_not_waive_the_other_or_nonempty_target(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    policy = policy_document(source, target)
    policy["mappings"] = policy["mappings"][:1]
    report = compare(source, target, policy)
    assert report["result"] == "failed"
    assert {i["table"] for i in report["blockers"]} == {"permissions_resources"}
    policy = policy_document(source, target)
    target["tables"][0]["rows"] = 1
    assert {i["code"] for i in compare(source, target, policy)["blockers"]} == {"target_business_table_not_empty"}


@pytest.mark.parametrize("change", ["version", "unknown", "mode", "column", "table", "duplicate", "empty", "missing"])
def test_bad_contract_never_falls_back_to_plain_preflight(tmp_path, change):
    _, source, target = policy_fixture(tmp_path)
    policy = policy_document(source, target)
    if change == "version": policy["version"] = True
    if change == "unknown": policy["approved"] = True
    if change == "mode": policy["mappings"][0]["mode"] = "generate_fresh_sequence"
    if change == "column": policy["mappings"][1]["column"] = "attributes_json"
    if change == "table": policy["mappings"][1]["table"] = "password_credentials"
    if change == "duplicate": policy["mappings"].append(copy.deepcopy(policy["mappings"][0]))
    if change == "empty": policy["mappings"] = []
    if change == "missing": del policy["source_sha256"]
    with pytest.raises(GuardFailure):
        compare(source, target, policy)


def test_snapshot_and_any_target_column_drift_invalidate_policy(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    policy = policy_document(source, target)
    other = copy.deepcopy(source)
    other["sha256"] = "0" * 64
    with pytest.raises(GuardFailure, match="source_digest_mismatch"):
        compare(other, target, policy)
    other = copy.deepcopy(target)
    other["tables"][1]["columns"][0]["not_null"] = False
    with pytest.raises(GuardFailure, match="target_shape_mismatch"):
        compare(source, other, policy)


def test_mappings_do_not_waive_missing_extra_columns_storage_or_key_checks(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    target["tables"][0]["columns"].pop(3)  # Missing stored prev_hash, never rebuilt.
    target["tables"][1]["columns"].append(dict(name="inferred", type="text", not_null=True, pk_order=0))
    source["tables"][0]["columns"][1]["storage_classes"] = {"text": 3}
    target["tables"][1]["columns"][0]["pk_order"] = 0
    report = compare(source, target, policy_document(source, target))
    assert report["result"] == "failed"
    assert {b["code"] for b in report["blockers"]} == {
        "source_column_missing_in_target", "target_only_column_requires_explicit_policy",
        "source_dynamic_storage_class_mismatch", "primary_key_shape_mismatch"}


def test_explicit_source_seq_cannot_be_replaced_by_rowid(tmp_path):
    path, _, target = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE audit_events ADD COLUMN seq INTEGER")
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(GuardFailure, match="source_seq_cannot_be_replaced"):
        compare(source, target, policy_document(source, target))


def test_private_duplicate_and_oversized_policy_reject(tmp_path):
    from migration_guard.conversion_policy import load_policy
    _, source, target = policy_fixture(tmp_path)
    policy = policy_document(source, target)
    path = private_policy(tmp_path, policy)
    path.write_text(path.read_text()[:-1] + ', "version":1}')
    with pytest.raises(GuardFailure, match="duplicate_policy_field"):
        load_policy(path)
    path.write_text(" " * 16385)
    with pytest.raises(GuardFailure, match="budget_invalid"):
        load_policy(path)
    path.write_text(json.dumps(policy))
    path.chmod(0o644)
    with pytest.raises(GuardFailure, match="file_mode"):
        load_policy(path)


@pytest.mark.parametrize("rowid", [0, -7, 9223372036854775807])
def test_nonpositive_or_exhausted_rowid_requires_another_reviewed_policy(tmp_path, rowid):
    path, _, _ = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE audit_events SET rowid=? WHERE id='b'", (rowid,))
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    _, _, target = policy_fixture_other_directory(tmp_path)
    with pytest.raises(GuardFailure, match="rowid_range"):
        compare(source, target, policy_document(source, target))


def policy_fixture_other_directory(root):
    other = root / "other"
    other.mkdir()
    return policy_fixture(other)


def test_dispatch_cannot_be_null_blob_or_reencoded(tmp_path):
    path, _, target = policy_fixture(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE permissions_resources SET dispatch_key=? WHERE id='1'", (b"raw\x00",))
    source = inspect_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(GuardFailure, match="dispatch_storage"):
        compare(source, target, policy_document(source, target))


def test_policy_cannot_resolve_missing_order_evidence_or_wrong_seq_shape(tmp_path):
    _, source, target = policy_fixture(tmp_path)
    source["tables"][0].pop("audit_rowid")
    with pytest.raises(GuardFailure, match="rowid_evidence"):
        compare(source, target, policy_document(source, target))
    _, source, target = policy_fixture_other_directory(tmp_path)
    target["tables"][0]["columns"][-1]["type"] = "int4"
    with pytest.raises(GuardFailure, match="seq_target_shape"):
        compare(source, target, policy_document(source, target))
