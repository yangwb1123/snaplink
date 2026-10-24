"""No table intersections, narrowing, default filling, or nonempty overwrite."""
import json

import pytest

from checks.migration_guard_fixture import sample_snapshot, sample_target
from migration_guard.cli import write_report
from migration_guard.compare import compare
from migration_guard.snapshot import GuardFailure


def codes(report):
    return {issue["code"] for issue in report["blockers"]}


def test_complete_synthetic_shape_passes_without_migration_claim(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    report = compare(source, sample_target(source))
    assert report["result"] == "passed" and not report["blockers"]
    assert report["source_business_rows"] == 3
    assert not report["content_copied_or_target_changed"]
    assert not report["runtime_semantics_certified"]
    assert not report["cutover_authorized"]
    assert not report["audit_chain_verified"]


def test_empty_missing_table_is_still_blocked(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    target = sample_target(source)
    source["tables"].append(dict(source["tables"][0], table="revocations", rows=0))
    report = compare(source, target)
    assert report["result"] == "failed"
    assert {"code": "source_business_table_missing_in_target", "table": "revocations"} in report["blockers"]


def test_missing_extra_column_and_nonempty_target_block(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    target = sample_target(source)
    target["tables"][0]["columns"].pop()
    target["tables"][0]["columns"].append({"name": "seq", "type": "int8", "pk_order": 0, "not_null": True})
    target["tables"][0]["rows"] = 1
    assert codes(compare(source, target)) == {"source_column_missing_in_target",
        "target_only_column_requires_explicit_policy", "target_business_table_not_empty"}


def test_int4_does_not_silently_narrow_int64(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    target = sample_target(source)
    next(c for c in target["tables"][0]["columns"] if c["name"] == "quota")["type"] = "int4"
    assert "existing_integer_outside_target_range" in codes(compare(source, target))


def test_null_key_and_nul_text_cannot_be_made_empty(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    target = sample_target(source)
    source["tables"][0]["columns"][0]["storage_classes"]["null"] = 1
    source["tables"][0]["columns"][1]["contains_nul"] = True
    assert codes(compare(source, target)) == {"source_null_rejected_by_target", "postgres_text_cannot_preserve_nul"}


def test_type_primary_key_and_nullable_drift_block(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    target = sample_target(source)
    target["tables"][0]["columns"][0]["pk_order"] = 0
    target["tables"][0]["columns"][1]["type"] = "bytea"
    target["tables"][0]["columns"][2]["not_null"] = False
    source["tables"][0]["columns"][2]["storage_classes"]["text"] = 1
    assert codes(compare(source, target)) == {"primary_key_shape_mismatch", "unapproved_column_type_mapping",
        "target_nullability_weaker_than_source", "source_dynamic_storage_class_mismatch"}


def test_evidence_is_private_complete_and_not_overwritten(tmp_path):
    _, _, source = sample_snapshot(tmp_path)
    report = compare(source, sample_target(source))
    path = tmp_path / "report.json"
    write_report(path, report)
    before = path.read_bytes()
    assert json.loads(before) == report
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_report(path, {"result": "passed"})
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".migration-preflight-*"))


def test_empty_source_cannot_be_noop_success(tmp_path):
    with pytest.raises(GuardFailure, match="business_tables_required"):
        compare({"tables": []}, {"tables": []})
