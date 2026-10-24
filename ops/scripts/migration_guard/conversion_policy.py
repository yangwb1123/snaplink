"""Explicit, versioned SHA-bound projections; never apply/approval/waiver authority."""
import hashlib
import json
import re

from .snapshot import GuardFailure, private_file
from .client_policy_defaults import CLIENT_MODES, client_policy_plan, policy_version

FIELDS = {"version", "source_sha256", "target_shape_sha256", "mappings"}
MODES = {("audit_events", "seq"): "sqlite_rowid_int8_v1",
         ("permissions_resources", "dispatch_key"): "text_utf8_bytea_v1"}
SHAPE_FIELDS = ("name", "type", "not_null", "pk_order")
MAX_INT8 = 9223372036854775807


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def is_sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def unique_policy_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardFailure("duplicate_policy_field")
        result[key] = value
    return result


def validate_document(data):
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise GuardFailure("unknown_or_missing_policy_field")
    version = policy_version(data)
    if not is_sha(data["source_sha256"]) or not is_sha(data["target_shape_sha256"]):
        raise GuardFailure("conversion_policy_digest_required")
    validate_mapping_entries(data["mappings"], version=version)
    return data


def validate_mapping_entries(entries, *, version=1):
    modes = MODES if version == 1 else {**MODES, **CLIENT_MODES}
    if not isinstance(entries, list) or not 1 <= len(entries) <= len(modes):
        raise GuardFailure("bounded_nonempty_mapping_list_required")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"table", "column", "mode"}:
            raise GuardFailure("unknown_or_missing_mapping_field")
        if any(not isinstance(value, str) for value in entry.values()):
            raise GuardFailure("mapping_fields_must_be_strings")
        key = (entry["table"], entry["column"])
        if key in seen or entry["mode"] != modes.get(key):
            raise GuardFailure("unsupported_or_duplicate_mapping")
        seen.add(key)


def load_policy(path):
    data = json.loads(private_file(path, 16 << 10).read_text(),
                      object_pairs_hook=unique_policy_object)
    return validate_document(data)


def target_shape_sha256(target):
    # Narrow shape binding, NOT index/FK/collation/default/sequence certification.
    shapes = [{"table": table["table"], "metadata_only": table["metadata_only"],
               "columns": [{key: col[key] for key in SHAPE_FIELDS} for col in
                           sorted(table["columns"], key=lambda c: c["name"])]}
              for table in sorted(target["tables"], key=lambda t: t["table"])]
    return digest(shapes)


def validate_audit_shape(source, target):
    column = next((c for c in target["columns"] if c["name"] == "seq"), {})
    source_id = next((c for c in source["columns"] if c["name"] == "id"), {})
    if (column.get("type"), column.get("not_null"), column.get("pk_order")) != ("int8", True, 0):
        raise GuardFailure("seq_target_shape_invalid")
    if any(c["name"] == "seq" for c in source["columns"]):
        raise GuardFailure("source_seq_cannot_be_replaced")
    if (source_id.get("type"), source_id.get("pk_order")) != ("TEXT", 1):
        raise GuardFailure("audit_source_id_shape_invalid")


def audit_plan(source, target):
    validate_audit_shape(source, target)
    proof = source.get("audit_rowid", {})
    if proof.get("available") is not True or proof.get("rows") != source["rows"] or not is_sha(proof.get("rowid_and_id_sha256")):
        raise GuardFailure("source_rowid_evidence_required")
    low, high = proof.get("min"), proof.get("max")
    if source["rows"]:
        if type(low) is not int or type(high) is not int or not 1 <= low <= high < MAX_INT8:
            raise GuardFailure("source_rowid_range_unsupported")
    elif low is not None or high is not None:
        raise GuardFailure("empty_source_rowid_evidence_invalid")
    return dict(table="audit_events", column="seq", mode=MODES[("audit_events", "seq")],
                rows=source["rows"], source_rowid_min=low, source_rowid_max=high,
                rowid_and_id_sha256=proof["rowid_and_id_sha256"],
                required_next_seq_floor=1 if high is None else high + 1,
                sequence_reset_executed=False, historical_fields_rewritten=False)


def dispatch_plan(source, target):
    left = next((c for c in source["columns"] if c["name"] == "dispatch_key"), {})
    right = next((c for c in target["columns"] if c["name"] == "dispatch_key"), {})
    if (left.get("type"), left.get("pk_order"), right.get("type"), right.get("pk_order")) != ("TEXT", 0, "bytea", 0):
        raise GuardFailure("dispatch_column_shape_invalid")
    if not set(left.get("storage_classes", {})).issubset({"text", "null"}):
        raise GuardFailure("source_dispatch_storage_invalid")
    proof = source.get("dispatch_bytes", {})
    if proof.get("valid_storage") is not True or proof.get("rows") != source["rows"]:
        raise GuardFailure("source_dispatch_storage_evidence_required")
    if proof.get("null_rows") != left.get("storage_classes", {}).get("null", 0) or not is_sha(proof.get("id_and_bytes_sha256")):
        raise GuardFailure("source_dispatch_byte_evidence_required")
    return dict(table="permissions_resources", column="dispatch_key", mode=MODES[("permissions_resources", "dispatch_key")],
                rows=proof["rows"], null_rows=proof["null_rows"], utf8_bytes=proof["utf8_bytes"],
                id_and_bytes_sha256=proof["id_and_bytes_sha256"], encoding="utf-8",
                errors="strict", normalization_or_key_regeneration=False)


def conversion_plan(source, target, document):
    policy = validate_document(document)
    if policy["source_sha256"] != source["sha256"]:
        raise GuardFailure("policy_source_digest_mismatch")
    shape = target_shape_sha256(target)
    if policy["target_shape_sha256"] != shape:
        raise GuardFailure("policy_target_shape_mismatch")
    left = {t["table"]: t for t in source["tables"] if not t["metadata_only"]}
    right = {t["table"]: t for t in target["tables"] if not t["metadata_only"]}
    mappings = []
    for entry in sorted(policy["mappings"], key=lambda e: (e["table"], e["column"])):
        name = entry["table"]
        if name not in left or name not in right:
            raise GuardFailure("mapping_source_and_target_table_required")
        if name == "clients":
            mappings.append(client_policy_plan(left[name], right[name], entry["column"]))
        else:
            planner = audit_plan if name == "audit_events" else dispatch_plan
            mappings.append(planner(left[name], right[name]))
    return dict(source_sha256=source["sha256"], target_shape_sha256=shape,
                policy_content_sha256=digest(policy), mappings=mappings,
                scope="explicit_scalar_mapping_plan_only", apply_supported=False,
                target_shape_scope="column name/type/nullability/PK; not full schema",
                defaults_indexes_fk_collation_and_sequence_state_verified=False)
