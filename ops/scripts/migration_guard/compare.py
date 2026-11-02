"""Coverage/data-shape guard, not runtime certification or migration authority."""
from .snapshot import GuardFailure
from .conversion_policy import conversion_plan

TYPE_PAIRS = {"TEXT": {"text"}, "INTEGER": {"int2", "int4", "int8"},
              "REAL": {"float8"}, "BLOB": {"bytea"}}
INT_RANGES = {"int2": (-32768, 32767), "int4": (-2147483648, 2147483647),
              "int8": (-9223372036854775808, 9223372036854775807)}
STORAGE = {"TEXT": {"text", "null"}, "INTEGER": {"integer", "null"},
           "REAL": {"real", "null"}, "BLOB": {"blob", "null"}}
# Shape-only report projection; these fields never grant observer/writer admission.
SHAPE_REPORT_FIELDS = {
    "verify_content": dict(scope="read_only_shape_for_content_verification", target_content_verified=False,
                           content_verification_required=True),
    "verify_schema": dict(scope="read_only_shape_for_schema_verification", target_content_verified=False,
                          target_schema_contract_matched=False, schema_verification_required=True),
    "verify_sequences": dict(scope="read_only_shape_for_sequence_inventory", target_content_verified=False,
                             sequence_inventory_verification_required=True),
}


def column_blockers(table, source, target, mapped=False):
    issues = []
    def reject(code):
        issues.append({"code": code, "table": table, "column": source["name"]})
    kind, pg_kind = source["type"].upper(), target["type"]
    if not mapped and pg_kind not in TYPE_PAIRS.get(kind, set()):
        reject("unapproved_column_type_mapping")
    classes = source["storage_classes"]
    if not set(classes).issubset(STORAGE.get(kind, set())):
        reject("source_dynamic_storage_class_mismatch")
    if target["not_null"] and classes.get("null", 0):
        reject("source_null_rejected_by_target")
    if source["not_null"] and not target["not_null"]:
        reject("target_nullability_weaker_than_source")
    if source["pk_order"] != target["pk_order"]:
        reject("primary_key_shape_mismatch")
    if source.get("contains_nul") and not mapped:
        reject("postgres_text_cannot_preserve_nul")
    if pg_kind in INT_RANGES and "min_integer" in source:
        low, high = INT_RANGES[pg_kind]
        if source["min_integer"] < low or source["max_integer"] > high:
            reject("existing_integer_outside_target_range")
    return issues


def table_blockers(source, target, mappings, *, purpose="preflight"):
    table, issues = source["table"], []
    if purpose == "preflight" and target["rows"]:
        issues.append({"code": "target_business_table_not_empty", "table": table})
    left = {col["name"]: col for col in source["columns"]}
    right = {col["name"]: col for col in target["columns"]}
    for column in sorted(left.keys() - right.keys()):
        issues.append({"code": "source_column_missing_in_target", "table": table, "column": column})
    for column in sorted(right.keys() - left.keys()):
        if (table, column) not in mappings:
            issues.append({"code": "target_only_column_requires_explicit_policy", "table": table, "column": column})
    for column in sorted(left.keys() & right.keys()):
        issues.extend(column_blockers(table, left[column], right[column], (table, column) in mappings))
    return issues


def require_comparison_policy(purpose, policy):
    if purpose not in ("preflight", "verify_content", "verify_schema", "verify_sequences"):
        raise GuardFailure("unsupported_comparison_purpose")
    if purpose != "preflight" and policy is None:
        prefix = {"verify_schema": "schema", "verify_sequences": "sequence"}.get(purpose, "content")
        raise GuardFailure(prefix + "_verification_explicit_policy_required")


def business_tables(snapshot):
    return {table["table"]: table for table in snapshot["tables"] if not table["metadata_only"]}


def compare(source, target, policy=None, *, purpose="preflight"):
    require_comparison_policy(purpose, policy)
    plan = conversion_plan(source, target, policy) if policy is not None else None
    mappings = {(m["table"], m["column"]) for m in plan["mappings"]} if plan else set()
    left, right = business_tables(source), business_tables(target)
    if not left:
        raise GuardFailure("source_business_tables_required")
    issues = [{"code": "source_business_table_missing_in_target", "table": t}
              for t in sorted(left.keys() - right.keys())]
    issues += [{"code": "target_only_business_table_requires_policy", "table": t}
               for t in sorted(right.keys() - left.keys())]
    for name in sorted(left.keys() & right.keys()):
        issues.extend(table_blockers(left[name], right[name], mappings, purpose=purpose))
    report = {"result": "failed" if issues else "passed", "scope": "read_only_snapshot_and_catalog_preflight",
            "source_business_tables": len(left), "source_business_rows": sum(t["rows"] for t in left.values()),
            "target_business_tables": len(right), "blockers": issues,
            "source": source, "target": target,
            "source_metadata_tables": [t["table"] for t in source["tables"] if t["metadata_only"]],
            "source_schema_history_must_not_overwrite_postgres_history": True,
            "runtime_semantics_certified": False, "audit_chain_verified": False,
            "content_copied_or_target_changed": False, "cutover_authorized": False,
            "missing_empty_tables_are_not_exempt": True,
            "future_range_collation_defaults_indexes_fk_and_topology_require_separate_acceptance": True}
    if plan is not None:
        report["conversion_plan"] = plan
    report.update(SHAPE_REPORT_FIELDS.get(purpose, {}))
    return report
