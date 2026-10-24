"""Checks only declared native FK relations; never infer business references."""
from .snapshot import GuardFailure, identifier


def validate_fk_columns(table, parent_table, child, parent, shapes):
    if not isinstance(child, list) or not isinstance(parent, list) or not 1 <= len(child) <= 80 or len(child) != len(parent):
        raise GuardFailure("declared_fk_column_arity_unsupported")
    if len(set(child)) != len(child) or len(set(parent)) != len(parent):
        raise GuardFailure("declared_fk_duplicate_columns")
    if not set(child).issubset(c["name"] for c in shapes[table]["columns"]) or not set(parent).issubset(c["name"] for c in shapes[parent_table]["columns"]):
        raise GuardFailure("declared_fk_columns_missing")


def validate_fk_behavior(record, arity):
    if record["equality_operators"] != ["pg_catalog.="] * arity or record["match_type"] not in ("s", "f"):
        raise GuardFailure("declared_fk_operator_or_match_unsupported")
    if record["on_delete"] not in ("a", "r", "c", "n", "d") or record["on_update"] not in ("a", "r", "c", "n", "d"):
        raise GuardFailure("declared_fk_action_unsupported")


def validate_foreign_key(table, record, shapes):
    child, parent = record["child_columns"], record["parent_columns"]
    if record["parent_schema"] != "public" or record["parent_table"] not in shapes or table not in shapes:
        raise GuardFailure("declared_fk_parent_scope_unsupported")
    validate_fk_columns(table, record["parent_table"], child, parent, shapes)
    validate_fk_behavior(record, len(child))
    for name in [table, record["parent_table"], record["name"], *child, *parent]:
        identifier(name)


def foreign_key_sql(table, record):
    child = ["c." + identifier(name) for name in record["child_columns"]]
    parent = ["p." + identifier(name) for name in record["parent_columns"]]
    nonnull = " AND ".join(value + " IS NOT NULL" for value in child)
    equality = " AND ".join(p + " OPERATOR(pg_catalog.=) " + c for p, c in zip(parent, child))
    orphan = "(" + nonnull + ") AND NOT EXISTS (SELECT 1 FROM public." + identifier(record["parent_table"]) + " p WHERE " + equality + ")"
    if record["match_type"] == "f":
        allnull = " AND ".join(value + " IS NULL" for value in child)
        orphan = "((NOT (" + allnull + ") AND NOT (" + nonnull + ")) OR (" + orphan + "))"
    return ("SELECT json_build_object('kind','foreign_key','table','" + table + "','constraint','" + record["name"] + "',"
            "'validated'," + ("true" if record["validated"] else "false") + ",'scanned_rows',count(*),'violations',count(*) FILTER (WHERE " + orphan + "))::jsonb "
            "FROM public." + identifier(table) + " c;")


def relationship_evidence(rows):
    if not rows:
        return dict(result="not_executed", reason="no_declared_foreign_keys", declared_foreign_keys=0,
                    all_business_relationships_verified=False, blockers=[])
    blockers = []
    for row in rows:
        if row["violations"]:
            blockers.append(dict(code="target_declared_fk_violations", table=row["table"], constraint=row["constraint"]))
        if row["validated"] is not True:
            blockers.append(dict(code="target_declared_fk_not_validated", table=row["table"], constraint=row["constraint"]))
    return dict(result="failed" if blockers else "passed", declared_foreign_keys=len(rows), checks=rows,
                all_business_relationships_verified=False, blockers=blockers)
