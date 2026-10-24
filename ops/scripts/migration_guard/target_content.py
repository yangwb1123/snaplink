"""All-table content/PK comparison in one read-only PostgreSQL MVCC snapshot."""
from contextlib import closing
import time

from .compare import compare
from .content_stream import PsqlStream
from .postgres import CATALOG_SQL, connection_file, psql_command
from .row_digest import ALGORITHM, TableDigest
from .row_projection import project_snapshot
from .snapshot import GuardFailure, MAX_ROWS, MAX_SCAN_BYTES, METADATA_TABLES, identifier, verify_snapshot
from .target_codec import column_expression, decode_cell


def bootstrap_sql(config, target, include_metadata=False):
    names = sorted(t["table"] for t in target["tables"] if include_metadata or not t["metadata_only"])
    locks = ",".join("public." + identifier(name) for name in names)
    return ("\\set VERBOSITY sqlstate\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
            "SET LOCAL search_path=pg_catalog,public;\nLOCK TABLE " + locks + " IN ACCESS SHARE MODE;\n"
            "SELECT json_build_object('kind','identity','database',current_database(),'user',current_user,"
            "'owned',(SELECT count(*)=1 AND bool_and(token='" + config["owner_token"] + "') FROM migration_guard.ownership),"
            "'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),'version',version())::jsonb;\n"
            "SELECT json_build_object('kind','catalog','tables',(" + CATALOG_SQL.strip().removesuffix(";") + "))::jsonb;\n")


def data_sql(target, include_metadata=False, *, transaction_end=True):
    statements = []
    for table in sorted(target["tables"], key=lambda t: t["table"]):
        if table["metadata_only"] and not include_metadata:
            continue
        name = table["table"]
        values = ",".join(column_expression(c) for c in sorted(table["columns"], key=lambda c: c["name"]))
        statements += ["SELECT json_build_object('kind','table_start','table','" + name + "')::jsonb;",
                       "SELECT json_build_object('kind','row','values',json_build_array(" + values + "))::jsonb FROM public." + identifier(name) + ";",
                       "SELECT json_build_object('kind','table_end','table','" + name + "')::jsonb;"]
    statements += ["SELECT json_build_object('kind','complete','read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'))::jsonb;"]
    if transaction_end:
        statements.append("COMMIT;")
    return "\n".join(statements) + "\n"


def catalog_default_flag(column):
    if 'canonical_zero_default' in column and type(column['canonical_zero_default']) is not bool:
        raise GuardFailure('target_content_column_default_invalid')


def catalog_columns(name, columns):
    seen = set()
    for column in columns:
        fields = {"name", "type", "type_namespace", "not_null", "pk_order"}
        if not isinstance(column, dict) or set(column) not in (fields, fields | {'canonical_zero_default'}):
            raise GuardFailure("target_content_column_format_invalid")
        identifier(column["name"])
        catalog_default_flag(column)
        if column["name"] in seen or type(column["not_null"]) is not bool or type(column["pk_order"]) is not int or not 0 <= column["pk_order"] <= 80 or not isinstance(column["type"], str) or not isinstance(column["type_namespace"], str):
            raise GuardFailure("target_content_column_shape_invalid")
        seen.add(column["name"])
        if name not in METADATA_TABLES:
            column_expression(column)


def catalog_table(item, names):
    if not isinstance(item, dict) or set(item) != {"table", "columns", "relkind", "rls_enabled", "force_rls"}:
        raise GuardFailure("target_content_catalog_format_invalid")
    name, columns = item["table"], item["columns"]
    identifier(name)
    if name in names or not isinstance(columns, list) or not 1 <= len(columns) <= 80:
        raise GuardFailure("target_content_column_budget_or_duplicate_table")
    names.add(name)
    if name not in METADATA_TABLES and (item["relkind"] != "r" or item["rls_enabled"] is not False or item["force_rls"] is not False):
        raise GuardFailure("target_content_visibility_or_relation_unsupported")
    catalog_columns(name, columns)
    return dict(item, rows=None, metadata_only=name in METADATA_TABLES)


def catalog_tables(items):
    if not isinstance(items, list) or not 1 <= len(items) <= 100:
        raise GuardFailure("target_content_catalog_budget_or_format_invalid")
    names = set()
    return [catalog_table(item, names) for item in items]


def snapshot_identity(frame, config):
    if set(frame) != {"kind", "database", "user", "owned", "read_only", "isolation", "version"}:
        raise GuardFailure("target_content_identity_format_invalid")
    if frame["owned"] is not True or frame["read_only"] != "on" or frame["isolation"] != "repeatable read":
        raise GuardFailure("target_content_ownership_or_snapshot_not_verified")
    if frame["database"] != config["database"] or frame["user"] != config["user"]:
        raise GuardFailure("target_content_database_or_role_mismatch")
    return dict(identity={k: v for k, v in frame.items() if k != "kind"}, read_only=True,
                credentials_in_report=False, counts_tracked_for_business_tables_only=True)


def snapshot_catalog(frame, source, policy, purpose="verify_content"):
    if set(frame) != {"kind", "tables"}:
        raise GuardFailure("target_content_catalog_format_invalid")
    tables = catalog_tables(frame["tables"])
    if compare(source, dict(tables=tables), policy, purpose=purpose)["result"] != "passed":
        raise GuardFailure("target_content_snapshot_shape_failed")
    return tables


class TargetReader:
    def __init__(self, config, source, policy, deadline):
        self.config, self.source, self.policy, self.deadline = config, source, policy, deadline
        self.stage, self.target, self.digest = "identity", None, None
        self.tables, self.names, self.rows, self.scanned = [], [], 0, 0

    def identity(self, frame):
        self.target = snapshot_identity(frame, self.config)
        self.stage = "catalog"

    def catalog(self, frame, stream):
        self.target["tables"] = snapshot_catalog(frame, self.source, self.policy)
        self.names = sorted(t["table"] for t in self.target["tables"] if not t["metadata_only"])
        stream.send(data_sql(self.target), final=True)  # Only after ownership, locks and in-snapshot catalog validation.
        self.stage = "tables"

    def start(self, frame):
        if set(frame) != {"kind", "table"} or self.digest is not None or len(self.tables) >= len(self.names) or frame["table"] != self.names[len(self.tables)]:
            raise GuardFailure("target_content_table_order_or_coverage_invalid")
        shape = next(t for t in self.target["tables"] if t["table"] == frame["table"])
        self.digest = TableDigest(shape, self.deadline, MAX_ROWS, MAX_SCAN_BYTES)

    def row(self, frame):
        if self.digest is None or set(frame) != {"kind", "values"} or not isinstance(frame["values"], list) or len(frame["values"]) != len(self.digest.columns):
            raise GuardFailure("target_content_row_shape_or_order_invalid")
        self.digest.add({c["name"]: decode_cell(value, c) for c, value in zip(self.digest.columns, frame["values"])})
        if self.rows + len(self.digest.entries) > MAX_ROWS or self.scanned + self.digest.scanned > MAX_SCAN_BYTES:
            raise GuardFailure("target_content_total_scan_budget_exceeded")

    def end(self, frame):
        if self.digest is None or set(frame) != {"kind", "table"} or frame["table"] != self.digest.table:
            raise GuardFailure("target_content_table_end_invalid")
        evidence = self.digest.finish()
        self.rows, self.scanned = self.rows + evidence["rows"], self.scanned + evidence["scanned_bytes"]
        self.tables.append(evidence)
        next(t for t in self.target["tables"] if t["table"] == evidence["table"])["rows"] = evidence["rows"]
        self.digest = None

    def accept(self, frame, stream):
        kind = frame.get("kind")
        if not isinstance(kind, str):
            raise GuardFailure("target_content_frame_kind_invalid")
        if self.stage == "identity" and kind == "identity":
            return self.identity(frame)
        if self.stage == "catalog" and kind == "catalog":
            return self.catalog(frame, stream)
        if self.stage != "tables":
            raise GuardFailure("target_content_frame_order_invalid")
        handlers = {"table_start": self.start, "row": self.row, "table_end": self.end}
        if kind in handlers:
            return handlers[kind](frame)
        if kind != "complete" or set(frame) != {"kind", "read_only", "isolation"} or self.digest is not None or len(self.tables) != len(self.names):
            raise GuardFailure("target_content_completion_missing_or_invalid")
        if frame["read_only"] != "on" or frame["isolation"] != "repeatable read":
            raise GuardFailure("target_content_snapshot_not_verified")
        self.stage = "complete"


def comparison_issues(expected, actual):
    left, right = {t["table"]: t for t in expected["tables"]}, {t["table"]: t for t in actual["tables"]}
    if set(left) != set(right):
        raise GuardFailure("target_content_table_coverage_mismatch")
    issues = []
    fields = {"rows": "target_row_count_mismatch", "primary_key_set_sha256": "target_primary_key_set_mismatch",
              "projected_content_sha256": "target_projected_content_mismatch"}
    for name in sorted(left):
        for field, code in fields.items():
            if left[name][field] != right[name][field]:
                issues.append(dict(code=code, table=name))
    return issues


def verify_content(snapshot, connection_path, source, target, policy, timeout=60):
    deadline = time.monotonic() + timeout
    expected = project_snapshot(snapshot, source, target, policy, timeout=timeout, purpose="verify_content")
    config = connection_file(connection_path)
    reader = TargetReader(config, source, policy, deadline)
    with closing(PsqlStream(*psql_command(config), timeout=max(0, deadline - time.monotonic()))) as stream:
        stream.send(bootstrap_sql(config, target))
        for frame in stream:
            reader.accept(frame, stream)
    if reader.stage != "complete":
        raise GuardFailure("target_content_completion_missing_or_invalid")
    verify_snapshot(snapshot, source["sha256"])
    if time.monotonic() >= deadline:
        raise GuardFailure("target_content_scan_window_exceeded")
    actual = dict(algorithm=ALGORITHM, tables=reader.tables, rows=reader.rows, scanned_bytes=reader.scanned)
    issues = comparison_issues(expected, actual)
    return dict(result="failed" if issues else "passed", blockers=issues, target_content_verified=not issues,
                scope="all business content/PK at one read-only repeatable-read snapshot", source_projection=expected,
                target_projection=actual, target_snapshot=reader.target, writer_fencing_verified=False,
                audit_chain_verified=False, cutover_authorized=False, content_copied_or_target_changed=False,
                sequence_state_in_mvcc_snapshot=False, full_ddl_or_relationships_certified=False)
