"""Private explicitly SHA-pinned expected DDL facets; not schema/export authority."""
import hashlib
import json
import re

from .postgres import unique_object
from .schema_sql import FACETS
from .snapshot import GuardFailure, identifier, private_file

ALGORITHM = "pg_native_schema_facets_v1"


def digest_required(value, length=64):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{" + str(length) + "}", value):
        raise GuardFailure("schema_contract_digest_required")


def validate_provenance(provenance):
    if not isinstance(provenance, dict) or set(provenance) != {"base_commit", "combination_sha256"}:
        raise GuardFailure("schema_contract_provenance_required")
    digest_required(provenance["base_commit"], 40)
    digest_required(provenance["combination_sha256"])


def validate_contract_table(table, names):
    if not isinstance(table, dict) or set(table) != {"table", "facets"}:
        raise GuardFailure("schema_contract_table_fields_invalid")
    identifier(table["table"])
    if table["table"] in names or not isinstance(table["facets"], dict) or set(table["facets"]) != set(FACETS):
        raise GuardFailure("schema_contract_duplicate_table_or_facets_invalid")
    names.add(table["table"])
    for value in table["facets"].values():
        digest_required(value)


def validate_contract(data):
    fields = {"version", "algorithm", "source_sha256", "target_shape_sha256", "schema_source", "environment_sha256", "tables"}
    if not isinstance(data, dict) or set(data) != fields or type(data["version"]) is not int or data["version"] != 1 or data["algorithm"] != ALGORITHM:
        raise GuardFailure("schema_contract_fields_or_version_invalid")
    for field in ("source_sha256", "target_shape_sha256", "environment_sha256"):
        digest_required(data[field])
    validate_provenance(data["schema_source"])
    if not isinstance(data["tables"], list) or not 1 <= len(data["tables"]) <= 100:
        raise GuardFailure("schema_contract_table_budget_or_format_invalid")
    names = set()
    for table in data["tables"]:
        validate_contract_table(table, names)
    return data


def load_contract(path, expected_sha256):
    digest_required(expected_sha256)
    raw = private_file(path, 256 << 10).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise GuardFailure("schema_contract_sha256_mismatch")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise GuardFailure("schema_contract_json_invalid") from exc
    return validate_contract(data)


def schema_fingerprint(table, facet, records):
    rows = sorted(json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) for r in records)
    raw = json.dumps([ALGORITHM, table, facet, rows], ensure_ascii=False, separators=(",", ":")).encode("utf-8", errors="strict")
    return hashlib.sha256(raw).hexdigest()


def schema_issues(contract, observed):
    validate_contract(contract)
    expected = {t["table"]: t["facets"] for t in contract["tables"]}
    if set(expected) != set(observed["tables"]):
        raise GuardFailure("schema_contract_table_coverage_mismatch")
    blockers = []
    if contract["environment_sha256"] != observed["environment_sha256"]:
        blockers.append(dict(code="target_schema_environment_mismatch"))
    for name in sorted(expected):
        for facet in FACETS:
            if expected[name][facet] != observed["tables"][name]["facets"][facet]:
                blockers.append(dict(code="target_native_schema_facet_mismatch", table=name, facet=facet))
    return blockers
