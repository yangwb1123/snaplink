#!/usr/bin/env python3
"""Bounded, read-only coverage decisions for the existing SDK surface owner.

The surface registry alone selects generated operations. This sidecar only
requires an explicit decision for every documented HTTP operation. OpenAPI
security is reported as a declaration, never inferred runtime authorization.
No external references are followed and no network or write operations occur.
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    import yaml
except ImportError:  # Keep the CLI's failure diagnostic closed and readable.
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
COVERAGE_PATH = ROOT / "ops/build/sdk-surface-coverage.json"
SCHEMA_PATH = ROOT / "ops/build/sdk-surface-coverage.schema.json"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
BOUNDARY_FIELDS = {"id", "rationale", "exposure", "authentication", "defaults", "licensing", "references"}
IDENTITY_FIELDS = {"operationId", "method", "path"}
ROOT_FIELDS = {"$schema", "schema_version", "included_groups", "excluded_groups"}


class SDKCoverageError(ValueError):
    """Invalid inventory, decision, or local reference; never a partial pass."""


def _object(value: object, where: str, fields: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise SDKCoverageError(f"{where}: must be an object")
    if fields is not None and value.keys() != fields:
        raise SDKCoverageError(
            f"{where}: unknown fields {sorted(value.keys() - fields)}; "
            f"missing fields {sorted(fields - value.keys())}"
        )
    return value


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SDKCoverageError(f"{where}: must be non-empty text")
    return value


def _array(value: object, where: str, nonempty: bool = True) -> list:
    if not isinstance(value, list) or (nonempty and not value):
        raise SDKCoverageError(f"{where}: must be {'a non-empty' if nonempty else 'an'} array")
    return value


def _unique_json(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SDKCoverageError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_coverage_file(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SDKCoverageError(f"{path}: {exc}") from exc
    return _object(value, str(path))


if yaml is not None:
    class _UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            seen = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise SDKCoverageError(f"YAML mapping key must be text at {key_node.start_mark}")
                if key in seen:
                    raise SDKCoverageError(f"duplicate YAML key {key!r} at {key_node.start_mark}")
                seen.add(key)
            return super().construct_mapping(node, deep=deep)


def _security(value: object, where: str) -> list:
    for requirement in _array(value, where, nonempty=False):
        for scheme, scopes in _object(requirement, where).items():
            _text(scheme, where)
            for scope in _array(scopes, where, nonempty=False):
                _text(scope, where)
    return value


def _local_object(doc: dict, value: object, where: str) -> dict:
    """Resolve only local requestBody/response objects, not schema graphs."""
    value = _object(value, where)
    seen = set()
    while "$ref" in value:
        ref = _text(value["$ref"], where)
        if not ref.startswith("#/") or ref in seen:
            raise SDKCoverageError(f"{where}: non-local or cyclic reference {ref!r}")
        seen.add(ref)
        target = doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            target = _object(target, where).get(part)
        value = _object(target, f"{where}: reference {ref}")
    return value


def _content_types(doc: dict, value: object, where: str) -> list[str]:
    content = _object(_local_object(doc, value, where).get("content", {}), where)
    for media_type, media in content.items():
        _text(media_type, where)
        _object(media, where)
    return sorted(content)


def _operation(doc: dict, raw: object, method: str, path: str) -> dict:
    where = f"{method.upper()} {path}"
    raw = _object(raw, where)
    operation_id = _text(raw.get("operationId"), f"{where}: operationId")
    source = "operation" if "security" in raw else "root" if "security" in doc else "unspecified"
    declaration = raw.get("security", doc.get("security"))
    if source != "unspecified":
        _security(declaration, f"{where}: security")
    responses = _object(raw.get("responses", {}), f"{where}: responses")
    return {
        "operationId": operation_id, "method": method.upper(), "path": path,
        "openapi_security": {"source": source, "declaration": declaration},
        "media_types": {
            "request": _content_types(doc, raw.get("requestBody", {}), where),
            "responses": {code: _content_types(doc, body, where) for code, body in sorted(responses.items())},
        },
    }


def load_operations_text(text: str, source: str) -> dict[str, dict]:
    if yaml is None:
        raise SDKCoverageError("PyYAML is required to read OpenAPI YAML")
    try:
        doc = _object(yaml.load(text, Loader=_UniqueLoader), source)
        paths = _object(doc.get("paths"), f"{source}: paths")
        if "security" in doc:
            _security(doc["security"], f"{source}: root security")
        operations = {}
        for path, item in paths.items():
            if not _text(path, source).startswith("/"):
                raise SDKCoverageError(f"{source}: invalid OpenAPI path {path!r}")
            item = _object(item, f"{source}: {path}")
            if "$ref" in item:
                raise SDKCoverageError(f"{source}: path-item references are not supported: {path}")
            for method in sorted(METHODS & item.keys()):
                operation = _operation(doc, item[method], method, path)
                key = operation["operationId"]
                if key in operations:
                    raise SDKCoverageError(f"{source}: duplicate operationId {key!r}")
                operations[key] = operation
        return operations
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise SDKCoverageError(f"{source}: invalid OpenAPI inventory: {exc}") from exc


def load_operations(path: Path) -> dict[str, dict]:
    try:
        return load_operations_text(path.read_text(encoding="utf-8"), str(path))
    except (OSError, UnicodeError) as exc:
        raise SDKCoverageError(f"{path}: {exc}") from exc


def _references(value: object, root: Path, where: str) -> None:
    refs = _array(value, f"{where}: references")
    seen = set()
    for ref in refs:
        _text(ref, f"{where}: reference")
        path = Path(ref)
        if path.is_absolute() or ".." in path.parts or any(c in ":#*?\\" or ord(c) < 32 for c in ref):
            raise SDKCoverageError(f"{where}: unsafe reference {ref!r}")
        try:
            internal_file = (root / path).resolve().is_relative_to(root.resolve()) and (root / path).is_file()
        except (OSError, RuntimeError, ValueError) as exc:
            raise SDKCoverageError(f"{where}: cannot resolve reference {ref!r}: {exc}") from exc
        if ref in seen or not internal_file:
            raise SDKCoverageError(f"{where}: duplicate, escaping or missing file reference {ref!r}")
        seen.add(ref)


def _groups(value: object, excluded: bool, root: Path) -> dict[str, dict]:
    groups = {}
    fields = BOUNDARY_FIELDS | ({"operations"} if excluded else set())
    for group in _array(value, "coverage groups", nonempty=not excluded):
        group = _object(group, "coverage group", fields)
        for field in sorted(BOUNDARY_FIELDS - {"references"}):
            _text(group[field], f"coverage group {group.get('id')!r}: {field}")
        group_id = group["id"]
        if group_id in groups:
            raise SDKCoverageError(f"duplicate coverage group {group_id!r}")
        _references(group["references"], root, group_id)
        if excluded:
            _array(group["operations"], f"{group_id}: operations")
        groups[group_id] = group
    return groups


def _selected(registry: dict) -> tuple[dict, set]:
    selected, groups = {}, set()
    for group in registry["groups"]:
        if group["id"] in groups:
            raise SDKCoverageError(f"duplicate selected group {group['id']!r}")
        groups.add(group["id"])
        for operation_id in group["operations"]:
            if operation_id in selected:
                raise SDKCoverageError(f"duplicate selected operationId {operation_id!r}")
            selected[operation_id] = group["id"]
    return selected, groups


def _exclusions(groups: dict, selected: dict, operations: dict) -> dict:
    excluded = {}
    for group_id, group in groups.items():
        for identity in group["operations"]:
            identity = _object(identity, group_id, IDENTITY_FIELDS)
            for field in IDENTITY_FIELDS:
                _text(identity[field], f"{group_id}: {field}")
            key = identity["operationId"]
            if key in selected:
                raise SDKCoverageError(f"{key}: included and excluded")
            if key in excluded:
                raise SDKCoverageError(f"duplicate exclusion {key!r}")
            if key not in operations:
                raise SDKCoverageError(f"stale exclusion {key!r}")
            if identity["method"].lower() not in METHODS or identity["method"] != identity["method"].upper():
                raise SDKCoverageError(f"{key}: invalid HTTP method")
            if identity != {field: operations[key][field] for field in IDENTITY_FIELDS}:
                raise SDKCoverageError(f"{key}: excluded method/path identity drift")
            excluded[key] = group_id
    return excluded


def validate_coverage(coverage: object, registry: dict, operations: dict, root: Path = ROOT) -> dict:
    """Validate the fixed v1 sidecar shape and exact I/E/O relationships."""
    coverage = _object(coverage, "coverage root", ROOT_FIELDS)
    if coverage["$schema"] != "./sdk-surface-coverage.schema.json":
        raise SDKCoverageError("coverage $schema must be ./sdk-surface-coverage.schema.json")
    if type(coverage["schema_version"]) is not int or coverage["schema_version"] != 1:
        raise SDKCoverageError("coverage schema_version must be 1")
    included_groups = _groups(coverage["included_groups"], False, root)
    excluded_groups = _groups(coverage["excluded_groups"], True, root)
    if included_groups.keys() & excluded_groups.keys():
        raise SDKCoverageError("duplicate included/excluded group id")
    selected, group_ids = _selected(registry)
    if included_groups.keys() != group_ids:
        raise SDKCoverageError(f"coverage included groups must match registry groups: {sorted(group_ids)}")
    excluded = _exclusions(excluded_groups, selected, operations)
    unknown = selected.keys() - operations.keys()
    if unknown:
        raise SDKCoverageError(f"selected operations absent from OpenAPI: {sorted(unknown)}")
    missing = operations.keys() - selected.keys() - excluded.keys()
    if missing:
        raise SDKCoverageError(f"unclassified OpenAPI operations: {sorted(missing)}")
    rows = []
    for key, operation in sorted(operations.items()):
        selection = "included" if key in selected else "excluded"
        group_id = selected[key] if key in selected else excluded[key]
        group = included_groups[group_id] if key in selected else excluded_groups[group_id]
        boundary = {field: group[field] for field in sorted(BOUNDARY_FIELDS - {"id"})}
        rows.append({**operation, "selection": selection, "group": group_id, "boundary": boundary})
    return {
        "schema_version": 1,
        "scope": "Generated selection decisions and OpenAPI declarations; not runtime authentication, exposure, licensing enforcement, full wire support or package/platform acceptance.",
        "counts": {"documented": len(operations), "included": len(selected), "excluded": len(excluded)},
        "operations": rows,
    }


def _validate_schema() -> None:
    """Check this fixed schema still describes the manually enforced v1 shape."""
    schema = load_coverage_file(SCHEMA_PATH)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise SDKCoverageError("coverage schema: invalid JSON Schema header")
    _schema_object(schema, ROOT_FIELDS)
    properties = schema["properties"]
    if properties["schema_version"] != {"const": 1, "type": "integer"}:
        raise SDKCoverageError("coverage schema: invalid version")
    definitions = _object(schema.get("$defs"), "coverage schema definitions")
    for name, fields in [("includedGroup", BOUNDARY_FIELDS), ("excludedGroup", BOUNDARY_FIELDS | {"operations"}), ("operation", IDENTITY_FIELDS)]:
        _schema_object(_object(definitions.get(name), name), fields)


def _schema_object(schema: dict, fields: set) -> None:
    required = _array(schema.get("required"), "coverage schema required")
    for field in required:
        _text(field, "coverage schema required field")
    properties = _object(schema.get("properties"), "coverage schema properties")
    if (schema.get("type") != "object" or schema.get("additionalProperties") is not False
            or len(required) != len(fields) or set(required) != fields or properties.keys() != fields):
        raise SDKCoverageError("coverage schema: invalid strict object fields")


def coverage_report(registry: dict, openapi_path: Path, coverage_path: Path | None = None) -> dict:
    _validate_schema()
    return validate_coverage(load_coverage_file(coverage_path or COVERAGE_PATH), registry, load_operations(openapi_path))
