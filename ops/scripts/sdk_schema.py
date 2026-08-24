#!/usr/bin/env python3
"""Bounded structural compatibility checks for OpenAPI component schemas.

This module intentionally compares only ``components.schemas``. It ignores
schema documentation/example metadata, classifies the supported structural
changes deterministically, and treats composition changes conservatively.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by the command boundary
    yaml = None


class SDKSchemaError(Exception):
    """Raised when an OpenAPI document cannot be safely compared."""


SCHEMA_DIFF_POLICY = (
    "bounded components.schemas structural diff; description/title/examples/"
    "default metadata is ignored; oneOf/anyOf/allOf and related composition "
    "changes are conservative breaking; other unsupported keyword changes are "
    "conservative breaking"
)

_METADATA_KEYS = {"description", "title", "example", "examples", "default"}
_LIST_COMPOSITIONS = {"oneOf", "anyOf", "allOf"}
_OTHER_COMPOSITIONS = {
    "not",
    "if",
    "then",
    "else",
    "dependentSchemas",
    "prefixItems",
    "contains",
    "unevaluatedProperties",
    "unevaluatedItems",
}
_COMPOSITION_KEYS = _LIST_COMPOSITIONS | _OTHER_COMPOSITIONS
_HANDLED_KEYS = {
    "$ref",
    "type",
    "format",
    "enum",
    "nullable",
    "properties",
    "required",
    "additionalProperties",
    "items",
}
_MISSING = object()


def _display(value: Any) -> str:
    if value is _MISSING:
        return "<absent>"
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _schema_path(parent: str, child: str) -> str:
    if child.replace("_", "").replace("-", "").isalnum():
        return f"{parent}.{child}"
    return f"{parent}[{json.dumps(child, ensure_ascii=True)}]"


def _error(source: str, path: str, message: str) -> SDKSchemaError:
    return SDKSchemaError(f"{source}: {path}: {message}")


def _validate_json_value(value: Any, source: str, path: str, active: set[int]) -> None:
    if value is None or isinstance(value, (str, int, bool)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _error(source, path, "non-finite numbers are unsupported")
        return
    marker = id(value)
    if marker in active:
        raise _error(source, path, "cyclic YAML alias is unsupported")
    active.add(marker)
    try:
        if isinstance(value, list):
            for index, item in enumerate(value):
                _validate_json_value(item, source, f"{path}[{index}]", active)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise _error(source, path, "mapping keys must be strings")
                _validate_json_value(item, source, f"{path}.{key}", active)
            return
    finally:
        active.remove(marker)
    raise _error(source, path, f"unsupported YAML value {type(value).__name__}")


def _validate_enum(value: list[Any], source: str, path: str) -> None:
    seen: set[str] = set()
    for index, item in enumerate(value):
        _validate_json_value(item, source, f"{path}[{index}]", set())
        key = _canonical(item)
        if key in seen:
            raise _error(source, path, "enum values must be unique")
        seen.add(key)


def _validate_schema_node(
    node: Any, source: str, path: str, active: set[int]
) -> None:
    if not isinstance(node, dict):
        raise _error(source, path, "schema must be an object")
    marker = id(node)
    if marker in active:
        raise _error(source, path, "cyclic YAML alias is unsupported")
    active.add(marker)
    try:
        for key, value in node.items():
            if not isinstance(key, str):
                raise _error(source, path, "schema keyword names must be strings")
            child_path = _schema_path(path, key)
            if key in _METADATA_KEYS or key.startswith("x-"):
                _validate_json_value(value, source, child_path, active)
            elif key in _LIST_COMPOSITIONS:
                if not isinstance(value, list) or not value:
                    raise _error(source, child_path, "composition must be a non-empty list")
                for index, branch in enumerate(value):
                    _validate_schema_node(branch, source, f"{child_path}[{index}]", active)
            elif key == "not" or key in {"if", "then", "else", "contains"}:
                _validate_schema_node(value, source, child_path, active)
            elif key == "dependentSchemas":
                if not isinstance(value, dict):
                    raise _error(source, child_path, "dependentSchemas must be an object")
                for name, child in value.items():
                    if not isinstance(name, str):
                        raise _error(source, child_path, "dependent schema names must be strings")
                    _validate_schema_node(child, source, f"{child_path}.{name}", active)
            elif key == "prefixItems":
                if not isinstance(value, list):
                    raise _error(source, child_path, "prefixItems must be a list")
                for index, child in enumerate(value):
                    _validate_schema_node(child, source, f"{child_path}[{index}]", active)
            elif key in {"unevaluatedProperties", "unevaluatedItems"}:
                if not isinstance(value, (bool, dict)):
                    raise _error(source, child_path, f"{key} must be boolean or object")
                if isinstance(value, dict):
                    _validate_schema_node(value, source, child_path, active)
            elif key in _OTHER_COMPOSITIONS:
                _validate_json_value(value, source, child_path, active)
            elif key == "properties":
                if not isinstance(value, dict):
                    raise _error(source, child_path, "properties must be an object")
                for name, child in value.items():
                    if not isinstance(name, str):
                        raise _error(source, child_path, "property names must be strings")
                    _validate_schema_node(child, source, f"{child_path}.{name}", active)
            elif key == "required":
                if not isinstance(value, list) or any(
                    not isinstance(item, str) or not item for item in value
                ):
                    raise _error(source, child_path, "required must be a list of names")
                if len(value) != len(set(value)):
                    raise _error(source, child_path, "required names must be unique")
            elif key == "additionalProperties":
                if not isinstance(value, (bool, dict)):
                    raise _error(source, child_path, "additionalProperties must be boolean or object")
                if isinstance(value, dict):
                    _validate_schema_node(value, source, child_path, active)
            elif key == "items":
                _validate_schema_node(value, source, child_path, active)
            elif key in {"$ref", "format", "type"}:
                if not isinstance(value, str) or not value:
                    raise _error(source, child_path, f"{key} must be a non-empty string")
            elif key == "enum":
                if not isinstance(value, list):
                    raise _error(source, child_path, "enum must be a list")
                _validate_enum(value, source, child_path)
            elif key == "nullable":
                if not isinstance(value, bool):
                    raise _error(source, child_path, "nullable must be boolean")
            else:
                _validate_json_value(value, source, child_path, active)
    finally:
        active.remove(marker)


def load_openapi_text(text: str, source: str) -> dict:
    """Parse and validate the OpenAPI portions needed by the diff."""
    if yaml is None:
        raise SDKSchemaError("PyYAML is required to read OpenAPI YAML")
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise SDKSchemaError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise _error(source, "$", "OpenAPI root must be an object")
    try:
        _schema_map(document, source)
    except RecursionError as exc:
        raise SDKSchemaError(f"{source}: schema nesting is too deep to compare") from exc
    return document


def load_openapi_file(path: Path, source: str | None = None) -> dict:
    label = source or str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SDKSchemaError(f"{label}: cannot read {path}: {exc}") from exc
    return load_openapi_text(text, label)


def _schema_map(document: dict, source: str) -> dict[str, dict]:
    components = document.get("components", {})
    if not isinstance(components, dict):
        raise _error(source, "$.components", "components must be an object")
    schemas = components.get("schemas", {})
    if not isinstance(schemas, dict):
        raise _error(source, "$.components.schemas", "schemas must be an object")
    result: dict[str, dict] = {}
    for name, schema in schemas.items():
        if not isinstance(name, str) or not name:
            raise _error(source, "$.components.schemas", "schema names must be non-empty strings")
        _validate_schema_node(schema, source, f"$.components.schemas.{name}", set())
        result[name] = schema
    return result


def _semantic_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _semantic_value(item)
            for key, item in sorted(value.items())
            if key not in _METADATA_KEYS
        }
    if isinstance(value, list):
        return [_semantic_value(item) for item in value]
    return value


def _record(changes: dict[str, list[dict]], severity: str, schema: str, path: str,
            reason: str, detail: str) -> None:
    item = {"schema": schema, "path": path, "reason": reason, "detail": detail}
    if item not in changes[severity]:
        changes[severity].append(item)


def _detail(old: Any, new: Any) -> str:
    return f"baseline={_display(old)} current={_display(new)}"


def _compare_compositions(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    keys = sorted(_COMPOSITION_KEYS & (set(base) | set(current)))
    for key in keys:
        old = base.get(key, _MISSING)
        new = current.get(key, _MISSING)
        if _semantic_value(old) == _semantic_value(new):
            continue
        _record(
            changes,
            "breaking",
            schema,
            _schema_path(path, key),
            "schema_composition_changed",
            "policy=conservative-breaking",
        )


def _compare_scalar_keywords(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    for key, reason in (("$ref", "ref_changed"), ("type", "type_changed"), ("format", "format_changed")):
        old = base.get(key, _MISSING)
        new = current.get(key, _MISSING)
        if old != new:
            _record(changes, "breaking", schema, _schema_path(path, key), reason, _detail(old, new))
    old_nullable = base.get("nullable", False)
    new_nullable = current.get("nullable", False)
    if old_nullable != new_nullable:
        severity = "additive" if new_nullable else "breaking"
        reason = "nullable_constraint_removed" if new_nullable else "nullable_restricted"
        _record(changes, severity, schema, _schema_path(path, "nullable"), reason,
               _detail(old_nullable, new_nullable))


def _compare_enum(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    old = base.get("enum", _MISSING)
    new = current.get("enum", _MISSING)
    if old is _MISSING and new is _MISSING:
        return
    enum_path = _schema_path(path, "enum")
    if old is _MISSING:
        _record(changes, "breaking", schema, enum_path, "enum_constraint_added", f"values={_display(new)}")
        return
    if new is _MISSING:
        _record(changes, "additive", schema, enum_path, "enum_constraint_removed", f"values={_display(old)}")
        return
    old_values = {_canonical(value): value for value in old}
    new_values = {_canonical(value): value for value in new}
    for key in sorted(old_values.keys() - new_values.keys()):
        _record(changes, "breaking", schema, enum_path, "enum_value_removed", f"value={_display(old_values[key])}")
    for key in sorted(new_values.keys() - old_values.keys()):
        _record(changes, "additive", schema, enum_path, "enum_value_added", f"value={_display(new_values[key])}")


def _compare_properties(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    old_properties = base.get("properties", {})
    new_properties = current.get("properties", {})
    old_required = set(base.get("required", []))
    new_required = set(current.get("required", []))
    property_path = _schema_path(path, "properties")
    for name in sorted(old_properties.keys() - new_properties.keys()):
        _record(changes, "breaking", schema, _schema_path(property_path, name), "property_removed", "")
    for name in sorted(new_properties.keys() - old_properties.keys()):
        if name in new_required:
            _record(changes, "breaking", schema, _schema_path(property_path, name),
                   "required_property_added", "property is new and required")
        else:
            _record(changes, "additive", schema, _schema_path(property_path, name),
                   "optional_property_added", "property is optional")
    for name in sorted(old_properties.keys() & new_properties.keys()):
        _compare_node(old_properties[name], new_properties[name], schema,
                      _schema_path(property_path, name), changes)
    _compare_required(base, current, schema, path, changes)


def _compare_required(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    old_required = set(base.get("required", []))
    new_required = set(current.get("required", []))
    old_properties = base.get("properties", {})
    new_properties = current.get("properties", {})
    required_path = _schema_path(path, "required")
    for name in sorted(new_required - old_required):
        if name not in old_properties and name in new_properties:
            continue
        _record(changes, "breaking", schema, _schema_path(required_path, name),
               "required_property_added", "property became required")
    for name in sorted(old_required - new_required):
        if name not in new_properties and name in old_properties:
            continue
        _record(changes, "additive", schema, _schema_path(required_path, name),
               "required_constraint_removed", "property is no longer required")


def _additional_value(node: dict) -> Any:
    return node.get("additionalProperties", True)


def _compare_additional_properties(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    old = _additional_value(base)
    new = _additional_value(current)
    if _semantic_value(old) == _semantic_value(new):
        return
    additional_path = _schema_path(path, "additionalProperties")
    if old is False and new is not False:
        _record(changes, "additive", schema, additional_path, "additional_properties_widened", _detail(old, new))
    elif new is False and old is not False:
        _record(changes, "breaking", schema, additional_path, "additional_properties_tightened", _detail(old, new))
    elif isinstance(old, dict) and isinstance(new, dict):
        _compare_node(old, new, schema, additional_path, changes)
    elif new is True:
        _record(changes, "additive", schema, additional_path, "additional_properties_widened", _detail(old, new))
    else:
        _record(changes, "breaking", schema, additional_path, "additional_properties_tightened", _detail(old, new))


def _compare_items(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    old = base.get("items", _MISSING)
    new = current.get("items", _MISSING)
    if old is _MISSING and new is _MISSING:
        return
    items_path = _schema_path(path, "items")
    if old is _MISSING:
        _record(changes, "breaking", schema, items_path, "items_schema_added", "array items became constrained")
    elif new is _MISSING:
        _record(changes, "additive", schema, items_path, "items_schema_removed", "array items became unconstrained")
    else:
        _compare_node(old, new, schema, items_path, changes)


def _compare_unsupported_keywords(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    ignored = _METADATA_KEYS | _COMPOSITION_KEYS | _HANDLED_KEYS
    keys = (set(base) | set(current)) - ignored
    for key in sorted(keys):
        old = base.get(key, _MISSING)
        new = current.get(key, _MISSING)
        if _semantic_value(old) == _semantic_value(new):
            continue
        _record(changes, "breaking", schema, _schema_path(path, key),
               "unsupported_schema_change", f"keyword={key}; policy=conservative-breaking")


def _compare_node(
    base: dict, current: dict, schema: str, path: str, changes: dict[str, list[dict]]
) -> None:
    if _semantic_value(base) == _semantic_value(current):
        return
    _compare_scalar_keywords(base, current, schema, path, changes)
    _compare_compositions(base, current, schema, path, changes)
    _compare_enum(base, current, schema, path, changes)
    _compare_properties(base, current, schema, path, changes)
    _compare_additional_properties(base, current, schema, path, changes)
    _compare_items(base, current, schema, path, changes)
    _compare_unsupported_keywords(base, current, schema, path, changes)


def _sorted_changes(changes: list[dict]) -> list[dict]:
    return sorted(changes, key=lambda item: tuple(item[key] for key in ("schema", "path", "reason", "detail")))


def compare_openapi_schemas(current: dict, baseline: dict) -> dict:
    """Return a stable bounded diff for OpenAPI ``components.schemas``."""
    try:
        current_schemas = _schema_map(current, "current OpenAPI")
        baseline_schemas = _schema_map(baseline, "baseline OpenAPI")
        changes = {"breaking": [], "additive": []}
        for name in sorted(baseline_schemas.keys() - current_schemas.keys()):
            _record(
                changes,
                "breaking",
                name,
                "$",
                "schema_removed",
                "schema is no longer declared",
            )
        for name in sorted(current_schemas.keys() - baseline_schemas.keys()):
            _record(
                changes,
                "additive",
                name,
                "$",
                "schema_added",
                "schema is newly declared",
            )
        for name in sorted(current_schemas.keys() & baseline_schemas.keys()):
            _compare_node(baseline_schemas[name], current_schemas[name], name, "$", changes)
    except RecursionError as exc:
        raise SDKSchemaError("OpenAPI schema nesting is too deep to compare") from exc
    breaking = _sorted_changes(changes["breaking"])
    additive = _sorted_changes(changes["additive"])
    return {
        "available": True,
        "breaking": breaking,
        "additive": additive,
        "status": "breaking" if breaking else "compatible",
    }
