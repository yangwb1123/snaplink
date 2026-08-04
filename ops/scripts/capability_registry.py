#!/usr/bin/env python3
"""Validate capability metadata and generate its human-readable matrix."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path
from typing import Iterable

try:
    from .module_catalog import ModuleConfigError, load_catalog
except ImportError:
    from module_catalog import ModuleConfigError, load_catalog


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "ops" / "build" / "capabilities.json"
SCHEMA_PATH = ROOT / "ops" / "build" / "capability.schema.json"
FEATURE_MATRIX_PATH = ROOT / "docs" / "feature-matrix.md"
FEATURE_GATES_PATH = ROOT / "config" / "config.go"

BEGIN_MARKER = "<!-- BEGIN GENERATED CAPABILITY AVAILABILITY -->"
END_MARKER = "<!-- END GENERATED CAPABILITY AVAILABILITY -->"
AVAILABILITY_CLASSES = (
    "sdk",
    "stock-binary",
    "module-only",
    "external-frontend",
)
DEFAULT_STATES = ("enabled", "disabled", "conditional", "external")
TOP_FIELDS = {
    "$schema",
    "schema_version",
    "availability_classes",
    "default_states",
    "feature_gates",
    "capabilities",
}
CAPABILITY_FIELDS = {
    "id",
    "name",
    "summary",
    "availability",
    "default_state",
    "feature_gate",
    "required_stores",
    "module_capabilities",
    "config_keys",
    "surfaces",
    "sources",
}
LIST_FIELDS = {
    "availability",
    "required_stores",
    "module_capabilities",
    "config_keys",
    "surfaces",
    "sources",
}
CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9.-]+$")
# Deprecated YAML aliases still parsed by FeatureGatesConfig (kept in the
# registry's feature_gates list because the drift check compares against the
# Go struct's YAML tags) but not standalone runtime gates: no capability may
# reference them, and they are excluded from the missing-gate error.
DEPRECATED_FEATURE_GATES = frozenset({"web_spa"})
FEATURE_GATES_RE = re.compile(
    r"type FeatureGatesConfig struct \{(?P<body>.*?)\n\}",
    re.DOTALL,
)
YAML_TAG_RE = re.compile(r'`yaml:"([^"]+)"`')


class CapabilityRegistryError(ValueError):
    """A deterministic capability registry or generated-document failure."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise CapabilityRegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise CapabilityRegistryError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CapabilityRegistryError(f"{path}: expected a JSON object")
    return data


def load_registry(path: Path = REGISTRY_PATH) -> dict:
    """Load registry JSON while rejecting duplicate object keys."""
    return _read_json(path)


def _reject_unknown(data: dict, allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    missing = sorted(allowed - set(data))
    if unknown:
        raise CapabilityRegistryError(
            f"{label}: unknown fields: {', '.join(unknown)}"
        )
    if missing:
        raise CapabilityRegistryError(
            f"{label}: missing fields: {', '.join(missing)}"
        )


def _string_list(data: dict, key: str, label: str) -> list[str]:
    value = data[key]
    if not isinstance(value, list):
        raise CapabilityRegistryError(f"{label}.{key}: expected an array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise CapabilityRegistryError(
            f"{label}.{key}: expected non-empty strings"
        )
    if len(set(value)) != len(value):
        raise CapabilityRegistryError(f"{label}.{key}: duplicate values")
    return value


def _runtime_feature_gates() -> tuple[str, ...]:
    try:
        source = FEATURE_GATES_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise CapabilityRegistryError(
            f"{FEATURE_GATES_PATH}: cannot read runtime feature gates"
        ) from exc
    match = FEATURE_GATES_RE.search(source)
    if not match:
        raise CapabilityRegistryError(
            f"{FEATURE_GATES_PATH}: FeatureGatesConfig not found"
        )
    gates = tuple(YAML_TAG_RE.findall(match.group("body")))
    if not gates or len(gates) != len(set(gates)):
        raise CapabilityRegistryError(
            f"{FEATURE_GATES_PATH}: invalid FeatureGatesConfig YAML tags"
        )
    return gates


def _known_module_capabilities() -> set[str]:
    try:
        catalog = load_catalog()
    except ModuleConfigError as exc:
        raise CapabilityRegistryError(f"module catalog: {exc}") from exc
    return {
        provided
        for module in catalog.modules.values()
        for provided in module.provides
    }


def _validate_schema(
    availability: list[str],
    defaults: list[str],
    feature_gates: list[str],
) -> None:
    schema = _read_json(SCHEMA_PATH)
    try:
        if (
            schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
            or schema["type"] != "object"
            or schema["properties"]["schema_version"]["const"] != 1
        ):
            raise CapabilityRegistryError(
                f"{SCHEMA_PATH}: invalid schema header or version"
            )
        schema_availability = schema["properties"]["availability_classes"][
            "items"
        ]["enum"]
        schema_defaults = schema["properties"]["default_states"]["items"]["enum"]
        schema_gates = schema["properties"]["feature_gates"]["items"]["enum"]
        capability_gates = schema["$defs"]["capability"]["properties"][
            "feature_gate"
        ]["enum"]
    except (KeyError, TypeError) as exc:
        raise CapabilityRegistryError(
            f"{SCHEMA_PATH}: required schema structure is missing"
        ) from exc
    for label, declared, expected in (
        ("availability classes", schema_availability, availability),
        ("default states", schema_defaults, defaults),
        ("feature gates", schema_gates, feature_gates),
        (
            "capability feature gates",
            [value for value in capability_gates if value is not None],
            feature_gates,
        ),
    ):
        if set(declared) != set(expected) or len(declared) != len(expected):
            raise CapabilityRegistryError(
                f"{SCHEMA_PATH}: {label} drift from capabilities.json"
            )


def _validate_source(source: str, label: str, root: Path) -> None:
    path = Path(source)
    if path.is_absolute() or ".." in path.parts:
        raise CapabilityRegistryError(
            f"{label}.sources: path must stay repository-relative: {source}"
        )
    if not (root / path).exists():
        raise CapabilityRegistryError(
            f"{label}.sources: path does not exist: {source}"
        )


def _validate_external(capability: dict, label: str) -> None:
    external = "external-frontend" in capability["availability"]
    if external and capability["availability"] != ["external-frontend"]:
        raise CapabilityRegistryError(
            f"{label}: external-frontend cannot be combined with server availability"
        )
    if external:
        empty_fields = ("required_stores", "module_capabilities", "config_keys")
        if (
            capability["default_state"] != "external"
            or capability["feature_gate"] is not None
            or any(capability[field] for field in empty_fields)
        ):
            raise CapabilityRegistryError(
                f"{label}: external frontend must have external state and no "
                "server gate, store, module, or config dependency"
            )
    elif capability["default_state"] == "external":
        raise CapabilityRegistryError(
            f"{label}: external state requires external-frontend availability"
        )


def _validate_capability(
    capability: object,
    index: int,
    feature_gates: set[str],
    module_capabilities: set[str],
    root: Path,
) -> str:
    label = f"capabilities[{index}]"
    if not isinstance(capability, dict):
        raise CapabilityRegistryError(f"{label}: expected an object")
    _reject_unknown(capability, CAPABILITY_FIELDS, label)
    for field in ("id", "name", "summary"):
        if not isinstance(capability[field], str) or not capability[field].strip():
            raise CapabilityRegistryError(
                f"{label}.{field}: expected a non-empty string"
            )
    capability_id = capability["id"]
    if not CAPABILITY_ID_RE.fullmatch(capability_id):
        raise CapabilityRegistryError(f"{label}.id: invalid capability id")
    for field in LIST_FIELDS:
        _string_list(capability, field, label)
    availability = capability["availability"]
    if not availability:
        raise CapabilityRegistryError(f"{label}.availability: cannot be empty")
    unknown_availability = sorted(set(availability) - set(AVAILABILITY_CLASSES))
    if unknown_availability:
        raise CapabilityRegistryError(
            f"{label}.availability: unknown values: "
            f"{', '.join(unknown_availability)}"
        )
    expected_order = sorted(
        availability, key=lambda value: AVAILABILITY_CLASSES.index(value)
    )
    if availability != expected_order:
        raise CapabilityRegistryError(
            f"{label}.availability: values must use registry order"
        )
    if capability["default_state"] not in DEFAULT_STATES:
        raise CapabilityRegistryError(f"{label}.default_state: invalid value")
    gate = capability["feature_gate"]
    if gate is not None and gate not in feature_gates:
        raise CapabilityRegistryError(f"{label}.feature_gate: unknown gate {gate!r}")
    unknown_modules = sorted(
        set(capability["module_capabilities"]) - module_capabilities
    )
    if unknown_modules:
        raise CapabilityRegistryError(
            f"{label}.module_capabilities: unknown capabilities: "
            f"{', '.join(unknown_modules)}"
        )
    if (
        "module-only" in availability
        and not capability["module_capabilities"]
    ):
        raise CapabilityRegistryError(
            f"{label}: module-only availability requires a module capability"
        )
    for source in capability["sources"]:
        _validate_source(source, label, root)
    if not capability["surfaces"]:
        raise CapabilityRegistryError(f"{label}.surfaces: cannot be empty")
    if not capability["sources"]:
        raise CapabilityRegistryError(f"{label}.sources: cannot be empty")
    _validate_external(capability, label)
    return capability_id


def validate_registry(
    data: dict,
    *,
    root: Path = ROOT,
    module_capabilities: set[str] | None = None,
    runtime_feature_gates: Iterable[str] | None = None,
) -> None:
    """Validate registry shape and its links to runtime/module sources."""
    _reject_unknown(data, TOP_FIELDS, str(REGISTRY_PATH))
    if data["$schema"] != "./capability.schema.json":
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.$schema: expected ./capability.schema.json"
        )
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.schema_version: expected 1"
        )
    availability = _string_list(
        data, "availability_classes", str(REGISTRY_PATH)
    )
    defaults = _string_list(data, "default_states", str(REGISTRY_PATH))
    feature_gates = _string_list(data, "feature_gates", str(REGISTRY_PATH))
    if tuple(availability) != AVAILABILITY_CLASSES:
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.availability_classes: unexpected vocabulary"
        )
    if tuple(defaults) != DEFAULT_STATES:
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.default_states: unexpected vocabulary"
        )
    runtime_gates = set(runtime_feature_gates or _runtime_feature_gates())
    if set(feature_gates) != runtime_gates or len(feature_gates) != len(runtime_gates):
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.feature_gates: drift from FeatureGatesConfig"
        )
    _validate_schema(availability, defaults, feature_gates)
    capabilities = data["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.capabilities: expected a non-empty array"
        )
    known_modules = module_capabilities or _known_module_capabilities()
    ids = [
        _validate_capability(
            capability,
            index,
            set(feature_gates),
            known_modules,
            root,
        )
        for index, capability in enumerate(capabilities)
    ]
    if len(ids) != len(set(ids)):
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.capabilities: duplicate capability ids"
        )
    if ids != sorted(ids):
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.capabilities: ids must be sorted"
        )
    used_gates = {
        capability["feature_gate"]
        for capability in capabilities
        if capability["feature_gate"] is not None
    }
    missing_gates = sorted(set(feature_gates) - used_gates - DEPRECATED_FEATURE_GATES)
    if missing_gates:
        raise CapabilityRegistryError(
            f"{REGISTRY_PATH}.capabilities: feature gates without a capability: "
            f"{', '.join(missing_gates)}"
        )


def _code_values(values: Iterable[str]) -> str:
    rendered = [f"`{value}`" for value in values]
    return "<br>".join(rendered) if rendered else "—"


def render_generated_section(data: dict) -> str:
    """Render the bounded Markdown section owned by the registry."""
    rows = [
        BEGIN_MARKER,
        "## Capability availability registry",
        "",
        "Generated from "
        "[`ops/build/capabilities.json`](../ops/build/capabilities.json); "
        "edit the registry and run `python cli.py capabilities generate`.",
        "",
        "| Capability | Availability | Default | Feature gate | Required store(s) | Surface(s) |",
        "|---|---|---|---|---|---|",
    ]
    for capability in data["capabilities"]:
        gate = capability["feature_gate"]
        rows.append(
            "| "
            + " | ".join(
                (
                    f"{capability['name']} (`{capability['id']}`)",
                    _code_values(capability["availability"]),
                    f"`{capability['default_state']}`",
                    f"`feature_gates.{gate}`" if gate else "—",
                    _code_values(capability["required_stores"]),
                    _code_values(capability["surfaces"]),
                )
            )
            + " |"
        )
    rows.extend((END_MARKER, ""))
    return "\n".join(rows)


def generated_document(data: dict, document: str) -> str:
    """Replace only the generated marker region in the feature matrix."""
    if document.count(BEGIN_MARKER) != 1 or document.count(END_MARKER) != 1:
        raise CapabilityRegistryError(
            f"{FEATURE_MATRIX_PATH}: expected one generated marker pair"
        )
    start = document.index(BEGIN_MARKER)
    end_start = document.index(END_MARKER)
    if end_start <= start:
        raise CapabilityRegistryError(
            f"{FEATURE_MATRIX_PATH}: generated markers are out of order"
        )
    end = end_start + len(END_MARKER)
    return document[:start] + render_generated_section(data).rstrip() + document[end:]


def check_repository() -> int:
    """Validate registry and fail when the generated feature matrix drifted."""
    data = load_registry()
    validate_registry(data)
    try:
        current = FEATURE_MATRIX_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise CapabilityRegistryError(
            f"{FEATURE_MATRIX_PATH}: cannot read feature matrix"
        ) from exc
    expected = generated_document(data, current)
    if current != expected:
        diff = "".join(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=str(FEATURE_MATRIX_PATH),
                tofile="generated",
                n=2,
            )
        )
        raise CapabilityRegistryError(
            "generated capability matrix is stale; run "
            "`python cli.py capabilities generate`\n" + diff[:4000]
        )
    return len(data["capabilities"])


def generate() -> bool:
    """Validate and refresh the generated feature-matrix section."""
    data = load_registry()
    validate_registry(data)
    current = FEATURE_MATRIX_PATH.read_text(encoding="utf-8")
    expected = generated_document(data, current)
    if current == expected:
        return False
    FEATURE_MATRIX_PATH.write_text(expected, encoding="utf-8")
    return True


def _list_capabilities(data: dict) -> None:
    for capability in data["capabilities"]:
        availability = ",".join(capability["availability"])
        print(f"{capability['id']}\t{availability}\t{capability['default_state']}")


def run(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python cli.py capabilities",
        description="Validate or generate the Snaplink capability registry.",
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=("check", "generate", "list"),
        default="check",
    )
    parsed = parser.parse_args(args)
    try:
        if parsed.action == "generate":
            changed = generate()
            print(
                "capability registry valid; feature matrix "
                + ("generated" if changed else "already current")
            )
        elif parsed.action == "list":
            data = load_registry()
            validate_registry(data)
            _list_capabilities(data)
        else:
            count = check_repository()
            print(
                "capability registry valid "
                f"({count} capabilities); feature matrix current"
            )
    except CapabilityRegistryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
