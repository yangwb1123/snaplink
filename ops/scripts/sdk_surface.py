#!/usr/bin/env python3
"""Validate, compare, and regenerate the SDK-surface registry.

The registry (ops/build/sdk-surface.json) is the single source of truth for
the operationId set the TS/Python generators emit. The generators themselves
(cmd/gensdk) carry no allowlist; this checker guarantees the registry stays
reconciled with docs/openapi.yaml (every operation must exist) and
ops/build/capabilities.json (every referenced capability must exist).

The ``diff`` action compares registry group/operation data and, when the
baseline OpenAPI document is available, a bounded structural diff of
components.schemas. It never compares generated source text and requires an
explicit local baseline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from sdk_baseline import SDKBaselineError, load_ref_bundle, load_registry_ref
from sdk_report import format_diff
from sdk_report import unavailable_schema_diff as _unavailable_schema_diff
from sdk_schema import (
    SCHEMA_DIFF_POLICY,
    SDKSchemaError,
    compare_openapi_schemas,
    load_openapi_file,
    load_openapi_text,
)

ROOT = Path(__file__).resolve().parents[2]
SURFACE_PATH = ROOT / "ops" / "build" / "sdk-surface.json"
SURFACE_RELATIVE_PATH = Path("ops/build/sdk-surface.json")
SCHEMA_PATH = ROOT / "ops" / "build" / "sdk-surface.schema.json"
CAPABILITIES_PATH = ROOT / "ops" / "build" / "capabilities.json"
OPENAPI_PATH = ROOT / "docs" / "openapi.yaml"
PYTHON_PACKAGE_PATH = ROOT / "sdks" / "python" / "snaplink_sso" / "client.py"

EXPECTED_SCHEMA_HEADER = "https://json-schema.org/draft/2020-12/schema"
KNOWN_LANGUAGE_STATUSES = {"stable", "preview", "deprecated"}


class SDKSurfaceError(Exception):
    """Raised for any registry, baseline, or contract violation."""


def _parse_json(text: str, source: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SDKSurfaceError(f"{source}: invalid JSON: {exc}") from exc


def _read_json(path: Path, source: str | None = None) -> object:
    label = source or str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SDKSurfaceError(f"{label}: cannot read {path}: {exc}") from exc
    return _parse_json(text, label)


def _require_object(value: object, source: str, description: str) -> dict:
    if not isinstance(value, dict):
        raise SDKSurfaceError(f"{source}: {description} must be an object")
    return value


def _validate_languages(compatibility: dict, source: str) -> None:
    required = {"policy", "languages"}
    missing = sorted(required - compatibility.keys())
    if missing:
        raise SDKSurfaceError(f"{source}: compatibility missing {', '.join(missing)}")
    if set(compatibility) - {"policy", "languages"}:
        extra = sorted(set(compatibility) - {"policy", "languages"})
        raise SDKSurfaceError(
            f"{source}: compatibility has unknown fields: {', '.join(extra)}"
        )
    if not isinstance(compatibility["policy"], str) or not compatibility["policy"]:
        raise SDKSurfaceError(f"{source}: compatibility.policy must be a non-empty string")
    languages = compatibility["languages"]
    if not isinstance(languages, list) or not languages:
        raise SDKSurfaceError(f"{source}: compatibility.languages must not be empty")
    language_ids: set[str] = set()
    for index, language in enumerate(languages):
        item = _require_object(language, source, f"language {index}")
        missing = {"id", "file", "status"} - item.keys()
        if missing:
            raise SDKSurfaceError(
                f"{source}: language {index} missing {', '.join(sorted(missing))}"
            )
        if set(item) - {"id", "file", "status", "notes"}:
            extra = sorted(set(item) - {"id", "file", "status", "notes"})
            raise SDKSurfaceError(
                f"{source}: language {index} has unknown fields: {', '.join(extra)}"
            )
        language_id = item["id"]
        if not isinstance(language_id, str) or not language_id:
            raise SDKSurfaceError(f"{source}: language {index} id must be non-empty")
        if language_id in language_ids:
            raise SDKSurfaceError(f"{source}: duplicate language id {language_id!r}")
        language_ids.add(language_id)
        if not isinstance(item["file"], str) or not item["file"]:
            raise SDKSurfaceError(f"{source}: language {language_id!r} file must be non-empty")
        if item["status"] not in KNOWN_LANGUAGE_STATUSES:
            raise SDKSurfaceError(
                f"{source}: language {language_id!r} has invalid status"
            )
        if "notes" in item and not isinstance(item["notes"], str):
            raise SDKSurfaceError(f"{source}: language {language_id!r} notes must be a string")


def _validate_groups(groups: object, source: str) -> None:
    if not isinstance(groups, list) or not groups:
        raise SDKSurfaceError(f"{source}: groups must not be empty")
    group_ids: set[str] = set()
    operation_ids: set[str] = set()
    for index, group in enumerate(groups):
        item = _require_object(group, source, f"group {index}")
        missing = {"id", "operations"} - item.keys()
        if missing:
            raise SDKSurfaceError(
                f"{source}: group {index} missing {', '.join(sorted(missing))}"
            )
        if set(item) - {"id", "name", "capability", "operations"}:
            extra = sorted(set(item) - {"id", "name", "capability", "operations"})
            raise SDKSurfaceError(
                f"{source}: group {index} has unknown fields: {', '.join(extra)}"
            )
        group_id = item["id"]
        if not isinstance(group_id, str) or not group_id:
            raise SDKSurfaceError(f"{source}: group {index} id must be non-empty")
        if group_id in group_ids:
            raise SDKSurfaceError(f"{source}: duplicate group id {group_id!r}")
        group_ids.add(group_id)
        if "name" in item and not isinstance(item["name"], str):
            raise SDKSurfaceError(f"{source}: group {group_id!r} name must be a string")
        capability = item.get("capability")
        if capability is not None and (
            not isinstance(capability, str) or not capability
        ):
            raise SDKSurfaceError(
                f"{source}: group {group_id!r} capability must be a string or null"
            )
        operations = item["operations"]
        if not isinstance(operations, list) or not operations:
            raise SDKSurfaceError(
                f"{source}: group {group_id!r} operations must not be empty"
            )
        for operation_id in operations:
            if not isinstance(operation_id, str) or not operation_id:
                raise SDKSurfaceError(
                    f"{source}: group {group_id!r} has an invalid operationId"
                )
            if operation_id in operation_ids:
                raise SDKSurfaceError(
                    f"{source}: operationId {operation_id!r} appears in more than one group"
                )
            operation_ids.add(operation_id)


def validate_surface_data(registry: object, source: str) -> dict:
    """Validate registry structure without consulting the current OpenAPI tree."""
    registry = _require_object(registry, source, "registry root")
    required = {"$schema", "schema_version", "compatibility", "groups"}
    missing = sorted(required - registry.keys())
    if missing:
        raise SDKSurfaceError(f"{source}: missing {', '.join(missing)}")
    if set(registry) - required:
        extra = sorted(set(registry) - required)
        raise SDKSurfaceError(f"{source}: unknown fields: {', '.join(extra)}")
    if registry["$schema"] != "./sdk-surface.schema.json":
        raise SDKSurfaceError(f"{source}: $schema must be ./sdk-surface.schema.json")
    if type(registry["schema_version"]) is not int or registry["schema_version"] != 1:
        raise SDKSurfaceError(f"{source}: schema_version must be 1")
    compatibility = _require_object(registry["compatibility"], source, "compatibility")
    _validate_languages(compatibility, source)
    _validate_groups(registry["groups"], source)
    return registry


def load_surface_file(path: Path, source: str | None = None) -> dict:
    """Load and structurally validate a registry JSON file."""
    label = source or str(path)
    return validate_surface_data(_read_json(path, label), label)


def validate_python_package(languages: list[dict]) -> None:
    """Keep the installable Python package byte-identical to its vendorable output."""
    if not any(lang.get("id") == "python" for lang in languages):
        return
    documented = ROOT / next(
        lang["file"] for lang in languages if lang.get("id") == "python"
    )
    if not PYTHON_PACKAGE_PATH.exists():
        raise SDKSurfaceError(f"Python package output missing: {PYTHON_PACKAGE_PATH}")
    if documented.read_bytes() != PYTHON_PACKAGE_PATH.read_bytes():
        raise SDKSurfaceError(
            "Python package output differs from the documented generated client: "
            f"{PYTHON_PACKAGE_PATH}"
        )


def _load_openapi_file(path: Path, source: str | None = None) -> dict:
    try:
        return load_openapi_file(path, source)
    except SDKSchemaError as exc:
        raise SDKSurfaceError(str(exc)) from exc


def _load_openapi_text(text: str, source: str) -> dict:
    try:
        return load_openapi_text(text, source)
    except SDKSchemaError as exc:
        raise SDKSurfaceError(str(exc)) from exc


def load_openapi_operation_ids() -> set[str]:
    doc = _load_openapi_file(OPENAPI_PATH)
    ids: set[str] = set()
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        raise SDKSurfaceError(f"{OPENAPI_PATH}: paths must be an object")
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict) or "operationId" not in operation:
                continue
            operation_id = operation["operationId"]
            if not isinstance(operation_id, str):
                raise SDKSurfaceError(f"{OPENAPI_PATH}: operationId must be a string")
            ids.add(operation_id)
    return ids


def validate_schema() -> None:
    schema = _require_object(_read_json(SCHEMA_PATH), str(SCHEMA_PATH), "schema root")
    properties = schema.get("properties")
    if (
        schema.get("$schema") != EXPECTED_SCHEMA_HEADER
        or schema.get("type") != "object"
        or not isinstance(properties, dict)
        or properties.get("schema_version", {}).get("const") != 1
    ):
        raise SDKSurfaceError(f"{SCHEMA_PATH}: invalid schema header or version")
    groups_schema = properties.get("groups", {})
    if not isinstance(groups_schema, dict) or groups_schema.get("type") != "array":
        raise SDKSurfaceError(f"{SCHEMA_PATH}: groups must be an array")
    compatibility = properties.get("compatibility", {})
    languages = compatibility.get("properties", {}).get("languages", {})
    if not isinstance(languages, dict) or languages.get("type") != "array":
        raise SDKSurfaceError(f"{SCHEMA_PATH}: compatibility.languages must be an array")


def validate_registry() -> dict:
    validate_schema()
    registry = load_surface_file(SURFACE_PATH)
    languages = registry["compatibility"]["languages"]
    validate_python_package(languages)
    openapi_ids = load_openapi_operation_ids()
    capabilities = _require_object(
        _read_json(CAPABILITIES_PATH), str(CAPABILITIES_PATH), "capabilities root"
    )
    capability_entries = capabilities.get("capabilities")
    if not isinstance(capability_entries, list):
        raise SDKSurfaceError(f"{CAPABILITIES_PATH}: capabilities must be an array")
    capability_ids: set[str] = set()
    for entry in capability_entries:
        item = _require_object(entry, str(CAPABILITIES_PATH), "capability")
        capability_id = item.get("id")
        if not isinstance(capability_id, str) or not capability_id:
            raise SDKSurfaceError(f"{CAPABILITIES_PATH}: capability id must be non-empty")
        capability_ids.add(capability_id)
    for group in registry["groups"]:
        for operation_id in group["operations"]:
            if operation_id not in openapi_ids:
                raise SDKSurfaceError(
                    f"{SURFACE_PATH}: operationId {operation_id!r} not found in docs/openapi.yaml"
                )
        capability = group.get("capability")
        if capability is not None and capability not in capability_ids:
            raise SDKSurfaceError(
                f"{SURFACE_PATH}: group {group['id']!r} references unknown capability {capability!r}"
            )
    return registry


def _operation_groups(registry: dict) -> dict[str, str]:
    return {
        operation_id: group["id"]
        for group in registry["groups"]
        for operation_id in group["operations"]
    }


def compare_surfaces(current: object, baseline: object) -> dict:
    """Return a deterministic operationId/group compatibility diff."""
    current_registry = validate_surface_data(current, "current registry")
    baseline_registry = validate_surface_data(baseline, "baseline registry")
    current_groups = _operation_groups(current_registry)
    baseline_groups = _operation_groups(baseline_registry)
    current_ids = set(current_groups)
    baseline_ids = set(baseline_groups)
    added = [
        {"operationId": operation_id, "group": current_groups[operation_id]}
        for operation_id in sorted(current_ids - baseline_ids)
    ]
    removed = [
        {"operationId": operation_id, "group": baseline_groups[operation_id]}
        for operation_id in sorted(baseline_ids - current_ids)
    ]
    relocated = [
        {
            "operationId": operation_id,
            "from_group": baseline_groups[operation_id],
            "to_group": current_groups[operation_id],
        }
        for operation_id in sorted(current_ids & baseline_ids)
        if current_groups[operation_id] != baseline_groups[operation_id]
    ]
    breaking = bool(removed or relocated)
    return {
        "added": added,
        "removed": removed,
        "relocated": relocated,
        "breaking": breaking,
        "status": "breaking" if breaking else "compatible",
    }


def load_baseline_ref(ref: str, root: Path = ROOT) -> dict:
    """Read only the registry at a local git ref without fetching or a shell."""
    try:
        return load_registry_ref(ref, root, validate_surface_data)
    except SDKBaselineError as exc:
        raise SDKSurfaceError(str(exc)) from exc


def _load_baseline_ref_bundle(ref: str, root: Path = ROOT) -> tuple[dict, dict]:
    """Read registry and OpenAPI from the same resolved local commit."""
    try:
        return load_ref_bundle(ref, root, validate_surface_data, _load_openapi_text)
    except SDKBaselineError as exc:
        raise SDKSurfaceError(str(exc)) from exc


def load_baseline_file(path: Path) -> dict:
    """Read and validate a baseline registry JSON file."""
    source = f"baseline file {path}"
    return validate_surface_data(_read_json(path, source), source)


def _baseline_selection(parsed: argparse.Namespace) -> tuple[dict, str, dict | None]:
    selected = [
        ("ref", parsed.baseline_ref),
        ("file", parsed.baseline_file),
    ]
    selected = [(kind, value) for kind, value in selected if value is not None]
    if len(selected) != 1:
        raise SDKSurfaceError(
            "diff requires exactly one explicit baseline: --baseline-ref REF or "
            "--baseline-file FILE"
        )
    kind, value = selected[0]
    if kind == "ref":
        if parsed.baseline_openapi_file is not None:
            raise SDKSurfaceError(
                "--baseline-openapi-file is only valid with --baseline-file; "
                "--baseline-ref reads docs/openapi.yaml from the same ref"
            )
        registry, openapi = _load_baseline_ref_bundle(value)
        return registry, f"ref={value}", openapi
    registry = load_baseline_file(Path(value))
    if parsed.baseline_openapi_file is None:
        return registry, f"file={value}", None
    openapi_path = Path(parsed.baseline_openapi_file)
    openapi = _load_openapi_file(openapi_path, f"baseline OpenAPI file {openapi_path}")
    return registry, f"file={value}", openapi


def _run_diff(parsed: argparse.Namespace) -> int:
    current = load_surface_file(SURFACE_PATH)
    baseline, label, baseline_openapi = _baseline_selection(parsed)
    diff = compare_surfaces(current, baseline)
    if baseline_openapi is None:
        schema_diff = _unavailable_schema_diff()
    else:
        current_openapi = _load_openapi_file(OPENAPI_PATH, "current OpenAPI")
        try:
            schema_diff = compare_openapi_schemas(current_openapi, baseline_openapi)
        except SDKSchemaError as exc:
            raise SDKSurfaceError(str(exc)) from exc
    diff = {**diff, "schema": schema_diff}
    breaking = diff["breaking"] or bool(schema_diff["breaking"])
    diff["breaking"] = breaking
    diff["status"] = "breaking" if breaking else "compatible"
    print(format_diff(diff, label))
    return 1 if breaking else 0


def run(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="sdk-surface",
        description=__doc__,
        epilog=(
            "diff is fail-closed: a baseline is mandatory and must be valid. "
            "--baseline-ref reads both registry and docs/openapi.yaml from that "
            "local ref without fetching. --baseline-file is registry-only unless "
            "paired explicitly with --baseline-openapi-file. Removed or renamed "
            "operationIds, group moves, and breaking schema changes fail; there "
            "is no breaking-change bypass. Schema comparison is a bounded "
            f"components.schemas subset ({SCHEMA_DIFF_POLICY})."
        ),
    )
    parser.add_argument(
        "action",
        choices=["check", "generate", "list", "diff"],
        help="check: validate registry vs OpenAPI/capabilities; "
        "generate: run cmd/gensdk for every language; "
        "list: print group coverage; "
        "diff: compare operation/group data and available components.schemas "
        "with an explicit baseline",
    )
    parser.add_argument(
        "--baseline-ref",
        help="diff baseline git ref, such as origin/main or HEAD^ (local git only)",
    )
    parser.add_argument(
        "--baseline-file",
        help="diff baseline JSON registry file (registry-only unless paired below)",
    )
    parser.add_argument(
        "--baseline-openapi-file",
        help="explicit OpenAPI YAML baseline; valid only with --baseline-file",
    )
    parsed, unknown = parser.parse_known_args(args)
    if unknown:
        print(f"ERROR: unknown sdk-surface argument(s): {' '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        baseline_selected = any(
            value is not None
            for value in (
                parsed.baseline_ref,
                parsed.baseline_file,
                parsed.baseline_openapi_file,
            )
        )
        if parsed.action == "diff":
            return _run_diff(parsed)
        if baseline_selected:
            raise SDKSurfaceError("baseline options are only valid with the diff action")
        if parsed.action == "check":
            registry = validate_registry()
            total = sum(len(g["operations"]) for g in registry["groups"])
            print(
                f"OK: sdk-surface registry valid "
                f"({len(registry['groups'])} groups, {total} operations, "
                f"{len(registry['compatibility']['languages'])} languages)"
            )
            return 0
        if parsed.action == "list":
            registry = validate_registry()
            for group in registry["groups"]:
                cap = group.get("capability") or "-"
                print(f"{group['id']:16} {len(group['operations']):4}  capability={cap}")
            return 0
        validate_registry()
        result = subprocess.run(
            ["go", "run", "./cmd/gensdk", "--lang=all"],
            cwd=ROOT,
            check=False,
        )
        return result.returncode
    except SDKSurfaceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
