#!/usr/bin/env python3
"""Validate, compare, and regenerate the SDK-surface registry.

The registry (ops/build/sdk-surface.json) is the single source of truth for
the operationId set the TS/Python generators emit. The generators themselves
(cmd/gensdk) carry no allowlist; this checker guarantees the registry stays
reconciled with docs/openapi.yaml (every operation must exist) and
ops/build/capabilities.json (every referenced capability must exist).

The ``diff`` action compares registry group/operation data only. It never
compares generated source text and requires an explicit baseline supplied as a
local git ref or JSON file.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    import yaml  # PyYAML
except ImportError:
    yaml = None

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


def load_openapi_operation_ids() -> set[str]:
    if yaml is None:
        raise SDKSurfaceError("PyYAML is required to read docs/openapi.yaml")
    try:
        doc = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SDKSurfaceError(f"{OPENAPI_PATH}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise SDKSurfaceError(f"{OPENAPI_PATH}: root must be an object")
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


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def format_diff(diff: dict, baseline_label: str) -> str:
    lines = [
        "sdk-surface diff",
        f"baseline: {baseline_label}",
        "current: ops/build/sdk-surface.json",
        f"added: {len(diff['added'])} (additive)",
    ]
    lines.extend(
        f"  + operationId={_quote(item['operationId'])} group={_quote(item['group'])}"
        for item in diff["added"]
    )
    lines.append(
        f"removed: {len(diff['removed'])} (breaking; rename is reported as added + removed)"
    )
    lines.extend(
        f"  - operationId={_quote(item['operationId'])} group={_quote(item['group'])}"
        for item in diff["removed"]
    )
    lines.append(f"relocated: {len(diff['relocated'])} (breaking by policy)")
    lines.extend(
        "  ~ operationId="
        f"{_quote(item['operationId'])} from_group={_quote(item['from_group'])} "
        f"to_group={_quote(item['to_group'])}"
        for item in diff["relocated"]
    )
    lines.append(f"compatibility: {diff['status']}")
    lines.append("version: unchanged (no automatic version update)")
    return "\n".join(lines)


def _run_git(args: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError) as exc:
        raise SDKSurfaceError("cannot run git for SDK-surface baseline") from exc


def load_baseline_ref(ref: str, root: Path = ROOT) -> dict:
    """Read the registry at a local git ref without fetching or using a shell."""
    if not ref or not ref.strip():
        raise SDKSurfaceError("baseline git ref must not be empty")
    resolved = _run_git(
        ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}"],
        root,
    )
    if resolved.returncode != 0 or not resolved.stdout.strip():
        raise SDKSurfaceError(f"baseline git ref {ref!r} is invalid")
    object_name = resolved.stdout.strip()
    path_spec = f"{object_name}:{SURFACE_RELATIVE_PATH.as_posix()}"
    shown = _run_git(["show", "--no-ext-diff", "--format=", path_spec], root)
    source = f"baseline git ref {ref!r}"
    if shown.returncode != 0:
        raise SDKSurfaceError(
            f"{source} does not contain {SURFACE_RELATIVE_PATH.as_posix()}"
        )
    return validate_surface_data(_parse_json(shown.stdout, source), source)


def load_baseline_file(path: Path) -> dict:
    """Read and validate a baseline registry JSON file."""
    source = f"baseline file {path}"
    return validate_surface_data(_read_json(path, source), source)


def _baseline_selection(parsed: argparse.Namespace) -> tuple[dict, str]:
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
        return load_baseline_ref(value), f"ref={value}"
    return load_baseline_file(Path(value)), f"file={value}"


def _run_diff(parsed: argparse.Namespace) -> int:
    current = load_surface_file(SURFACE_PATH)
    baseline, label = _baseline_selection(parsed)
    diff = compare_surfaces(current, baseline)
    print(format_diff(diff, label))
    return 1 if diff["breaking"] else 0


def run(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="sdk-surface",
        description=__doc__,
        epilog=(
            "diff is fail-closed: a baseline is mandatory and must be a valid "
            "registry. Removed or renamed operationIds are breaking; additions "
            "are additive; moving an operationId between groups is breaking by "
            "policy. There is no breaking-change bypass."
        ),
    )
    parser.add_argument(
        "action",
        choices=["check", "generate", "list", "diff"],
        help="check: validate registry vs OpenAPI/capabilities; "
        "generate: run cmd/gensdk for every language; "
        "list: print group coverage; "
        "diff: compare registry operation/group data with an explicit baseline",
    )
    parser.add_argument(
        "--baseline-ref",
        help="diff baseline git ref, such as origin/main or HEAD^ (local git only)",
    )
    parser.add_argument(
        "--baseline-file",
        help="diff baseline JSON registry file",
    )
    parsed, unknown = parser.parse_known_args(args)
    if unknown:
        print(f"ERROR: unknown sdk-surface argument(s): {' '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        baseline_selected = any(
            value is not None
            for value in (parsed.baseline_ref, parsed.baseline_file)
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
