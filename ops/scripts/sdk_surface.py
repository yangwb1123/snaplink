#!/usr/bin/env python3
"""Validate the SDK-surface registry and regenerate the consumer SDKs.

The registry (ops/build/sdk-surface.json) is the single source of truth for
the operationId set the TS/Python generators emit. The generators themselves
(cmd/gensdk) carry no allowlist; this checker guarantees the registry stays
reconciled with docs/openapi.yaml (every operation must exist) and
ops/build/capabilities.json (every referenced capability must exist).
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
SCHEMA_PATH = ROOT / "ops" / "build" / "sdk-surface.schema.json"
CAPABILITIES_PATH = ROOT / "ops" / "build" / "capabilities.json"
OPENAPI_PATH = ROOT / "docs" / "openapi.yaml"

EXPECTED_SCHEMA_HEADER = "https://json-schema.org/draft/2020-12/schema"


class SDKSurfaceError(Exception):
    """Raised for any registry/contract violation."""


def load_openapi_operation_ids() -> set[str]:
    if yaml is None:
        raise SDKSurfaceError("PyYAML is required to read docs/openapi.yaml")
    doc = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for path_item in doc.get("paths", {}).values():
        for method, op in path_item.items():
            if isinstance(op, dict) and "operationId" in op:
                ids.add(op["operationId"])
    return ids


def validate_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if (
        schema.get("$schema") != EXPECTED_SCHEMA_HEADER
        or schema.get("type") != "object"
        or schema.get("properties", {}).get("schema_version", {}).get("const") != 1
    ):
        raise SDKSurfaceError(f"{SCHEMA_PATH}: invalid schema header or version")
    groups_schema = schema["properties"]["groups"]
    if groups_schema.get("type") != "array":
        raise SDKSurfaceError(f"{SCHEMA_PATH}: groups must be an array")
    language_schema = schema["properties"]["compatibility"]["properties"]["languages"]
    if language_schema.get("type") != "array":
        raise SDKSurfaceError(f"{SCHEMA_PATH}: compatibility.languages must be an array")


def validate_registry() -> dict:
    validate_schema()
    try:
        registry = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SDKSurfaceError(f"{SURFACE_PATH}: invalid JSON: {exc}") from exc
    if registry.get("$schema") != "./sdk-surface.schema.json":
        raise SDKSurfaceError(f"{SURFACE_PATH}: $schema must be ./sdk-surface.schema.json")
    if registry.get("schema_version") != 1:
        raise SDKSurfaceError(f"{SURFACE_PATH}: schema_version must be 1")
    languages = registry.get("compatibility", {}).get("languages", [])
    if not languages:
        raise SDKSurfaceError(f"{SURFACE_PATH}: compatibility.languages must not be empty")
    known_statuses = {"stable", "preview", "deprecated"}
    for lang in languages:
        if lang.get("status") not in known_statuses:
            raise SDKSurfaceError(
                f"{SURFACE_PATH}: language {lang.get('id')!r} has invalid status"
            )
        if not (ROOT / lang["file"]).exists():
            raise SDKSurfaceError(
                f"{SURFACE_PATH}: language {lang.get('id')!r} output {lang['file']} missing"
            )
    groups = registry.get("groups", [])
    if not groups:
        raise SDKSurfaceError(f"{SURFACE_PATH}: groups must not be empty")
    group_ids = [g.get("id") for g in groups]
    if len(group_ids) != len(set(group_ids)):
        raise SDKSurfaceError(f"{SURFACE_PATH}: duplicate group ids")

    openapi_ids = load_openapi_operation_ids()
    capabilities = json.loads(CAPABILITIES_PATH.read_text(encoding="utf-8"))
    capability_ids = {c["id"] for c in capabilities["capabilities"]}

    seen: set[str] = set()
    for group in groups:
        for op_id in group["operations"]:
            if op_id in seen:
                raise SDKSurfaceError(
                    f"{SURFACE_PATH}: operationId {op_id!r} appears in more than one group"
                )
            seen.add(op_id)
            if op_id not in openapi_ids:
                raise SDKSurfaceError(
                    f"{SURFACE_PATH}: operationId {op_id!r} not found in docs/openapi.yaml"
                )
        cap = group.get("capability")
        if cap is not None and cap not in capability_ids:
            raise SDKSurfaceError(
                f"{SURFACE_PATH}: group {group['id']!r} references unknown capability {cap!r}"
            )
    return registry


def run(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="sdk-surface", description=__doc__)
    parser.add_argument(
        "action",
        choices=["check", "generate", "list"],
        help="check: validate registry vs OpenAPI/capabilities; "
        "generate: run cmd/gensdk for every language; list: print group coverage",
    )
    parsed, _ = parser.parse_known_args(args)
    try:
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
                print(
                    f"{group['id']:16} {len(group['operations']):4}  capability={cap}"
                )
            return 0
        # generate
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
