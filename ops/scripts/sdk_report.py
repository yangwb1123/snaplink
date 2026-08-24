#!/usr/bin/env python3
"""Stable human-readable output for the SDK-surface compatibility diff."""

from __future__ import annotations

import json

from sdk_schema import SCHEMA_DIFF_POLICY


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def unavailable_schema_diff() -> dict:
    return {"available": False, "breaking": [], "additive": [], "status": "unavailable"}


def _format_schema_changes(items: list[dict], marker: str) -> list[str]:
    return [
        f"  {marker} schema={_quote(item['schema'])} path={_quote(item['path'])} "
        f"reason={_quote(item['reason'])} detail={_quote(item['detail'])}"
        for item in items
    ]


def format_diff(diff: dict, baseline_label: str) -> str:
    schema = diff.get("schema", unavailable_schema_diff())
    lines = [
        "sdk-surface diff",
        f"baseline: {baseline_label}",
        "current: ops/build/sdk-surface.json",
        "operation surface:",
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
    if schema["available"]:
        lines.append("schema comparison: available (components.schemas)")
        lines.append(f"schema breaking: {len(schema['breaking'])}")
        lines.extend(_format_schema_changes(schema["breaking"], "-"))
        lines.append(f"schema additive: {len(schema['additive'])}")
        lines.extend(_format_schema_changes(schema["additive"], "+"))
    else:
        lines.append("schema comparison: unavailable (registry-only baseline)")
        lines.append("schema breaking: unavailable")
        lines.append("schema additive: unavailable")
    lines.append(f"schema policy: {SCHEMA_DIFF_POLICY}")
    lines.append(f"compatibility: {diff['status']}")
    lines.append("version: unchanged (no automatic version update)")
    return "\n".join(lines)
