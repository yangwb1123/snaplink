#!/usr/bin/env python3
"""Fail when a proto message field drifts from its OpenAPI schema."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROTO_FILE = Path("proto/admin/v1/clients.proto")
OPENAPI_FILE = Path("docs/openapi.yaml")

# Proto message name -> OpenAPI schema name. Extend when a new message gains a
# schema; the check then keeps both sides in lockstep automatically.
MESSAGE_TO_SCHEMA = {
    "Client": "AdminClient",
}

MESSAGE_BLOCK = re.compile(r"^message\s+(\w+)\s*\{", re.MULTILINE)
# Top-level proto3 scalar/repeated field declarations. Trailing comments are
# tolerated; comment lines cannot match because they start with "//".
FIELD = re.compile(r"^\s*(?:repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+\s*;", re.MULTILINE)
NESTED_BLOCK = re.compile(r"^message\s+\w+\s*\{", re.MULTILINE)


def _message_body(text: str, message: str) -> str:
    """Return the raw body of a top-level message block, failing loudly on
    constructs the flat field parser cannot represent."""
    match = MESSAGE_BLOCK.search(text)
    while match and match.group(1) != message:
        match = MESSAGE_BLOCK.search(text, match.end())
    if not match:
        raise ValueError(f"message {message} not found in {PROTO_FILE}")
    body = text[match.end():]
    end = re.search(r"^\}", body, re.MULTILINE)
    if not end:
        raise ValueError(f"message {message} block is not closed")
    body = body[:end.start()]
    if "oneof " in body or NESTED_BLOCK.search(body):
        raise ValueError(
            f"message {message} contains oneof/nested messages; parity is unsupported"
        )
    if "reserved" in body:
        raise ValueError(
            f"message {message} contains a reserved range; parity is unsupported"
        )
    return body


def proto_fields(root: Path = ROOT, message: str = "Client") -> list[str]:
    """Collect top-level field names declared in the proto message."""
    text = (root / PROTO_FILE).read_text()
    body = _message_body(text, message)
    return [match.group(1) for match in FIELD.finditer(body)]


def schema_properties(root: Path = ROOT, schema: str = "AdminClient") -> set[str]:
    """Load the documented property names for an OpenAPI schema."""
    document = yaml.safe_load((root / OPENAPI_FILE).read_text())
    schemas = document.get("components", {}).get("schemas", {})
    if schema not in schemas:
        raise ValueError(f"schema {schema} not found in {OPENAPI_FILE}")
    return set(schemas[schema].get("properties", {}))


def contract_errors(root: Path = ROOT) -> tuple[list[str], int, int]:
    """Return drift lines plus proto-field and schema-property counts."""
    errors: list[str] = []
    field_count = 0
    property_count = 0
    for message, schema in sorted(MESSAGE_TO_SCHEMA.items()):
        try:
            fields = proto_fields(root, message)
            properties = schema_properties(root, schema)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"{message} -> {schema}: {exc}")
            continue
        field_count += len(fields)
        property_count += len(properties)
        for field in fields:
            if field not in properties:
                errors.append(
                    f"{message}.{field}: proto field absent from {schema} schema"
                )
        for prop in sorted(properties - set(fields)):
            errors.append(
                f"{schema} {prop}: schema property without a {message} proto field"
            )
    return errors, field_count, property_count


def run() -> int:
    try:
        errors, field_count, property_count = contract_errors(ROOT)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"FAIL: proto/OpenAPI parity check could not run: {exc}")
        return 1
    if errors:
        print("FAIL: proto/OpenAPI field parity drift")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        "PASS: proto/OpenAPI field parity "
        f"({field_count} proto fields, {property_count} schema properties)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
