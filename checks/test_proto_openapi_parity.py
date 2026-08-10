from pathlib import Path

import pytest
import yaml

from checks.proto_openapi_parity import (
    contract_errors,
    proto_fields,
    schema_properties,
)


def _write_fixture(root: Path, fields, properties):
    """Write a minimal proto + OpenAPI tree mirroring the repo layout."""
    proto_dir = root / "proto" / "admin" / "v1"
    proto_dir.mkdir(parents=True)
    body = "\n".join(
        f"  string {name} = {index};"
        for index, name in enumerate(fields, start=1)
    )
    (proto_dir / "clients.proto").write_text(
        f"message Client {{\n{body}\n}}\n"
    )
    docs = root / "docs"
    docs.mkdir()
    (docs / "openapi.yaml").write_text(yaml.safe_dump({
        "components": {
            "schemas": {
                "AdminClient": {
                    "type": "object",
                    "properties": {prop: {"type": "string"} for prop in properties},
                },
            },
        },
    }))


def test_proto_fields_parses_declarations_and_ignores_comments(tmp_path: Path):
    proto_dir = tmp_path / "proto" / "admin" / "v1"
    proto_dir.mkdir(parents=True)
    (proto_dir / "clients.proto").write_text(
        "// Client mirrors sso.Client.\n"
        "message Client {\n"
        "  string id     = 1;\n"
        "  repeated string redirect_uris = 4; // trailing comment\n"
        "  int64  client_secret_expires_at = 9;\n"
        "}\n"
    )

    fields = proto_fields(tmp_path)

    assert fields == ["id", "redirect_uris", "client_secret_expires_at"]


def test_proto_fields_rejects_oneof_and_nested_messages(tmp_path: Path):
    proto_dir = tmp_path / "proto" / "admin" / "v1"
    proto_dir.mkdir(parents=True)
    (proto_dir / "clients.proto").write_text(
        "message Client {\n"
        "  string id = 1;\n"
        "  oneof creds { string secret = 2; }\n"
        "}\n"
    )

    with pytest.raises(ValueError, match="oneof/nested"):
        proto_fields(tmp_path)


def test_schema_properties_loads_openapi_property_names(tmp_path: Path):
    _write_fixture(tmp_path, ["id"], ["id", "active"])

    properties = schema_properties(tmp_path, "AdminClient")

    assert properties == {"id", "active"}


def test_schema_properties_rejects_unknown_schema(tmp_path: Path):
    _write_fixture(tmp_path, ["id"], ["id"])

    with pytest.raises(ValueError, match="not found"):
        schema_properties(tmp_path, "Missing")


def test_parity_missing_proto_field_fails(tmp_path: Path):
    _write_fixture(tmp_path, ["id", "tenant_id"], ["id"])

    errors, field_count, property_count = contract_errors(tmp_path)

    assert any("tenant_id: proto field absent" in error for error in errors)
    assert field_count == 2
    assert property_count == 1


def test_parity_extra_schema_property_fails(tmp_path: Path):
    _write_fixture(tmp_path, ["id"], ["id", "tenant_id"])

    errors, _, _ = contract_errors(tmp_path)

    assert any("tenant_id: schema property without" in error for error in errors)


def test_parity_exact_match_passes(tmp_path: Path):
    fields = ["id", "secret", "name", "tenant_id", "grant_types"]
    _write_fixture(tmp_path, fields, fields)

    errors, field_count, property_count = contract_errors(tmp_path)

    assert errors == []
    assert field_count == property_count == 5


def test_repository_client_admin_schema_matches_proto():
    errors, field_count, property_count = contract_errors()

    assert field_count >= 10
    assert property_count == field_count
    assert errors == []
