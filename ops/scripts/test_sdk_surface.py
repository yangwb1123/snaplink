#!/usr/bin/env python3
"""Unit tests for the SDK-surface compatibility diff."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sdk_schema
import sdk_surface


def registry(*groups: tuple[str, list[str]]) -> dict:
    return {
        "$schema": "./sdk-surface.schema.json",
        "schema_version": 1,
        "compatibility": {
            "policy": "test policy",
            "languages": [
                {"id": "python", "file": "client.py", "status": "stable"}
            ],
        },
        "groups": [
            {"id": group_id, "operations": operations}
            for group_id, operations in groups
        ],
    }


def document(*schemas: tuple[str, dict]) -> dict:
    return {"components": {"schemas": dict(schemas)}}


def one_schema(schema: dict) -> dict:
    return document(("Thing", schema))


def schema_diff(current: dict, baseline: dict) -> dict:
    return sdk_schema.compare_openapi_schemas(one_schema(current), one_schema(baseline))


def reasons(diff: dict, severity: str) -> set[str]:
    return {item["reason"] for item in diff[severity]}


class SDKSurfaceDiffTests(unittest.TestCase):
    def test_added_operation_is_additive(self) -> None:
        diff = sdk_surface.compare_surfaces(
            registry(("auth", ["login", "logout"])),
            registry(("auth", ["login"])),
        )
        self.assertEqual(diff["added"], [{"operationId": "logout", "group": "auth"}])
        self.assertEqual(diff["removed"], [])
        self.assertFalse(diff["breaking"])

    def test_removed_operation_is_breaking(self) -> None:
        diff = sdk_surface.compare_surfaces(
            registry(("auth", ["login"])),
            registry(("auth", ["login", "logout"])),
        )
        self.assertEqual(diff["removed"], [{"operationId": "logout", "group": "auth"}])
        self.assertTrue(diff["breaking"])

    def test_group_relocation_is_reported_as_breaking(self) -> None:
        diff = sdk_surface.compare_surfaces(
            registry(("admin", ["login"])),
            registry(("auth", ["login"])),
        )
        self.assertEqual(
            diff["relocated"],
            [{"operationId": "login", "from_group": "auth", "to_group": "admin"}],
        )
        self.assertTrue(diff["breaking"])

    def test_no_change_is_compatible(self) -> None:
        surface = registry(("auth", ["login"]))
        diff = sdk_surface.compare_surfaces(surface, surface)
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["relocated"], [])
        self.assertEqual(diff["status"], "compatible")

    def test_baseline_file_is_loaded_as_registry_only(self) -> None:
        surface = sdk_surface.load_surface_file(sdk_surface.SURFACE_PATH)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(surface), encoding="utf-8")
            self.assertEqual(sdk_surface.load_baseline_file(path), surface)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = sdk_surface.run(["diff", "--baseline-file", str(path)])
        self.assertEqual(result, 0)
        self.assertIn("schema comparison: unavailable (registry-only baseline)", stdout.getvalue())
        self.assertIn("schema breaking: unavailable", stdout.getvalue())

    def test_baseline_git_ref_reads_registry_and_openapi_from_same_ref(self) -> None:
        surface = registry(("auth", ["login"]))
        openapi = "components:\n  schemas:\n    Thing:\n      type: object\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_git_file(root, sdk_surface.SURFACE_RELATIVE_PATH, json.dumps(surface))
            self._write_git_file(root, Path("docs/openapi.yaml"), openapi)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "sdk-test@example.invalid")
            self._git(root, "config", "user.name", "sdk-test")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "baseline")
            loaded_registry, loaded_openapi = sdk_surface._load_baseline_ref_bundle("HEAD", root)
        self.assertEqual(loaded_registry, surface)
        self.assertEqual(loaded_openapi["components"]["schemas"]["Thing"]["type"], "object")

    def test_bad_json_baseline_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(sdk_surface.SDKSurfaceError):
                sdk_surface.load_baseline_file(path)

    def test_missing_baseline_file_fails_closed(self) -> None:
        with self.assertRaises(sdk_surface.SDKSurfaceError):
            sdk_surface.load_baseline_file(Path("does-not-exist.json"))

    def test_bad_git_ref_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            with self.assertRaises(sdk_surface.SDKSurfaceError):
                sdk_surface.load_baseline_ref("not-a-ref", root)

    def test_bad_ref_openapi_and_missing_ref_file_fail_closed(self) -> None:
        surface = registry(("auth", ["login"]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_git_file(root, sdk_surface.SURFACE_RELATIVE_PATH, json.dumps(surface))
            self._write_git_file(root, Path("docs/openapi.yaml"), "components: [")
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "sdk-test@example.invalid")
            self._git(root, "config", "user.name", "sdk-test")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "bad-openapi")
            with self.assertRaises(sdk_surface.SDKSurfaceError):
                sdk_surface._load_baseline_ref_bundle("HEAD", root)

            self._git(root, "rm", "-q", "docs/openapi.yaml")
            self._git(root, "commit", "-q", "-m", "missing-openapi")
            with self.assertRaises(sdk_surface.SDKSurfaceError):
                sdk_surface._load_baseline_ref_bundle("HEAD", root)

    def test_baseline_openapi_file_is_compared_when_explicitly_paired(self) -> None:
        surface = sdk_surface.load_surface_file(sdk_surface.SURFACE_PATH)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "baseline.json"
            openapi_path = root / "baseline.yaml"
            registry_path.write_text(json.dumps(surface), encoding="utf-8")
            openapi_path.write_text(
                "components:\n  schemas:\n    ErrorResponse:\n      type: string\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = sdk_surface.run(
                    [
                        "diff",
                        "--baseline-file",
                        str(registry_path),
                        "--baseline-openapi-file",
                        str(openapi_path),
                    ]
                )
        self.assertEqual(result, 1)
        self.assertIn("schema comparison: available (components.schemas)", stdout.getvalue())
        self.assertIn('reason="type_changed"', stdout.getvalue())

    def test_bad_openapi_file_fails_closed_at_command_boundary(self) -> None:
        surface = sdk_surface.load_surface_file(sdk_surface.SURFACE_PATH)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "baseline.json"
            openapi_path = root / "broken.yaml"
            registry_path.write_text(json.dumps(surface), encoding="utf-8")
            openapi_path.write_text("components: [", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = sdk_surface.run(
                    [
                        "diff",
                        "--baseline-file",
                        str(registry_path),
                        "--baseline-openapi-file",
                        str(openapi_path),
                    ]
                )
        self.assertEqual(result, 1)
        self.assertIn("ERROR:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_duplicate_operation_id_fails_closed(self) -> None:
        bad = registry(("auth", ["login"]), ("admin", ["login"]))
        with self.assertRaises(sdk_surface.SDKSurfaceError):
            sdk_surface.compare_surfaces(bad, registry(("auth", ["login"])))

    def test_diff_command_requires_an_explicit_baseline(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = sdk_surface.run(["diff"])
        self.assertNotEqual(result, 0)
        self.assertIn("exactly one explicit baseline", stderr.getvalue())

    def test_baseline_openapi_file_has_explicit_pairing_semantics(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = sdk_surface.run(["diff", "--baseline-ref", "HEAD^", "--baseline-openapi-file", "x"])
        self.assertEqual(result, 1)
        self.assertIn("only valid with --baseline-file", stderr.getvalue())

    def test_breaking_change_bypass_is_not_an_option(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = sdk_surface.run(
                ["diff", "--baseline-ref", "HEAD^", "--allow-breaking"]
            )
        self.assertEqual(result, 2)
        self.assertIn("unknown sdk-surface argument", stderr.getvalue())

    def test_diff_command_rejects_removed_operation(self) -> None:
        baseline = sdk_surface.load_surface_file(sdk_surface.SURFACE_PATH)
        baseline["groups"][0]["operations"].append("removedForTest")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(baseline), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = sdk_surface.run(["diff", "--baseline-file", str(path)])
        self.assertEqual(result, 1)
        self.assertIn('operationId="removedForTest"', stdout.getvalue())
        self.assertIn("compatibility: breaking", stdout.getvalue())

    def test_diff_command_file_output_is_stable(self) -> None:
        surface = sdk_surface.load_surface_file(sdk_surface.SURFACE_PATH)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(surface), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = sdk_surface.run(["diff", "--baseline-file", str(path)])
        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("operation surface:", output)
        self.assertIn("schema comparison: unavailable", output)
        self.assertEqual(
            output,
            sdk_surface.format_diff(
                sdk_surface.compare_surfaces(surface, surface), f"file={path}"
            )
            + "\n",
        )

    def test_schema_no_change_is_compatible(self) -> None:
        schema = {"type": "object", "properties": {"id": {"type": "string"}}}
        diff = schema_diff(schema, schema)
        self.assertEqual(diff["breaking"], [])
        self.assertEqual(diff["additive"], [])
        self.assertEqual(diff["status"], "compatible")

    def test_schema_and_property_removal_are_breaking(self) -> None:
        current = {"type": "object", "properties": {"id": {"type": "string"}}}
        baseline = {"type": "object", "properties": {"id": {"type": "string"}, "old": {"type": "string"}}}
        property_diff = schema_diff(current, baseline)
        self.assertIn("property_removed", reasons(property_diff, "breaking"))
        deleted_schema = sdk_schema.compare_openapi_schemas(
            document(("New", current)), document(("New", current), ("Old", {"type": "string"}))
        )
        self.assertIn("schema_removed", reasons(deleted_schema, "breaking"))

    def test_new_schema_is_additive(self) -> None:
        current = document(("Existing", {"type": "string"}), ("New", {"type": "object"}))
        baseline = document(("Existing", {"type": "string"}))
        diff = sdk_schema.compare_openapi_schemas(current, baseline)
        self.assertEqual(diff["breaking"], [])
        self.assertEqual(reasons(diff, "additive"), {"schema_added"})

    def test_required_property_addition_is_breaking(self) -> None:
        baseline = {"type": "object", "properties": {"name": {"type": "string"}}}
        current = {"type": "object", "required": ["name"], "properties": baseline["properties"]}
        diff = schema_diff(current, baseline)
        self.assertIn("required_property_added", reasons(diff, "breaking"))

    def test_ref_type_and_format_changes_are_breaking(self) -> None:
        cases = [
            ({"type": "integer"}, {"type": "string"}, "type_changed"),
            ({"format": "uri"}, {"format": "email"}, "format_changed"),
            ({"$ref": "#/components/schemas/New"}, {"$ref": "#/components/schemas/Old"}, "ref_changed"),
        ]
        for current, baseline, reason in cases:
            with self.subTest(reason=reason):
                self.assertIn(reason, reasons(schema_diff(current, baseline), "breaking"))

    def test_enum_addition_and_removal_are_classified(self) -> None:
        baseline = {"type": "string", "enum": ["a", "b"]}
        removal = schema_diff({"type": "string", "enum": ["a"]}, baseline)
        addition = schema_diff({"type": "string", "enum": ["a", "b", "c"]}, baseline)
        self.assertIn("enum_value_removed", reasons(removal, "breaking"))
        self.assertIn("enum_value_added", reasons(addition, "additive"))
        self.assertFalse(addition["breaking"])

    def test_additional_properties_and_array_nested_changes_are_breaking(self) -> None:
        baseline = {
            "type": "object",
            "additionalProperties": True,
            "properties": {"rows": {"type": "array", "items": {"type": "string"}}},
        }
        current = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"rows": {"type": "array", "items": {"type": "integer"}}},
        }
        diff = schema_diff(current, baseline)
        self.assertIn("additional_properties_tightened", reasons(diff, "breaking"))
        self.assertIn("type_changed", reasons(diff, "breaking"))
        self.assertTrue(any("items.type" in item["path"] for item in diff["breaking"]))

    def test_nested_property_type_change_is_breaking(self) -> None:
        baseline = {
            "type": "object",
            "properties": {
                "profile": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                }
            },
        }
        current = {
            "type": "object",
            "properties": {
                "profile": {
                    "type": "object",
                    "properties": {"name": {"type": "integer"}},
                }
            },
        }
        diff = schema_diff(current, baseline)
        self.assertIn("type_changed", reasons(diff, "breaking"))
        self.assertTrue(
            any("properties.profile.properties.name.type" in item["path"] for item in diff["breaking"])
        )

    def test_optional_property_and_required_removal_are_additive(self) -> None:
        baseline = {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
        current = {
            "type": "object",
            "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
        }
        diff = schema_diff(current, baseline)
        self.assertEqual(diff["breaking"], [])
        self.assertIn("optional_property_added", reasons(diff, "additive"))
        self.assertIn("required_constraint_removed", reasons(diff, "additive"))

    def test_description_title_examples_and_default_are_not_breaking(self) -> None:
        baseline = {
            "type": "object",
            "description": "old",
            "title": "Old",
            "example": {"id": "a"},
            "examples": [{"id": "a"}],
            "default": {"id": "a"},
            "properties": {"id": {"type": "string", "description": "old"}},
        }
        current = {
            "type": "object",
            "description": "new",
            "title": "New",
            "example": {"id": "b"},
            "examples": [{"id": "b"}],
            "default": {"id": "b"},
            "properties": {"id": {"type": "string", "description": "new"}},
        }
        self.assertEqual(schema_diff(current, baseline)["status"], "compatible")

    def test_changed_composition_is_conservative_breaking(self) -> None:
        baseline = {"oneOf": [{"required": ["a"]}, {"required": ["b"]}]}
        current = {"oneOf": [{"required": ["a"]}, {"required": ["c"]}]}
        diff = schema_diff(current, baseline)
        self.assertIn("schema_composition_changed", reasons(diff, "breaking"))

    def test_unsupported_keyword_change_is_conservative_breaking(self) -> None:
        baseline = {"type": "string", "minLength": 1}
        current = {"type": "string", "minLength": 2}
        diff = schema_diff(current, baseline)
        self.assertEqual(diff["status"], "breaking")
        self.assertIn("unsupported_schema_change", reasons(diff, "breaking"))

    def test_malformed_schema_yaml_and_unsupported_shape_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.yaml"
            path.write_text("components: [", encoding="utf-8")
            with self.assertRaises(sdk_surface.SDKSurfaceError):
                sdk_surface._load_openapi_file(path)
        with self.assertRaises(sdk_schema.SDKSchemaError):
            sdk_schema.load_openapi_text(
                "components:\n  schemas:\n    Thing:\n      oneOf: nope\n", "test OpenAPI"
            )
        with self.assertRaises(sdk_schema.SDKSchemaError):
            sdk_schema.load_openapi_text(
                "components:\n  schemas:\n    Thing:\n      items: [string, integer]\n", "test OpenAPI"
            )

    def test_schema_output_is_sorted_and_has_fixed_fields(self) -> None:
        current = {"type": "object", "properties": {"z": {"type": "integer"}, "a": {"type": "integer"}}}
        baseline = {"type": "object", "properties": {"z": {"type": "string"}, "b": {"type": "string"}}}
        diff = schema_diff(current, baseline)
        operation = sdk_surface.compare_surfaces(registry(("auth", ["login"])), registry(("auth", ["login"])))
        combined = {**operation, "schema": diff, "breaking": True, "status": "breaking"}
        output = sdk_surface.format_diff(combined, "test")
        self.assertEqual(output, sdk_surface.format_diff(combined, "test"))
        records = [line for line in output.splitlines() if " schema=" in line]
        breaking = [line for line in records if line.startswith("  -")]
        additive = [line for line in records if line.startswith("  +")]
        self.assertEqual(breaking, sorted(breaking))
        self.assertEqual(additive, sorted(additive))
        self.assertTrue(all("path=" in line and "reason=" in line and "detail=" in line for line in records))

    @staticmethod
    def _write_git_file(root: Path, relative: Path, content: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    @staticmethod
    def _git(root: Path, *args: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
