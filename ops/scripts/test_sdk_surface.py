#!/usr/bin/env python3
"""Unit tests for the stdlib SDK-surface compatibility diff."""

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

    def test_baseline_file_is_loaded(self) -> None:
        surface = registry(("auth", ["login"]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(surface), encoding="utf-8")
            self.assertEqual(sdk_surface.load_baseline_file(path), surface)

    def test_baseline_git_ref_is_loaded_without_network(self) -> None:
        surface = registry(("auth", ["login"]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            surface_path = root / sdk_surface.SURFACE_RELATIVE_PATH
            surface_path.parent.mkdir(parents=True)
            surface_path.write_text(json.dumps(surface), encoding="utf-8")
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "sdk-test@example.invalid")
            self._git(root, "config", "user.name", "sdk-test")
            self._git(root, "add", str(sdk_surface.SURFACE_RELATIVE_PATH))
            self._git(root, "commit", "-q", "-m", "baseline")
            self.assertEqual(sdk_surface.load_baseline_ref("HEAD", root), surface)

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
        self.assertIn("added: 0 (additive)", output)
        self.assertIn("removed: 0", output)
        self.assertIn("relocated: 0", output)
        self.assertEqual(output, sdk_surface.format_diff(
            sdk_surface.compare_surfaces(surface, surface), f"file={path}"
        ) + "\n")

    @staticmethod
    def _git(root: Path, *args: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True, text=True
        )


if __name__ == "__main__":
    unittest.main()
