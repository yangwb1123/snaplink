#!/usr/bin/env python3
"""Unit tests for the fixed SDK package-version release gate."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sdk_surface
import sdk_toml
import sdk_versions


VERSIONS = ("0.3.0", "0.3.0", "0.3.0", "0.3.0")
NAMES = (
    "@snaplink/sso-client",
    "snaplink-sso",
    "snaplink-sso",
    "snaplink/sso-client",
)


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_fixtures(
    root: Path,
    versions: tuple[str, str, str, str] = VERSIONS,
    lock_version: str | None = None,
) -> None:
    ts_version, py_version, rust_version, php_version = versions
    lock_version = lock_version or ts_version
    _write(
        root,
        "docs/sdks/typescript/package.json",
        json.dumps({"name": NAMES[0], "version": ts_version}),
    )
    _write(
        root,
        "docs/sdks/typescript/package-lock.json",
        json.dumps(
            {
                "name": NAMES[0],
                "version": lock_version,
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": NAMES[0],
                        "version": lock_version,
                        "devDependencies": {"typescript": "99.99.99"},
                    },
                    "node_modules/typescript": {"version": "99.99.99"},
                },
            }
        ),
    )
    _write(
        root,
        "sdks/python/pyproject.toml",
        f'''[project]
name = "{NAMES[1]}"
version = "{py_version}"
dependencies = ["example-dependency==99.99.99"]

[tool.example]
version = "88.88.88"
''',
    )
    _write(
        root,
        "sdks/rust/Cargo.toml",
        f'''[package]
name = "{NAMES[2]}"
version = "{rust_version}"
edition = "2021"

[dependencies]
example-dependency = "77.77.77"
''',
    )
    _write(
        root,
        "sdks/php/composer.json",
        json.dumps(
            {
                "name": NAMES[3],
                "version": php_version,
                "require": {"example/dependency": "66.66.66"},
            }
        ),
    )


def _package(report: sdk_versions.VersionReport, package_id: str) -> sdk_versions.PackageVersion:
    return next(package for package in report.packages if package.id == package_id)


class SDKVersionGateTests(unittest.TestCase):
    def test_current_repository_versions_pass(self) -> None:
        report = sdk_versions.load_version_report()
        self.assertTrue(report.ok)
        self.assertEqual([package.version for package in report.packages], list(VERSIONS))
        self.assertEqual([package.name for package in report.packages], list(NAMES))

    def test_semver_supports_prerelease_and_build_metadata(self) -> None:
        self.assertTrue(sdk_versions.is_valid_semver("1.2.3-alpha.1+build.5"))
        self.assertTrue(sdk_versions.is_valid_semver("0.3.0-rc.0"))
        self.assertFalse(sdk_versions.is_valid_semver("0.3.0-01"))
        self.assertFalse(sdk_versions.is_valid_semver("0.3.0-rc..1"))
        self.assertFalse(sdk_versions.is_valid_semver("01.3.0"))
        self.assertFalse(sdk_versions.is_valid_semver("0.3"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, versions=("1.2.3-alpha.1+build.5",) * 4)
            report = sdk_versions.load_version_report(root)
        self.assertTrue(report.ok)

    def test_typescript_lock_root_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, lock_version="0.3.1")
            report = sdk_versions.load_version_report(root)
        package = _package(report, "typescript")
        self.assertFalse(report.ok)
        self.assertIn("package-lock root version", package.error or "")
        self.assertEqual(package.version, "0.3.0")

    def test_package_version_mismatch_fails_without_normalizing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, versions=("0.3.0", "0.3.1", "0.3.0", "0.3.0"))
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("SDK package versions differ", report.failure_message())
        output = sdk_versions.format_version_report(report)
        self.assertIn('id="python" name="snaplink-sso" version="0.3.1"', output)
        self.assertTrue(output.endswith("verdict: FAIL"))

    def test_invalid_semver_is_rejected_in_each_manifest_format(self) -> None:
        for invalid in ("0.3.0-01", "0.3.0-rc..1", "0.3", "1.2.3+"):
            with self.subTest(version=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_fixtures(root, versions=(invalid,) * 4)
                report = sdk_versions.load_version_report(root)
            self.assertFalse(report.ok)
            self.assertIn("invalid SemVer", report.failure_message())

    def test_bad_json_fails_closed(self) -> None:
        for relative in (
            "docs/sdks/typescript/package.json",
            "docs/sdks/typescript/package-lock.json",
            "sdks/php/composer.json",
        ):
            with self.subTest(manifest=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_fixtures(root)
                (root / relative).write_text("{", encoding="utf-8")
                report = sdk_versions.load_version_report(root)
            self.assertFalse(report.ok)
            self.assertIn("invalid JSON", report.failure_message())

    def test_bad_toml_fails_closed(self) -> None:
        for relative in ("sdks/python/pyproject.toml", "sdks/rust/Cargo.toml"):
            with self.subTest(manifest=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_fixtures(root)
                (root / relative).write_text("[project\nversion = \"0.3.0\"", encoding="utf-8")
                report = sdk_versions.load_version_report(root)
            self.assertFalse(report.ok)
            self.assertIn("invalid TOML", report.failure_message())

    def test_missing_manifest_and_version_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            (root / "sdks/rust/Cargo.toml").unlink()
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("manifest is missing", _package(report, "rust").error or "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            package_path = root / "docs/sdks/typescript/package.json"
            package_path.write_text(json.dumps({"name": NAMES[0]}), encoding="utf-8")
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("package version is missing", _package(report, "typescript").error or "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            lock_path = root / "docs/sdks/typescript/package-lock.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            del lock["packages"][""]["version"]
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn('packages[""] version must be a string', _package(report, "typescript").error or "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            package_path = root / "sdks/python/pyproject.toml"
            package_path.write_text('[project]\nname = "snaplink-sso"\nversion = 3\n', encoding="utf-8")
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("version must be a string", _package(report, "python").error or "")

    def test_dependency_versions_are_not_package_versions(self) -> None:
        cases = {
            "typescript": ("docs/sdks/typescript/package.json", {"name": NAMES[0]}),
            "python": (
                "sdks/python/pyproject.toml",
                '[project]\nname = "snaplink-sso"\n\n[dependency]\nversion = "99.99.99"\n',
            ),
            "rust": (
                "sdks/rust/Cargo.toml",
                '[package]\nname = "snaplink-sso"\n\n[dependency]\nversion = "99.99.99"\n',
            ),
            "php": (
                "sdks/php/composer.json",
                {"name": NAMES[3], "require": {"example/dependency": "99.99.99"}},
            ),
        }
        for package_id, (relative, content) in cases.items():
            with self.subTest(package=package_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_fixtures(root)
                rendered = content if isinstance(content, str) else json.dumps(content)
                _write(root, relative, rendered)
                report = sdk_versions.load_version_report(root)
            self.assertFalse(report.ok)
            self.assertIn("package version is missing", _package(report, package_id).error or "")

    def test_older_python_fallback_parses_current_fixture_shapes(self) -> None:
        original = sdk_toml._tomllib
        try:
            sdk_toml._tomllib = None
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_fixtures(root)
                report = sdk_versions.load_version_report(root)
        finally:
            sdk_toml._tomllib = original
        self.assertTrue(report.ok)

    def test_success_output_is_stable(self) -> None:
        report = sdk_versions.VersionReport(
            tuple(
                sdk_versions.PackageVersion(package_id, name, "0.3.0")
                for package_id, name in zip((spec.id for spec in sdk_versions.MANIFEST_SPECS), NAMES)
            )
        )
        self.assertEqual(
            sdk_versions.format_version_report(report),
            "\n".join(
                [
                    "sdk-surface versions",
                    'package id="typescript" name="@snaplink/sso-client" version="0.3.0" status=PASS',
                    'package id="python" name="snaplink-sso" version="0.3.0" status=PASS',
                    'package id="rust" name="snaplink-sso" version="0.3.0" status=PASS',
                    'package id="php" name="snaplink/sso-client" version="0.3.0" status=PASS',
                    "verdict: PASS",
                ]
            ),
        )

    def test_cli_failure_is_nonzero_and_output_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, lock_version="0.3.1")
            report = sdk_versions.load_version_report(root)
        stdout = io.StringIO()
        with patch.object(sdk_versions, "load_version_report", return_value=report):
            with contextlib.redirect_stdout(stdout):
                result = sdk_surface.run(["versions"])
        self.assertEqual(result, 1)
        output = stdout.getvalue()
        self.assertIn('status=FAIL reason=', output)
        self.assertTrue(output.endswith("verdict: FAIL\n"))

    def test_sdk_surface_check_reuses_version_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, lock_version="0.3.1")
            report = sdk_versions.load_version_report(root)
        stderr = io.StringIO()
        with patch.object(sdk_surface, "load_version_report", return_value=report):
            with contextlib.redirect_stderr(stderr):
                result = sdk_surface.run(["check"])
        self.assertEqual(result, 1)
        self.assertIn("SDK package version gate failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
