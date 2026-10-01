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

# Manifest formats whose package version is carried by a release tag rather
# than by a version field in the manifest. Kept here as a set so the rule stays
# format-derived: adding a third such format is a one-line change, not a new
# special case in the assertion below.
TAG_VERSIONED_FORMATS = frozenset({"swift", "gomod"})


VERSIONS = ("0.3.0", "0.3.0", "0.3.0", "0.3.0", "0.3.0", "")

#: What the committed manifests actually say. Rust is ahead at 0.4.0 because it
#: took a breaking change (async transport); the others are 0.3.0 with additive
#: changes only, which the train rule permits.
# Swift and Go report no version: both derive it from the release tag, so the
# gate checks their name and leaves the version unavailable.
REPOSITORY_VERSIONS = ("0.3.0", "0.3.0", "0.4.0", "0.3.0", "0.3.0", "", "")
NAMES = (
    "@snaplink/sso",
    "snaplink-sso",
    "snaplink-sso",
    "snaplink/sso",
    "site.ywbsd.sso:snaplink",
    "SnaplinkSSO",
    "github.com/yangwb1123/snaplink/sdks/go",
)


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_fixtures(
    root: Path,
    versions: tuple[str, ...] = VERSIONS,
    lock_version: str | None = None,
) -> None:
    # Swift and Go take no version from a manifest; their slots are ignored.
    ts_version, py_version, rust_version, php_version, kotlin_version = versions[:5]
    lock_version = lock_version or ts_version
    _write(
        root,
        "sdks/typescript/package.json",
        json.dumps({"name": NAMES[0], "version": ts_version}),
    )
    _write(
        root,
        "sdks/typescript/package-lock.json",
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
    _write(
        root,
        "sdks/settings.gradle.kts",
        '''rootProject.name = "snaplink-native-sdks"
include(":snaplink")
project(":snaplink").projectDir = file("kotlin")
''',
    )
    _write(
        root,
        "sdks/kotlin/build.gradle.kts",
        f'''plugins {{ id("com.android.library") }}
group = "site.ywbsd.sso"
version = "{kotlin_version}"

android {{ namespace = "com.snaplink.sso" }}
''',
    )
    # SwiftPM derives its version from the release tag, so the fixture pins the
    # package name only. That is the one manifest with no version to read.
    _write(
        root,
        "Package.swift",
        '''// swift-tools-version: 5.9
let package = Package(
    name: "SnaplinkSSO"
)
''',
    )
    # The Go client SDK is a nested module. It reports no version for the same
    # reason Swift does: the go command resolves the version from the tag.
    _write(
        root,
        "sdks/go/go.mod",
        """module github.com/yangwb1123/snaplink/sdks/go

go 1.26.1
""",
    )


def _package(report: sdk_versions.VersionReport, package_id: str) -> sdk_versions.PackageVersion:
    return next(package for package in report.packages if package.id == package_id)


class SDKVersionGateTests(unittest.TestCase):
    def test_current_repository_versions_pass(self) -> None:
        """The committed manifests must satisfy the gate, now and after a release.

        The expected versions are read from the manifests rather than pinned
        here: a hardcoded list breaks on every version bump, which is exactly
        when the gate matters least and trains people to ignore it.
        """
        report = sdk_versions.load_version_report()
        self.assertTrue(report.ok, report.failure_message())
        self.assertEqual(
            [spec.id for spec in sdk_versions.MANIFEST_SPECS],
            [package.id for package in report.packages],
        )
        self.assertEqual(list(NAMES), [package.name for package in report.packages])

        # A package must carry a version unless its manifest format is one
        # where the version lives elsewhere — SwiftPM derives it from the release
        # tag, and a Go module's version is its module tag. Deriving this from
        # the format keeps the rule correct when another such package is added,
        # instead of naming today's ones.
        tag_versioned = {
            spec.id for spec in sdk_versions.MANIFEST_SPECS if spec.format in TAG_VERSIONED_FORMATS
        }

        majors = set()
        for package in report.packages:
            if package.version is None:
                self.assertIn(
                    package.id,
                    tag_versioned,
                    f"{package.id} publishes to a registry but has no manifest version",
                )
                continue
            self.assertTrue(
                sdk_versions.is_valid_semver(package.version),
                f"{package.id}={package.version!r} is not valid SemVer",
            )
            majors.add(package.version.split(".", 1)[0])
        self.assertEqual(
            1, len(majors), f"the release train split across majors: {majors}"
        )

    def test_the_train_rule_accepts_a_minor_split(self) -> None:
        packages = (
            sdk_versions.PackageVersion("typescript", "a", "0.3.0"),
            sdk_versions.PackageVersion("rust", "b", "0.4.0"),
            sdk_versions.PackageVersion("swift", "c", None),
        )
        self.assertIsNone(sdk_versions.check_train_consistency(packages))

    def test_the_train_rule_rejects_a_major_split(self) -> None:
        packages = (
            sdk_versions.PackageVersion("typescript", "a", "0.3.0"),
            sdk_versions.PackageVersion("rust", "b", "1.0.0"),
        )
        error = sdk_versions.check_train_consistency(packages)
        self.assertIsNotNone(error)
        self.assertIn("majors differ", error)

    def test_the_repository_declares_every_sdk_directory(self) -> None:
        """The check that would have caught Kotlin and Swift."""
        self.assertEqual([], sdk_versions.discover_undeclared_sdk_directories())

    def test_semver_supports_prerelease_and_build_metadata(self) -> None:
        self.assertTrue(sdk_versions.is_valid_semver("1.2.3-alpha.1+build.5"))
        self.assertTrue(sdk_versions.is_valid_semver("0.3.0-rc.0"))
        self.assertFalse(sdk_versions.is_valid_semver("0.3.0-01"))
        self.assertFalse(sdk_versions.is_valid_semver("0.3.0-rc..1"))
        self.assertFalse(sdk_versions.is_valid_semver("01.3.0"))
        self.assertFalse(sdk_versions.is_valid_semver("0.3"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, versions=("1.2.3-alpha.1+build.5",) * 5 + ("", ""))
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

    def test_a_minor_difference_is_allowed(self) -> None:
        """Rust is 0.4.0 for a real breaking change while the rest are 0.3.0.

        Semver is per language: forcing every manifest to the same number to
        keep one tidy train would misstate the packages whose changes were
        additive only.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, versions=("0.3.0", "0.3.0", "0.4.0", "0.3.0", "0.3.0", "", ""))
            report = sdk_versions.load_version_report(root)
        self.assertTrue(report.ok, report.failure_message())
        output = sdk_versions.format_version_report(report)
        self.assertIn('id="rust" name="snaplink-sso" version="0.4.0"', output)
        self.assertTrue(output.endswith("verdict: PASS"))

    def test_a_major_difference_fails_without_normalizing(self) -> None:
        """A package left on a different major is a broken release train."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root, versions=("0.3.0", "0.3.0", "1.0.0", "0.3.0", "0.3.0", "", ""))
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("SDK package majors differ", report.failure_message())
        output = sdk_versions.format_version_report(report)
        self.assertIn('id="rust" name="snaplink-sso" version="1.0.0"', output)
        self.assertTrue(output.endswith("verdict: FAIL"))

    def test_the_gradle_coordinate_follows_the_project_not_the_directory(self) -> None:
        """`:sso` builds from `kotlin/`, so the published coordinate
        must be read from the settings script rather than the folder name."""
        manifest = Path("sdks/kotlin/build.gradle.kts")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            self.assertEqual("snaplink", sdk_versions._gradle_project_name(root, manifest))
            _write(root, "sdks/settings.gradle.kts", 'include(":kotlin")\n')
            self.assertEqual("kotlin", sdk_versions._gradle_project_name(root, manifest))
            (root / "sdks/settings.gradle.kts").unlink()
            self.assertEqual("kotlin", sdk_versions._gradle_project_name(root, manifest))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            _write(root, "sdks/settings.gradle.kts", 'include(":snaplink")\n')
            with self.assertRaises(sdk_versions.SDKVersionError):
                sdk_versions._gradle_project_name(root, manifest)

    def test_an_undeclared_sdk_directory_fails(self) -> None:
        """A new SDK must not ship without a version gate, which is how Kotlin
        and Swift escaped review the first time."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            _write(root, "sdks/brandnew/package.json", json.dumps({"name": "x", "version": "0.1.0"}))
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("brandnew", report.failure_message())
        self.assertIn("MANIFEST_SPECS", report.failure_message())

    def test_invalid_semver_is_rejected_in_each_manifest_format(self) -> None:
        for invalid in ("0.3.0-01", "0.3.0-rc..1", "0.3", "1.2.3+"):
            with self.subTest(version=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_fixtures(root, versions=(invalid,) * 5 + ("", ""))
                report = sdk_versions.load_version_report(root)
            self.assertFalse(report.ok)
            self.assertIn("invalid SemVer", report.failure_message())

    def test_bad_json_fails_closed(self) -> None:
        for relative in (
            "sdks/typescript/package.json",
            "sdks/typescript/package-lock.json",
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
            package_path = root / "sdks/typescript/package.json"
            package_path.write_text(json.dumps({"name": NAMES[0]}), encoding="utf-8")
            report = sdk_versions.load_version_report(root)
        self.assertFalse(report.ok)
        self.assertIn("package version is missing", _package(report, "typescript").error or "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fixtures(root)
            lock_path = root / "sdks/typescript/package-lock.json"
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
            "typescript": ("sdks/typescript/package.json", {"name": NAMES[0]}),
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
                # SwiftPM and the Go module both take their version from the
                # release tag, so the synthetic report leaves them versionless
                # the way the real gate does.
                sdk_versions.PackageVersion(
                    package_id,
                    name,
                    None if package_id in ("swift", "go") else "0.3.0",
                )
                for package_id, name in zip((spec.id for spec in sdk_versions.MANIFEST_SPECS), NAMES)
            )
        )
        self.assertEqual(
            sdk_versions.format_version_report(report),
            "\n".join(
                [
                    "sdk-surface versions",
                    'package id="typescript" name="@snaplink/sso" version="0.3.0" status=PASS',
                    'package id="python" name="snaplink-sso" version="0.3.0" status=PASS',
                    'package id="rust" name="snaplink-sso" version="0.3.0" status=PASS',
                    'package id="php" name="snaplink/sso" version="0.3.0" status=PASS',
                    'package id="kotlin" name="site.ywbsd.sso:snaplink" version="0.3.0" status=PASS',
                    'package id="swift" name="SnaplinkSSO" version="<unavailable>" status=PASS',
                    'package id="go" name="github.com/yangwb1123/snaplink/sdks/go" version="<unavailable>" status=PASS',
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

    def test_non_diff_actions_reject_all_baseline_options(self) -> None:
        for action in ("check", "generate", "list", "versions"):
            for option in (
                "--baseline-ref",
                "--baseline-file",
                "--baseline-openapi-file",
            ):
                with self.subTest(action=action, option=option):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result = sdk_surface.run([action, option, "ignored"])
                    self.assertEqual(result, 1)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn(
                        "baseline options are only valid with the diff action",
                        stderr.getvalue(),
                    )

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
