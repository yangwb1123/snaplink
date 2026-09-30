"""Tests for the PHP SDK release reference and subtree safeguards."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import php_sdk_release as release


def _write_package(root: Path, name: str = release.PACKAGE_NAME, version: str = "1.2.3") -> None:
    manifest = root / release.PACKAGE_PATH
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"name": name, "version": version}), encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


class PHPReleaseMetadataTests(unittest.TestCase):
    def test_package_metadata_requires_fixed_name_and_semver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_package(root)
            self.assertEqual(release.load_package_metadata(root).version, "1.2.3")

            _write_package(root, name="attacker/package")
            with self.assertRaisesRegex(release.PHPReleaseError, "package name"):
                release.load_package_metadata(root)

            _write_package(root, version="01.2.3")
            with self.assertRaisesRegex(release.PHPReleaseError, "invalid SemVer"):
                release.load_package_metadata(root)

    def test_release_requires_exact_protected_version_tag(self) -> None:
        metadata = release.PackageMetadata(release.PACKAGE_NAME, "1.2.3")
        self.assertEqual(
            release.validate_release_ref("sdk-php-v1.2.3", "true", metadata),
            "v1.2.3",
        )
        for ref_name, protected, expected_error in (
            ("sdk-php-v1.2.3", "false", "not protected"),
            ("v1.2.3", "true", "does not match"),
            ("sdk-php-v1.2.4", "true", "does not match"),
        ):
            with self.subTest(ref_name=ref_name, protected=protected):
                with self.assertRaisesRegex(release.PHPReleaseError, expected_error):
                    release.validate_release_ref(ref_name, protected, metadata)

    def test_prepare_split_rejects_non_full_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_package(root)
            with self.assertRaisesRegex(release.PHPReleaseError, "full Git commit hash"):
                release.prepare_split(root, "HEAD", "sdk-php-v1.2.3", "true")


class PHPReleaseSubtreeTests(unittest.TestCase):
    def test_split_contains_only_package_root_and_validates_tag_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_package(root)
            package_readme = root / "sdks/php/README.md"
            package_readme.write_text("PHP SDK package", encoding="utf-8")
            (root / "unrelated-root-file.txt").write_text("not shipped", encoding="utf-8")
            _git(root, "init", "--quiet", "--initial-branch=main")
            _git(root, "config", "user.name", "SDK release test")
            _git(root, "config", "user.email", "sdk-release-test@example.invalid")
            _git(root, "add", "sdks/php/composer.json", "sdks/php/README.md", "unrelated-root-file.txt")
            _git(root, "commit", "--quiet", "-m", "test fixture")
            source_sha = _git(root, "rev-parse", "HEAD")

            result = release.prepare_split(
                root, source_sha, "sdk-php-v1.2.3", "true"
            )

            self.assertRegex(result.commit, r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
            self.assertEqual((result.version, result.target_tag), ("1.2.3", "v1.2.3"))
            split_manifest = json.loads(
                _git(root, "show", f"{result.commit}:composer.json")
            )
            self.assertEqual(split_manifest["name"], release.PACKAGE_NAME)
            self.assertEqual(
                _git(root, "show", f"{result.commit}:README.md"), "PHP SDK package"
            )
            with self.assertRaises(release.PHPReleaseError):
                release._git(root, "show", f"{result.commit}:unrelated-root-file.txt")


if __name__ == "__main__":
    unittest.main()
