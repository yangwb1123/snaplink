#!/usr/bin/env python3
"""Fail-closed metadata and subtree checks for the PHP SDK release workflow."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from sdk_versions import SDKVersionError, validate_semver


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_PATH = Path("sdks/php/composer.json")
PACKAGE_NAME = "snaplink/sso-client"
SUBTREE_PREFIX = "sdks/php"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)


class PHPReleaseError(ValueError):
    """Raised when a PHP SDK release reference or split is unsafe."""


@dataclass(frozen=True)
class PackageMetadata:
    """Versioned Composer metadata for the one supported PHP package."""

    name: str
    version: str


@dataclass(frozen=True)
class ReleaseSplit:
    """Validated subtree commit and the version/tag to publish."""

    commit: str
    version: str
    target_tag: str


def load_package_metadata(root: Path = ROOT) -> PackageMetadata:
    """Read the fixed Composer manifest and validate name and SemVer."""
    manifest_path = root / PACKAGE_PATH
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PHPReleaseError(f"{PACKAGE_PATH}: manifest is missing") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PHPReleaseError(f"{PACKAGE_PATH}: cannot read valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise PHPReleaseError(f"{PACKAGE_PATH}: manifest root must be an object")
    name = manifest.get("name")
    if name != PACKAGE_NAME:
        raise PHPReleaseError(
            f"{PACKAGE_PATH}: package name must be {PACKAGE_NAME!r}"
        )
    try:
        version = validate_semver(manifest.get("version"), str(PACKAGE_PATH))
    except SDKVersionError as exc:
        raise PHPReleaseError(str(exc)) from exc
    return PackageMetadata(name=name, version=version)


def validate_release_ref(
    ref_name: str, ref_protected: str, metadata: PackageMetadata
) -> str:
    """Require a protected source tag whose name matches the package version."""
    if ref_protected != "true":
        raise PHPReleaseError("source tag is not protected by a GitHub ruleset")
    expected = f"sdk-php-v{metadata.version}"
    if ref_name != expected:
        raise PHPReleaseError(
            f"source tag {ref_name!r} does not match expected {expected!r}"
        )
    return f"v{metadata.version}"


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args], cwd=root, check=False, capture_output=True, text=True
        )
    except OSError as exc:
        raise PHPReleaseError(f"cannot execute git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip()[:4096] or "git command failed"
        raise PHPReleaseError(detail)
    return result.stdout.strip()


def _validate_split_manifest(
    root: Path, commit: str, expected: PackageMetadata
) -> None:
    raw = _git(root, "show", f"{commit}:composer.json")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PHPReleaseError(f"split composer.json is invalid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise PHPReleaseError("split composer.json root must be an object")
    if manifest.get("name") != expected.name or manifest.get("version") != expected.version:
        raise PHPReleaseError("split package metadata does not match the release tag")


def prepare_split(
    root: Path,
    source_sha: str,
    ref_name: str,
    ref_protected: str,
) -> ReleaseSplit:
    """Generate and validate the package-only commit without pushing it."""
    metadata = load_package_metadata(root)
    target_tag = validate_release_ref(ref_name, ref_protected, metadata)
    if not _SHA.fullmatch(source_sha):
        raise PHPReleaseError("source revision must be a full Git commit hash")
    commit = _git(
        root,
        "subtree",
        "split",
        "--quiet",
        f"--prefix={SUBTREE_PREFIX}",
        source_sha,
    )
    if not _SHA.fullmatch(commit):
        raise PHPReleaseError("git subtree did not return a full commit hash")
    _validate_split_manifest(root, commit, metadata)
    return ReleaseSplit(commit=commit, version=metadata.version, target_tag=target_tag)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="check protected source-tag metadata")
    verify.add_argument("--ref-name", required=True)
    verify.add_argument("--ref-protected", required=True)
    split = subparsers.add_parser("split", help="prepare and validate subtree split")
    split.add_argument("--source-sha", required=True)
    split.add_argument("--ref-name", required=True)
    split.add_argument("--ref-protected", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            metadata = load_package_metadata()
            target_tag = validate_release_ref(
                args.ref_name, args.ref_protected, metadata
            )
            print(f"PASS: protected PHP SDK release tag {target_tag}")
            return 0
        result = prepare_split(
            ROOT, args.source_sha, args.ref_name, args.ref_protected
        )
        print(f"{result.commit}\t{result.version}\t{result.target_tag}")
        return 0
    except PHPReleaseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
