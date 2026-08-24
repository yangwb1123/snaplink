#!/usr/bin/env python3
"""Read and validate the four committed SDK package manifests.

The production entry point has no path arguments: every manifest path and
parser is fixed here. TOML parsing lives in :mod:`sdk_toml` so this module
only owns package metadata and version policy.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from sdk_toml import load_toml


ROOT = Path(__file__).resolve().parents[2]
UNAVAILABLE = "<unavailable>"


@dataclass(frozen=True)
class ManifestSpec:
    """An audited package manifest location and its expected package name."""

    id: str
    path: Path
    expected_name: str
    format: str


MANIFEST_SPECS = (
    ManifestSpec(
        "typescript",
        Path("docs/sdks/typescript/package.json"),
        "@snaplink/sso-client",
        "json",
    ),
    ManifestSpec(
        "python",
        Path("sdks/python/pyproject.toml"),
        "snaplink-sso",
        "toml:project",
    ),
    ManifestSpec(
        "rust",
        Path("sdks/rust/Cargo.toml"),
        "snaplink-sso",
        "toml:package",
    ),
    ManifestSpec(
        "php",
        Path("sdks/php/composer.json"),
        "snaplink/sso-client",
        "json",
    ),
)

TYPESCRIPT_LOCK_PATH = Path("docs/sdks/typescript/package-lock.json")
_CORE_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z",
    re.ASCII,
)
_IDENTIFIER = re.compile(r"[0-9A-Za-z-]+\Z", re.ASCII)


class SDKVersionError(ValueError):
    """Raised when a fixed SDK manifest cannot provide valid metadata."""


@dataclass(frozen=True)
class PackageVersion:
    """One package's parsed metadata and any package-local failure."""

    id: str
    name: str
    version: str | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class VersionReport:
    """Deterministic result for all four package manifests."""

    packages: tuple[PackageVersion, ...]
    consistency_error: str | None = None

    @property
    def ok(self) -> bool:
        return not any(not package.ok for package in self.packages) and (
            self.consistency_error is None
        )

    def failure_message(self) -> str:
        failures = [
            f"{package.id}: {package.error}"
            for package in self.packages
            if package.error is not None
        ]
        if self.consistency_error is not None:
            failures.append(self.consistency_error)
        return "; ".join(failures) or "unknown SDK version failure"


def is_valid_semver(value: object) -> bool:
    """Return whether value is a SemVer 2.0.0 string."""
    if not isinstance(value, str) or not value:
        return False
    base, separator, build = value.partition("+")
    if separator and (not build or "+" in build):
        return False
    if separator and any(
        not _valid_identifier(part, numeric_leading_zero=False)
        for part in build.split(".")
    ):
        return False
    core, separator, prerelease = base.partition("-")
    if not _CORE_SEMVER.fullmatch(core):
        return False
    if separator and any(
        not _valid_identifier(part, numeric_leading_zero=True)
        for part in prerelease.split(".")
    ):
        return False
    return True


def _valid_identifier(value: str, numeric_leading_zero: bool) -> bool:
    if not value or not _IDENTIFIER.fullmatch(value):
        return False
    return not (
        numeric_leading_zero
        and value.isdigit()
        and len(value) > 1
        and value[0] == "0"
    )


def validate_semver(value: object, source: str) -> str:
    """Validate and return a SemVer string without normalizing it."""
    if not isinstance(value, str):
        raise SDKVersionError(f"{source}: version must be a string")
    if not is_valid_semver(value):
        raise SDKVersionError(f"{source}: invalid SemVer 2.0.0 version {value!r}")
    return value


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _read_fixed(root: Path, relative: Path) -> str:
    source = relative.as_posix()
    try:
        return (root / relative).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SDKVersionError(f"{source}: manifest is missing") from exc
    except (OSError, UnicodeError) as exc:
        raise SDKVersionError(f"{source}: cannot read manifest: {exc}") from exc


def _parse_json(text: str, source: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SDKVersionError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SDKVersionError(f"{source}: manifest root must be an object")
    return value


def _parse_toml(text: str, source: str) -> dict:
    try:
        value = load_toml(text)
    except (TypeError, ValueError) as exc:
        raise SDKVersionError(f"{source}: invalid TOML: {exc}") from exc
    if not isinstance(value, dict):
        raise SDKVersionError(f"{source}: manifest root must be a table")
    return value


def _metadata(value: dict, table: str | None, source: str) -> tuple[str, str]:
    metadata = value if table is None else value.get(table)
    if not isinstance(metadata, dict):
        label = "root" if table is None else f"[{table}]"
        raise SDKVersionError(f"{source}: required {label} table is missing")
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        raise SDKVersionError(f"{source}: package name must be a non-empty string")
    if "version" not in metadata:
        raise SDKVersionError(f"{source}: package version is missing")
    version = metadata["version"]
    if not isinstance(version, str):
        raise SDKVersionError(f"{source}: version must be a string")
    return name, version


def _validate_package_name(name: str, expected: str, source: str) -> None:
    if name != expected:
        raise SDKVersionError(
            f"{source}: package name {name!r} does not match expected {expected!r}"
        )


def _lock_root_version(lock: dict, package_version: str) -> None:
    source = TYPESCRIPT_LOCK_PATH.as_posix()
    if "version" not in lock:
        raise SDKVersionError(f"{source}: top-level version is missing")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise SDKVersionError(f"{source}: packages table is missing")
    root = packages.get("")
    if not isinstance(root, dict):
        raise SDKVersionError(f'{source}: packages[""] root entry is missing')
    root_version = root.get("version")
    if not isinstance(root_version, str):
        raise SDKVersionError(f'{source}: packages[""] version must be a string')
    validate_semver(root_version, f'{source} packages[""]')
    if root_version != package_version:
        raise SDKVersionError(
            f'{source}: package-lock root version {root_version!r} does not match '
            f"package.json version {package_version!r}"
        )
    top_level_version = lock.get("version")
    if top_level_version is not None:
        if not isinstance(top_level_version, str):
            raise SDKVersionError(f"{source}: top-level version must be a string")
        validate_semver(top_level_version, f"{source} top-level")
        if top_level_version != package_version:
            raise SDKVersionError(
                f"{source}: top-level version {top_level_version!r} does not match "
                f"package.json version {package_version!r}"
            )


def _load_package(spec: ManifestSpec, root: Path) -> PackageVersion:
    result = PackageVersion(spec.id, spec.expected_name, None)
    source = spec.path.as_posix()
    try:
        if spec.format == "json":
            data = _parse_json(_read_fixed(root, spec.path), source)
            table = None
        elif spec.format == "toml:project":
            data = _parse_toml(_read_fixed(root, spec.path), source)
            table = "project"
        elif spec.format == "toml:package":
            data = _parse_toml(_read_fixed(root, spec.path), source)
            table = "package"
        else:  # The tuple above is fixed; guard accidental code drift.
            raise SDKVersionError(f"{source}: unsupported fixed manifest parser")
        name, version = _metadata(data, table, source)
        result = PackageVersion(spec.id, name, version)
        _validate_package_name(name, spec.expected_name, source)
        validate_semver(version, source)
        if spec.id == "typescript":
            lock_source = TYPESCRIPT_LOCK_PATH.as_posix()
            lock = _parse_json(_read_fixed(root, TYPESCRIPT_LOCK_PATH), lock_source)
            _lock_root_version(lock, version)
        return result
    except SDKVersionError as exc:
        return PackageVersion(result.id, result.name, result.version, str(exc))


def load_version_report(root: Path = ROOT) -> VersionReport:
    """Read only the fixed manifests and return their complete validation report."""
    packages = tuple(_load_package(spec, root) for spec in MANIFEST_SPECS)
    if any(not package.ok for package in packages):
        return VersionReport(packages)
    versions = [package.version for package in packages]
    unique_versions = sorted(set(versions))
    consistency_error = None
    if len(unique_versions) != 1:
        details = ", ".join(
            f"{package.id}={_quote(package.version or UNAVAILABLE)}"
            for package in packages
        )
        consistency_error = f"SDK package versions differ: {details}"
    return VersionReport(packages, consistency_error)


def format_version_report(report: VersionReport) -> str:
    """Render a stable report suitable for CI logs and release evidence."""
    lines = ["sdk-surface versions"]
    for package in report.packages:
        status = "PASS" if package.ok else "FAIL"
        line = (
            f"package id={_quote(package.id)} name={_quote(package.name)} "
            f"version={_quote(package.version or UNAVAILABLE)} status={status}"
        )
        if package.error is not None:
            line += f" reason={_quote(package.error)}"
        lines.append(line)
    if report.consistency_error is not None:
        lines.append(f"reason: {_quote(report.consistency_error)}")
    lines.append(f"verdict: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


def run_versions() -> int:
    """Run the explicit CLI version gate without side effects."""
    report = load_version_report()
    print(format_version_report(report))
    return 0 if report.ok else 1
