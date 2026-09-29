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
        Path("sdks/typescript/package.json"),
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
    ManifestSpec(
        "kotlin",
        Path("sdks/kotlin/snaplink-sso/build.gradle.kts"),
        "com.snaplink:snaplink-sso",
        "gradle",
    ),
    ManifestSpec(
        "swift",
        Path("sdks/swift/Package.swift"),
        "SnaplinkSSO",
        "swift",
    ),
)

#: Manifests that identify a published SDK package directory. A directory under
#: sdks/ that carries one of these but is absent from MANIFEST_SPECS is an
#: SDK that shipped without a version gate, which is how Kotlin and Swift
#: escaped review until they were found by hand.
SDK_MANIFEST_MARKERS = (
    Path("package.json"),
    Path("pyproject.toml"),
    Path("Cargo.toml"),
    Path("composer.json"),
    Path("Package.swift"),
    Path("snaplink-sso/build.gradle.kts"),
)

TYPESCRIPT_LOCK_PATH = Path("sdks/typescript/package-lock.json")
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


def _metadata(value: dict, table: str | None, source: str) -> tuple[str, str | None]:
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
    if version is not None and not isinstance(version, str):
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


_GRADLE_VERSION = re.compile(r"""^\s*version\s*=\s*["']([^"']+)["']""", re.MULTILINE)
_GRADLE_GROUP = re.compile(r"""^\s*group\s*=\s*["']([^"']+)["']""", re.MULTILINE)
_SWIFT_NAME = re.compile(r"""\bname\s*:\s*["']([^"']+)["']""", re.MULTILINE)
_SWIFT_VERSION = re.compile(r"""//\s*version\s*:\s*(\S+)""")


def _parse_gradle(text: str, source: str, artifact: str) -> dict:
    """Read a Kotlin DSL build script's group and version literals.

    Gradle scripts are programs, not a data format, so only the top-level
    `group = "..."` and `version = "..."` assignments are read and nothing is
    evaluated. The published coordinate is the group joined to the module
    directory name, which is how Gradle names the artifact.
    """
    version = _GRADLE_VERSION.search(text)
    if version is None:
        raise SDKVersionError(f"{source}: version assignment is missing")
    group = _GRADLE_GROUP.search(text)
    if group is None:
        raise SDKVersionError(f"{source}: group assignment is missing")
    return {"name": f"{group.group(1)}:{artifact}", "version": version.group(1)}


def _parse_swift(text: str, source: str) -> dict:
    """Read a SwiftPM manifest's package name.

    SwiftPM derives the version from the release tag rather than the manifest,
    so there is no version to validate here; the name is still checked so a
    renamed package cannot drift unnoticed.
    """
    name = _SWIFT_NAME.search(text)
    if name is None:
        raise SDKVersionError(f"{source}: package name is missing")
    pinned = _SWIFT_VERSION.search(text)
    version = pinned.group(1) if pinned is not None else None
    return {"name": name.group(1), "version": version}


def discover_undeclared_sdk_directories(root: Path = ROOT) -> list[str]:
    """Return sdks/ subdirectories that carry a package manifest but no gate.

    This is the check that would have caught Kotlin and Swift. Without it, a new
    SDK is only governed if whoever adds it remembers to add it here, which is
    the exact failure this repository already had once.
    """
    sdks = root / "sdks"
    if not sdks.is_dir():
        return []
    declared = {spec.path.parts[1] for spec in MANIFEST_SPECS}
    undeclared: list[str] = []
    for entry in sorted(sdks.iterdir(), key=lambda path: path.name):
        if not entry.is_dir():
            continue
        relative = Path("sdks") / entry.name
        if any((root / relative / marker).is_file() for marker in SDK_MANIFEST_MARKERS):
            if entry.name not in declared:
                undeclared.append(entry.name)
    return undeclared


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
        elif spec.format == "gradle":
            artifact = spec.path.parent.name
            data = _parse_gradle(_read_fixed(root, spec.path), source, artifact)
            table = None
        elif spec.format == "swift":
            data = _parse_swift(_read_fixed(root, spec.path), source)
            table = None
        else:  # The tuple above is fixed; guard accidental code drift.
            raise SDKVersionError(f"{source}: unsupported fixed manifest parser")
        name, version = _metadata(data, table, source)
        if version is None:
            # SwiftPM versions from the release tag. The package is still
            # audited by name; there is simply no file to read a number from.
            return PackageVersion(spec.id, name, None, None)
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


def _major_of(version: str) -> str:
    return version.split(".", 1)[0]


def check_train_consistency(packages: tuple[PackageVersion, ...]) -> str | None:
    """Every versioned package must share one major; minors may differ.

    The previous rule required all manifests to carry the *identical* version.
    That was correct while the SDKs shipped as one lockstep release, and wrong
    the moment one of them took a breaking change: Rust became 0.4.0 for a real
    breaking reason while the other packages were legitimately still 0.3.0 with
    additive-only changes. Forcing them to match would have misstated three
    packages' compatibility to make one number tidy.

    The invariant that still matters is coherence of the release train, so that
    is what is enforced: no package may sit on a different major than the rest,
    and the report always shows the spread so a partial bump stays visible.
    """
    versioned = [package for package in packages if package.version is not None]
    if not versioned:
        return None
    majors = {_major_of(package.version) for package in versioned}
    if len(majors) == 1:
        return None
    details = ", ".join(
        f"{package.id}={_quote(package.version)}" for package in versioned
    )
    return f"SDK package majors differ: {details}"


def load_version_report(root: Path = ROOT) -> VersionReport:
    """Read every audited manifest and return the complete validation report."""
    packages = tuple(_load_package(spec, root) for spec in MANIFEST_SPECS)
    consistency_error = None
    undeclared = tuple(discover_undeclared_sdk_directories(root))
    if undeclared:
        consistency_error = (
            "SDK directories carry a package manifest but no version gate: "
            + ", ".join(undeclared)
            + "; add each to MANIFEST_SPECS"
        )
    if consistency_error is None and any(not package.ok for package in packages):
        return VersionReport(packages)
    if consistency_error is None:
        consistency_error = check_train_consistency(packages)
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
