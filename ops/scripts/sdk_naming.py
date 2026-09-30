#!/usr/bin/env python3
"""Enforce the canonical Snaplink SDK package naming scheme.

The name of a published package is the one identifier that cannot be changed
after release, and four registries spell the same product four different ways
(`@snaplink/sso`, `snaplink-sso`, `snaplink/sso`, `site.ywbsd.sso:snaplink`). Every
platform also has its own rules for what a legal name looks like, and a name
that satisfies the house scheme can still be rejected by the registry. This gate
holds both properties at once:

1. Scheme — the brand token ``snaplink`` owns the platform's namespace slot
   (npm scope, Composer vendor) and the product token ``sso`` fills the name
   slot. Platforms with no namespace slot carry the brand as the name prefix.
   The one exception is Maven, where the namespace slot must be a domain the
   publisher controls, so the product host owns the groupId and the brand moves
   into the artifactId. The token is the product name itself: Snaplink ships an
   SSO server, so a client library published under its own brand is named for the
   product, not for the role it plays. A `client` suffix would be redundant on
   registries where a library is a client by definition, and the server side is
   the Go module rather than anything published to these registries.
2. Platform rules — the rendered name matches that registry's own grammar.

It is deliberately a pure name check. It never inspects versions, build output,
or a registry, and it never reaches the network: a name that satisfies these
rules is *eligible* for publication, never proof that it was published.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

#: The brand token. It is the single source of truth for the scheme below; a
#: name that spells the brand differently is a scheme violation, not a variant.
BRAND = "snaplink"

#: The product token. Snaplink is an SSO server, so a client library published
#: under the same brand is named for the product itself. The `Client` role word
#: is redundant on every registry that carries this SDK, and the server side is
#: the Go module, not a package on these registries.
CAPABILITY = "sso"

#: The SwiftPM module name. Swift modules are PascalCase and a single name
#: carries both brand and product token, so the same `sso` token is rendered
#: `SnaplinkSSO` and stays identical to the canonical name.
SWIFT_MODULE = "SnaplinkSSO"

#: The Maven groupId. Maven Central verifies a groupId against a domain the
#: publisher controls, so this is the reverse-DNS form of the project's own
#: product host rather than a brand name. `com.snaplink` would assert a
#: `snaplink.com` this project does not control, and an unverifiable groupId is
#: rejected at publication — the worst possible moment to discover it. The
#: product host is `sso.ywbsd.site`, so the group is `site.ywbsd.sso`.
MAVEN_GROUP = "site.ywbsd.sso"


@dataclass(frozen=True)
class Convention:
    """One platform's rendering of the canonical name and its legal grammar."""

    id: str
    manifest: Path
    expected: str
    pattern: re.Pattern[str]
    rule: str
    namespace_slot: str
    #: True when the platform's namespace slot must be a domain the publisher
    #: controls, so it cannot hold the brand token. Maven Central verifies a
    #: groupId against a domain, so there the domain owns the groupId and the
    #: brand moves into the artifactId. The scheme is therefore stated per
    #: platform rather than as one global sentence.
    namespace_is_domain: bool = False


#: npm scopes are lowercase and a package name may not repeat the scope. The
#: pattern mirrors npm's published-name grammar rather than a loose subset.
_NPM = re.compile(r"^@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")

#: PEP 503 normalizes runs of ``-_.`` to a single ``-``; the published form must
#: already be normalized, and a normalized flat name is all-lowercase dashes.
_PYPI = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

#: crates.io allows letters, digits, ``-`` and ``_`` but forbids mixing
#: separators, so the canonical form uses dashes only.
_CRATES = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")

#: Packagist requires ``vendor/package`` in lowercase; the package half forbids
#: a doubled dash, which is why the canonical form is single-dashed.
_PACKAGIST = re.compile(r"^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9]+(-[a-z0-9]+)*$")

#: Maven splits a reverse-DNS group from an artifactId; Central's grammar is
#: permissive, and the gate holds the reverse-DNS shape instead.
#: Maven splits a reverse-DNS group from an artifactId. The group must be a
#: domain the publisher controls; the artifact carries the brand identifier, so
#: the product token is already spoken for by the group.
_MAVEN = re.compile(
    r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+:[a-z][a-z0-9]*(-[a-z0-9]+)*$"
)

#: SwiftPM module names are Swift identifiers; PascalCase is the house rule.
_SWIFT = re.compile(r"^[A-Z][A-Za-z0-9]*$")


CONVENTIONS = (
    Convention(
        id="typescript",
        manifest=Path("sdks/typescript/package.json"),
        expected=f"@{BRAND}/{CAPABILITY}",
        pattern=_NPM,
        rule="lowercase @scope/name; the scope carries the brand",
        namespace_slot="npm scope",
    ),
    Convention(
        id="python",
        manifest=Path("sdks/python/pyproject.toml"),
        expected=f"{BRAND}-{CAPABILITY}",
        pattern=_PYPI,
        rule="PEP 503 normalized flat name",
        namespace_slot="none",
    ),
    Convention(
        id="rust",
        manifest=Path("sdks/rust/Cargo.toml"),
        expected=f"{BRAND}-{CAPABILITY}",
        pattern=_CRATES,
        rule="lowercase, single-dash, no separator mixing",
        namespace_slot="none",
    ),
    Convention(
        id="php",
        manifest=Path("sdks/php/composer.json"),
        expected=f"{BRAND}/{CAPABILITY}",
        pattern=_PACKAGIST,
        rule="lowercase vendor/package",
        namespace_slot="Composer vendor",
    ),
    Convention(
        id="kotlin",
        manifest=Path("sdks/kotlin/build.gradle.kts"),
        expected=f"{MAVEN_GROUP}:{BRAND}",
        pattern=_MAVEN,
        rule="reverse-DNS groupId:artifactId, groupId is a controlled domain",
        namespace_slot="Maven groupId",
        namespace_is_domain=True,
    ),
    Convention(
        id="swift",
        manifest=Path("Package.swift"),
        expected=SWIFT_MODULE,
        pattern=_SWIFT,
        rule="PascalCase SwiftPM module; brand and product token in one slot",
        namespace_slot="none",
    ),
)


class SDKNamingError(Exception):
    """Raised when a package name breaks the scheme or a platform grammar."""


#: The registry each manifest is published to. A name is only scarce *within* a
#: registry, so uniqueness is asserted per registry: PyPI and crates.io may
#: both carry `snaplink-sso` without conflict, while two PyPI claims on one name
#: make the second upload ambiguous and are rejected.
REGISTRIES = {
    "typescript": "npm",
    "python": "PyPI",
    "rust": "crates.io",
    "php": "Packagist",
    "kotlin": "Maven Central",
    "swift": "SwiftPM",
}

#: The repository's own engineering CLI. It is installed with
#: `pip install -e .` and never published, but it is a pip distribution like
#: the Python SDK, so it shares the PyPI namespace and must hold a distinct
#: name there. The engineering CLI is a developer tool, not an SDK, so the
#: registry scheme does not apply to it - uniqueness does.
ENGINEERING_CLI = Path("pyproject.toml")
ENGINEERING_CLI_LABEL = "engineering-cli"


def _import_module():
    """Import sdk_versions so the two gates read manifests through one seam."""
    from pathlib import Path as _Path  # local alias keeps the import obvious

    sys.path.insert(0, str(_Path(__file__).resolve().parent))
    import sdk_versions  # noqa: PLC0415 — deliberate late import, shared reader

    return sdk_versions


def declared_name(root: Path, convention: Convention) -> str:
    """Read one package name through the shared manifest reader.

    The actual name is never re-parsed here. sdk_versions already knows how to
    read a JSON, TOML, Gradle, or SwiftPM manifest, and a second parser would be
    a second thing to keep in step with the first.
    """
    sdk_versions = _import_module()
    spec = next(
        (s for s in sdk_versions.MANIFEST_SPECS if s.path == convention.manifest),
        None,
    )
    if spec is None:
        raise SDKNamingError(
            f"{convention.manifest.as_posix()}: manifest is not registered with the version gate"
        )
    name = _read_via_spec(sdk_versions, root, spec).get("name")
    if not name:
        raise SDKNamingError(f"{convention.manifest.as_posix()}: package name is missing")
    return str(name)


def _read_via_spec(sdk_versions, root: Path, spec) -> dict:
    """Call the version gate's own per-format reader for *spec*."""
    if spec.format == "json":
        return sdk_versions._parse_json(
            sdk_versions._read_fixed(root, spec.path), spec.path.as_posix()
        )
    if spec.format == "toml:project":
        return sdk_versions._parse_toml(
            sdk_versions._read_fixed(root, spec.path), spec.path.as_posix()
        )["project"]
    if spec.format == "toml:package":
        return sdk_versions._parse_toml(
            sdk_versions._read_fixed(root, spec.path), spec.path.as_posix()
        )["package"]
    if spec.format == "gradle":
        artifact = sdk_versions._gradle_project_name(root, spec.path)
        return sdk_versions._parse_gradle(
            sdk_versions._read_fixed(root, spec.path), spec.path.as_posix(), artifact
        )
    if spec.format == "swift":
        return sdk_versions._parse_swift(
            sdk_versions._read_fixed(root, spec.path), spec.path.as_posix()
        )
    raise SDKNamingError(f"{spec.path.as_posix()}: unknown manifest format {spec.format!r}")


def check_name(convention: Convention, name: str) -> list[str]:
    """Return every way *name* violates this platform's convention."""
    errors: list[str] = []
    if not convention.pattern.match(name):
        errors.append(
            f"id={convention.id} name={name!r} violates the platform rule "
            f"({convention.rule})"
        )
    if name != convention.expected:
        errors.append(
            f"id={convention.id} name={name!r} does not match the canonical name "
            f"{convention.expected!r}; the brand token {BRAND!r} belongs in the "
            f"{convention.namespace_slot} and the product token "
            f"{CAPABILITY!r} in the name slot"
        )
    return errors


def _normalize(name: str) -> str:
    """Normalize a distribution name the way its registry does before comparing.

    Only the rules that matter for equality are applied. PEP 503 collapses runs
    of ``-_.`` to a single ``-``, so `Snaplink_SSO` and `snaplink-sso` are one
    PyPI project; treating them as different would let the uniqueness check
    pass on two claims that are actually the same name. Every other registry
    form is already lowercase, so the same normalization is harmless there.
    """
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _engineering_cli_name(root: Path) -> str:
    """Read the root CLI's distribution name from its own pyproject."""
    sdk_versions = _import_module()
    manifest = root / ENGINEERING_CLI
    try:
        data = sdk_versions._parse_toml(
            sdk_versions._read_fixed(root, ENGINEERING_CLI), ENGINEERING_CLI.as_posix()
        )
    except OSError as exc:
        raise SDKNamingError(f"{ENGINEERING_CLI.as_posix()}: {exc}") from exc
    name = (data.get("project") or {}).get("name")
    if not name:
        raise SDKNamingError(f"{ENGINEERING_CLI.as_posix()}: project name is missing")
    return str(name)


def check_uniqueness(root: Path, claims: list[tuple[str, str, str]]) -> list[str]:
    """Fail when two distributions claim one name on the same registry.

    *claims* is a list of ``(registry, label, name)``. A name is only scarce
    within a registry, so PyPI and crates.io may both hold ``snaplink-sso``;
    two PyPI claims on one name are an ambiguous upload and are rejected. This
    is the check that catches a copy-pasted name, a renamed package that kept
    an old one, or a developer tool squatting on a published SDK's identity.
    """
    by_registry: dict[str, dict[str, list[str]]] = {}
    for registry, label, name in claims:
        by_registry.setdefault(registry, {}).setdefault(_normalize(name), []).append(label)
    errors: list[str] = []
    for registry, names in sorted(by_registry.items()):
        for normalized, labels in sorted(names.items()):
            if len(labels) < 2:
                continue
            errors.append(
                f"registry {registry} name {normalized!r} is claimed by "
                f"{len(labels)} distributions ({', '.join(sorted(labels))}); "
                f"one registry allows one owner per name"
            )
    return errors


def check(root: Path = ROOT) -> list[str]:
    """Check every registered SDK name, its scheme, and per-registry uniqueness."""
    errors: list[str] = []
    claims: list[tuple[str, str, str]] = []
    for convention in CONVENTIONS:
        try:
            name = declared_name(root, convention)
        except (SDKNamingError, OSError) as exc:
            errors.append(f"id={convention.id} {exc}")
            continue
        errors.extend(check_name(convention, name))
        claims.append((REGISTRIES[convention.id], convention.id, name))
    try:
        claims.append(("PyPI", ENGINEERING_CLI_LABEL, _engineering_cli_name(root)))
    except (SDKNamingError, OSError) as exc:
        errors.append(f"id={ENGINEERING_CLI_LABEL} {exc}")
    errors.extend(check_uniqueness(root, claims))
    return errors


def run(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="sdk-naming",
        description="Validate SDK package names against the canonical scheme and platform grammars.",
    )
    parser.add_argument("action", choices=["check", "list"], help="check names, or print the scheme")
    parsed = parser.parse_args(args)
    if parsed.action == "list":
        for convention in CONVENTIONS:
            print(f"{convention.id:11} {convention.expected:26} {convention.rule}")
        return 0
    errors = check()
    if errors:
        print("sdk-naming: FAIL")
        for error in errors:
            print(f"  {error}")
        return 1
    print(
        f"sdk-naming: OK ({len(CONVENTIONS)} SDK packages + the engineering CLI, "
        f"brand={BRAND}, product={CAPABILITY}, one name per registry)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
