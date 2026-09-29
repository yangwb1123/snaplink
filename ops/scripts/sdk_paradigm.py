#!/usr/bin/env python3
"""Validate the hand-written SDK-layer paradigm registry.

``ops/build/sdk-surface.json`` governs the generated operationId surface, which
is emitted for TypeScript and Python only. This module governs everything the
generator never sees: the transport, session, entitlement, preferences, and
runtime behaviour that each SDK hand-writes. Without it the hosted-login layer
drifts silently, which is exactly what happened before this registry existed:
Rust had no logout, four of five SDKs had no refresh, Python had no transport
seam, and no SDK could read an entitlement with its time semantics intact.

The registry is the only source of truth. The checker never infers a capability
from source: every ``present`` entry names the exact file and symbol that
provides it, and every ``missing`` entry names the wave that will add it. A
capability declared ``parity`` must be present in every language, so closing a
gap means flipping an entry to ``present`` with a real symbol rather than
relaxing the declaration.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sdk_versions import MANIFEST_SPECS

ROOT = Path(__file__).resolve().parents[2]
PARADIGM_PATH = ROOT / "ops" / "build" / "sdk-paradigm.json"
PARADIGM_RELATIVE_PATH = Path("ops/build/sdk-paradigm.json")
SCHEMA_PATH = ROOT / "ops" / "build" / "sdk-paradigm.schema.json"
CONFORMANCE_DIR_RELATIVE_PATH = Path("ops/build/sdk-conformance")

KNOWN_LAYERS = {"transport", "session", "entitlement", "preferences", "runtime"}
KNOWN_STATUSES = {"present", "missing"}
KNOWN_PARITIES = {"parity", "divergent"}
REQUIRED_CONFORMANCE_FILES = ("entitlement.json", "errors.json", "transport.json", "license_file.json")
EXPECTED_SCHEMA_HEADER = "https://json-schema.org/draft/2020-12/schema"


class SDKParadigmError(Exception):
    """Raised for any registry, declaration, or conformance violation."""


def _parse_json(text: str, source: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SDKParadigmError(f"{source}: invalid JSON: {exc}") from exc


def _read_json(path: Path, source: str | None = None) -> object:
    label = source or str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SDKParadigmError(f"{label}: cannot read {path}: {exc}") from exc
    return _parse_json(text, label)


def _require_dict(value: object, source: str, description: str) -> dict:
    if not isinstance(value, dict):
        raise SDKParadigmError(f"{source}: {description} must be an object")
    return value


def _require_list(value: object, source: str, description: str) -> list:
    if not isinstance(value, list):
        raise SDKParadigmError(f"{source}: {description} must be an array")
    return value


def _require_str(value: object, source: str, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SDKParadigmError(f"{source}: {description} must be a non-empty string")
    return value


def validate_schema() -> None:
    """Confirm the schema still declares the structure the checker enforces."""
    if not SCHEMA_PATH.is_file():
        raise SDKParadigmError(f"missing schema {SCHEMA_PATH.name}")
    schema = _require_dict(_read_json(SCHEMA_PATH), SCHEMA_PATH.name, "schema")
    properties = schema.get("properties")
    if (
        schema.get("$schema") != EXPECTED_SCHEMA_HEADER
        or schema.get("type") != "object"
        or not isinstance(properties, dict)
        or properties.get("schema_version", {}).get("const") != 1
    ):
        raise SDKParadigmError(f"{SCHEMA_PATH.name}: invalid schema header or version")
    languages_schema = properties.get("compatibility", {}).get("properties", {}).get("languages")
    items = languages_schema.get("items", {}).get("properties", {}) if isinstance(languages_schema, dict) else {}
    for required in ("id", "package"):
        if required not in items:
            raise SDKParadigmError(f"{SCHEMA_PATH.name}: language item is missing required key {required}")
    if "patternProperties" not in properties.get("capabilities", {}).get("items", {}).get(
        "properties", {}
    ).get("languages", {}):
        raise SDKParadigmError(f"{SCHEMA_PATH.name}: capability languages must be a patternProperties map")


def validate_languages(compatibility: dict, source: str) -> list[str]:
    """Return the declared language ids after checking shape and completeness."""
    missing_keys = sorted({"policy", "languages"} - compatibility.keys())
    if missing_keys:
        raise SDKParadigmError(f"{source}: compatibility missing {', '.join(missing_keys)}")
    extra_keys = sorted(compatibility.keys() - {"policy", "languages"})
    if extra_keys:
        raise SDKParadigmError(f"{source}: compatibility has unknown keys {', '.join(extra_keys)}")
    _require_str(compatibility["policy"], source, "compatibility.policy")

    declared: list[str] = []
    for index, entry in enumerate(_require_list(compatibility["languages"], source, "compatibility.languages")):
        where = f"{source}: compatibility.languages[{index}]"
        entry = _require_dict(entry, where, "language entry")
        language_id = _require_str(entry.get("id"), where, "id")
        if not language_id.islower() or not language_id.replace("_", "").isalnum():
            raise SDKParadigmError(f"{where}: id must be lowercase alphanumeric")
        if not isinstance(entry.get("package"), bool):
            raise SDKParadigmError(f"{where}: package must be a boolean")
        if "notes" in entry and not isinstance(entry["notes"], str):
            raise SDKParadigmError(f"{where}: notes must be a string")
        declared.append(language_id)
    if len(set(declared)) != len(declared):
        raise SDKParadigmError(f"{source}: compatibility.languages has duplicate ids")
    return declared


def validate_package_coverage(declared: list[str], source: str) -> None:
    """Every manifest-audited SDK package must declare its paradigm languages."""
    package_ids = {spec.id for spec in MANIFEST_SPECS}
    missing = sorted(package_ids - set(declared))
    if missing:
        raise SDKParadigmError(
            f"{source}: SDK packages {', '.join(missing)} are absent from compatibility.languages; "
            "a package released without a paradigm declaration is unmanaged drift"
        )


def validate_capabilities(capabilities: object, source: str, languages: list[str]) -> None:
    """Check every capability entry, its per-language declarations, and the parity contract."""
    entries = _require_list(capabilities, source, "capabilities")
    if not entries:
        raise SDKParadigmError(f"{source}: capabilities must not be empty")

    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"{source}: capabilities[{index}]"
        entry = _require_dict(entry, where, "capability entry")
        capability_id = _require_str(entry.get("id"), where, "id")
        if "." not in capability_id:
            raise SDKParadigmError(f"{where}: id must be layer-qualified, such as session.refresh")
        if capability_id in seen:
            raise SDKParadigmError(f"{where}: duplicate capability id {capability_id}")
        seen.add(capability_id)

        layer = _require_str(entry.get("layer"), where, "layer")
        if layer not in KNOWN_LAYERS:
            raise SDKParadigmError(f"{where}: unknown layer {layer}; expected one of {sorted(KNOWN_LAYERS)}")
        if not capability_id.startswith(f"{layer}."):
            raise SDKParadigmError(f"{where}: id {capability_id} does not match its layer {layer}")
        _require_str(entry.get("summary"), where, "summary")

        parity = _require_str(entry.get("parity"), where, "parity")
        if parity not in KNOWN_PARITIES:
            raise SDKParadigmError(f"{where}: unknown parity {parity}; expected one of {sorted(KNOWN_PARITIES)}")
        extra = sorted(entry.keys() - {"id", "layer", "summary", "parity", "languages"})
        if extra:
            raise SDKParadigmError(f"{where}: unknown keys {', '.join(extra)}")

        declarations = _require_dict(entry.get("languages"), where, "languages")
        unknown = sorted(set(declarations) - set(languages))
        if unknown:
            raise SDKParadigmError(f"{where}: undeclared language ids {', '.join(unknown)}")
        undeclared = sorted(set(languages) - set(declarations))
        if undeclared:
            raise SDKParadigmError(
                f"{where}: capability {capability_id} is silent for {', '.join(undeclared)}; "
                "declare every language so a new SDK cannot be added silently"
            )

        for language_id, declaration in declarations.items():
            _validate_declaration(
                declaration, f"{where}.languages.{language_id}", parity, language_id
            )


def _validate_declaration(declaration: object, where: str, parity: str, language_id: str) -> None:
    """One language's claim about one capability, checked against the parity contract."""
    declaration = _require_dict(declaration, where, "declaration")
    status = _require_str(declaration.get("status"), where, "status")
    if status not in KNOWN_STATUSES:
        raise SDKParadigmError(f"{where}: unknown status {status}; expected one of {sorted(KNOWN_STATUSES)}")

    allowed = {"status", "file", "symbol", "note", "plan"}
    extra = sorted(declaration.keys() - allowed)
    if extra:
        raise SDKParadigmError(f"{where}: unknown keys {', '.join(extra)}")
    for optional_text in ("note", "plan"):
        if optional_text in declaration and not isinstance(declaration[optional_text], str):
            raise SDKParadigmError(f"{where}: {optional_text} must be a string")

    if status == "present":
        for required in ("file", "symbol"):
            _require_str(declaration.get(required), where, required)
        if "plan" in declaration:
            raise SDKParadigmError(
                f"{where}: a present declaration must not carry plan; remove the capability or mark it missing"
            )
        return

    if "file" in declaration or "symbol" in declaration:
        raise SDKParadigmError(f"{where}: a missing declaration must not name a file or symbol")
    _require_str(declaration.get("plan"), where, "plan")
    if parity == "parity":
        raise SDKParadigmError(
            f"{where}: capability is declared parity but {language_id} is missing; "
            "either close the gap or change parity to divergent with a CHANGELOG entry"
        )


def validate_symbol_presence(capabilities: object, source: str) -> list[str]:
    """Confirm every present declaration resolves to a real file and symbol."""
    problems: list[str] = []
    for entry in _require_list(capabilities, source, "capabilities"):
        capability_id = _require_str(entry.get("id"), source, "id") if isinstance(entry, dict) else "?"
        declarations = entry.get("languages", {}) if isinstance(entry, dict) else {}
        for language_id, declaration in declarations.items():
            if not isinstance(declaration, dict) or declaration.get("status") != "present":
                continue
            relative = declaration["file"]
            target = ROOT / relative
            label = f"{capability_id}.{language_id}"
            if not target.is_file():
                problems.append(f"{label}: declared file {relative} does not exist")
                continue
            try:
                body = target.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                problems.append(f"{label}: cannot read {relative}: {exc}")
                continue
            if declaration["symbol"] not in body:
                problems.append(
                    f"{label}: symbol {declaration['symbol']!r} is not present in {relative}"
                )
    return problems


def validate_conformance() -> list[str]:
    """The shared cross-language fixtures must exist and carry their invariants."""
    problems: list[str] = []
    for name in REQUIRED_CONFORMANCE_FILES:
        path = CONFORMANCE_DIR_RELATIVE_PATH / name
        absolute = ROOT / path
        if not absolute.is_file():
            problems.append(f"missing conformance fixture {path}")
            continue
        try:
            document = _read_json(absolute)
        except SDKParadigmError as exc:
            problems.append(str(exc))
            continue
        document = _require_dict(document, name, "fixture")
        for required in ("schema_version", "invariants"):
            if required not in document:
                problems.append(f"{name}: missing required key {required}")
        invariants = document.get("invariants")
        if not isinstance(invariants, list) or not invariants:
            problems.append(f"{name}: invariants must be a non-empty array")
        elif not all(isinstance(item, str) and item.strip() for item in invariants):
            problems.append(f"{name}: every invariant must be a non-empty string")
    return problems


def check() -> int:
    """Validate the registry end to end and print a stable report."""
    source = str(PARADIGM_RELATIVE_PATH)
    try:
        document = _require_dict(_read_json(PARADIGM_PATH), source, "registry")
    except SDKParadigmError as exc:
        print(f"sdk-paradigm: {exc}", file=sys.stderr)
        return 1

    if document.get("schema_version") != 1:
        print(f"sdk-paradigm: {source}: unsupported schema_version", file=sys.stderr)
        return 1
    try:
        validate_schema()
    except SDKParadigmError as exc:
        print(f"sdk-paradigm: {exc}", file=sys.stderr)
        return 1

    try:
        compatibility = _require_dict(document.get("compatibility"), source, "compatibility")
        languages = validate_languages(compatibility, source)
        validate_package_coverage(languages, source)
        capabilities = document.get("capabilities")
        validate_capabilities(capabilities, source, languages)
    except SDKParadigmError as exc:
        print(f"sdk-paradigm: {exc}", file=sys.stderr)
        return 1

    problems = validate_symbol_presence(capabilities, source) + validate_conformance()
    if problems:
        for problem in problems:
            print(f"sdk-paradigm: {problem}", file=sys.stderr)
        return 1

    entries = _require_list(capabilities, source, "capabilities")
    present = sum(
        1
        for entry in entries
        for declaration in entry["languages"].values()
        if declaration["status"] == "present"
    )
    total = sum(len(entry["languages"]) for entry in entries)
    parity_count = sum(1 for entry in entries if entry["parity"] == "parity")
    print(
        f"sdk-paradigm: languages={len(languages)} capabilities={len(entries)} "
        f"parity={parity_count} coverage={present}/{total} "
        f"conformance={len(REQUIRED_CONFORMANCE_FILES)}"
    )
    print("verdict: PASS")
    return 0


def list_capabilities() -> int:
    """Print the capability matrix as one aligned row per capability."""
    source = str(PARADIGM_RELATIVE_PATH)
    try:
        document = _require_dict(_read_json(PARADIGM_PATH), source, "registry")
        languages = validate_languages(
            _require_dict(document.get("compatibility"), source, "compatibility"), source
        )
    except SDKParadigmError as exc:
        print(f"sdk-paradigm: {exc}", file=sys.stderr)
        return 1

    entries = _require_list(document.get("capabilities"), source, "capabilities")
    width = max((len(entry["id"]) for entry in entries), default=0)
    print(f"{'capability'.ljust(width)}  parity      " + "  ".join(f"{lang:<10}" for lang in languages))
    for entry in entries:
        cells = "  ".join(
            f"{('yes' if entry['languages'][lang]['status'] == 'present' else 'MISSING'):<10}"
            for lang in languages
        )
        print(f"{entry['id'].ljust(width)}  {entry['parity']:<10}  {cells}")
    return 0


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sdk-paradigm", description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check", help="validate the registry, its symbols, and the conformance fixtures")
    sub.add_parser("list", help="print the capability matrix")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.action == "check":
        return check()
    return list_capabilities()


if __name__ == "__main__":
    sys.exit(run())
