#!/usr/bin/env python3
"""Strict module catalog loading and dependency planning.

The v1alpha1 format is deliberately JSON-only: manifests are data, never
templates or executable registration scripts.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = ROOT / "ops" / "build"
CATALOG_PATH = BUILD_DIR / "modules.json"
PROFILES_DIR = BUILD_DIR / "profiles"

MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.-]*\.v[0-9]+$")
HOST_API_RE = re.compile(r"^v[0-9]+(?:alpha[0-9]+|beta[0-9]+)?$")
GO_SYMBOL_RE = re.compile(r"^[A-Z][A-Za-z0-9_]*$")
GO_IMPORT_RE = re.compile(r"^[A-Za-z0-9._~/-]+$")
GO_VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
LICENSE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")

MODULE_FIELDS = {
    "$schema",
    "schema_version",
    "id",
    "summary",
    "kind",
    "state",
    "activation",
    "locked",
    "host_api",
    "version",
    "module_path",
    "source",
    "provides",
    "requires",
    "conflicts",
    "registration",
    "targets",
    "licenses",
    "security",
}
PROFILE_FIELDS = {
    "$schema",
    "schema_version",
    "id",
    "summary",
    "maturity",
    "modules",
    "policy",
}
SUPPORTED_REGISTRATIONS = {"audit.kafka.factory.v1"}
REGISTRATION_CONTRACTS = {
    "audit.kafka.factory.v1": {
        "provides": {"audit.sink.kafka.v1"},
        "requires": {"audit.host.v1"},
        "failure_policy": "fail-open",
    }
}


class ModuleConfigError(ValueError):
    """A deterministic catalog/profile validation or resolution failure."""


@dataclass(frozen=True)
class Module:
    data: dict
    origin: Path
    inline: bool = False

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def provides(self) -> tuple[str, ...]:
        return tuple(self.data["provides"])

    @property
    def requires(self) -> tuple[str, ...]:
        return tuple(self.data["requires"])

    @property
    def state(self) -> str:
        return self.data["state"]

    @property
    def locked(self) -> bool:
        return bool(self.data.get("locked", False))

    @property
    def digest(self) -> str:
        return "sha256:" + _digest_json(self.data)

    @property
    def source_dir(self) -> Path | None:
        source = self.data.get("source")
        if not source:
            return None
        base = ROOT if self.inline else self.origin.parent
        return (base / source).resolve()


@dataclass(frozen=True)
class Profile:
    data: dict
    origin: Path

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def modules(self) -> tuple[str, ...]:
        return tuple(self.data["modules"])

    @property
    def digest(self) -> str:
        return "sha256:" + _digest_json(self.data)


@dataclass(frozen=True)
class Catalog:
    host_api: str
    modules: dict[str, Module]
    digest: str


@dataclass(frozen=True)
class Plan:
    catalog: Catalog
    profile: Profile
    modules: tuple[Module, ...]
    dependencies: dict[str, tuple[str, ...]]
    explicit: tuple[str, ...]
    blockers: tuple[str, ...]

    @property
    def buildable(self) -> bool:
        return not self.blockers


def _read_json(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ModuleConfigError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ModuleConfigError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ModuleConfigError(f"{path}: top level must be an object")
    return raw


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reject_unknown(data: dict, allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ModuleConfigError(f"{label}: unknown fields: {', '.join(unknown)}")


def _string_list(data: dict, key: str, label: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ModuleConfigError(f"{label}.{key}: expected a string array")
    if len(value) != len(set(value)):
        raise ModuleConfigError(f"{label}.{key}: duplicate values are forbidden")
    return value


def _validate_capabilities(values: Iterable[str], label: str) -> None:
    for value in values:
        if not CAPABILITY_RE.fullmatch(value):
            raise ModuleConfigError(f"{label}: invalid capability {value!r}")


def _validate_registration(data: dict, label: str) -> None:
    if not isinstance(data, dict):
        raise ModuleConfigError(f"{label}: expected object")
    allowed = {"type", "package", "symbol"}
    _reject_unknown(data, allowed, label)
    if set(data) != allowed:
        raise ModuleConfigError(f"{label}: type, package, and symbol are required")
    if any(not isinstance(data[key], str) for key in allowed):
        raise ModuleConfigError(f"{label}: all fields must be strings")
    if data["type"] not in SUPPORTED_REGISTRATIONS:
        raise ModuleConfigError(f"{label}: unsupported type {data['type']!r}")
    if not GO_IMPORT_RE.fullmatch(data["package"]) or ".." in data["package"]:
        raise ModuleConfigError(f"{label}.package: invalid Go import path")
    if not GO_SYMBOL_RE.fullmatch(data["symbol"]):
        raise ModuleConfigError(f"{label}.symbol: invalid Go identifier")


def _validate_targets(data: dict, label: str) -> None:
    if not isinstance(data, dict):
        raise ModuleConfigError(f"{label}: expected object")
    _reject_unknown(data, {"goos", "goarch", "cgo", "fips"}, label)
    if not isinstance(data.get("cgo"), bool):
        raise ModuleConfigError(f"{label}.cgo: expected boolean")
    for key in ("goos", "goarch"):
        if key in data:
            _string_list(data, key, label)
    fips = data.get("fips", "unknown")
    if not isinstance(fips, str) or fips not in {
        "compatible",
        "incompatible",
        "unknown",
    }:
        raise ModuleConfigError(f"{label}.fips: invalid value")


def _validate_security(data: dict, label: str) -> None:
    if not isinstance(data, dict):
        raise ModuleConfigError(f"{label}: expected object")
    _reject_unknown(data, {"removable", "failure_policy"}, label)
    if not isinstance(data.get("removable"), bool):
        raise ModuleConfigError(f"{label}.removable: expected boolean")
    failure_policy = data.get("failure_policy")
    allowed = {"fail-open", "fail-closed", "not-applicable"}
    if not isinstance(failure_policy, str) or failure_policy not in allowed:
        raise ModuleConfigError(f"{label}.failure_policy: invalid value")


def _validate_module_semantics(data: dict, label: str) -> None:
    kind = data["kind"]
    state = data["state"]
    activation = data["activation"]
    locked = data.get("locked", False)
    removable = data["security"]["removable"]

    expected_activation = {
        "kernel": "locked",
        "bundle": "restart",
        "cold": "restart",
        "hot-precompiled": "hot",
        "hot-external": "hot",
    }[kind]
    if activation != expected_activation:
        raise ModuleConfigError(
            f"{label}: kind {kind} requires activation {expected_activation}"
        )
    if kind == "kernel":
        if state != "embedded" or not locked or removable:
            raise ModuleConfigError(
                f"{label}: kernel modules must be embedded, locked, and non-removable"
            )
    if locked and (activation != "locked" or removable):
        raise ModuleConfigError(
            f"{label}: locked modules must use locked activation and be non-removable"
        )
    if activation == "locked" and not locked:
        raise ModuleConfigError(f"{label}: locked activation requires locked=true")
    if state == "isolated" and kind != "cold":
        raise ModuleConfigError(
            f"{label}: v1alpha1 isolated modules must be cold modules"
        )
    if activation == "hot" and state != "planned":
        raise ModuleConfigError(
            f"{label}: hot activation remains planned until generation drain exists"
        )
    if kind == "hot-external" and "registration" in data:
        raise ModuleConfigError(
            f"{label}: hot-external modules cannot use in-process registration"
        )
    if state != "isolated" and "registration" in data:
        raise ModuleConfigError(
            f"{label}: in-process registration is only valid for isolated cold modules"
        )
    if "registration" in data:
        contract = REGISTRATION_CONTRACTS[data["registration"]["type"]]
        if not contract["provides"].issubset(data["provides"]):
            raise ModuleConfigError(
                f"{label}: registration requires capabilities "
                f"{', '.join(sorted(contract['provides']))}"
            )
        if not contract["requires"].issubset(data["requires"]):
            raise ModuleConfigError(
                f"{label}: registration requires host capabilities "
                f"{', '.join(sorted(contract['requires']))}"
            )
        if data["security"]["failure_policy"] != contract["failure_policy"]:
            raise ModuleConfigError(
                f"{label}: registration requires failure_policy "
                f"{contract['failure_policy']}"
            )


def validate_module(data: dict, origin: Path, host_api: str) -> Module:
    label = str(origin)
    _reject_unknown(data, MODULE_FIELDS, label)
    required = {
        "schema_version",
        "id",
        "summary",
        "kind",
        "state",
        "activation",
        "provides",
        "requires",
        "conflicts",
        "security",
    }
    missing = sorted(required - set(data))
    if missing:
        raise ModuleConfigError(f"{label}: missing fields: {', '.join(missing)}")
    module_id = data["id"]
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or not isinstance(module_id, str)
        or not MODULE_ID_RE.fullmatch(module_id)
    ):
        raise ModuleConfigError(f"{label}: invalid schema_version or module id")
    if "$schema" in data and (
        not isinstance(data["$schema"], str) or not data["$schema"].strip()
    ):
        raise ModuleConfigError(f"{label}.$schema: expected non-empty string")
    if not isinstance(data["summary"], str) or not data["summary"].strip():
        raise ModuleConfigError(f"{label}.summary: expected non-empty string")
    if not isinstance(data["kind"], str) or data["kind"] not in {
        "kernel",
        "bundle",
        "cold",
        "hot-precompiled",
        "hot-external",
    }:
        raise ModuleConfigError(f"{label}.kind: invalid value")
    if not isinstance(data["state"], str) or data["state"] not in {
        "embedded",
        "isolated",
        "planned",
    }:
        raise ModuleConfigError(f"{label}.state: invalid value")
    if not isinstance(data["activation"], str) or data["activation"] not in {
        "locked",
        "restart",
        "hot",
    }:
        raise ModuleConfigError(f"{label}.activation: invalid value")
    if "locked" in data and not isinstance(data["locked"], bool):
        raise ModuleConfigError(f"{label}.locked: expected boolean")
    for key in ("host_api", "version", "module_path", "source"):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            raise ModuleConfigError(f"{label}.{key}: expected non-empty string")
    if data.get("host_api", host_api) != host_api:
        raise ModuleConfigError(f"{label}.host_api: requires {host_api}")
    _validate_capabilities(_string_list(data, "provides", label), f"{label}.provides")
    _validate_capabilities(_string_list(data, "requires", label), f"{label}.requires")
    conflicts = _string_list(data, "conflicts", label)
    if any(not MODULE_ID_RE.fullmatch(value) for value in conflicts):
        raise ModuleConfigError(f"{label}.conflicts: invalid module id")
    if "registration" in data:
        _validate_registration(data["registration"], f"{label}.registration")
    if "targets" in data:
        _validate_targets(data["targets"], f"{label}.targets")
    if "licenses" in data:
        licenses = _string_list(data, "licenses", label)
        if not licenses:
            raise ModuleConfigError(f"{label}.licenses: expected a non-empty array")
        if any(not LICENSE_RE.fullmatch(value) for value in licenses):
            raise ModuleConfigError(
                f"{label}.licenses: expected SPDX license identifiers"
            )
    _validate_security(data["security"], f"{label}.security")
    _validate_module_semantics(data, label)
    if data["state"] == "isolated":
        isolated = {
            "module_path",
            "version",
            "source",
            "registration",
            "targets",
            "licenses",
        }
        missing_isolated = sorted(isolated - set(data))
        if missing_isolated:
            raise ModuleConfigError(
                f"{label}: isolated module missing: {', '.join(missing_isolated)}"
            )
        if not data["licenses"]:
            raise ModuleConfigError(
                f"{label}.licenses: isolated modules require a declared license"
            )
        if not GO_IMPORT_RE.fullmatch(data["module_path"]):
            raise ModuleConfigError(f"{label}.module_path: invalid Go module path")
        if not GO_VERSION_RE.fullmatch(data["version"]):
            raise ModuleConfigError(f"{label}.version: expected canonical Go version")
        package = data["registration"]["package"]
        module_path = data["module_path"]
        if package != module_path and not package.startswith(module_path + "/"):
            raise ModuleConfigError(
                f"{label}.registration.package must be inside module_path"
            )
    return Module(data=data, origin=origin)


def _validate_local_source(module: Module) -> None:
    if module.state != "isolated":
        return
    source = module.source_dir
    if not source:
        raise ModuleConfigError(f"{module.origin}: isolated module needs source")
    try:
        source.relative_to(module.origin.parent.resolve())
    except ValueError as exc:
        raise ModuleConfigError(
            f"{module.origin}.source: must stay inside the module directory"
        ) from exc
    go_mod = source / "go.mod"
    if not go_mod.is_file():
        raise ModuleConfigError(f"{module.origin}.source: missing go.mod")
    result = subprocess.run(
        ["go", "mod", "edit", "-json", f"-modfile={go_mod}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ModuleConfigError(
            f"{module.origin}.source: invalid go.mod: {result.stderr.strip()}"
        )
    declared = json.loads(result.stdout).get("Module", {}).get("Path")
    if declared != module.data["module_path"]:
        raise ModuleConfigError(
            f"{module.origin}.module_path does not match go.mod module " f"{declared!r}"
        )


def _manifest_path(path: Path) -> Path:
    candidate = path.expanduser().resolve()
    if candidate.is_dir():
        candidate = candidate / "snaplink.module.json"
    return candidate


def load_catalog(add_modules: Iterable[str | Path] = ()) -> Catalog:
    raw = _read_json(CATALOG_PATH)
    _reject_unknown(
        raw, {"$schema", "schema_version", "host_api", "modules"}, str(CATALOG_PATH)
    )
    if (
        type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw.get("host_api"), str)
        or not HOST_API_RE.fullmatch(raw["host_api"])
    ):
        raise ModuleConfigError(f"{CATALOG_PATH}: invalid schema_version or host_api")
    if "$schema" in raw and (
        not isinstance(raw["$schema"], str) or not raw["$schema"].strip()
    ):
        raise ModuleConfigError(f"{CATALOG_PATH}.$schema: expected non-empty string")
    if not isinstance(raw.get("modules"), list):
        raise ModuleConfigError(f"{CATALOG_PATH}.modules: expected array")
    loaded: list[Module] = []
    for entry in raw["modules"]:
        if not isinstance(entry, dict):
            raise ModuleConfigError(f"{CATALOG_PATH}.modules: entries must be objects")
        if set(entry) == {"manifest"}:
            if not isinstance(entry["manifest"], str) or not entry["manifest"].strip():
                raise ModuleConfigError(
                    f"{CATALOG_PATH}.manifest: expected non-empty string"
                )
            path = (CATALOG_PATH.parent / entry["manifest"]).resolve()
            module = validate_module(_read_json(path), path, raw["host_api"])
            _validate_local_source(module)
            loaded.append(module)
        else:
            module = validate_module(entry, CATALOG_PATH, raw["host_api"])
            if module.state == "isolated":
                raise ModuleConfigError(
                    f"{CATALOG_PATH}: isolated modules require their own manifest"
                )
            loaded.append(Module(module.data, module.origin, inline=True))
    for requested in add_modules:
        path = _manifest_path(Path(requested))
        module = validate_module(_read_json(path), path, raw["host_api"])
        if module.state == "embedded":
            raise ModuleConfigError(f"{path}: added module cannot claim embedded state")
        _validate_local_source(module)
        loaded.append(module)
    by_id: dict[str, Module] = {}
    by_module_path: dict[str, str] = {}
    for module in loaded:
        if module.id in by_id:
            raise ModuleConfigError(f"duplicate module id: {module.id}")
        by_id[module.id] = module
        module_path = module.data.get("module_path")
        if module_path:
            if module_path in by_module_path:
                raise ModuleConfigError(
                    f"duplicate module_path {module_path}: "
                    f"{by_module_path[module_path]}, {module.id}"
                )
            by_module_path[module_path] = module.id
    for module in loaded:
        unknown_conflicts = sorted(set(module.data["conflicts"]) - set(by_id))
        if unknown_conflicts:
            raise ModuleConfigError(
                f"module {module.id} has unknown conflicts: "
                f"{', '.join(unknown_conflicts)}"
            )
    return Catalog(raw["host_api"], by_id, "sha256:" + _digest_json(raw))


def load_profile(profile: str) -> Profile:
    requested = Path(profile)
    path = (
        requested if requested.suffix == ".json" else PROFILES_DIR / f"{profile}.json"
    )
    path = path.expanduser().resolve()
    raw = _read_json(path)
    _reject_unknown(raw, PROFILE_FIELDS, str(path))
    required = {"schema_version", "id", "summary", "maturity", "modules", "policy"}
    missing = sorted(required - set(raw))
    if missing:
        raise ModuleConfigError(f"{path}: missing fields: {', '.join(missing)}")
    profile_id = raw["id"]
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not isinstance(profile_id, str)
        or not MODULE_ID_RE.fullmatch(profile_id)
    ):
        raise ModuleConfigError(f"{path}: invalid schema_version or profile id")
    if "$schema" in raw and (
        not isinstance(raw["$schema"], str) or not raw["$schema"].strip()
    ):
        raise ModuleConfigError(f"{path}.$schema: expected non-empty string")
    if not isinstance(raw["summary"], str) or not raw["summary"].strip():
        raise ModuleConfigError(f"{path}.summary: expected non-empty string")
    if not isinstance(raw["maturity"], str) or raw["maturity"] not in {
        "supported",
        "preview",
        "planned",
    }:
        raise ModuleConfigError(f"{path}.maturity: invalid value")
    modules = _string_list(raw, "modules", str(path))
    if any(not MODULE_ID_RE.fullmatch(value) for value in modules):
        raise ModuleConfigError(f"{path}.modules: invalid module id")
    policy = raw["policy"]
    if not isinstance(policy, dict):
        raise ModuleConfigError(f"{path}.policy: expected object")
    _reject_unknown(policy, {"allow_cgo", "fips", "allowed_licenses"}, f"{path}.policy")
    if not isinstance(policy.get("allow_cgo"), bool):
        raise ModuleConfigError(f"{path}.policy.allow_cgo: expected boolean")
    if not isinstance(policy.get("fips"), str) or policy["fips"] not in {
        "required",
        "compatible",
        "any",
    }:
        raise ModuleConfigError(f"{path}.policy.fips: invalid value")
    if "allowed_licenses" in policy:
        licenses = _string_list(policy, "allowed_licenses", f"{path}.policy")
        if any(not LICENSE_RE.fullmatch(value) for value in licenses):
            raise ModuleConfigError(
                f"{path}.policy.allowed_licenses: expected SPDX identifiers"
            )
    built_in = PROFILES_DIR / f"{raw['id']}.json"
    if path.parent != PROFILES_DIR.resolve() and built_in.is_file():
        raise ModuleConfigError(
            f"{path}: custom profile cannot reuse built-in id {raw['id']!r}"
        )
    return Profile(raw, path)


def _provider_for(
    capability: str,
    selected: set[str],
    excluded: set[str],
    modules: dict[str, Module],
) -> str:
    active = sorted(mid for mid in selected if capability in modules[mid].provides)
    if len(active) == 1:
        return active[0]
    if len(active) > 1:
        raise ModuleConfigError(
            f"capability {capability} has multiple selected providers: {', '.join(active)}"
        )
    candidates = sorted(
        mid
        for mid, module in modules.items()
        if mid not in excluded and capability in module.provides
    )
    if not candidates:
        raise ModuleConfigError(f"no provider for required capability {capability}")
    if len(candidates) > 1:
        raise ModuleConfigError(
            f"capability {capability} is ambiguous; select one of: {', '.join(candidates)}"
        )
    return candidates[0]


def _resolve_closure(
    selected: set[str],
    excluded: set[str],
    modules: dict[str, Module],
) -> dict[str, set[str]]:
    dependencies: dict[str, set[str]] = {}
    changed = True
    while changed:
        changed = False
        for mid in sorted(selected):
            dependencies.setdefault(mid, set())
            for capability in modules[mid].requires:
                provider = _provider_for(capability, selected, excluded, modules)
                dependencies[mid].add(provider)
                if provider not in selected:
                    selected.add(provider)
                    changed = True
    return dependencies


def _topological_order(
    selected: set[str],
    dependencies: dict[str, set[str]],
) -> tuple[str, ...]:
    pending = {mid: set(dependencies.get(mid, ())) for mid in selected}
    ordered: list[str] = []
    while pending:
        ready = sorted(mid for mid, deps in pending.items() if not deps)
        if not ready:
            cycle = ", ".join(sorted(pending))
            raise ModuleConfigError(f"module dependency cycle: {cycle}")
        for mid in ready:
            ordered.append(mid)
            pending.pop(mid)
        for deps in pending.values():
            deps.difference_update(ready)
    return tuple(ordered)


def _policy_blockers(profile: Profile, modules: Iterable[Module]) -> list[str]:
    blockers: list[str] = []
    if profile.data["maturity"] == "planned":
        blockers.append(f"profile {profile.id} is planned, not buildable")
    policy = profile.data["policy"]
    allowed_licenses = set(policy.get("allowed_licenses", ()))
    for module in modules:
        if module.state == "planned":
            blockers.append(
                f"module {module.id} has not been isolated from stock-server"
            )
        targets = module.data.get("targets", {})
        if targets.get("cgo") and not policy["allow_cgo"]:
            blockers.append(f"module {module.id} requires CGO")
        denied = sorted(set(module.data.get("licenses", ())) - allowed_licenses)
        if "allowed_licenses" in policy and denied:
            blockers.append(
                f"module {module.id} uses disallowed licenses: {', '.join(denied)}"
            )
        if policy["fips"] == "required" and targets.get("fips") != "compatible":
            blockers.append(f"module {module.id} is not declared FIPS compatible")
        if policy["fips"] == "compatible" and targets.get("fips") == "incompatible":
            blockers.append(f"module {module.id} is declared FIPS incompatible")
    return blockers


def _composition_blockers(selected: set[str]) -> list[str]:
    if "stock-server" in selected:
        return []
    return [
        "current composition still requires stock-server; complete the "
        "minimal entry-point extraction before building this profile"
    ]


def _validate_registration_slots(modules: Iterable[Module]) -> None:
    slots: dict[str, str] = {}
    for module in modules:
        registration = module.data.get("registration")
        if not registration:
            continue
        slot = registration["type"]
        if slot in slots:
            raise ModuleConfigError(
                f"registration slot {slot} is selected by both "
                f"{slots[slot]} and {module.id}"
            )
        slots[slot] = module.id


def resolve_plan(
    profile_name: str,
    with_modules: Iterable[str] = (),
    without_modules: Iterable[str] = (),
    add_modules: Iterable[str | Path] = (),
) -> Plan:
    catalog = load_catalog(add_modules)
    profile = load_profile(profile_name)
    modules = catalog.modules
    explicit = set(profile.modules) | set(with_modules)
    excluded = set(without_modules)
    unknown = sorted((explicit | excluded) - set(modules))
    if unknown:
        raise ModuleConfigError(f"unknown modules: {', '.join(unknown)}")
    for mid in excluded:
        removable = modules[mid].data["security"]["removable"]
        if modules[mid].locked or modules[mid].state == "embedded" or not removable:
            raise ModuleConfigError(f"module {mid} cannot be excluded")
    selected = explicit - excluded
    selected.update(mid for mid, module in modules.items() if module.locked)
    dependencies = _resolve_closure(selected, excluded, modules)
    for mid in sorted(selected):
        conflicts = sorted(set(modules[mid].data["conflicts"]) & selected)
        if conflicts:
            raise ModuleConfigError(
                f"module {mid} conflicts with {', '.join(conflicts)}"
            )
    ordered_ids = _topological_order(selected, dependencies)
    ordered = tuple(modules[mid] for mid in ordered_ids)
    _validate_registration_slots(ordered)
    frozen_deps = {mid: tuple(sorted(dependencies.get(mid, ()))) for mid in ordered_ids}
    blockers = tuple(
        _composition_blockers(selected) + _policy_blockers(profile, ordered)
    )
    return Plan(
        catalog,
        profile,
        ordered,
        frozen_deps,
        tuple(sorted(explicit)),
        blockers,
    )


def format_plan(plan: Plan) -> str:
    lines = [
        f"profile: {plan.profile.id} ({plan.profile.data['maturity']})",
        f"host_api: {plan.catalog.host_api}",
        f"buildable: {'yes' if plan.buildable else 'no'}",
        "modules:",
    ]
    for module in plan.modules:
        deps = plan.dependencies.get(module.id, ())
        suffix = f" <- {', '.join(deps)}" if deps else ""
        lines.append(
            f"  - {module.id} [{module.state}/{module.data['activation']}]{suffix}"
        )
    if plan.blockers:
        lines.append("blockers:")
        lines.extend(f"  - {blocker}" for blocker in plan.blockers)
    return "\n".join(lines)


def format_catalog(catalog: Catalog) -> str:
    rows = ["ID\tSTATE\tACTIVATION\tKIND"]
    for module in sorted(catalog.modules.values(), key=lambda item: item.id):
        rows.append(
            f"{module.id}\t{module.state}\t{module.data['activation']}\t{module.data['kind']}"
        )
    return "\n".join(rows)


def graph_lines(plan: Plan) -> list[str]:
    lines: list[str] = []
    for module in plan.modules:
        deps = plan.dependencies.get(module.id, ())
        if deps:
            lines.extend(f"{module.id} -> {dependency}" for dependency in deps)
        else:
            lines.append(module.id)
    return lines


def why_lines(plan: Plan, target: str) -> list[str]:
    selected = {module.id for module in plan.modules}
    if target not in selected:
        raise ModuleConfigError(f"module {target} is not selected")
    roots = list(plan.explicit) + [
        module.id for module in plan.modules if module.locked
    ]

    def visit(current: str, path: list[str]) -> list[str] | None:
        if current == target:
            return path + [current]
        for dependency in plan.dependencies.get(current, ()):
            if dependency not in path:
                found = visit(dependency, path + [current])
                if found:
                    return found
        return None

    for root in roots:
        found = visit(root, [])
        if found:
            return found
    return [target]


def _validate_schema_documents() -> None:
    module_schema = _read_json(BUILD_DIR / "module.schema.json")
    catalog_schema = _read_json(BUILD_DIR / "catalog.schema.json")
    profile_schema = _read_json(BUILD_DIR / "profile.schema.json")
    try:
        for schema in (module_schema, catalog_schema, profile_schema):
            if (
                schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
                or not isinstance(schema["$id"], str)
                or not schema["$id"]
                or schema["type"] != "object"
            ):
                raise ModuleConfigError("module schema headers are invalid")
        module_ref = catalog_schema["properties"]["modules"]["items"]["oneOf"][0][
            "$ref"
        ]
    except (KeyError, TypeError, IndexError) as exc:
        raise ModuleConfigError("module schema structure is invalid") from exc
    if module_ref != module_schema["$id"]:
        raise ModuleConfigError("catalog module $ref does not match module schema $id")


def validate_repository() -> list[str]:
    _validate_schema_documents()
    catalog = load_catalog()
    checked = [f"catalog ({len(catalog.modules)} modules)"]
    profile_ids: set[str] = set()
    for path in sorted(PROFILES_DIR.glob("*.json")):
        plan = resolve_plan(str(path))
        if plan.profile.id != path.stem:
            raise ModuleConfigError(
                f"{path}: profile id must match filename {path.stem!r}"
            )
        if plan.profile.id in profile_ids:
            raise ModuleConfigError(f"duplicate profile id: {plan.profile.id}")
        profile_ids.add(plan.profile.id)
        checked.append(f"profile {plan.profile.id} ({len(plan.modules)} selected)")
    return checked


def supported_profile_ids() -> tuple[str, ...]:
    """Return every repository profile covered by the build smoke gate."""
    validate_repository()
    profiles = (load_profile(str(path)) for path in sorted(PROFILES_DIR.glob("*.json")))
    return tuple(
        sorted(
            profile.id
            for profile in profiles
            if profile.data["maturity"] == "supported"
        )
    )
