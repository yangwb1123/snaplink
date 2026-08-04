#!/usr/bin/env python3
"""Configure and build an explicit Snaplink cold-module profile."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from module_catalog import (
    ROOT,
    Module,
    ModuleConfigError,
    Plan,
    buildable_profile_ids,
    format_catalog,
    format_plan,
    graph_lines,
    load_catalog,
    resolve_plan,
    supported_profile_ids,
    validate_repository,
    why_lines,
)


DEFAULT_OUT_ROOT = ROOT / "dist" / "modules"
DEFAULT_BUILD_VERSION = "v0.0.0-dev"
OUTPUT_MARKER = ".snaplink-modules-output"
OVERLAY_TARGET = (
    ROOT / "cmd" / "sso-server" / "servermodules" / "register_configured.go"
)
BUILDINFO_IMPORT = "github.com/yangwb1123/snaplink/platform/buildinfo"
CORE_BUILDINFO_IMPORT = "github.com/yangwb1123/snaplink/shared/core"
ROOT_MODULE_PATH = "github.com/yangwb1123/snaplink"
EDITION_PROFILES = frozenset({"prototype", "minimal", "full"})
SEMVER_PRERELEASE_ID = (
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
BUILD_VERSION_RE = re.compile(
    r"^v(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*)"
    rf"(?:-{SEMVER_PRERELEASE_ID}(?:\.{SEMVER_PRERELEASE_ID})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SOURCE_FILE_FIELDS = (
    "GoFiles",
    "CgoFiles",
    "CFiles",
    "CXXFiles",
    "MFiles",
    "HFiles",
    "FFiles",
    "SFiles",
    "SwigFiles",
    "SwigCXXFiles",
    "SysoFiles",
    "EmbedFiles",
)
GO_ENV_KEYS = (
    "GOVERSION",
    "GOOS",
    "GOARCH",
    "CGO_ENABLED",
    "GOAMD64",
    "GO386",
    "GOARM",
    "GOARM64",
    "GOMIPS",
    "GOMIPS64",
    "GOPPC64",
    "GORISCV64",
    "GOWASM",
    "GOEXPERIMENT",
    "GOFIPS140",
    "GOFLAGS",
)
CGO_ENV_KEYS = (
    "CC",
    "CXX",
    "AR",
    "PKG_CONFIG",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_FFLAGS",
    "CGO_LDFLAGS",
)

REGISTRATION_HANDLERS = {
    "audit.kafka.factory.v1": {
        "host_alias": "serverbuildauthn",
        "host_package": "github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn",
        "host_symbol": "RegisterAuditKafkaSinkFactory",
    }
}


class BuildModulesError(RuntimeError):
    """A profile materialization or Go build failure."""


def _build_version(value: str) -> str:
    if not BUILD_VERSION_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "expected vMAJOR.MINOR.PATCH with optional SemVer pre-release/build metadata"
        )
    return value


def _validate_output_dir(out_dir: Path) -> None:
    try:
        relative = out_dir.relative_to(ROOT)
    except ValueError:
        return
    if relative.parts and relative.parts[0] == "dist":
        return
    raise BuildModulesError(
        "--out inside the repository must be under dist/ so generated Go "
        "files cannot affect source-tree gates"
    )


def _validate_owned_output(out_dir: Path) -> None:
    if not out_dir.exists():
        return
    if not out_dir.is_dir():
        raise BuildModulesError(f"module output is not a directory: {out_dir}")
    marker = out_dir / OUTPUT_MARKER
    if any(out_dir.iterdir()) and (
        not marker.is_file() or marker.read_bytes() != b"v1\n"
    ):
        raise BuildModulesError(
            f"refusing to replace unowned non-empty output directory: {out_dir}"
        )


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    capture: bool = True,
) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=capture,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise BuildModulesError(f"{' '.join(args)} failed: {detail}")
    return result.stdout if capture else ""


def _registration_modules(plan: Plan) -> list[Module]:
    return [module for module in plan.modules if "registration" in module.data]


def render_registration(plan: Plan) -> str:
    imports: list[tuple[str, str]] = []
    calls: list[str] = []
    used_types: set[str] = set()
    for index, module in enumerate(_registration_modules(plan)):
        registration = module.data["registration"]
        kind = registration["type"]
        if kind in used_types:
            raise BuildModulesError(f"registration slot {kind} selected more than once")
        used_types.add(kind)
        handler = REGISTRATION_HANDLERS.get(kind)
        if not handler:
            raise BuildModulesError(f"registration type {kind} has no host adapter")
        module_alias = f"module{index}"
        imports.append((module_alias, registration["package"]))
        imports.append((handler["host_alias"], handler["host_package"]))
        calls.append(
            f"\t{handler['host_alias']}.{handler['host_symbol']}"
            f"({module_alias}.{registration['symbol']})"
        )
    unique_imports = sorted(set(imports), key=lambda value: (value[1], value[0]))
    lines = [
        "// Code generated by `python cli.py configure`; DO NOT EDIT.",
        "//go:build snaplink_configured",
        "",
        "package servermodules",
        "",
    ]
    if unique_imports:
        lines.append("import (")
        lines.extend(f'\t{alias} "{path}"' for alias, path in unique_imports)
        lines.extend([")", ""])
    lines.append("func Register() {")
    lines.extend(calls)
    lines.extend(["}", ""])
    return "\n".join(lines)


def _write_overlay(plan: Plan, out_dir: Path) -> tuple[Path, Path]:
    generated = out_dir / "register_configured.go"
    generated.write_text(render_registration(plan), encoding="utf-8")
    _run(["gofmt", "-w", str(generated)])
    overlay = out_dir / "overlay.json"
    payload = {"Replace": {str(OVERLAY_TARGET): str(generated.resolve())}}
    overlay.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return generated, overlay


def _prepare_published_overlay(staging: Path, out_dir: Path) -> None:
    overlay = staging / "overlay.json"
    payload = {
        "Replace": {
            str(OVERLAY_TARGET): str((out_dir / "register_configured.go").resolve())
        }
    }
    overlay.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _copy_root_module(out_dir: Path) -> tuple[Path, Path]:
    modfile = out_dir / "modules.mod"
    sumfile = out_dir / "modules.sum"
    shutil.copyfile(ROOT / "go.mod", modfile)
    shutil.copyfile(ROOT / "go.sum", sumfile)
    return modfile, sumfile


def _materialize_module_requirements(plan: Plan, modfile: Path) -> None:
    for module in plan.modules:
        module_path = module.data.get("module_path")
        if not module_path:
            continue
        version = module.data.get("version", "v0.0.0")
        _run(
            [
                "go",
                "mod",
                "edit",
                f"-modfile={modfile}",
                f"-require={module_path}@{version}",
            ]
        )
        source = module.source_dir
        if source:
            try:
                source_ref = Path(os.path.relpath(source, start=ROOT)).as_posix()
                if not source_ref.startswith("."):
                    source_ref = "./" + source_ref
            except ValueError as exc:
                raise BuildModulesError(
                    f"local module {module.id} and the repository must share a volume"
                ) from exc
            _run(
                [
                    "go",
                    "mod",
                    "edit",
                    f"-modfile={modfile}",
                    f"-replace={module_path}@{version}={source_ref}",
                ]
            )


def _go_env(target: str | None) -> tuple[str, str, str]:
    values = _run(["go", "env", "GOVERSION", "GOOS", "GOARCH"]).splitlines()
    if len(values) != 3:
        raise BuildModulesError("go env returned an unexpected result")
    go_version, default_os, default_arch = values
    if not target:
        return go_version, default_os, default_arch
    parts = target.split("/")
    if len(parts) != 2 or not all(parts):
        raise BuildModulesError("--target must be GOOS/GOARCH")
    return go_version, parts[0], parts[1]


def _validate_target(plan: Plan, goos: str, goarch: str) -> None:
    for module in plan.modules:
        targets = module.data.get("targets", {})
        if targets.get("goos") and goos not in targets["goos"]:
            raise BuildModulesError(f"module {module.id} does not support GOOS={goos}")
        if targets.get("goarch") and goarch not in targets["goarch"]:
            raise BuildModulesError(
                f"module {module.id} does not support GOARCH={goarch}"
            )


def _go_build_environment(env: dict[str, str]) -> dict[str, str]:
    values = json.loads(_run(["go", "env", "-json", *GO_ENV_KEYS], env=env))
    result = {key: str(values.get(key, "")) for key in GO_ENV_KEYS}
    if result["CGO_ENABLED"] == "1":
        cgo_values = json.loads(_run(["go", "env", "-json", *CGO_ENV_KEYS], env=env))
        result.update({key: str(cgo_values.get(key, "")) for key in CGO_ENV_KEYS})
    return result


def _go_flags(
    modfile: Path,
    overlay: Path,
    mod_mode: str,
) -> list[str]:
    return [
        f"-mod={mod_mode}",
        f"-modfile={modfile}",
        f"-overlay={overlay}",
        "-tags=snaplink_configured",
    ]


def _resolve_go_graph(
    modfile: Path,
    overlay: Path,
    env: dict[str, str],
    package: str,
) -> tuple[list[dict], list[dict]]:
    package_output = _run(
        [
            "go",
            "list",
            "-deps",
            "-json",
            *_go_flags(modfile, overlay, "mod"),
            package,
        ],
        env=env,
    )
    _run(["go", "mod", "verify", f"-modfile={modfile}"], env=env)
    output = _run(
        [
            "go",
            "list",
            "-m",
            "-json",
            *_go_flags(modfile, overlay, "readonly"),
            "all",
        ],
        env=env,
    )
    return _decode_json_stream(output), _decode_json_stream(package_output)


def _list_go_packages(
    modfile: Path,
    overlay: Path,
    env: dict[str, str],
    package: str,
) -> list[dict]:
    output = _run(
        [
            "go",
            "list",
            "-deps",
            "-json",
            *_go_flags(modfile, overlay, "readonly"),
            package,
        ],
        env=env,
    )
    return _decode_json_stream(output)


def _decode_json_stream(content: str) -> list[dict]:
    decoder = json.JSONDecoder()
    index = 0
    values: list[dict] = []
    while index < len(content):
        while index < len(content) and content[index].isspace():
            index += 1
        if index >= len(content):
            break
        value, index = decoder.raw_decode(content, index)
        values.append(value)
    return values


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _local_source_ref(path: Path) -> str:
    root = path.resolve()
    if not root.is_dir():
        raise BuildModulesError(f"local module source is not a directory: {root}")
    records: list[dict[str, str]] = []
    skipped = {".git", ".hg", ".svn"}
    for current, directories, files in os.walk(root, followlinks=False):
        base = Path(current)
        retained: list[str] = []
        for name in sorted(directories):
            candidate = base / name
            if name in skipped:
                continue
            if candidate.is_symlink():
                records.append(
                    {
                        "type": "symlink-directory",
                        "path": candidate.relative_to(root).as_posix(),
                        "target_digest": _content_digest(
                            os.readlink(candidate).encode()
                        ),
                    }
                )
                continue
            retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            candidate = base / name
            record = {
                "type": "symlink-file" if candidate.is_symlink() else "file",
                "path": candidate.relative_to(root).as_posix(),
                "content_digest": _content_digest(candidate.read_bytes()),
            }
            if candidate.is_symlink():
                record["target_digest"] = _content_digest(
                    os.readlink(candidate).encode()
                )
            records.append(record)
    return "local:" + _json_digest(records)


def _content_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _json_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _overlay_map(overlay: Path) -> dict[Path, Path]:
    payload = json.loads(overlay.read_text(encoding="utf-8"))
    return {
        Path(target).absolute(): Path(source).resolve()
        for target, source in payload.get("Replace", {}).items()
    }


def _local_module_path(package: dict) -> str | None:
    module = package.get("Module")
    if not isinstance(module, dict):
        return None
    if module.get("Main"):
        return module.get("Path")
    replacement = module.get("Replace")
    if isinstance(replacement, dict) and replacement.get("Dir"):
        return module.get("Path")
    return None


def _build_input_digests(
    packages: list[dict],
    overlay: Path,
) -> tuple[str, dict[str, str]]:
    replacements = _overlay_map(overlay)
    by_module: dict[str, list[dict[str, str]]] = {}
    all_records: list[dict[str, str]] = []
    module_roots: dict[str, Path] = {}
    for package in packages:
        module_path = _local_module_path(package)
        directory = package.get("Dir")
        import_path = package.get("ImportPath")
        if not module_path or not directory or not import_path:
            continue
        module = package["Module"]
        if module.get("Main"):
            module_roots[module_path] = ROOT
        else:
            module_roots[module_path] = Path(module["Replace"]["Dir"]).resolve()
        for field in SOURCE_FILE_FIELDS:
            for filename in package.get(field, ()):
                logical = Path(directory) / filename
                source = replacements.get(logical.absolute(), logical)
                if not source.is_file():
                    raise BuildModulesError(
                        f"go list reported missing build input "
                        f"{import_path}:{filename}"
                    )
                record = {
                    "module": module_path,
                    "package": import_path,
                    "kind": field,
                    "path": Path(filename).as_posix(),
                    "digest": _content_digest(source.read_bytes()),
                }
                by_module.setdefault(module_path, []).append(record)
                all_records.append(record)
    for module_path, module_root in sorted(module_roots.items()):
        for filename in ("go.mod", "go.sum"):
            source = module_root / filename
            if not source.is_file():
                continue
            record = {
                "module": module_path,
                "package": "@module",
                "kind": "ModuleFile",
                "path": filename,
                "digest": _content_digest(source.read_bytes()),
            }
            by_module.setdefault(module_path, []).append(record)
            all_records.append(record)
    module_digests = {
        module: _json_digest(sorted(records, key=_record_key))
        for module, records in by_module.items()
    }
    return _json_digest(sorted(all_records, key=_record_key)), module_digests


def _record_key(record: dict[str, str]) -> tuple[str, ...]:
    return tuple(record.get(key, "") for key in sorted(record))


def _normalize_go_module(
    item: dict,
    source_digests: dict[str, str] | None = None,
) -> dict:
    normalized = {
        "path": item["Path"],
        "version": item.get("Version", ""),
        "go_version": item.get("GoVersion", ""),
        "sum": item.get("Sum", ""),
        "go_mod_sum": item.get("GoModSum", ""),
    }
    replacement = item.get("Replace")
    if replacement:
        if replacement.get("Dir"):
            digest = (source_digests or {}).get(item["Path"])
            repl = {"local": digest or _local_source_ref(Path(replacement["Dir"]))}
        else:
            repl = {
                "path": replacement.get("Path", ""),
                "version": replacement.get("Version", ""),
                "sum": replacement.get("Sum", ""),
            }
        normalized["replace"] = repl
    return normalized


def _git_state() -> tuple[str, bool]:
    revision = _run(["git", "rev-parse", "HEAD"]).strip()
    dirty = bool(_run(["git", "status", "--porcelain"]).strip())
    return revision, dirty


def _build_timestamp() -> str:
    source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_epoch is None:
        instant = datetime.datetime.now(datetime.timezone.utc)
    else:
        try:
            instant = datetime.datetime.fromtimestamp(
                int(source_epoch),
                datetime.timezone.utc,
            )
        except (OverflowError, OSError, ValueError) as exc:
            raise BuildModulesError(
                "SOURCE_DATE_EPOCH must be a valid Unix timestamp"
            ) from exc
    return instant.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _lock_modules(
    plan: Plan,
    source_digests: dict[str, str],
) -> list[dict]:
    modules: list[dict] = []
    for module in plan.modules:
        source = None
        if module.source_dir:
            source = source_digests.get(module.data.get("module_path", ""))
            if not source:
                source = _local_source_ref(module.source_dir)
        modules.append(
            {
                "id": module.id,
                "state": module.state,
                "activation": module.data["activation"],
                "module_path": module.data.get("module_path", ""),
                "version": module.data.get("version", ""),
                "source": source,
                "manifest_digest": module.digest,
                "provides": list(module.provides),
                "requires": list(module.requires),
            }
        )
    return modules


def _lock_payload(
    plan: Plan,
    go_modules: list[dict],
    build_input_digest: str,
    source_digests: dict[str, str],
    go_environment: dict[str, str],
    build_version: str,
) -> dict:
    revision, dirty = _git_state()
    return {
        "schema_version": 1,
        "profile": plan.profile.id,
        "host_api": plan.catalog.host_api,
        "catalog_digest": plan.catalog.digest,
        "profile_digest": plan.profile.digest,
        "core": {
            "module_path": "github.com/yangwb1123/snaplink",
            "revision": revision,
            "dirty": dirty,
            "source_digest": source_digests.get(ROOT_MODULE_PATH, ""),
        },
        "target": {
            "go_env": go_environment,
            "tags": ["snaplink_configured"],
            "package": plan.profile.build_package,
            "binary": plan.profile.binary_name,
            "program": plan.profile.program_name,
            "version": build_version,
        },
        "build_input_digest": build_input_digest,
        "modules": _lock_modules(plan, source_digests),
        "go_modules": sorted(
            (_normalize_go_module(item, source_digests) for item in go_modules),
            key=lambda item: item["path"],
        ),
    }


def _write_lock(payload: dict, out_dir: Path) -> tuple[Path, str]:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    lock = dict(payload)
    lock["lock_digest"] = digest
    path = out_dir / "modules.lock.json"
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, digest


def _build_ldflags(
    plan: Plan,
    lock_digest: str,
    build_version: str,
    build_time: str,
    git_hash: str,
    dirty: bool,
) -> str:
    modules = ",".join(module.id for module in plan.modules)
    capabilities = ",".join(
        sorted(
            {
                capability
                for module in plan.modules
                for capability in module.provides
            }
        )
    )
    values = {
        f"{BUILDINFO_IMPORT}.BuildProfile": plan.profile.id,
        f"{BUILDINFO_IMPORT}.ModuleLockDigest": lock_digest,
        f"{BUILDINFO_IMPORT}.CompiledModules": modules,
        f"{BUILDINFO_IMPORT}.CompiledCapabilities": capabilities,
        f"{BUILDINFO_IMPORT}.Version": build_version,
        f"{CORE_BUILDINFO_IMPORT}.BuildVersion": build_version,
        f"{CORE_BUILDINFO_IMPORT}.BuildTime": build_time,
        f"{CORE_BUILDINFO_IMPORT}.GitHash": git_hash,
        f"{CORE_BUILDINFO_IMPORT}.BuildModified": str(dirty).lower(),
    }
    return " ".join(f"-X {name}={value}" for name, value in values.items())


def _build_binary(
    plan: Plan,
    modfile: Path,
    overlay: Path,
    binary: Path,
    lock_digest: str,
    build_input_digest: str,
    env: dict[str, str],
    build_version: str,
    build_time: str,
    git_hash: str,
    dirty: bool,
) -> None:
    binary.parent.mkdir(parents=True, exist_ok=True)
    args = [
        "go",
        "build",
        "-trimpath",
        "-buildvcs=true",
        *_go_flags(modfile, overlay, "readonly"),
        "-ldflags",
        _build_ldflags(
            plan,
            lock_digest,
            build_version,
            build_time,
            git_hash,
            dirty,
        ),
        "-o",
        str(binary),
        plan.profile.build_package,
    ]
    _run(args, env=env, capture=False)
    post_packages = _list_go_packages(
        modfile, overlay, env, plan.profile.build_package
    )
    post_digest, _ = _build_input_digests(post_packages, overlay)
    if post_digest != build_input_digest:
        raise BuildModulesError("build inputs changed during compilation")
    metadata = _run(["go", "version", "-m", str(binary)])
    linked = _binary_module_paths(metadata)
    selected = {
        module.data["module_path"]
        for module in plan.modules
        if module.data.get("module_path")
    }
    known = {
        module.data["module_path"]
        for module in plan.catalog.modules.values()
        if module.data.get("module_path")
    }
    for module_path in sorted(selected):
        if module_path not in linked:
            raise BuildModulesError(
                f"built binary does not contain selected module {module_path}"
            )
    unexpected = sorted((known - selected) & linked)
    if unexpected:
        raise BuildModulesError(
            "built binary contains unselected modules: " + ", ".join(unexpected)
        )
    if _is_native_target(env):
        _verify_binary_inventory(plan, binary, lock_digest, env)
        _verify_binary_version(
            plan,
            binary,
            build_version,
            build_time,
            git_hash,
            dirty,
            env,
        )


def _binary_module_paths(metadata: str) -> set[str]:
    paths: set[str] = set()
    for line in metadata.splitlines():
        fields = line.split("\t")
        if len(fields) >= 3 and fields[1] == "dep":
            paths.add(fields[2])
    return paths


def _is_native_target(env: dict[str, str]) -> bool:
    host = _run(["go", "env", "GOHOSTOS", "GOHOSTARCH"]).splitlines()
    return len(host) == 2 and host == [env["GOOS"], env["GOARCH"]]


def _verify_binary_inventory(
    plan: Plan,
    binary: Path,
    lock_digest: str,
    env: dict[str, str],
) -> None:
    try:
        inventory = json.loads(_run([str(binary), "modules", "--json"], env=env))
    except json.JSONDecodeError as exc:
        raise BuildModulesError(
            "built binary returned invalid module inventory"
        ) from exc
    expected = {
        "program": plan.profile.program_name,
        "profile": plan.profile.id,
        "lock_digest": lock_digest,
        "modules": [module.id for module in plan.modules],
        "capabilities": sorted(
            {
                capability
                for module in plan.modules
                for capability in module.provides
            }
        ),
    }
    if inventory != expected:
        raise BuildModulesError(
            "built binary module inventory does not match the generated lock"
        )


def _expected_version_line(plan: Plan, build_version: str) -> str:
    if plan.profile.id in EDITION_PROFILES:
        return f"snaplink-{build_version}.{plan.profile.id}"
    return f"{plan.profile.program_name} {build_version}"


def _verify_binary_version(
    plan: Plan,
    binary: Path,
    build_version: str,
    build_time: str,
    git_hash: str,
    dirty: bool,
    env: dict[str, str],
) -> None:
    lines = _run([str(binary), "version"], env=env).splitlines()
    modified = " (modified)" if dirty else ""
    expected = [
        _expected_version_line(plan, build_version),
        f"  build time: {build_time}",
        f"  git hash:   {git_hash}{modified}",
    ]
    if lines[:3] != expected:
        actual = lines[:3] if lines else ["<empty>"]
        raise BuildModulesError(
            f"built binary version mismatch: expected {expected!r}, got {actual!r}"
        )


def _smoke_profile_ids() -> tuple[str, ...]:
    return tuple(
        sorted(set(supported_profile_ids()) | set(buildable_profile_ids()))
    )


def _publish_output(staging: Path, out_dir: Path) -> None:
    _prepare_published_overlay(staging, out_dir)
    backup = out_dir.parent / (f".{out_dir.name}.previous-{uuid.uuid4().hex}")
    moved_existing = False
    try:
        if out_dir.exists():
            os.replace(out_dir, backup)
            moved_existing = True
        os.replace(staging, out_dir)
    except Exception:
        if moved_existing and backup.exists() and not out_dir.exists():
            os.replace(backup, out_dir)
        raise
    if moved_existing:
        shutil.rmtree(backup, ignore_errors=True)


def _staging_dir(out_dir: Path) -> Path:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{out_dir.name}.staging-",
            dir=out_dir.parent,
        )
    )
    mode = out_dir.stat().st_mode & 0o777 if out_dir.exists() else 0o755
    staging.chmod(mode)
    return staging


def _configure_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python cli.py configure")
    parser.add_argument("--profile", default="standard")
    parser.add_argument("--with-module", action="append", default=[])
    parser.add_argument("--without-module", action="append", default=[])
    parser.add_argument("--add-module", action="append", default=[])
    parser.add_argument("--target", help="GOOS/GOARCH; defaults to go env")
    parser.add_argument(
        "--version",
        default=DEFAULT_BUILD_VERSION,
        type=_build_version,
        help=f"release version to embed (default: {DEFAULT_BUILD_VERSION})",
    )
    parser.add_argument("--out", type=Path)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--output-binary", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def configure(argv: list[str]) -> int:
    args = _configure_parser().parse_args(argv)
    plan = resolve_plan(
        args.profile,
        args.with_module,
        args.without_module,
        args.add_module,
    )
    print(format_plan(plan))
    if args.dry_run:
        return 0
    if not plan.buildable:
        raise BuildModulesError(
            "profile is not buildable:\n  " + "\n  ".join(plan.blockers)
        )
    _, goos, goarch = _go_env(args.target)
    _validate_target(plan, goos, goarch)
    cgo_enabled = any(
        module.data.get("targets", {}).get("cgo", False) for module in plan.modules
    )
    out_dir = (args.out or DEFAULT_OUT_ROOT / plan.profile.id).resolve()
    _validate_output_dir(out_dir)
    _validate_owned_output(out_dir)
    binary_relative = Path(plan.profile.binary_name)
    if args.output_binary:
        requested_binary = args.output_binary.resolve()
        try:
            binary_relative = requested_binary.relative_to(out_dir)
        except ValueError as exc:
            raise BuildModulesError(
                "--output-binary must be inside the profile --out directory"
            ) from exc
    staging = _staging_dir(out_dir)
    env = os.environ.copy()
    env.update(
        {
            "CGO_ENABLED": "1" if cgo_enabled else "0",
            "GOOS": goos,
            "GOARCH": goarch,
            "GOFLAGS": "",
            "GOWORK": "off",
        }
    )
    try:
        (staging / OUTPUT_MARKER).write_text("v1\n", encoding="utf-8")
        _, overlay = _write_overlay(plan, staging)
        modfile, _ = _copy_root_module(staging)
        _materialize_module_requirements(plan, modfile)
        go_modules, packages = _resolve_go_graph(
            modfile, overlay, env, plan.profile.build_package
        )
        build_input_digest, source_digests = _build_input_digests(packages, overlay)
        payload = _lock_payload(
            plan,
            go_modules,
            build_input_digest,
            source_digests,
            _go_build_environment(env),
            args.version,
        )
        _, lock_digest = _write_lock(payload, staging)
        if args.build:
            build_time = _build_timestamp()
            _build_binary(
                plan,
                modfile,
                overlay,
                staging / binary_relative,
                lock_digest,
                build_input_digest,
                env,
                args.version,
                build_time,
                payload["core"]["revision"],
                payload["core"]["dirty"],
            )
        _publish_output(staging, out_dir)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    lock_path = out_dir / "modules.lock.json"
    print(f"lock: {_display_path(lock_path)}")
    print(f"digest: {lock_digest}")
    if args.build:
        print(f"binary: {_display_path(out_dir / binary_relative)}")
    return 0


def _modules_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python cli.py modules")
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("check")
    subparsers.add_parser("smoke")
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--add-module", action="append", default=[])
    for name in ("plan", "graph", "why"):
        child = subparsers.add_parser(name)
        child.add_argument("--profile", default="standard")
        child.add_argument("--with-module", action="append", default=[])
        child.add_argument("--without-module", action="append", default=[])
        child.add_argument("--add-module", action="append", default=[])
        if name == "why":
            child.add_argument("module")
    return parser


def modules(argv: list[str]) -> int:
    args = _modules_parser().parse_args(argv)
    if args.action == "check":
        for checked in validate_repository():
            print(f"OK: {checked}")
        return 0
    if args.action == "smoke":
        for profile in _smoke_profile_ids():
            configure(["--profile", profile, "--build"])
        return 0
    if args.action == "list":
        print(format_catalog(load_catalog(args.add_module)))
        return 0
    plan = resolve_plan(
        args.profile,
        args.with_module,
        args.without_module,
        args.add_module,
    )
    if args.action == "plan":
        print(format_plan(plan))
    elif args.action == "graph":
        print("\n".join(graph_lines(plan)))
    else:
        print(" -> ".join(why_lines(plan, args.module)))
    return 0


def _run_with_errors(handler, argv: list[str]) -> int:
    try:
        return handler(argv)
    except (ModuleConfigError, BuildModulesError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def run_configure(argv: list[str] | None = None) -> int:
    return _run_with_errors(configure, list(argv or []))


def run_modules(argv: list[str] | None = None) -> int:
    return _run_with_errors(modules, list(argv or []))


if __name__ == "__main__":
    sys.exit(run_configure(sys.argv[1:]))
