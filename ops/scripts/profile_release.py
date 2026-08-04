#!/usr/bin/env python3
"""Prepare and verify target-specific prototype/minimal release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from module_catalog import ROOT, load_catalog


PROFILES = ("prototype", "minimal", "full", "billing")
TARGETS = (
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
)
PROFILE_TARGETS = {
    "prototype": TARGETS,
    "minimal": TARGETS,
    "full": TARGETS[:4],
    "billing": TARGETS[:2],
}
ENV_ROOT = "SNAPLINK_PROFILE_RELEASE_ROOT"
ENV_VERSION = "SNAPLINK_PROFILE_RELEASE_VERSION"
ENV_SNAPSHOT_VERSION = "SNAPLINK_PROFILE_RELEASE_SNAPSHOT_VERSION"


class ProfileReleaseError(RuntimeError):
    """A release profile could not be prepared or verified."""


def _run(args: list[str], *, capture: bool = True) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=capture,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ProfileReleaseError(f"{' '.join(args)} failed: {detail}")
    return result.stdout if capture else ""


def _target_key(target: str) -> str:
    return target.replace("/", "_")


def _env_key(profile: str, target: str) -> str:
    suffix = target.replace("/", "_").upper()
    return f"SNAPLINK_RELEASE_{profile.upper()}_{suffix}_LOCK_DIGEST"


def _profile_env_key(profile: str, field: str) -> str:
    return f"SNAPLINK_RELEASE_{profile.upper()}_{field}"


def _output_dir(root: Path, profile: str, target: str) -> Path:
    return root / profile / _target_key(target)


def _configure(profile: str, target: str, version: str, output: Path) -> None:
    _run(
        [
            sys.executable,
            "cli.py",
            "configure",
            "--profile",
            profile,
            "--target",
            target,
            "--version",
            version,
            "--out",
            str(output),
        ],
        capture=False,
    )


def _read_lock(path: Path, profile: str, target: str, version: str) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    go_env = lock.get("target", {}).get("go_env", {})
    actual_target = f"{go_env.get('GOOS', '')}/{go_env.get('GOARCH', '')}"
    if lock.get("profile") != profile or actual_target != target:
        raise ProfileReleaseError(f"{path}: profile or target mismatch")
    if lock.get("target", {}).get("version") != version:
        raise ProfileReleaseError(f"{path}: version mismatch")
    if not str(lock.get("lock_digest", "")).startswith("sha256:"):
        raise ProfileReleaseError(f"{path}: missing canonical lock digest")
    return lock


def _inventory(lock: dict) -> dict:
    modules = lock["modules"]
    return {
        "program": lock["target"]["program"],
        "profile": lock["profile"],
        "lock_digest": lock["lock_digest"],
        "modules": [module["id"] for module in modules],
        "capabilities": sorted(
            {capability for module in modules for capability in module["provides"]}
        ),
    }


def _write_inventory(output: Path, inventory: dict) -> None:
    path = output / "profile-inventory.json"
    path.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    for key, value in values.items():
        if "\n" in value or "\r" in value:
            raise ProfileReleaseError(f"{key} contains a newline")
    content = "".join(f"{key}={value}\n" for key, value in sorted(values.items()))
    path.write_text(content, encoding="utf-8")


def prepare(
    version: str,
    output_root: Path,
    env_file: Path,
    profiles: tuple[str, ...],
    targets: tuple[str, ...] | None,
) -> None:
    root = output_root.resolve()
    try:
        root.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise ProfileReleaseError("release evidence must survive outside repository dist/")
    values = {
        ENV_ROOT: str(root),
        ENV_VERSION: version,
        ENV_SNAPSHOT_VERSION: version.removeprefix("v"),
    }
    for profile in profiles:
        profile_targets = targets or PROFILE_TARGETS[profile]
        unsupported = sorted(set(profile_targets) - set(PROFILE_TARGETS[profile]))
        if unsupported:
            raise ProfileReleaseError(
                f"{profile}: unsupported release targets: {unsupported}"
            )
        canonical: dict | None = None
        for target in profile_targets:
            output = _output_dir(root, profile, target)
            _configure(profile, target, version, output)
            lock = _read_lock(output / "modules.lock.json", profile, target, version)
            inventory = _inventory(lock)
            _write_inventory(output, inventory)
            canonical = canonical or inventory
            if inventory["modules"] != canonical["modules"]:
                raise ProfileReleaseError(f"{profile}: target module inventory drift")
            if inventory["capabilities"] != canonical["capabilities"]:
                raise ProfileReleaseError(f"{profile}: target capability inventory drift")
            values[_env_key(profile, target)] = lock["lock_digest"]
        values[_profile_env_key(profile, "MODULES")] = ",".join(canonical["modules"])
        values[_profile_env_key(profile, "CAPABILITIES")] = ",".join(
            canonical["capabilities"]
        )
    _write_env(env_file.resolve(), values)


def _build_settings(binary: Path) -> tuple[set[str], dict[str, str]]:
    metadata = _run(["go", "version", "-m", str(binary)])
    modules: set[str] = set()
    settings: dict[str, str] = {}
    for line in metadata.splitlines():
        fields = line.split("\t")
        if len(fields) >= 3 and fields[1] == "dep":
            modules.add(fields[2])
        if len(fields) >= 3 and fields[1] == "build" and "=" in fields[2]:
            key, value = fields[2].split("=", 1)
            settings[key] = value
    return modules, settings


def _verify_linked_modules(linked: set[str], lock: dict) -> None:
    selected = {
        module["module_path"] for module in lock["modules"] if module["module_path"]
    }
    known = {
        module.data["module_path"]
        for module in load_catalog().modules.values()
        if module.data.get("module_path")
    }
    missing = sorted(selected - linked)
    unexpected = sorted((known - selected) & linked)
    if missing or unexpected:
        raise ProfileReleaseError(
            f"module linkage mismatch: missing={missing}, unexpected={unexpected}"
        )


def _verify_embedded_values(binary: Path, inventory: dict) -> None:
    content = binary.read_bytes()
    values = (
        inventory["profile"],
        inventory["lock_digest"],
        ",".join(inventory["modules"]),
        ",".join(inventory["capabilities"]),
        inventory.get("version", ""),
    )
    missing = [value for value in values if value and value.encode() not in content]
    if missing:
        raise ProfileReleaseError(f"binary is missing embedded profile values: {missing}")


def _verify_native_inventory(binary: Path, target: str, expected: dict) -> bool:
    host = _run(["go", "env", "GOHOSTOS", "GOHOSTARCH"]).splitlines()
    if target != "/".join(host):
        return False
    actual = json.loads(_run([str(binary), "modules", "--json"]))
    if actual != expected:
        raise ProfileReleaseError("native binary inventory does not match release lock")
    return True


def verify_binary(
    profile: str,
    target: str,
    binary: Path,
    root: Path,
    archive_root: Path,
) -> None:
    output = _output_dir(root.resolve(), profile, target)
    lock_path = output / "modules.lock.json"
    raw_lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock = _read_lock(
        lock_path,
        profile,
        target,
        raw_lock["target"]["version"],
    )
    inventory = _inventory(lock)
    embedded = dict(inventory, version=lock["target"]["version"])
    linked, settings = _build_settings(binary.resolve())
    actual_target = f"{settings.get('GOOS', '')}/{settings.get('GOARCH', '')}"
    if actual_target != target or settings.get("-tags") != "snaplink_configured":
        raise ProfileReleaseError("binary build target or configured tag mismatch")
    _verify_linked_modules(linked, lock)
    _verify_embedded_values(binary, embedded)
    native = _verify_native_inventory(binary.resolve(), target, inventory)
    verified = [
        "target_build_info",
        "configured_build_tag",
        "embedded_profile_lock_and_inventory",
        "selected_external_module_linkage",
    ]
    if native:
        verified.append("native_modules_command")
    evidence = {
        "schema_version": 1,
        "profile": profile,
        "target": target,
        "lock_digest": lock["lock_digest"],
        "binary_sha256": "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest(),
        "verified": verified,
        "not_claimed": ["complete_package_level_physical_dependency_isolation"],
    }
    content = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    (output / "binary-evidence.json").write_text(content, encoding="utf-8")
    resolved_archive_root = archive_root.resolve()
    try:
        resolved_archive_root.relative_to(ROOT / "dist")
    except ValueError as exc:
        raise ProfileReleaseError("archive evidence must be staged under dist/") from exc
    archive_output = _output_dir(resolved_archive_root, profile, target)
    archive_output.mkdir(parents=True, exist_ok=True)
    for name in ("modules.lock.json", "profile-inventory.json"):
        shutil.copyfile(output / name, archive_output / name)
    (archive_output / "binary-evidence.json").write_text(content, encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="profile_release.py")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--version", required=True)
    prepare_parser.add_argument("--output-root", type=Path, required=True)
    prepare_parser.add_argument("--env-file", type=Path, required=True)
    prepare_parser.add_argument("--profile", action="append", choices=PROFILES)
    prepare_parser.add_argument("--target", action="append", choices=TARGETS)
    verify = commands.add_parser("verify-binary")
    verify.add_argument("--profile", required=True, choices=PROFILES)
    verify.add_argument("--target", required=True, choices=TARGETS)
    verify.add_argument("--binary", type=Path, required=True)
    verify.add_argument("--evidence-root", type=Path, required=True)
    verify.add_argument("--archive-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            prepare(
                args.version,
                args.output_root,
                args.env_file,
                tuple(args.profile or PROFILES),
                tuple(args.target) if args.target else None,
            )
        else:
            verify_binary(
                args.profile,
                args.target,
                args.binary,
                args.evidence_root,
                args.archive_root,
            )
    except (OSError, ValueError, json.JSONDecodeError, ProfileReleaseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
