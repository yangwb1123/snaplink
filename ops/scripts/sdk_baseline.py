#!/usr/bin/env python3
"""Local, non-networked baseline readers for the SDK-surface diff."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable


REGISTRY_PATH = Path("ops/build/sdk-surface.json")
OPENAPI_PATH = Path("docs/openapi.yaml")


class SDKBaselineError(Exception):
    """Raised when a local git baseline cannot be read safely."""


def _run_git(args: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SDKBaselineError("cannot run git for SDK-surface baseline") from exc


def _resolve_ref(ref: str, root: Path) -> str:
    if not ref or not ref.strip():
        raise SDKBaselineError("baseline git ref must not be empty")
    result = _run_git(
        ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}"],
        root,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise SDKBaselineError(f"baseline git ref {ref!r} is invalid")
    return result.stdout.strip()


def _read_file(object_name: str, path: Path, source: str, root: Path) -> str:
    result = _run_git(["show", "--no-ext-diff", "--format=", f"{object_name}:{path}"], root)
    if result.returncode != 0:
        raise SDKBaselineError(f"{source} does not contain {path.as_posix()}")
    return result.stdout


def _parse_registry(text: str, source: str, validator: Callable[[object, str], dict]) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SDKBaselineError(f"{source}: invalid JSON: {exc}") from exc
    try:
        return validator(value, source)
    except Exception as exc:
        raise SDKBaselineError(f"{source}: invalid registry: {exc}") from exc


def load_registry_ref(
    ref: str, root: Path, validator: Callable[[object, str], dict]
) -> dict:
    """Load and validate only the registry at a local commit."""
    object_name = _resolve_ref(ref, root)
    source = f"baseline git ref {ref!r}"
    text = _read_file(object_name, REGISTRY_PATH, source, root)
    return _parse_registry(text, source, validator)


def load_ref_bundle(
    ref: str,
    root: Path,
    registry_validator: Callable[[object, str], dict],
    openapi_loader: Callable[[str, str], dict],
) -> tuple[dict, dict]:
    """Load registry and OpenAPI from one resolved local commit."""
    object_name = _resolve_ref(ref, root)
    source = f"baseline git ref {ref!r}"
    registry_text = _read_file(object_name, REGISTRY_PATH, source, root)
    openapi_text = _read_file(object_name, OPENAPI_PATH, source, root)
    registry = _parse_registry(registry_text, source, registry_validator)
    try:
        openapi = openapi_loader(openapi_text, f"{source} {OPENAPI_PATH}")
    except Exception as exc:
        raise SDKBaselineError(
            f"{source} {OPENAPI_PATH}: invalid OpenAPI: {exc}"
        ) from exc
    return registry, openapi
