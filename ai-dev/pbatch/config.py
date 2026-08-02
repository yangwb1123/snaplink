"""Declarative configuration for pi-batch: pi-batch.yaml resolution,
agent defaults, session flags, and the named validator registry."""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pi-batch")

def _find_batch_config() -> Optional[dict]:
    """Locate and parse pi-batch.yaml: the entry script directory
    (PBATCH_SCRIPT_DIR, set by the pi-batch.py shim) wins, then the package
    directory, then the process working directory. None when absent."""
    if not yaml:
        return None
    candidates = []
    script_dir = os.environ.get("PBATCH_SCRIPT_DIR", "")
    if script_dir:
        candidates.append(Path(script_dir) / "pi-batch.yaml")
    candidates.append(Path(__file__).resolve().parent / "pi-batch.yaml")
    candidates.append(Path("pi-batch.yaml"))
    for p in candidates:
        if not p.exists():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            return data
    return None


def _find_sidecar(name: str) -> Optional[dict]:
    """Locate and parse a sidecar YAML (e.g. role_keywords.yaml) next to the
    entry script, the package dir, or the cwd; None when absent."""
    if not yaml:
        return None
    candidates = []
    script_dir = os.environ.get("PBATCH_SCRIPT_DIR", "")
    if script_dir:
        candidates.append(Path(script_dir) / name)
    candidates.append(Path(__file__).resolve().parent / name)
    candidates.append(Path(__file__).resolve().parent.parent / name)  # ai-dev/ next to pbatch/
    candidates.append(Path(name))
    for p in candidates:
        if not p.exists():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            return data
    return None


def _load_role_keywords() -> dict:
    """Role -> keyword list for meta-stage relevance scoring. Empty when the
    sidecar is absent (orchestration then falls back to the plain role
    list, i.e. the pre-scoring behavior)."""
    data = _find_sidecar("role_keywords.yaml") or {}
    return {k: v for k, v in data.items() if isinstance(v, list) and v}


ROLE_KEYWORDS = _load_role_keywords()


def _load_batch_config(path: str = "pi-batch.yaml") -> dict:
    """Optional defaults for pi-batch. Missing file -> {} (built-in defaults
    below apply), so the tool still runs standalone with zero config -- copy
    pi-batch.yaml alongside pi-batch.py to point it at a different agent
    CLI."""
    data = _find_batch_config()
    return data if data is not None else {}


_BATCH_CFG = _load_batch_config()


_AGENT_CFG = _BATCH_CFG.get("agent", {})


AGENT_BIN = _AGENT_CFG.get("bin", "pi")


AGENT_DEFAULT_MODEL = _AGENT_CFG.get("default_model", "")


AGENT_DEFAULT_TIMEOUT = _AGENT_CFG.get("default_timeout", 900)


AGENT_DEFAULT_WORKERS = _AGENT_CFG.get("default_workers", 4)


COMMIT_PREFIX_DEFAULT = _BATCH_CFG.get("commit", {}).get("prefix", "[pi-batch]")


_DEFAULT_SESSION_FLAGS = {
    "start": ["--session-id", "{session}", "--name", "{name}"],
    "continue": ["--session-id", "{session}"],
}


def _session_flags(key: str, session_id: str, session_name: str) -> list:
    """Resolve the configured session flags for a call (start or continue),
    replacing {session} and {name} placeholders. Falls back to pi-style
    flags when the config does not define agent.session_flags."""
    cfg = (_AGENT_CFG.get("session_flags") or {}) if isinstance(_AGENT_CFG.get("session_flags"), dict) else {}
    flags = cfg.get(key) or _DEFAULT_SESSION_FLAGS[key]
    return [f.replace("{session}", session_id).replace("{name}", session_name) for f in flags]


def _load_validators() -> dict:
    """Read the named validators registry from pi-batch.yaml (like the
    project's engineering.yaml declares gates for cli.py); empty when absent
    so the script stays portable."""
    data = _find_batch_config()
    if not data:
        return {}
    v = data.get("validators")
    return dict(v) if isinstance(v, dict) else {}


VALIDATORS = _load_validators()


def _resolve_validators(value: str) -> list:
    """Expand a comma-separated list into validation commands: registry names
    are replaced by their pi-batch.yaml command, anything else is used as a
    raw shell command. Empty value -> no validation."""
    out = []
    for item in [x.strip() for x in (value or "").split(",") if x.strip()]:
        out.append(VALIDATORS.get(item, item))
    return out
