#!/usr/bin/env python3
"""Declarative config loader for the checks/ engineering harness.

Loads engineering.yaml once and exposes it as typed sections. A project
reusing this harness edits engineering.yaml; check modules read Config
instead of hardcoding thresholds/paths/package names.
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_CONFIG_PATH = "engineering.yaml"


@dataclass
class ProjectConfig:
    name: str = ""
    module: str = ""
    language: str = "go"


@dataclass
class FilesizeConfig:
    max_lines: int = 500
    ignore_patterns: list = field(default_factory=list)
    exemptions: list = field(default_factory=list)
    required_exemptions: list = field(default_factory=list)


@dataclass
class ComplexityConfig:
    max_cyclomatic: int = 15
    max_cognitive: int = 20
    ignore_pattern: str = ""
    exempt_functions: list = field(default_factory=list)
    gocyclo_path: str = "~/go/bin/gocyclo"
    gocognit_path: str = "~/go/bin/gocognit"


@dataclass
class ArchitectureConfig:
    forbidden: dict = field(default_factory=dict)
    excluded_dirs: list = field(default_factory=list)


@dataclass
class DirectoryFanoutConfig:
    max_subdirs: int = 15
    exempt_dirs: list = field(default_factory=list)


@dataclass
class RootPolicyConfig:
    max_files: int = 15
    allowed_files: list = field(default_factory=list)
    allowed_prefixes: list = field(default_factory=list)
    banned_patterns: list = field(default_factory=list)
    banned_files: list = field(default_factory=list)
    exempt_files: list = field(default_factory=list)


@dataclass
class BuildConfig:
    output_dir: str = "bin"
    binaries: list = field(default_factory=list)  # [{"name": ..., "path": ...}]


@dataclass
class Config:
    project: ProjectConfig
    filesize: FilesizeConfig
    complexity: ComplexityConfig
    architecture: ArchitectureConfig
    directory_fanout: DirectoryFanoutConfig
    root_policy: RootPolicyConfig
    coverage_targets: dict
    build: BuildConfig
    skills_dir: str = "skills"
    path: Optional[Path] = None


def _load_raw(path: Path) -> dict:
    if yaml is None:
        print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    if not path.exists():
        print(f"ERROR: config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        print(f"ERROR: {path} did not parse to a mapping", file=sys.stderr)
        sys.exit(1)
    return data


def load(path=DEFAULT_CONFIG_PATH) -> Config:
    """Load and parse engineering.yaml. Missing sections fall back to the
    dataclass defaults above, so a new adopter can start with a partial file
    and grow it gate by gate."""
    p = Path(path)
    data = _load_raw(p)
    return Config(
        project=ProjectConfig(**data.get("project", {})),
        filesize=FilesizeConfig(**data.get("filesize", {})),
        complexity=ComplexityConfig(**data.get("complexity", {})),
        architecture=ArchitectureConfig(**data.get("architecture", {})),
        directory_fanout=DirectoryFanoutConfig(**data.get("directory_fanout", {})),
        root_policy=RootPolicyConfig(**data.get("root_policy", {})),
        coverage_targets=data.get("coverage", {}).get("targets", {}),
        build=BuildConfig(**data.get("build", {})),
        skills_dir=data.get("skills", {}).get("dir", "skills"),
        path=p,
    )


_cached: Optional[Config] = None


def get_config() -> Config:
    """Process-wide cached config, loaded from DEFAULT_CONFIG_PATH relative
    to the current working directory (cli.py and every check run with the
    repo root as cwd)."""
    global _cached
    if _cached is None:
        _cached = load()
    return _cached


def reset_cache() -> None:
    """Test-only: force the next get_config() to reload from disk."""
    global _cached
    _cached = None
