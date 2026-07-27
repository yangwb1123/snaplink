#!/usr/bin/env python3
"""Build gate: compile the project's binaries into the configured output dir.

Binary list and output dir live in engineering.yaml (`build:` section) — see
checks/config.py.
"""
import datetime
import os
import subprocess
import sys
from pathlib import Path

# Allow standalone invocation (python checks/build.py) as well as package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks.config import get_config

CORE_BUILDINFO = "github.com/yangwb1123/snaplink/shared/core"


def _build_timestamp() -> str:
    source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_epoch is None:
        instant = datetime.datetime.now(datetime.timezone.utc)
    else:
        instant = datetime.datetime.fromtimestamp(
            int(source_epoch),
            datetime.timezone.utc,
        )
    return instant.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git_state() -> tuple[str, bool]:
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        )
        return revision, dirty
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "", False


def _ldflags() -> str:
    revision, dirty = _git_state()
    values = {
        "BuildTime": _build_timestamp(),
        "GitHash": revision,
        "BuildModified": str(dirty).lower(),
    }
    return " ".join(
        f"-X {CORE_BUILDINFO}.{name}={value}" for name, value in values.items()
    )


def run() -> int:
    cfg = get_config().build
    bin_dir = Path.cwd() / cfg.output_dir
    bin_dir.mkdir(exist_ok=True)
    ldflags = _ldflags()
    for binary in cfg.binaries:
        out = bin_dir / binary["name"]
        result = subprocess.run(
            [
                "go",
                "build",
                "-trimpath",
                "-buildvcs=true",
                "-ldflags",
                ldflags,
                "-o",
                str(out),
                binary["path"],
            ],
            capture_output=False,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(run())
