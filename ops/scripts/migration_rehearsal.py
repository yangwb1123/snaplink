#!/usr/bin/env python3
"""Owned SQLite -> PostgreSQL rehearsal driver; no cutover or production mode."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from migration_guard.rehearsal_cli import main  # noqa: E402 - path set above

if __name__ == "__main__":
    raise SystemExit(main())
