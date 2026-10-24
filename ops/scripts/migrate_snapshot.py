#!/usr/bin/env python3
"""Private SQLite-backup / PostgreSQL-candidate preflight; no data-writing mode."""
from migration_guard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
