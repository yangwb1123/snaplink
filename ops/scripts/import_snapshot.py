#!/usr/bin/env python3
"""One-shot protected import into an explicitly owned disposable PostgreSQL candidate."""
from migration_guard.import_cli import main

if __name__ == '__main__':
    raise SystemExit(main())
