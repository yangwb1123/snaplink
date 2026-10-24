#!/usr/bin/env python3
"""Read-only, evidence-only comparison of a restored owned PostgreSQL candidate."""
from migration_guard.recovery_cli import main

if __name__ == '__main__':
    raise SystemExit(main())
