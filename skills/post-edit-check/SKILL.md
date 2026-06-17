# Skill: Post-Edit Check

**Trigger:** After every Go file edit.

**Usage:** `python skills/post-edit-check/run.py`

## Checks
1. make check-quick -- filesize + vet
2. If fails, exit immediately and fix
3. If passes, continue
