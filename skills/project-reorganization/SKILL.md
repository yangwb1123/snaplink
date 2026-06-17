# Skill: Project Reorganization

**Trigger:** Root directory file count exceeds 15 non-exempt files.

**Usage:** `python skills/project-reorganization/run.py [--analyze-only] [--dry-run]`

## Principles
1. Root minimum — only README, build config, agent docs, entry dirs (cmd/)
2. Feature-first grouping — by domain, not by technical layer
3. File size hard gates — file <= 500, function <= 50, cyclo <= 15
4. Entry file minimization — one entry per binary (cmd/<name>/main.go)
5. Anti-patterns — no utils/, helpers/, god files

## Execution
1. `python skills/project-reorganization/run.py --analyze-only` → review proposed structure
2. Create module dirs, move files, update imports
3. `python skills/post-edit-check/run.py` after each batch
4. `make acceptance && bash .check-root-files.sh` to verify
