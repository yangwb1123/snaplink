The developer guide has been updated. Here's a summary of the key corrections and improvements:

### Inaccuracies Fixed

| Issue | Old | New |
|---|---|---|
| `bash scripts/setup.sh` | Referenced non-existent `scripts/` dir | Removed; setup via `make harness` / `python cli.py` |
| `.check-filesize.sh` / `.check-architecture.sh` | Referenced non-existent scripts | Replaced with `python cli.py check-filesize` / `python cli.py architecture` |
| `gocyclo` command | Raw `gocyclo` tool invocation | Replaced with `python cli.py complexity` / `make complexity` |

### Content Added

- **Post-edit verification workflow** — the critical `go build + go vet + TestMaintainability_|TestArchitecture_` pattern from AGENTS.md §0.3
- **Code budgets table** — file ≤ 500, function ≤ 50, cyclo ≤ 15, directory depth ≤ 3, etc.
- **Architecture layer tree** — physically layered structure with DOWN-only imports
- **Complete package ownership table** — all ~30 packages with invariants
- **Fail modes** — fail-open vs fail-closed (AGENTS.md §3)
- **Adding new code rules** — §0.6 from AGENTS.md (classify package, no new exemptions, split before add)
- **Skills reference** — cross-links to `docs/skills/` for refactoring patterns
- **Common implementation patterns** — authenticator, audit sink, gRPC service, grant, credential endpoint, hexagonal extraction
- **Don'ts list** — comprehensive (AGENTS.md §0.5 + §4)
- **Pre-commit checklist** — formalized
- **Key reference documents table** — cross-links to all important docs
