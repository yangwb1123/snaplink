# HARNESS.md — Gate specification

Numeric policy is declared in `engineering.yaml`; contributor behavior is in
`AGENTS.md`. This file maps the committed root Go gates to their purpose.

## Committed gates

| Test file | Protects | Exemption policy |
|---|---|---|
| `maintainability_budget_test.go` | Production Go file size | Shrink-only inventory |
| `maintainability_complexity_test.go` | Function length and cyclomatic complexity | Shrink-only inventories |
| `architecture_gate_test.go` | Core and OAuth/OIDC import prohibitions | No exemptions |
| `architecture_layer_test.go` | One-way layer imports and package classification | Existing edges shrink only; review blocks additions |
| `directory_fanout_test.go` | Flat-package and subdirectory growth | Frozen ceilings shrink only |
| `maxdepth_test.go` | Package nesting depth | Fixed excluded paths only |

They run inside normal root tests and `make ci`:

```bash
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
```

Committed tests are preferred for build-blocking rules because generation
cannot overwrite them and every `go test ./...` execution sees them.

## Python harness boundary

`cli.py` and `checks/` provide fast checks, diagnostics, acceptance reports,
coverage, and scaffolding validation. They are not a second release authority.
See [`CHECKS_REGISTRY.md`](CHECKS_REGISTRY.md) for the command catalog and
[`TODO.md`](TODO.md) for known synchronization/false-green debt.

| Command | Role |
|---|---|
| `python cli.py check` | Fast file-size and vet loop |
| `python cli.py harness` | Scaffolding plus selected Python checks |
| `python cli.py accept` | Supplementary U1–U9 report |
| `python cli.py self-test` | Probes the Python harness |
| `python cli.py generate` | Validates tracked Markdown and refreshes non-document scaffolding |
| `python cli.py modules check` | Validates module schemas, manifests, catalog, dependency plans and profiles |

Generation must not rewrite Agent OS, prompt, checklist, skill, or feature-spec
Markdown.

## Failure handling

Fix the structure or dependency; never widen an exemption. Use the playbooks in
[`docs/skills/`](../skills/) and the response table in
[`docs/maintainability-gates.md`](../maintainability-gates.md).

After an accepted debt reduction, seed commands may update only the matching
shrink-only inventory:

```bash
SEED_MAINTAINABILITY=1 go test -run TestSeedMaintainabilityExemptions -v .
SEED_DIRFANOUT=1 go test -run TestSeedDirectoryFanout -v .
```
