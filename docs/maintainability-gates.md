# Maintainability gates

Snaplink encodes architecture and code-shape rules as committed root Go tests
so they run anywhere `go test ./...` runs. This document explains ownership;
it does not duplicate thresholds.

## Authority

- `engineering.yaml` declares numeric policy.
- [`AGENTS.md`](../AGENTS.md) turns that policy into contributor rules and
  records security-sensitive invariants.
- Root `package archgate` tests enforce the build-blocking subset.
- [`agent-os/HARNESS.md`](agent-os/HARNESS.md) maps each gate to its test and
  command.
- [`agent-os/CHECKS_REGISTRY.md`](agent-os/CHECKS_REGISTRY.md) catalogs the
  supplementary Python and Make checks.

When these sources disagree, satisfy the stricter behavior and report the
drift. Never loosen a gate during unrelated feature work.

## Committed gates

| Test | Protects |
|---|---|
| `maintainability_budget_test.go` | Production Go file size |
| `maintainability_complexity_test.go` | Function length and cyclomatic complexity |
| `architecture_gate_test.go` | Core and OAuth/OIDC import prohibitions |
| `architecture_layer_test.go` | One-way physical layer dependencies and package classification |
| `directory_fanout_test.go` | Flat-package and directory fan-out growth |
| `maxdepth_test.go` | Package nesting depth |

The file, function, and directory exemption inventories are ratchets: existing
entries may shrink but new work must not add one. `layerExemptions` lacks a
mechanical count latch, so review must reject additions explicitly.

## Workflow

After every Go edit:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Before handoff:

```bash
make ci
```

Use `python cli.py check` for a fast diagnostic loop, not as a substitute for
the committed tests or `make ci`.

## Responding to a failure

| Failure | Response |
|---|---|
| File budget | Split cohesive declarations; if the directory is already at its frozen ceiling, extract to the owning lower layer |
| Function budget | Add guard clauses and extract behavior-preserving stages |
| Directory fan-out/depth | Regroup by responsibility or flatten a backend variant |
| Forbidden import | Move the abstraction down or inject it through a small interface |
| Stale exemption | Remove the exemption after verifying the measured debt is gone |

Playbooks live under [`docs/skills/`](skills/). Do not hide a violation in a
generic helper, new package, or expanded allowlist.

## Known tooling drift

- Python and committed Go checks currently disagree on the immediate
  subdirectory threshold.
- The declarative file-size exemption inventory contains two stale paths even
  though committed file/function backlogs are empty.
- The Python coverage diagnostic can miss a failing subprocess or unmatched
  package.
- Local complexity diagnostics can succeed when optional analyzers are absent.
- Optional chaos, DR, load, and benchmark suites remain outside `make ci`.

Current details and commands belong in the Agent OS files above; update them
instead of copying another gate table here.
