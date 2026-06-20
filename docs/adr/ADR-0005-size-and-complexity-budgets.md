# ADR-0005 — Size/complexity budgets, enforced as committed tests

## Status

Accepted.

## Context

The dominant failure mode of long, autonomous development is *silent erosion*:
god-files, runaway complexity, and leaf-package creep that the Go compiler and
per-function linters don't catch. A template harness proposed enforcing limits
(file ≤300, package ≤20 files, fan-in ≤50) via `scripts/*.sh` invoked from CI.
Two problems: the numbers don't fit a mature library, and shell-script gates are
fragile here — `python cli.py harness` regenerates a scaffolding stack and has
historically clobbered hand-placed scripts, `Makefile`, and `AGENTS.md`
(see `docs/maintainability-gates.md`).

## Decision

**Budgets (recalibrated to snaplink reality):**

| Budget | Limit | Notes |
|---|---|---|
| File length | **500** lines | generated (`gen/proto`, `*.pb.go`) and `_test.go` excluded |
| Cyclomatic complexity | **15** / function | |
| Cognitive complexity | **20** / function | |
| Function length | **50** lines | committed test; golangci uses 60/40 as a looser lint |
| Root files (non-exempt) | **≤ 15** | ADR-0001 |

There is **no** per-package file-count cap and **no** fan-in cap — both would
flag healthy, cohesive packages (e.g. `oauth/` 43 files, `core <- 219` importers).

**Enforcement mechanism — committed Go tests, not shell stubs.** Each budget is
a `*_test.go` (`maintainability_budget_test.go`,
`maintainability_complexity_test.go`, `architecture_gate_test.go`) that runs
inside the normal `go test ./...` / `make ci` `race` step. It can't be
regenerated away, runs everywhere `go test` runs, and needs no extra wiring.
`checks/*.py` (via `cli.py`) provide the same checks for the CLI path.

**Ratchet rule.** Each gate carries an exemption list of files that already
violated the rule when it was introduced. **The list may only shrink**: a new
violation fails the build (fix it, don't list it); a stale exemption (file
refactored back under budget) also fails, so it gets deleted. Regenerate the
seeded exemptions with `SEED_MAINTAINABILITY=1 go test -run
TestSeedMaintainabilityExemptions -v .` and diff the result — never let it
silently widen.

## Consequences

**Pros** — erosion is caught at `go test` time; the backlog trends to zero;
generated code is correctly exempt; no CI-only shell layer to drift.

**Cons** — the ratchet exemption lists are real artifacts that must be
co-migrated on any file move (they key on relative path + function name).

**Risks** — running `cli.py harness` / `check-filesize` / `generate` on an
uncommitted tree regenerates scaffolding. **Safe post-edit checks** that do not
regenerate: `go build ./... && go vet ./...`, `go test -run
'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`, and
`python cli.py check-root|complexity|architecture|check-invariants`.

## Enforcement

Committed tests above + `python cli.py {check-filesize,complexity,architecture}`
+ `.golangci.yml` (`make lint`). Source numbers: `checks/filesize.py`
(`MAX_LINES=500`), `checks/complexity.py` (`MAX_CYCLO=15`, `MAX_COGNIT=20`),
`checks/root_files.py` (`MAX=15`). Manifest: [`.arch/rules.yaml`](../../.arch/rules.yaml).
