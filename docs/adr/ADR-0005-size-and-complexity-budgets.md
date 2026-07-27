# ADR-0005 — Size/complexity budgets and committed core gates

## Status

Accepted.

## Context

The dominant failure mode of long, autonomous development is *silent erosion*:
god-files, runaway complexity, and leaf-package creep that the Go compiler and
per-function linters don't catch. A template harness proposed enforcing limits
(file ≤300, package ≤20 files, fan-in ≤50) via `scripts/*.sh` invoked from CI.
Two problems: the numbers don't fit a mature library, and shell-script gates are
fragile here — an earlier `python cli.py harness` implementation regenerated a
scaffolding stack and could clobber hand-authored references
(see [maintainability gates](../maintainability-gates.md)).

## Decision

**Budgets (recalibrated to snaplink reality):**

| Budget | Limit | Notes |
|---|---|---|
| File length | **500** lines | committed root test; generated (`gen/proto`, `*.pb.go`) and `_test.go` excluded |
| Cyclomatic complexity | **15** / function | committed root test |
| Cognitive complexity | **20** / function | Python `complexity` diagnostic via `gocognit`; CI installs the tool |
| Function length | **50** lines | committed root test |
| Non-test Go files / directory | **≤ 10** | committed root test; frozen ceilings under ADR-0007 |
| Immediate subdirectories | **≤ 15 contributor target** | Python config uses 15; committed Go test currently uses 16 |
| Directory depth | **≤ 3** | committed root test; `ops/deploy`, `testdata`, generated/tool paths exempt |
| Root files (non-exempt) | **≤ 15** | Python root-policy check; ADR-0001 |

There is no fan-in cap. ADR-0007 later added a per-directory file-count cap and
frozen ceilings for cohesive packages that cannot split safely.

**Enforcement mechanism — committed Go tests for the core budgets, not shell
stubs.** File length, cyclomatic/function length, directory fan-out/depth, and
architecture boundaries have committed `*_test.go` gates that run inside the
normal `go test ./...` / `make ci` `race` step. Cognitive complexity and root
policy remain Python checks; if their tools/configuration drift, they are not
equivalent evidence. If-nesting depth remains a review rule.

**Ratchet rule.** Each committed gate carries an exemption list of files,
functions, directories, or imports that already
violated the rule when it was introduced. **The list may only shrink**: a new
violation fails the build (fix it, don't list it); a stale exemption (file
refactored back under budget) also fails, so it gets deleted. Regenerate the
seeded exemptions with
`SEED_MAINTAINABILITY=1 go test -run TestSeedMaintainabilityExemptions -v .`
and diff the result — never let it silently widen. The committed file and
function exemption maps are now empty.

## Consequences

**Pros** — erosion is caught at `go test` time; the backlog trends to zero;
generated code is correctly exempt; no CI-only shell layer to drift.

**Cons** — the ratchet exemption lists are real artifacts that must be
co-migrated on any file move (they key on relative path + function name).

**Risks** — Python and committed Go gates can drift because they are distinct
implementations. The canonical post-edit checks are:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Use `python cli.py check-root`, `complexity`, `architecture`, and
`check-invariants` for their separate checks.

## Enforcement

Committed tests above + `python cli.py {check-filesize,complexity,architecture}`
+ `.golangci.yml` (`make lint`). Python thresholds are loaded from
`engineering.yaml`; committed Go thresholds remain constants in their root
tests. Golangci currently provides its default correctness linters plus
`misspell` and `unconvert`, not the complexity/function-length gates. The
current subdirectory values differ (15 versus 16), so contributors must satisfy
15 until the implementations are reconciled. Manifest:
[`.arch/rules.yaml`](../../.arch/rules.yaml).
