# Prompt: refactor

Refactoring outranks feature work: if a file you must touch is at/over a budget,
fix that first (AGENTS.md §0.1 Cardinal rule).

## Rules
- **Behavior-preserving.** A refactor must not change observable behavior.
  Prove it: run the relevant tests (and `go test ./test/ -race`) before and
  after; for security-critical paths run with `-count=10`.
- **No "while I'm here" scope creep** (AGENTS.md Don'ts). One concern per change.
- **Stay in budget** (ADR-0005): split a >500-line file into cohesive
  `*_<domain>.go` files in the *same* package (pure relocation + `goimports -w`),
  per `docs/skills/split-large-file/SKILL.md`. Don't add to an exemption list.
- **Ratchet artifacts move with the code.** The size/complexity/architecture
  gates key on relative path (+ function name). When you move or rename a file,
  update the matching exemption keys **in the same commit**, then regenerate +
  diff: `SEED_MAINTAINABILITY=1 go test -run TestSeedMaintainabilityExemptions -v .`
- **Boundaries hold** (ADR-0002): never introduce an upward import; resolve
  cross-package coupling via an interface in the lower/destination package.
- **Public import paths are frozen** (ADR-0001/0003): moving a package's import
  path is a breaking change — needs an ADR + (for nested modules) a `go.mod`
  path + `replace` update, deferred to a major version.

## High-risk zone
Extracting auth/token/crypto behavior from `interfaces/sso` into a lower layer
must preserve the composition package's wire behavior. Declare the narrow
`Deps` interface in the destination package and prove parity with oracle-leak,
anti-enumeration, refresh-replay, and cross-server tests. Do not move public
import paths merely to reduce a file count.

## Verify (safe; no scaffolding regen)
```
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./... -race
python cli.py check-root && python cli.py check-invariants
```
