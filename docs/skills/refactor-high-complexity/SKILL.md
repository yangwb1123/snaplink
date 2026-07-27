# Skill: Refactor high complexity

**Trigger:** A function approaches/exceeds cyclomatic 15, 50 lines, cognitive
20, or nesting depth 3.

**Analyzer:**
`python docs/skills/refactor-high-complexity/run.py <file> [--function <name>]`.
It requires `gocyclo`; the committed root test remains authoritative for
cyclomatic and line length.

## Strategies

- Invert conditions into guard clauses.
- Extract validation, mutation, persistence, and response work into named
  helpers.
- Use a strategy table only when it preserves ordering/default behavior.
- Keep protocol error mapping and audit ordering at the caller.
- Avoid helpers that merely hide branches or create upward dependencies.

Do not add a function exemption; both committed maps are empty.

## Verify

```bash
go test -run 'TestMaintainability_' .
go build ./... && go vet ./...
make ci
```
