# Skill: Refactor High Complexity

**Trigger:** Function with cyclo > 15 or cognitive > 20.

**Usage:** `python skills/refactor-high-complexity/run.py <file> [--function <name>]`

## Strategies
- **Guard Clauses:** Invert conditions for early return (deep nesting)
- **Strategy Table:** Replace switch with >10 cases via `map[string]HandlerFunc`
- **Extract Sub-Functions:** Pull cohesive blocks into named functions (<= 50 lines)
- **Separation of Concerns:** Split validation + business logic + response

## Verify
gocyclo <file> && make check-quick && make acceptance
