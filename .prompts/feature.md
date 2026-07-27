# Prompt: implement a feature

Use this as the standing brief for any feature work in snaplink.

## Before coding
1. Read `AGENTS.md` (§0 gates, §2 module map, §3 global constraints).
2. Read the relevant `docs/adr/` records; if your change would alter a rule in
   `.arch/rules.yaml`, add a top-level directory, or move a package's public
   import path — **stop and propose an ADR first** (per AGENTS.md Refactoring Rules).
3. Find the owning domain package and **extend it**; don't create a root-level
   business file or a new top-level directory (ADR-0001).
4. Reuse the existing SPI + real `Memory*`/`sqlite` implementation; no mocks
   where a `Memory*` impl exists (ADR-0004).

## While coding
- Keep the dependency direction
  `composition → interfaces → infrastructure → protocols → domains → platform → shared`;
  put shared SPIs/types in `shared/core`, and never import an upper layer
  (ADR-0006).
- Budgets (ADR-0005): file ≤ 500 lines, function ≤ 50 lines, cyclomatic ≤ 15,
  cognitive ≤ 20. If an edit would push a file over 500, **split first**
  (`docs/skills/split-large-file/SKILL.md`), then continue.
- Honor the relevant §3 invariants (oracle-leak collapse, anti-enumeration,
  fail-open vs fail-closed, RFC 9068 claim stamping, cache headers, `iss`).
- New `Err*` → update `docs/error-codes.md`; documented endpoint change →
  update `docs/openapi.yaml`; both in the same commit.

## Before marking complete (safe checks — do NOT regenerate scaffolding)
```
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./... -race                 # or: go test ./test/ -run TestE2E -v
python cli.py check-root && python cli.py check-invariants
```
> Do not run a scaffolding generator on an uncommitted tree. Use `make ci`
> (`fmt vet race build examples proto-lint ci-modules config-validate-all`)
> for the core executable gate.

## Output
1. Design (which package, which SPI, why no new directory)
2. Implementation
3. Tests (beside the code; cross-server → `test/`)
4. Architecture impact (rules touched, ADR needed? gates run + results)
