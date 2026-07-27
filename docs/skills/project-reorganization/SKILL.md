# Skill: Project reorganization

**Trigger:** A package is in the wrong physical layer, a directory crosses a
frozen fan-out ceiling, or `python cli.py check-root` detects production
business code at the repository root.

The current `run.py` analyzer predates the layered migration and counts the
intentional root `package archgate` tests as violations. Do not use it for a
migration plan until its root-policy model is updated.

## Principles

1. Keep the six physical library layers:
   `shared`, `platform`, `domains`, `protocols`, `infrastructure`,
   `interfaces`.
2. Preserve public import paths unless the change explicitly authorizes a
   breaking migration.
3. Move behavior by responsibility, not merely to reduce counts.
4. Keep imports pointing toward `shared`; do not add `layerExemptions`.
5. Preserve API-only Server composition in `interfaces/sso`.
6. Never move or rewrite committed root gate tests as production code.

## Process

1. Inventory packages, imports, public symbols, generated references, nested
   module boundaries, and frozen ceilings.
2. Write the target mapping and compatibility impact before moving files.
3. Move one cohesive boundary at a time with `git mv`.
4. Update imports, `layerName()` classification when required, protobuf
   `go_package` values, nested-module `replace` paths, and docs in the same
   change.
5. Build and run root gates after every batch.
6. Run full root/nested-module and consumer-facing tests before handoff.

### Hexagonal extraction

When `interfaces/sso` owns protocol or business decisions, keep its handler and
wire mapping thin and move the behavior to the owning `protocols/` or
`domains/` package:

1. List the Server state, dependencies, side effects, and ordering constraints.
2. Define a minimal `Deps` interface beside the lower-layer free function.
3. Satisfy it through `interfaces/sso/accessors.go`; never pass the whole
   Server or import `interfaces/sso` from below.
4. Preserve no-store/challenge order, oracle-safe errors, audit order,
   tenant/client context, atomic consumption, and refresh `FamilyID`.
5. Keep strongly Server-private mechanics in the same package rather than
   inventing a leaky dependency interface only to reduce line count.

## Stop conditions

- The move changes a published import path without explicit authorization.
- A proposed package would need an upward import or new exemption.
- A fourth directory level would be introduced.
- Security/error/timing behavior cannot be shown equivalent.
- Nested-module versioning or consumer migration is unspecified.

## Verify

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
python cli.py check-root
make ci
```
