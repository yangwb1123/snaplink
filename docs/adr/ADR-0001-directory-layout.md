# ADR-0001 — Physically layered library, gate-only repository root

## Status

Accepted; amended after the layered-topology migration. The original flat-tree
decision is historical and is superseded by ADR-0006 plus the executed
migration summarized in [`docs/HISTORY.md`](../HISTORY.md).

## Context

snaplink is an embeddable Go library plus runnable server. Its packages need a
clear dependency direction, while the repository root must not become a
business-logic package or a second public facade.

The project originally kept public packages flat to avoid import-path changes.
It later performed an in-place breaking reorganization without changing the
root module major version. The current public Server import is
`github.com/yangwb1123/snaplink/interfaces/sso`.

## Decision

1. Library packages live under the physical layer directories `shared/`,
   `platform/`, `domains/`, `protocols/`, `infrastructure/`, and `interfaces/`.
   The first path segment is the architectural layer.
2. The repository root contains no production Go. Its Go files are committed
   `package archgate` tests only; repository and build files are controlled by
   `engineering.yaml`'s `root_policy`.
3. The public Server API and HTTP composition live in `interfaces/sso`.
   Business behavior extracts downward into protocol/domain packages through
   small dependency interfaces.
4. `cmd/`, `config/`, examples, tests, protobuf sources/generated code,
   deployment files, and engineering checks are composition/tooling surfaces.
5. Do not recreate old flat-package compatibility shims or a root
   `package sso` facade without a separately reviewed versioning decision.

## Consequences

**Benefits**

- The filesystem communicates the dependency model before code is read.
- The root cannot silently regrow into a god package.
- New packages have a deterministic placement rule and are classified by the
  architecture gate.

**Costs**

- Consumers of former flat imports had to move to layered paths despite the
  unchanged module major version.
- Some cohesive public packages exceed the directory file-count budget and
  remain at frozen ceilings under ADR-0007.

## Enforcement

- `architecture_layer_test.go`
- `maxdepth_test.go`
- `checks/root_business_code.py` and `checks/root_files.py`
- [directory map](../architecture/DIRECTORY_MAP.md)
