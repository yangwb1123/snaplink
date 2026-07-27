# Architecture Decision Records

ADRs capture the *why* behind snaplink's structural rules so that long-running,
largely autonomous (AI-agent-driven) development doesn't silently re-litigate or
erode them. They are descriptive of decisions already in force — the machine
enforcement lives in the committed `*_test.go` gates and `checks/*.py`
(see [`.arch/rules.yaml`](../../.arch/rules.yaml) for the index, and
[`docs/maintainability-gates.md`](../maintainability-gates.md) for the gate mechanics).

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](ADR-0001-directory-layout.md) | Physically layered library; repository root contains gate tests, not production Go | Accepted, amended |
| [ADR-0002](ADR-0002-layering-and-import-boundaries.md) | One-way seven-layer imports; `shared/core` is a leaf; OAuth/OIDC mutually independent | Accepted, amended |
| [ADR-0003](ADR-0003-protocol-grouping.md) | Root-module protocol orchestration is physically grouped under `protocols/` | Accepted, supersedes flat layout |
| [ADR-0004](ADR-0004-domain-boundaries.md) | SPI-per-concern + per-backend impls (`memory`/`sqlite`/`etcd`/`redis`); no mocks where `Memory*` exists | Accepted |
| [ADR-0005](ADR-0005-size-and-complexity-budgets.md) | File ≤500, cyclo ≤15, cognit ≤20, func ≤50; ratcheting; enforced as committed tests not shell stubs | Accepted |
| [ADR-0006](ADR-0006-cognitive-architecture.md) | Seven-layer model is physical and enforced; first path segment identifies the layer | Accepted, amended |
| [ADR-0007](ADR-0007-directory-fanout-and-the-monolith-exemption-class.md) | Per-directory fan-out budget (≤10 files; ≤15 contributor subdir target) with frozen ceilings for irreducible cohesive packages | Accepted |
| [ADR-0008](ADR-0008-proto-versioning.md) | Proto API versioning strategy (v1 stable / v2alpha preview / v2beta near-stable / v2 stable); deprecation annotations; buf breaking policy | Accepted |
| [ADR-0009](ADR-0009-static-and-runtime-modules.md) | NGINX-style static build profiles; generation-based hot activation; external-process third-party plugins | Accepted, incremental |

## Writing a new ADR

Copy the structure of an existing record (Status / Context / Decision /
Consequences). Number sequentially. An ADR is required *before* changing an
enforced architecture rule, adding a top-level library layer, or moving a
package's public import path. The committed Go/Python enforcer is authoritative;
`.arch/rules.yaml` is only a descriptive mirror.
