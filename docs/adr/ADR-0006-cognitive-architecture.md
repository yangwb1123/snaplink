# ADR-0006 — Physical seven-layer architecture

## Status

Accepted; amended after execution of the layered-topology migration.

## Context

A flat package tree made the dependency model hard to discover and allowed
layering erosion that the compiler could not detect. The original decision
introduced a seven-layer conceptual overlay without moving paths. The
repository subsequently executed the physical move while preserving the root
module path.

## Decision

Use seven enforced ranks:

```text
shared(0) < platform(1) < domains(2) < protocols(3)
          < infrastructure(4) < interfaces(5) < composition(6)
```

The first path segment is the layer for the six library ranks. Composition
includes commands, configuration, examples, and integration wiring.

A package may import only the same rank or a lower rank. The gate classifies
special composition/generated/internal paths explicitly and fails any
unclassified package.

Judgment calls of record:

- `shared/security` is a reusable security kernel below protocols.
- `platform/audit` owns audit recording/sink mechanics used across domains.
- `domains/anomaly` is behavioral detection, while `platform/geo` is
  cross-cutting request enrichment.
- `interfaces/sso` is the public Server and route-composition edge.
- `interfaces/ssoclient` is the downstream consumer interface.
- Concrete memory/SQLite/Redis/Postgres adapters are infrastructure.

Nine inherited upward edges remain in `layerExemptions`. Their exact set is
shrink-only and no new edge may be added. The map has no automatic count latch;
code review is the enforcement against adding a matching exemption alongside a
new upward import.

## Consequences

- The filesystem, import paths, and gate all express the same model.
- Moving a package across layers changes its public import path and requires an
  explicit compatibility/versioning decision.
- New top-level paths must be classified; new one-off packages should usually
  extend an existing cohesive package instead.

## Enforcement

`architecture_layer_test.go`
(`TestArchitecture_LayerBoundaries`) and
[DIRECTORY_MAP.md](../architecture/DIRECTORY_MAP.md).
