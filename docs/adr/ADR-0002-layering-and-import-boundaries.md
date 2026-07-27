# ADR-0002 — Layering and import boundaries

## Status

Accepted; updated for the physical layered tree.

## Context

The Go compiler prevents cycles, but it does not prevent a low-level package
from reaching upward into HTTP composition or concrete infrastructure. Those
edges erode the architecture before they form a compile-time cycle.

## Decision

The layer ranks, from most shared to most concrete, are:

```text
shared(0) < platform(1) < domains(2) < protocols(3)
          < infrastructure(4) < interfaces(5) < composition(6)
```

An importer may reference only its own rank or a lower rank.

Additional hard boundaries:

1. `shared/core` imports no snaplink package.
2. `protocols/oauth` and `protocols/oidc` do not import one another. Both
   directions have zero exemptions.
3. No library package imports `cmd/`.
4. A dependency that appears to require an upward edge is inverted through an
   interface owned by the lower layer, or wired in `interfaces/sso`/
   composition.
5. New top-level or `internal/` packages must be classified in
   `layerName()`; an unclassified package fails the gate.

The whole-layer gate retains nine frozen upward edges inherited at adoption.
They are explicit, shrink-only debt; new entries are prohibited by policy.
Unlike the file/function/fan-out maps, `layerExemptions` has no count latch, so
review must enforce this rule.

## Consequences

- Cross-layer design errors fail during root gate tests, not after a cycle
  appears.
- Shared interfaces belong in `shared/core`, `shared/spi`, or the lower owning
  package rather than in interfaces/infrastructure.
- Some pre-existing couplings remain visible in `layerExemptions`, but their
  count and exact edges cannot grow.

## Enforcement

- `architecture_gate_test.go`
- `architecture_layer_test.go`
- `python cli.py architecture` (a separate declarative check)
- [directory map](../architecture/DIRECTORY_MAP.md)
