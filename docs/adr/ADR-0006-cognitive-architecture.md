# ADR-0006 — Cognitive architecture: enforced layers over a flat tree

## Status

Accepted (2026-06-19).

## Context

The repo has ~53 top-level package directories. Flat-but-many is hard for a
newcomer to form a model from, and nothing stops *layering erosion* — a domain
package quietly importing infrastructure, a protocol importing the HTTP edge —
which the Go compiler permits right up until it becomes a cycle.

The goal (per the "cognitive architecture" framing) is **low cognitive load,
clear boundaries, single responsibility, sustainable evolution** — Screaming
Architecture + the Stable/Acyclic Dependencies principles — *not* a smaller
directory count.

The obvious move — physically retree into `domains/ protocols/ platform/
interfaces/ infrastructure/ shared/` — was rejected for v1: this is a **library**
whose import paths are a published API, so moving public packages breaks every
consumer and is a v2-major change ([ADR-0001](ADR-0001-directory-layout.md),
[ADR-0003](ADR-0003-protocol-grouping.md)).

## Decision

Adopt a **seven-layer cognitive model as an enforced overlay**, without moving
public import paths:

```
shared(0) < platform(1) < domains(2) < protocols(3) < infrastructure(4) < interfaces(5) < composition(6)
```

A package may import only its own layer or a **lower-rank** (more-shared) one.
Two mechanisms realize it:

1. **An enforcement gate** — `architecture_layer_test.go`
   (`TestArchitecture_LayerBoundaries`): every main-module package is classified
   in `layerName()`; an upward import fails the build; an **unclassified** package
   also fails, so the model can't drift behind the package list. Pre-existing
   upward edges are grandfathered in a **shrink-only** `layerExemptions` (same
   ratchet as the other gates).
2. **A navigability map** — [`docs/architecture/DIRECTORY_MAP.md`](../architecture/DIRECTORY_MAP.md):
   the flat packages presented under their layers, with the dependency-direction
   diagram (the 30-second view).

Layer-placement judgment calls of record: `security` → **shared** (crypto/security
kernel below the protocols); `audit` → **platform** (the Recorder/Sink *mechanism*
is observability used by every layer, distinct from the DDD audit *domain*);
`geo`/`anomaly` → **platform**/**domains** respectively; the root `sso` package →
**interfaces** (it is the public `Server` API + `server_*.go` handlers); `ssoclient`
→ **interfaces** (outbound consumer SDK). `internal/` is already layer-aligned
(`internal/auth/*` = domains, `internal/handler` = interfaces), so no relocation
was performed.

The seeded backlog at adoption was **9 upward edges** across 112 packages — almost
all the root god-package fan-in (`authenticators`/`defaultimpl` → root) plus a few
cross-cutting couplings (`audit`→tenant/region, `oauth`/`selfservice`→middleware,
`scim`→admin).

## Consequences

**Pros**
- The cognitive model is a *checked invariant*, not a wiki page that rots — new
  upward edges fail CI; the backlog only shrinks.
- Zero consumer breakage; no import-path churn; the path-keyed gates stay valid.
- The newcomer 30-second test is met by the map + enforced layers.

**Cons / risks**
- Physical tree and logical layers differ; the map is the bridge (a contributor
  must read it). Mitigated by linking it from `AGENTS.md` and `.arch/rules.yaml`.
- `layerName()` is a hand-maintained classification; a new top-level package must
  be added (the gate fails loudly until it is — intended).

## Alternatives considered

- **Full physical v2 retree** — correct end-state if/when a major version is cut
  (with deprecation aliases, atomic gate-prefix edits, one layer per reviewed PR);
  deferred, not rejected.
- **Documentation only** — rejected: a doc without enforcement erodes, which is the
  exact failure mode this ADR exists to prevent.

## Enforcement

`go test -run TestArchitecture_LayerBoundaries ./...` (rides `make ci`'s `race`
step). Manifest: [`.arch/rules.yaml`](../../.arch/rules.yaml) `architecture.layers`.
