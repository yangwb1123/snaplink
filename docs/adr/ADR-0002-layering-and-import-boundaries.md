# ADR-0002 — Layering and import boundaries

## Status

Accepted.

## Context

The compiler forbids import *cycles* but does not enforce a *direction*. Under
long autonomous development the silent failure mode is leaf-package erosion: a
low-level package grows an upward import, and the architecture quietly inverts
until a cycle finally appears. The original harness template proposed a generic
`interfaces → application → domain ; infrastructure → domain` onion. snaplink
already runs a concrete, narrower direction that matches its actual code.

## Decision

The allowed dependency direction is:

```
handlers (root package sso) → oauth | oidc → security → core
infrastructure (defaultimpl, redis, sqlite, …) → core
```

Invariants (enforced, not aspirational):

1. **`core` imports no internal package** — it is the SPI / types / sentinels
   leaf. Everything may depend on it; it depends on nothing internal.
2. **`oauth` MUST NOT import `oidc`** and **`oidc` MUST NOT import `oauth`** —
   this prevents the `oauth ↔ oidc` cycle. Two pre-existing files
   (`oidc/handle_silent_renewal.go`, `oidc/handle_end_session.go`) import
   `oauth` and are **grandfathered** under a shrink-only ratchet; they are
   one-way, so no compile cycle exists. They should be dissolved via an injected
   interface, not extended.
3. **Nothing imports `cmd/`.**
4. Cross-package coupling that must cross a boundary goes through an **interface
   defined in the lower/destination package** (the hexagonal `Deps` pattern),
   never by reaching back up to the root.

There is deliberately **no fan-in cap** (see ADR-0004): `core` is imported by
~219 files by design.

## Consequences

**Pros**
- The dependency graph stays acyclic and one-directional with a committed proof.
- New shared types have an obvious home (`core`), discouraging root coupling.

**Cons / Risks**
- Renaming `oauth/` or `oidc/` requires editing the gate's literal `fromDir`
  prefixes *in the same commit*, or the cycle guard silently stops matching
  (goes green while no longer enforcing). This is the primary reason ADR-0003
  keeps the protocol packages flat.
- The grandfathered `oidc → oauth` edge is a latent coupling; the ratchet keeps
  it from spreading but it should be retired.

## Enforcement

`architecture_gate_test.go` (`go test -run TestArchitecture_ImportBoundaries
./...`, rides the `race`/`make ci` step) and `python cli.py architecture`
(`checks/architecture.py`). Manifest: [`.arch/rules.yaml`](../../.arch/rules.yaml)
`architecture:`.
