# ADR-0004 — Domain boundaries: SPI-per-concern, per-backend impls, no mocks

## Status

Accepted.

## Context

snaplink ships as an embeddable SDK with **no external SaaS dependencies**.
Every concern (User/Client/Session/Token store, Authenticator, TokenIssuer,
RiskScorer, Bus, …) must be swappable by the embedder. The risk under
autonomous development is two-fold: (a) concrete infrastructure leaking into
domain logic, and (b) test doubles drifting from real behavior.

## Decision

1. **Every concern is an interface (an SPI) plus at least one real
   implementation.** Interfaces and shared types live in `core/` (or the owning
   domain package); implementations live in `defaultimpl/` and the per-backend
   packages.
2. **Per-backend implementations are parallel packages**, not branches inside
   one file: `memory` (always), and `sqlite` / `etcd` / `redis` / `file` /
   `vaulttransit` / `kms` where applicable. Each is a self-contained adapter.
3. **No mocks where a `Memory*` implementation exists.** Tests use the real
   `MemoryProvider` / `MemorySink` / `memory.Registry` etc. This keeps tests
   honest about real behavior (ordering, error paths, fail-open/closed).
4. **No fan-in cap.** A shared SPI/types kernel is *supposed* to be widely
   imported; `core <- ~219` files and `audit <- ~160` are healthy cohesion, not
   smells. God-object risk is policed by fan-OUT discipline (the root cannot
   hold business logic, ADR-0001) and by the size/complexity budgets (ADR-0005),
   not by penalizing reuse.
5. **Nested modules** (`saml/`, `ldap/`, `kerberos/`, `radius/`, `extauthz/`,
   `redis/`, `kms/*`) keep their own `go.mod` — that boundary *is* the
   isolation seam for their heavy/optional third-party deps. They are built and
   tested via `make ci-modules`.

## Consequences

**Pros** — embedders can replace any concern; tests exercise real code paths;
optional heavy deps stay quarantined behind module boundaries.

**Cons** — more packages and more `go.mod` files to build (handled by
`ci-modules`); contributors must place new shared types in `core`, not root.

**Risks** — a new concern implemented only as a mock, or with infra types in the
domain package. Mitigated by the convention plus `python cli.py
check-invariants` and code review (`docs/review-checklist.md`).

## Enforcement

Convention + `python cli.py check-invariants` (`checks/invariants.py`) +
ADR-0002 boundary gate. Module map of record: `AGENTS.md` §2. Manifest:
[`.arch/rules.yaml`](../../.arch/rules.yaml) `fanin:`.
