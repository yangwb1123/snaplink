# Architecture Decision Records

ADRs capture the *why* behind snaplink's structural rules so that long-running,
largely autonomous (AI-agent-driven) development doesn't silently re-litigate or
erode them. They are descriptive of decisions already in force — the machine
enforcement lives in the committed `*_test.go` gates and `checks/*.py`
(see [`.arch/rules.yaml`](../../.arch/rules.yaml) for the index, and
[`docs/maintainability-gates.md`](../maintainability-gates.md) for the gate mechanics).

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](ADR-0001-directory-layout.md) | Flat library layout; root holds composition only; no `domains/application/infrastructure` retree | Accepted |
| [ADR-0002](ADR-0002-layering-and-import-boundaries.md) | Dependency direction `handlers → oauth/oidc → security → core`; `core` is a leaf | Accepted |
| [ADR-0003](ADR-0003-protocol-grouping.md) | Keep `oauth/oidc/saml/scim` flat at their public import paths | Accepted |
| [ADR-0004](ADR-0004-domain-boundaries.md) | SPI-per-concern + per-backend impls (`memory`/`sqlite`/`etcd`/`redis`); no mocks where `Memory*` exists | Accepted |
| [ADR-0005](ADR-0005-size-and-complexity-budgets.md) | File ≤500, cyclo ≤15, cognit ≤20, func ≤50; ratcheting; enforced as committed tests not shell stubs | Accepted |
| [ADR-0006](ADR-0006-cognitive-architecture.md) | Seven-layer cognitive model enforced as a committed gate over the flat tree (no public-path moves) | Accepted |
| [ADR-0007](ADR-0007-directory-fanout-and-the-monolith-exemption-class.md) | Per-directory fan-out budget (≤10 files); permanent exemption class for monolithic-shared-state / binary-root / depth-blocked / kernel dirs — never break a published import path to chase it | Accepted |

## Writing a new ADR

Copy the structure of an existing record (Status / Context / Decision /
Consequences). Number sequentially. An ADR is required *before* any change that
would alter a rule in `.arch/rules.yaml`, add a top-level directory, or move a
package's public import path — per the "Refactoring Rules" in AGENTS.md.
