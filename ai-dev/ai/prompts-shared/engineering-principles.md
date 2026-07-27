# Snaplink engineering principles

Read [`AGENTS.md`](../../../AGENTS.md) completely before reviewing. It is the
authority for numeric budgets, dependency direction, oracle-safe behavior,
anti-enumeration, fail modes, wire contracts, proxy trust, tenant isolation,
key handling, and coding conventions. This file intentionally does not copy
those rules.

Use the following evidence:

| Concern | Authority |
|---|---|
| Numeric policy | `engineering.yaml` |
| Enforced architecture/maintainability | Root `package archgate` tests |
| Package ownership | `docs/architecture/DIRECTORY_MAP.md` |
| Security design and operations | `docs/SECURITY.md` |
| HTTP/config/errors | `docs/openapi.yaml`, `docs/config-reference.md`, `docs/error-codes.md` |
| Implemented/deferred product scope | `docs/feature-matrix.md`, `docs/deferred-backlog.md` |

Review current code and tests, not historical plans or generated reports.
Classify every claim as SDK, stock binary, nested module, or external frontend.
A policy/enforcer mismatch is a tooling defect; it is not permission to select
the weaker rule or add an exemption.
