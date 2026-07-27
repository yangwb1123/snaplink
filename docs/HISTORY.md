# Documentation history

This index replaces retired plans and point-in-time audit reports. Those files
described an implementation moment; they are not current requirements,
runbooks, or release evidence.

## Current authorities

| Question | Source |
|---|---|
| What the product implements | [Feature matrix](feature-matrix.md) |
| What is intentionally open or unsupported | [Deferred backlog](deferred-backlog.md) |
| What is planned next | [Roadmap](ROADMAP.md) |
| HTTP and configuration contracts | [OpenAPI](openapi.yaml) and [configuration reference](config-reference.md) |
| Package ownership and architecture | [Directory map](architecture/DIRECTORY_MAP.md) and [ADRs](adr/) |
| Engineering invariants | [AGENTS.md](../AGENTS.md) and [Agent OS](agent-os/) |
| Technical security behavior | [Security architecture](SECURITY.md) |

Runtime wiring and executable tests remain authoritative when documentation
and code disagree.

## Retired records

| Area | Former documents | Current location or outcome |
|---|---|---|
| Layered-tree migration | `docs/architecture/V2-MIGRATION.md`, `docs/migration-roadmap.md` | Migration completed. Use the directory map and ADR-0001/0003/0006. |
| Bare-metal HA design | `docs/superpowers/specs/2026-06-26-baremetal-ha-data-layer-design.md`, matching implementation plan | Current status and blockers are in [the deployment README](../ops/deploy/baremetal-ha/README.md) and [runbook](../ops/deploy/baremetal-ha/RUNBOOK.md). |
| MCP gateway design | `docs/superpowers/specs/2026-06-29-sso-mcp-design.md`, matching implementation plan | Implemented as a nested module; see [cmd/sso-mcp/README.md](../cmd/sso-mcp/README.md). |
| July 2026 implementation waves | implementation roadmap, Wave 1 plan, Wave 2 tranche index | Superseded by the current feature matrix, backlog, and roadmap. |
| Documentation audits | `docs/docs-audit-feature-inventory.md`, `docs/docs-audit-implementation-detail.md` | Candidate findings were either incorporated into current authorities or retired as stale. |
| Completed feature records | Federation resolve endpoint and security-documentation authority records | Federation is covered by the feature matrix/OpenAPI; reporting policy and technical security have separate authorities. |
| Expanded user-API example | `docs/requirements/example-user-api.md` | Replaced by a compact pipeline seed; real proposals use [the feature-spec template](templates/feature-spec.md) and [evaluation criteria](agent-os/EVALUATION.md). |

## Retrieving an archived file

The complete content remains in Git history:

```bash
git log --all -- <former-path>
git show <commit>:<former-path>
```

Before reviving a historical proposal, verify it against the current tree and
promote only confirmed work into the feature matrix, deferred backlog, roadmap,
OpenAPI, or configuration reference as appropriate.
