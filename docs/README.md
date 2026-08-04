# Documentation index

Index of maintained project documentation. Start with the
[root README](../README.md) for integration, or jump to a section below.

## Product boundary and source of truth

`snaplink/sso` is an API-first identity backend. The repository ships the Go
SDK, the `sso-server` runtime, control-plane APIs and operator tools. It does
**not** ship a hosted-login application, admin console, self-service portal,
developer portal or setup wizard UI. Those are separate frontend projects that
call the HTTP APIs and are normally reverse-proxied beside `sso-server`.

Documentation should be read in this order when statements disagree:

1. Runtime route and option wiring in `interfaces/sso` and `cmd/sso-server`.
2. [feature-matrix.md](feature-matrix.md) plus
   [deferred-backlog.md](deferred-backlog.md), the bounded capability baseline.
3. [openapi.yaml](openapi.yaml), the static HTTP contract. A configured
   replica's actual route set is available from the admin-gated
   `GET /api/v1/admin/endpoints` inventory; optional routes only exist when
   their stores/options are wired.
4. [ROADMAP.md](ROADMAP.md), which contains future priorities rather than
   claims about already-shipped behavior.

Retired plans and audits are indexed in [HISTORY.md](HISTORY.md).
Exploratory AI output is ignored by default. Neither is a product commitment.

Keep each fact in its authority above and link to it elsewhere; do not copy
feature, gate, configuration, or error tables into another guide.

## Getting started / integration

- [../README.md](../README.md) — the integration quickstart: the five external
  surfaces (Go SDK, `sso-server` binary, `ssoclient` consumer packages, the
  HTTP/gRPC wire API, the `sso-ctl` CLI) with a copy-pasteable snippet for each.
- [examples/](examples/) — runnable samples. `examples/quickstart` is a single
  `go run` end-to-end demo (embed → PKCE login → token → userinfo → local JWKS
  verify); `examples/basic` shows representative baseline auth methods plus a
  config file;
  `examples/{remote-app,embedded-app,appcore}` show the consumer modes;
  `examples/grpc-client` drives the admin gRPC API.
- [openapi.yaml](openapi.yaml) — the OpenAPI 3 contract for the documented HTTP
  surface. Use the runtime endpoint inventory to distinguish configured
  optional routes from routes that are absent on a particular replica.
- [deployment.md](deployment.md) — build, run, Kubernetes/Compose, the four call
  surfaces, and the **distributed architecture** (cluster Bus, shared-state
  tiers, which modules scale, microservices decomposition).

## Reference

- [commercial-model.md](commercial-model.md) — separation of build editions,
  tenant subscriptions and deployment topology, with the recommended plan and
  quota bands.
- [config-reference.md](config-reference.md) — curated stock-binary YAML reference.
- [error-codes.md](error-codes.md) — the wire error-code catalogue.
- [feature-matrix.md](feature-matrix.md) — supported RFCs / features and their wiring.
- [observability.md](observability.md) — metrics, tracing, audit hash chain, probes.
- [security-policy.md](security-policy.md) — pointers to the authoritative
  vulnerability-reporting policy and the technical security architecture.
- [wasmauthz.md](wasmauthz.md) — the pluggable WASM authorization engine: ABI
  contract, how to author a compatible policy module, fail-closed guarantee.
- [plugin-system.md](plugin-system.md) — NGINX-style cold build profiles,
  compiled module inventory, and the generation/drain boundary for future hot
  activation.

## Architecture

- [architecture/DIRECTORY_MAP.md](architecture/DIRECTORY_MAP.md) — the layered
  tree (`composition → interfaces → infrastructure → protocols → domains → platform → shared`)
  and where each package lives.
- [adr/](adr/) — Architecture Decision Records (ADR-0001 layout … ADR-0009
  module builds and safe runtime activation); see [adr/README.md](adr/README.md).
- [HISTORY.md](HISTORY.md) — retired migration records, implementation plans,
  feature records, and documentation audits.

## Development

- [../AGENTS.md](../AGENTS.md) — the master operational guide: code budgets,
  dependency direction, root policy, global protocol invariants (oracle-leak /
  anti-enumeration / fail-closed), and the coding conventions. **§0 gates are
  hard gates.** Both human and AI contributors should read this first.
- [developer-guide.md](developer-guide.md) — first-time setup, the daily
  workflow, make/`cli.py` targets, and common tasks.
- [maintainability-gates.md](maintainability-gates.md) — the committed
  guardrail tests (per-file size, per-function complexity/length, directory
  fan-out + depth, import boundaries, layer boundaries) and the ratchet rule.
- [review-checklist.md](review-checklist.md) — what to check before merging.
- [templates/feature-spec.md](templates/feature-spec.md) — the feature-spec template.
- [skills/](skills/) — focused refactor/architecture playbooks (split a large
  file, reduce complexity, hexagonal extraction, add a handler, oracle-leak review).

## Operations & process

- [RELEASE.md](RELEASE.md) — the release process and distributed artifacts.
- [CHANGELOG.md](../CHANGELOG.md) — release history.
- [ROADMAP.md](ROADMAP.md) — current priorities and explicit non-goals.

## Agent OS (AI-agent harness)

The autonomous-development support stack, mostly machine-oriented:
[agent-os/](agent-os/) — `BOOTSTRAP`, `ARCHITECTURE`, `HARNESS`, `EVALUATION`,
`CHECKS_REGISTRY`, `TODO`. See AGENTS.md's "Agent OS" header for the read order.
