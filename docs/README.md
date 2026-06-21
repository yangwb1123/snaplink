# Documentation index

Map of everything under `docs/` (plus the cross-cutting root docs). Start with
the [root README](../README.md) for integration, or jump to a section below.

## Getting started / integration

- [../README.md](../README.md) — the integration quickstart: the five external
  surfaces (Go SDK, `sso-server` binary, `ssoclient` consumer packages, the
  HTTP/gRPC wire API, the `sso-ctl` CLI) with a copy-pasteable snippet for each.
- [examples/](examples/) — runnable samples. `examples/quickstart` is a single
  `go run` end-to-end demo (embed → PKCE login → token → userinfo → local JWKS
  verify); `examples/basic` shows all auth methods + a config file;
  `examples/{remote-app,embedded-app,appcore}` show the consumer modes;
  `examples/grpc-client` drives the admin gRPC API.
- [openapi.yaml](openapi.yaml) — the OpenAPI 3 contract for the HTTP surface.
- [deployment.md](deployment.md) — build, run, Kubernetes/Compose, the four call
  surfaces, and the **distributed architecture** (cluster Bus, shared-state
  tiers, which modules scale, microservices decomposition).

## Reference

- [config-reference.md](config-reference.md) — every `config.yaml` key (server binary).
- [error-codes.md](error-codes.md) — the wire error-code catalogue.
- [feature-matrix.md](feature-matrix.md) — supported RFCs / features and their wiring.
- [observability.md](observability.md) — metrics, tracing, audit hash chain, probes.
- [security-policy.md](security-policy.md) — the security model and reporting.

## Architecture

- [architecture/DIRECTORY_MAP.md](architecture/DIRECTORY_MAP.md) — the layered tree
  (`shared < platform < domains < protocols < infrastructure < interfaces`) and
  where each package lives.
- [adr/](adr/) — Architecture Decision Records (ADR-0001 layout … ADR-0006
  cognitive architecture); see [adr/README.md](adr/README.md).
- [architecture/V2-MIGRATION.md](architecture/V2-MIGRATION.md) — the layered-topology migration notes.

## Development

- [../AGENTS.md](../AGENTS.md) — the master operational guide: code budgets,
  dependency direction, root policy, global protocol invariants (oracle-leak /
  anti-enumeration / fail-closed), and the coding conventions. **§4 gates are
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

- [RELEASE.md](RELEASE.md) — the release process (goreleaser, two binaries).
- [CHANGELOG.md](CHANGELOG.md) — release history.
- [ROADMAP.md](ROADMAP.md) / [migration-roadmap.md](migration-roadmap.md) — planned + historical work.

## Agent OS (AI-agent harness)

The autonomous-development support stack, mostly machine-oriented:
[agent-os/](agent-os/) — `BOOTSTRAP`, `ARCHITECTURE`, `HARNESS`, `EVALUATION`,
`CHECKS_REGISTRY`, `TODO`. See AGENTS.md's "Agent OS" header for the read order.
