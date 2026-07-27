# BOOTSTRAP.md — Project context

Snaplink is an OAuth 2.0/OIDC identity backend delivered as an embeddable Go
SDK (`interfaces/sso`) and an API-only `sso-server`. Optional protocol,
connector, KMS, operator, and MCP integrations live in nested modules. Browser
frontends are separate projects.

Cold-start verification:

```bash
go build ./...
go test ./... -race
make ci
```

Read in this order:

1. `AGENTS.md` — mandatory behavior, security, and gate rules.
2. `docs/architecture/DIRECTORY_MAP.md` — canonical package ownership.
3. `docs/agent-os/HARNESS.md` — committed gate meaning.
4. `docs/agent-os/EVALUATION.md` — acceptance criteria by change type.
5. `docs/agent-os/CHECKS_REGISTRY.md` — Python/Make command catalog.
6. `docs/feature-matrix.md` and `docs/deferred-backlog.md` — bounded product
   baseline.

Default memory/SQLite compositions need no external SaaS. Multi-replica
deployments require shared state according to `docs/deployment.md`.
