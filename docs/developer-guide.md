# Developer guide

This guide covers the local engineering loop. [`AGENTS.md`](../AGENTS.md) is
the authority for architecture, budgets, wire behavior, and security
invariants.

Snaplink ships an embeddable Go SDK and an API-only server. Browser frontends
are separate projects; do not add static UI assets to this repository.

## Setup

Use the Go version in `go.mod` and Python version in `pyproject.toml`.

```bash
git clone https://github.com/yangwb1123/snaplink
cd sso
go build ./...
go test ./...
```

The default build is pure Go and needs no external SaaS. `make help` lists the
supported workflows.

## Daily loop

After every Go edit:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Run focused package tests while iterating, then choose additional suites by
risk:

| Change | Additional evidence |
|---|---|
| Cross-server HTTP/gRPC behavior | `make test-e2e` |
| Shared backend semantics | `make backend-semantics` |
| Recovery or background failure mode | `make chaos-test` |
| Snapshot/restore or DR | `make dr-drill` |
| Gated hot path | `make bench-gate` |
| Public contract | `make docs-validate && make docs-check` |
| Cold module/profile | `python cli.py modules check`, profile build, and `go version -m` inventory |

Finish with `make ci`. Chaos, DR, load, and benchmark suites are intentionally
opt-in and must be reported when relevant.

## Navigate before editing

| Need | Source |
|---|---|
| Package owner and import direction | [Directory map](architecture/DIRECTORY_MAP.md) |
| Implemented capability and wiring | [Feature matrix](feature-matrix.md) |
| HTTP/config/error contract | [OpenAPI](openapi.yaml), [config](config-reference.md), [errors](error-codes.md) |
| Gate behavior | [Harness](agent-os/HARNESS.md) and [checks registry](agent-os/CHECKS_REGISTRY.md) |
| Review criteria | [Evaluation](agent-os/EVALUATION.md) and [review checklist](review-checklist.md) |
| Cold/hot extension boundary | [Module guide](plugin-system.md) and [ADR-0009](adr/ADR-0009-static-and-runtime-modules.md) |
| Refactor/handler workflow | [Skills](skills/) |

## Implement a change

1. Extend the package that owns the responsibility; avoid a one-off package.
2. Check dependency direction and frozen directory ceilings before adding a
   file or import.
3. Keep Server/transport methods thin and move business behavior to the owning
   domain or protocol package behind a small dependency interface.
4. Test with real `Memory*` implementations. Cross-server flows belong in
   `test/` (`package ssotest`).
5. Update coupled documentation in the same change:
   - new wire error → `docs/error-codes.md`;
   - HTTP route or shape → `docs/openapi.yaml`;
   - configuration → `docs/config-reference.md`;
   - architecture decision → `docs/adr/`.

For a credential or authorization endpoint, also:

- bind OAuth form/JSON through `oauth.BindParams`;
- preserve HTTP Basic precedence where required;
- set no-store headers at entry and the standard Bearer challenge on 401;
- collapse oracle-sensitive failures;
- use atomic consumption for single-use state;
- update discovery when the capability is advertised; and
- test replay, expiry, mismatch, and cross-tenant behavior.

See [`skills/add-new-handler/SKILL.md`](skills/add-new-handler/SKILL.md).

## Common extension points

| Task | Owning path |
|---|---|
| Authenticator | `domains/authenticators` → `config` → `cmd/sso-server/serverbuildauthn` |
| Audit sink | `platform/audit` plus runtime composition |
| Permissions backend | `domains/permissions`; run `permissionstest.ConformanceSuite` |
| gRPC service | `proto/<name>/v1` → generated code → `interfaces/grpcserver` |
| OAuth/OIDC behavior | `protocols/` with a thin `interfaces/sso` adapter |
| Concrete store/integration | `infrastructure/`, using a nested module for heavy optional dependencies |

## Generated engineering scaffolding

`python cli.py generate` validates source-controlled Agent OS, prompt,
checklist, and feature-template Markdown. It may refresh hooks, settings, and
skill symlinks, but it must not overwrite project documentation.

Before handoff, inspect `git diff --check`, record every suite run or skipped,
and keep unrelated worktree changes out of the change.
