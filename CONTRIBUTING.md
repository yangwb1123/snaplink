# Contributing to snaplink/sso

Thank you for contributing. Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
and read [`AGENTS.md`](AGENTS.md) before editing; it is the authority for code,
security, architecture, and commit rules.

## Quick start

```bash
git clone <your-fork>
cd sso
go build ./...
go test ./... -race
make ci
git commit -s -m "feat(scope): describe the change"
```

The root module is pure Go by default. Optional integrations and tools under
`infrastructure/` and `cmd/` may have their own `go.mod`; `make ci-modules`
builds those nested modules. There is deliberately no `go.work`.

For local workflows and proportional test selection, see the
[developer guide](docs/developer-guide.md).

## Before opening a change

- Security vulnerabilities must use the private process in
  [`.github/SECURITY.md`](.github/SECURITY.md), never a public issue.
- Bugs should include a commit/version, minimal reproducer, expected/actual
  behavior, and redacted configuration.
- Discuss new public API or product scope in an issue before implementation.
- UI work belongs to the separately deployed frontend projects; this
  repository provides the API backend.

## Pull requests

1. Keep one concern per PR and preserve unrelated worktree changes.
2. Add tests for new behavior and use the real memory/backend
   implementations rather than mocks.
3. Run the post-edit gates from `AGENTS.md`, the relevant risk-based suites,
   and `make ci`.
4. Update contract documentation with code: OpenAPI for HTTP, the error
   catalog for wire errors, the configuration reference for settings, and an
   ADR for architectural decisions.
5. Use a Conventional Commit title with an imperative summary. The body
   explains why and calls out compatibility, migration, security, or wire
   consequences.

Hosted CI adds lint, security, protocol-breaking, OpenAPI, container, and
infrastructure checks to the local `make ci` baseline.

## Review

A maintainer approval is required. Changes to protobuf wire formats, audit,
bootstrap/snapshot integrity, or cryptographic code require two approvals.
Review comments are marked blocking, nit, or suggestion; only blocking
comments prevent merge.

Squash merge is the default, so the PR title and description must be suitable
as the final commit message.

## DCO sign-off

Every commit must carry a Developer Certificate of Origin sign-off:

```bash
git commit -s -m "fix(oauth): preserve refresh-family replay semantics"
```

Do not bypass hooks, rewrite shared history, or use destructive Git commands
without authorization.

## Do not send

- unrelated formatting or cleanup mixed into a feature;
- dependencies without a justified use case and supply-chain review;
- speculative public APIs for private experiments;
- generated binaries, secrets, or unreviewed AI output; or
- documentation claims that were not verified against current code.

For searchable development questions, use GitHub Discussions. For implementation
details, see [the documentation index](docs/README.md).
