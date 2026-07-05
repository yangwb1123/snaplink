# Contributing to snaplink/sso

Thanks for your interest. This file covers the contributor-facing
process. **For day-to-day development conventions** (commit style,
coding rules, "things not to do" list, repository layout, capability
catalog) read [`AGENTS.md`](AGENTS.md) — that's the source of truth
and is significantly more detailed than this file. Everyone
participating is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## TL;DR

```bash
git clone <your-fork>
cd sso
go build ./...                # compiles everything
go test ./... -race           # unit + integration tests, race detector on
make ci                       # gofmt + vet + race + build + proto-lint + ci-modules
# write code
make ci                       # again, must stay green
git commit -s -m "feat(scope): one-line summary"
gh pr create
```

## Build & test commands

| Command | What it does |
|---|---|
| `go build ./...` | Compiles every package in the root module. |
| `go test ./... -race` | Unit + integration tests (`package ssotest` under `test/`), race detector on. |
| `go test ./test/ -run TestE2E -v` | Cross-wired HTTP + JWKS + bufconn end-to-end suite. |
| `make ci` | Full local gate: gofmt + `go vet` + `-race` tests + build + example apps + proto-lint + nested-module build/test + config validation. Mirrors what CI runs. |
| `make dev` | Hot-reload dev loop for `cmd/sso-server` (see "Local dev loop" below). |
| `python cli.py check` / `make check-quick` | Fast post-edit check (file-size + `go vet`) — run this after every edit, before the full suite. |

`go.mod` has no external SaaS dependencies and pure-Go (no CGO) default
backends; nested modules under `kms/*`, `saml/`, `ldap/`, `kerberos/`,
`radius/`, `extauthz/`, `redis/` each carry their own `go.mod` and are
built/tested separately (`make ci-modules`; no `go.work` on purpose —
see the comment at the top of `.github/workflows/ci.yml`).

## Hard gates (AGENTS.md §0 — violations are regressions, not style nits)

Every change is held to these committed, CI-enforced budgets:

- **File size** — `.go` files ≤ 500 lines. Over budget → split first,
  don't append (`docs/skills/split-large-file/SKILL.md`).
- **Function size** — ≤ 50 lines; **cyclomatic complexity** ≤ 15;
  **if-nesting depth** ≤ 3 (guard clauses / early return instead).
- **Directory depth** ≤ 3; ≤ 10 Go files per directory; ≤ 15 subdirs
  per directory.
- **Dependency direction** — imports point one-way toward the shared
  kernel (`interfaces/* → protocols/* → shared/security → shared/core`).
  No upward import, no `protocols/oauth ↔ protocols/oidc`, nothing
  imports `cmd/`.
- **Never widen an exemption list** to grandfather a new violation —
  the maintainability exemption lists are count-capped and only
  shrink.

Run `go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
after any `.go` change — these are the same committed tests CI runs
(part of `make ci`'s `race` target). See
[`AGENTS.md` §0](AGENTS.md#0-engineering-principles-hard-gates) and
[`docs/maintainability-gates.md`](docs/maintainability-gates.md) for
the full rationale and the refactor playbooks under `docs/skills/`.

## Local dev loop

For iterating on `cmd/sso-server` with automatic rebuild-and-restart on
save, use [air](https://github.com/air-verse/air) via `make dev` (or
`go run github.com/air-verse/air@latest -c .air.toml` directly) — it is
fetched on demand like the other `go run <tool>@latest` invocations in
this `Makefile` (`proto-lint`, `docs-validate`, `release-check`), so it
is **not** a `go.mod` dependency. See `.air.toml` at the repo root for
the watched paths and build command.

Config changes to a *running* process (without a rebuild) can instead
use `SIGHUP`-triggered hot reload — see `config/reload` (currently
wires `logging.level` live; everything else needs a restart, by
design — see that package's doc comment for why).

## Reporting issues

- **Security vulnerabilities** — do NOT open a public issue. Follow
  [`.github/SECURITY.md`](.github/SECURITY.md).
- **Bugs** — open a GitHub issue. Include version / commit SHA,
  minimal reproducer, expected vs actual, and any relevant config
  (with secrets redacted).
- **Feature requests** — open a GitHub issue describing the use case
  *first*. Drive-by PRs adding new public API surface without prior
  discussion are likely to be sent back for design iteration.

## Development setup

The full setup walkthrough lives in [`AGENTS.md` §"Setup commands"](AGENTS.md#setup-commands).
Short version:

- Go (version pinned in `go.mod`)
- Python ≥ 3.12 (`pyproject.toml`) — the engineering CLI (`cli.py`)
  that `make harness` / `make check` / `make generate-engineering`
  shell out to
- `make` for the standard task bundle
- Docker (optional, for `make docker` and the CI smoke job locally)
- `kubectl` (optional, for `deploy/k8s/`)
- `buf` is fetched on demand via `go run` — no local install required

A ready-to-use environment with all of the above is provided by
[`.devcontainer/`](.devcontainer/) (VS Code Dev Containers / GitHub
Codespaces) — opening the repo in the devcontainer runs `go build
./...` once via `postCreateCommand` to warm the module cache.

## Submitting a pull request

1. **Fork + branch** — branch names are not enforced; descriptive
   helps (`feat/sql-user-provider`, `fix/jwks-cache-race`).
2. **One concern per PR** — multiple commits inside a PR are fine, but
   each PR should have one focus. A "while I was in there" cleanup
   PR is easier to review than the same cleanup tangled with a
   feature.
3. **Tests** — every new behavior gets a test in the same package.
   See [`AGENTS.md` §"Test instructions"](AGENTS.md#test-instructions)
   for the coverage convention (informational, not a gate).
4. **`make ci`** must stay green locally before pushing. CI runs the
   same checks; failing CI on a fixable thing slows everyone down.
5. **Conventional commits** — `<type>(scope): summary` (see [§"Commit
   conventions" in AGENTS.md](AGENTS.md#commit-conventions)).
   Common types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`,
   `ci`, `deploy`. Imperative subject, body explains *why*.

## Review process

- PRs require a maintainer LGTM. Two LGTMs for changes touching:
  - `proto/` (wire format)
  - `audit/` (compliance surface)
  - `bootstrap/` or `snapshot/` (data integrity)
  - cryptographic code (`defaultimpl/ed25519_*`,
    `snapshot/encryption/`, `authenticators/keypair`,
    `authenticators/certificate`)
- Reviewers will tag concerns as **blocking**, **nit**, or
  **suggestion**. Only blocking comments must be addressed before
  merge; the rest are optional.
- Squash-merge is the default; the squashed commit message inherits
  the PR title + description, so make the title PR-quality.

## DCO / Sign-off

We use the Developer Certificate of Origin (DCO) — each commit must
be signed-off:

```bash
git commit -s -m "feat(scope): summary"
```

This adds a `Signed-off-by:` trailer affirming you have the right to
contribute the change under the project's license (Apache 2.0, see
[`LICENSE`](LICENSE)).

CI will block merges of unsigned commits. To retroactively sign past
commits:

```bash
git rebase --signoff HEAD~N
```

## Coding conventions

The full list is in [`AGENTS.md` §"Conventions"](AGENTS.md#conventions).
Highlights:

- **No literals leak** — paths / headers / error codes go in
  `consts.go` (root or per-package).
- **Comments explain *why*, not *what***. Reach for one only when
  there's a hidden constraint a future reader would otherwise
  reverse-engineer.
- **No mocks for storage** — tests use the real `MemoryProvider` /
  `MemorySink` / `memory.Registry`. Mocks invite test↔prod drift.
- **No emojis** in code, comments, or commits.

## What NOT to send

- Drive-by reformatting of unrelated files (use a focused `chore:
  gofmt` if you must).
- New dependencies without a use case justifying the supply-chain
  cost — open an issue first.
- Public API additions to make a private experiment easier — keep
  experiments in your fork.
- AI-generated PRs without human review of every line. Tools welcome;
  unreviewed bot PRs not.

## Questions

For development questions, prefer GitHub Discussions over private
emails so future contributors can search the same answer. For
security, see [`.github/SECURITY.md`](.github/SECURITY.md).
