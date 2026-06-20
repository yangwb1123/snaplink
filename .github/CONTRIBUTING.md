# Contributing to snaplink/sso

Thanks for your interest. This file covers the contributor-facing
process. **For day-to-day development conventions** (commit style,
coding rules, "things not to do" list, repository layout, capability
catalog) read [`AGENTS.md`](../AGENTS.md) — that's the source of truth
and is significantly more detailed than this file.

## TL;DR

```bash
git clone <your-fork>
cd sso
make ci            # gofmt + vet + race + build + proto-lint
# write code
make ci            # again, must stay green
git commit -m "feat(scope): one-line summary"
gh pr create
```

## Reporting issues

- **Security vulnerabilities** — do NOT open a public issue. Follow
  [`SECURITY.md`](SECURITY.md).
- **Bugs** — open a GitHub issue. Include version / commit SHA,
  minimal reproducer, expected vs actual, and any relevant config
  (with secrets redacted).
- **Feature requests** — open a GitHub issue describing the use case
  *first*. Drive-by PRs adding new public API surface without prior
  discussion are likely to be sent back for design iteration.

## Development setup

The full setup walkthrough lives in [`AGENTS.md` §"Setup commands"](../AGENTS.md#setup-commands).
Short version:

- Go (version pinned in `go.mod`)
- `make` for the standard task bundle
- Docker (optional, for `make docker` and the CI smoke job locally)
- `kubectl` (optional, for `deploy/k8s/`)
- `buf` is fetched on demand via `go run` — no local install required

## Submitting a pull request

1. **Fork + branch** — branch names are not enforced; descriptive
   helps (`feat/sql-user-provider`, `fix/jwks-cache-race`).
2. **One concern per PR** — multiple commits inside a PR are fine, but
   each PR should have one focus. A "while I was in there" cleanup
   PR is easier to review than the same cleanup tangled with a
   feature.
3. **Tests** — every new behavior gets a test in the same package.
   See [`AGENTS.md` §"Test instructions"](../AGENTS.md#test-instructions)
   for the coverage convention (informational, not a gate).
4. **`make ci`** must stay green locally before pushing. CI runs the
   same checks; failing CI on a fixable thing slows everyone down.
5. **Conventional commits** — `<type>(scope): summary` (see [§"Commit
   conventions" in AGENTS.md](../AGENTS.md#commit-conventions)).
   Common types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`,
   `ci`, `deploy`.

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
[`LICENSE`](../LICENSE)).

CI will block merges of unsigned commits. To retroactively sign past
commits:

```bash
git rebase --signoff HEAD~N
```

## Coding conventions

The full list is in [`AGENTS.md` §"Conventions"](../AGENTS.md#conventions).
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
security, see [`SECURITY.md`](SECURITY.md).
