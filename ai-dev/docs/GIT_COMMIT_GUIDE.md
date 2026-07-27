# Commit Guide

This repository uses Conventional Commits and requires imperative subjects:

```text
<type>(<area>): <imperative summary>
```

Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, and
`deploy`. The body should explain why the change is necessary and any security,
wire-contract, migration, or compatibility consequence.

## Before committing

1. Review `git status --short` and the scoped diff.
2. Run tests proportionate to the change. Go changes require the post-edit
   checks in `AGENTS.md`; merge-ready changes require `make ci`.
3. Confirm contract-coupled documentation changed with the code:
   - new `Err*` → `docs/error-codes.md`;
   - endpoint change → `docs/openapi.yaml`;
   - config change → `docs/config-reference.md`;
   - architecture-rule change → an ADR.
4. Stage only files belonging to the commit and inspect `git diff --cached`.
5. Add the DCO sign-off when required:

```bash
git commit -s -m "fix(oauth): preserve refresh-family replay semantics"
```

## AI-SDLC output

Review output from `ai-dev/` is advisory. Commit it only after a human or
responsible agent verifies every material claim against the current tree and
promotes accepted work into the bounded requirements baseline. Do not commit
bulk speculative reports as product commitments.

## Auto-commit helper

`ai-dev/git-auto-commit.sh` stages the entire worktree and can push. Read
[`GIT_AUTO_COMMIT_GUIDE.md`](GIT_AUTO_COMMIT_GUIDE.md) before using it; a scoped
manual commit is safer when other changes are present.
