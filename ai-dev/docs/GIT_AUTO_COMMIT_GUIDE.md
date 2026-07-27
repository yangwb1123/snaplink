# Git Auto-Commit Helper

`ai-dev/git-auto-commit.sh` is an optional interactive helper. It displays the
worktree, runs `git add -A`, creates one commit, and optionally runs
`git push`.

## Safety boundary

The helper stages **all tracked and untracked changes in the repository**. Use
it only when:

- the worktree contains only changes that belong in one commit;
- `git status --short` and `git diff` have been reviewed;
- no secrets, generated binaries, unrelated user changes, or exploratory AI
  output are present; and
- the relevant tests and `make ci` have passed.

It does not select files, create a branch, add a DCO sign-off, or determine
whether pushing is authorized. Contributors subject to the DCO should prefer a
scoped manual commit:

```bash
git status --short
git diff -- path/to/file1 path/to/file2
git add path/to/file1 path/to/file2
git diff --cached
git commit -s -m "docs(area): describe the change"
```

## Running the helper

```bash
./ai-dev/git-auto-commit.sh "docs(area): describe the change"
```

Do not rely on its timestamp-based default message for project commits; use the
Conventional Commit format defined in `AGENTS.md`.

## Recovery

Do not use `git reset --hard`, force-push, or broad restore commands to recover
from a mistaken commit. First inspect the exact state:

```bash
git status
git show --stat --oneline HEAD
git diff HEAD^ HEAD -- path/to/file
```

Choose a targeted, recoverable operation or ask a maintainer when the commit has
already been shared.

## Related documentation

- [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)
- [`../../AGENTS.md`](../../AGENTS.md)
- [`GIT_COMMIT_GUIDE.md`](GIT_COMMIT_GUIDE.md)
