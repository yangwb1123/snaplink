# Skill: Post-edit verification

**Trigger:** After every Go edit.

Use the committed fail-fast loop:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

`python docs/skills/post-edit-check/run.py` delegates to `make check-quick`,
which exercises only the Python file-size path plus vet; it does not replace
the committed root gates above.

Before handoff, run `make ci` and the risk-specific backend, chaos, DR, load, or
benchmark suite.
