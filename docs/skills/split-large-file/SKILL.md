# Skill: Split a large file

**Trigger:** A production Go file exceeds 500 lines, or a change would cross
that limit.

**Analyzer:** `python docs/skills/split-large-file/run.py <file>` lists exported
functions; it does not edit files.

## Steps

1. Map top-level declarations and references with `rg`.
2. Group declarations by cohesive responsibility.
3. Move each group to a clearly named file in the same package.
4. Preserve symbol names, ordering-sensitive behavior, wire errors, and
   security gate order.
5. If the package is also at a frozen directory file-count ceiling, do not add
   another sibling file: combine with an existing cohesive file or extract a
   lower-layer package.
6. Do not add a file-size exemption. The committed exemption map is empty.
7. Remove an existing directory exemption only when the measured directory is
   back within its base limit.

## Verify

```bash
gofmt -w <changed-go-files>
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
```
