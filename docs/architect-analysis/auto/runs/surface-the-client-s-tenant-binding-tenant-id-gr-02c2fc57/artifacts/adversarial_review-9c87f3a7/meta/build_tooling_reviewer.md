Resolution complete. Report written to `docs/architect-analysis/auto/runs/surface-the-client-s-tenant-binding-tenant-id-gr-02c2fc57/artifacts/design_gate-6a76b0dd/task-1-proto-regen-resolution.md`.

## Contradiction resolved: both reviewers were right — different facets

| Claim | Measured truth |
|---|---|
| wire: "ran buf 1.59.0 from `~/go/bin`" | `~/go/bin/buf` exists (1.59.0) — explicit path works |
| harness: "`buf: No such file or directory`" | `~/go/bin` is **not on PATH** — bare `buf` (as `make proto-gen`/design §6 runs it) fails exactly so |
| harness: "skew rewrites all 15 gen files" | **Confirmed empirically**: `~/go/bin/protoc-gen-go` = v1.36.11 (go.mod runtime) vs v1.34.1 in all 15 committed `.pb.go` headers; regenerating with it rewrites **15/37 files** (negative control, P2) |
| wire: "regenerated with the repo's pinned toolchain" | **No pin existed**; their env was the skewed one. Their wire-shape conclusions survive (protojson behavior is plugin-version-independent); their regeneration claim did not |
| buf 1.59.0 vs 1.69.0 (CI pin at `ci.yml:349`) | **Immaterial to codegen**: buf 1.59.0 + pinned plugins → zero diff (P3). Pin 1.69.0 for lint/breaking parity |

## Pinned procedure (exact, never `@latest`)

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.1        # committed .pb.go headers
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1        # committed *_grpc.pb.go headers
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.28.0  # go.mod:15
go install github.com/bufbuild/buf/cmd/buf@v1.69.0                     # CI pin
export PATH="$HOME/go/bin:$PATH"    # the missing piece
cd proto && buf generate             # design migration step 1, as written
git add gen/proto/admin/v1
```

## Proof (all executed, in isolated worktrees/scratch — main worktree untouched)

- **P0 baseline**: pinned toolchain + pristine HEAD proto → **zero-byte diff** across all 37 gen files (toolchain reproduces committed gen exactly)
- **P1 R1 delta**: + R1 edit → **exactly 1 of 37 files differs: `clients.pb.go`**; `.gw.go` byte-identical ("+ .gw.go if touched" → not touched); content purely additive (2 struct fields + getters + descriptor bytes)
- **P4 F1 fail-fast**: R1+R2 with stale gen → `go build ./...` fails hard: `admin_clients.go:408:3: unknown field TenantId in struct literal of type adminv1.Client` (exactly the design's F1 row)
- **P5 remedy**: `cd proto && buf generate` (pinned) → build + vet pass; worktree diff = exactly 3 files (proto +6, `clients.pb.go`, mapper +4)
- **P6 gates**: `buf lint` exit 0; `buf breaking --against "../.git#branch=main,subdir=proto"` exit 0; R-1 pin test (`UpdatePreservesFieldsNotInAdminProto`) passes with R2 applied
- **P7**: the 3 root-gate failures (`DirectoryDepth`, `SubdirFanout`, `FileSizeBudget`) reproduce at pristine HEAD — pre-existing, reported separately per AGENTS.md §5.7

## Live hazard note

The main worktree currently sits in the exact F1 state: R1 proto edit applied, gen/ still stale (v1.34.1, no `TenantId`). The next `go build` with the mapper will fail until regen runs with the pin — and running `buf generate` today fails (PATH) or, with `~/go/bin` prepended, silently rewrites all 15 `.pb.go`. The concurrent agent's next step must use the pinned toolchain.
