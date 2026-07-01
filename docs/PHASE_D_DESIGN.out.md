I've read the Phase D design doc and surveyed the actual implementation. Here's the status gap:

**The design doc says:** *"D-1 implemented; D-2 / D-3 design only"*

**The codebase says all three are implemented:**

| Phase | Location | Non-test Go | Backends / Plugins | Proto |
|-------|----------|-------------|--------------------|-------|
| D-1 (Lock) | `platform/bootstrap/lock*` | 649 lines | noop / file / etcd | — (Runner integration) |
| D-2 (Snapshot) | `interfaces/snapshot/` | 2,597 lines | JSON codec, aesgcm/none/passphrase encryption, file/inline storage, loader | `snapshots_grpc.pb.go` |
| D-3 (Releases) | `platform/releases/` | 1,121 lines | noop/docker/static pinners, file/memory stores, http probe | `releases_grpc.pb.go` |

No `TODO`/`FIXME`/`PLACEHOLDER` markers in the D-2 or D-3 source trees — they look fully fleshed out, not stubs.

**The "Today" column in the per-layer architecture table also needs updating** — Snapshot shows `(planned)` and Releases shows `(planned)` but both have real backends wired in.

What would you like me to do with this? A few options:

1. **Update the design doc** — refresh the status line and the per-layer table to reflect actual implementation
2. **Verify the builds/tests pass** — `go build ./...`, `go vet`, run the Phase D tests
3. **Audit the implementations against the design** — check that the code matches every invariant in the doc (restore ordering, encryption defaults, pin ordering, etc.)
4. **Update AGENTS.md** — add the condensed Capabilities section the doc says will land "once each piece lands"
5. Something else — just tell me what you need
