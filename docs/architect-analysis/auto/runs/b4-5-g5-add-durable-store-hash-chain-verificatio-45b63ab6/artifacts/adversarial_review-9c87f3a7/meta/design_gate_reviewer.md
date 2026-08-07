Trace complete. The revised design is written to the design artifact the gate consumes:

**`docs/architect-analysis/auto/runs/b4-5-g5-add-durable-store-hash-chain-verificatio-45b63ab6/artifacts/design-a77de8a6/task-1-design.md`** (413 lines, replaces the 19-line v1 summary; v1 kept verbatim in §0 for provenance; doc-only, no `.go` edits, so no build gates triggered).

## How every finding was traced

**§2 revised design** commits the security reviewer's 9 deltas as numbered pins:
- P1/P2 — per-page `Limit = MaxQueryLimit` copied from `pageAll`, `--dsn --limit` default 0 (uncapped); reached cap → `verification incomplete` exit 3, never `chain verified`
- P3 — page errors abort with offset-in-error, never EOF; P6 — same-snapshot completeness cross-check `len(set) == snap.Count()` before `VerifyChain`, else exit 3
- P4a/P4b/P4d — `OpenReadOnly` normalizes to `file:` URI + `mode=ro`, rejects `immutable=1`/`nolock=1`/conflicting mode, appends `_pragma=query_only(1)` + `_pragma=busy_timeout(5000)`, fixes the "append ?mode=ro" help drift
- P5 — one pinned read txn (`Snapshot`) with `ts DESC, rowid DESC`, pages + counts; P7 — L1 `token_issued events: N` from the same-snapshot count, printed only after clean verify; P8 — exit contract 0/1/2/3 with `chain BROKEN` reserved; P9-P9e — single-writer attestation, `-wal` staleness, `_pragma=journal_mode(WAL)` scoping, v0-rejection operator note, tie-break framing correction

**§3** commits the test reviewer's pins: T-1 (seed > MaxQueryLimit + stdout count/head vs `OpenReadOnly`+`LastHash` ground truth), T-2 (`prev_hash` flip past the first page via raw `UPDATE` through `sink.DB()`), T-3, T-4 (>1000-row static parity), T-5 (mixed-type seed, exact K, fewer-arm DELETE → K−1 chain-safe, more-arm verbatim INSERT → export EventCount K+1 while verify exits 1 with no L1 line), **T-6 the required sixth FM-3 test** (deterministic pager seam, concurrent writer, count-at-exit invariant == frozen read, append + delete drift arms, T-6c cross-check trip → exit 3), T-7 (both `postgres://` and libpq keyword arms), T-8 (offset-in-error arm), T-9 (FM-2/FM-4 cited at sink level, `sink_test.go:506/539/563/586`).

**§4 coverage matrix**: 27 rows (SEC-1..13, TEST-1..8, DB-1..6) → 27 committed pins. **§2.9**: all 8 failure modes FM-1..FM-8 with committed verification pins.

## Gate result

Mechanical self-check confirms: 27/27 matrix rows `COMMITTED`, every design pin ref resolves, all 17 pins defined in §2 are referenced (none dangling), FM-1..FM-8 all carry pins + verification pins, verdict is the final plain-text line.

**VERDICT: PASS** — zero orphaned findings, zero failure modes without a committed verification pin; the gate should pass on this artifact. Pre-existing `TestArchitecture_DirectoryDepth`/`_DirectorySubdirFanout` environmental failures remain reported separately and unchanged.
