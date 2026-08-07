Verification complete. All four gates confirmed, three real gaps found and fixed in `design.md` (7 edits, documentation only; no `.go` files touched).

## 1. os.Exit blocker — resolved in the design

- `auditverify/main.go` is 240 lines with `usageErr` (230) / `errorf` (237) calling `os.Exit` — the blocker was real: AC-4/7a/7d/F1/F2/F5/F6/F12 exit codes would kill the test binary.
- Design §3.1 now specifies Run-return routing: new failure paths print and `return` 2/1 from `Run`; binary behavior is unchanged because `cmd/sso-ctl/main.go:72` does `os.Exit(run(args))` (verified in HEAD). AC-8 documents the legacy `os.Exit` paths as explicitly out of the lockable set.
- **Caveat found**: the auditexport precedent (`--anchor`, `loadCheckpoint` 270, `enforceAnchorHead` 290, "never calls os.Exit") is **uncommitted worktree state** — HEAD's auditexport is 294 lines with `os.Exit(2)/os.Exit(1)` and no anchor flags. I amended the §1 row to say so: it's a pattern reference; the hard dependency (`main.go:72`) is in HEAD.

## 2. main.go budget — confirmed

240 → ~335 lines is sound (~95-line delta: 2 flags, 3 helpers ≈ 55, Run routing ≈ 25, loaders ≈ 10). Added an §8 estimate-band note: the 305-vs-335 drift is doc-only; even +10% overrun (~370) leaves ~130 lines under the 500 cap.

## 3. Zero kernel changes — confirmed with exact gate numbers

- `chainer.go` = exactly 500 lines = `maxFileLines` (empty exemption map) — verified.
- `platform/audit` = exactly 16 non-test files = frozen `dirFileCountExemptions["platform/audit"]=16` — verified.
- `cmd/sso-ctl` = 16/16 subdirs (`maxSubdirsPerDir=16`), test files excluded from fan-out — verified.
- Design consumes only exported HEAD symbols (`VerifyChain`, `VerifyChainAgainstCheckpoint`, `VerifyCheckpointSignature`, `GenesisHash`, `SignedCheckpoint`); empty-chain path verified mechanically (`verifyChainFrom([])` returns nil → the chainer's empty-set rule at 480–484 is reachable).

## 4. Every AC in-process testable — confirmed, with two gaps fixed

Fixtures verified at cited lines: `chainedEvents` (main_test.go:174), `captureStdout`/`captureStderr` (coverage_test.go:156/197, same package), `NewEd25519CheckpointSigner` (exported; notary_test.go:51), `resignCheckpoint`/`genesisCheckpoint`/`writeCheckpoint` (auditexport/main_test.go:487–549). The GenesisHash guard for the empty-chain print was already specified (reviewer amendment) — I verified it against the F10/AC-6a line and the `events[-1]` panic it prevents.

**Gaps I found and fixed:**
- **AC-9 URL variant was unimplementable as specced**: "probe one extra page past the cap" misses the over-captured-page case (server with 6 events, `--limit 5`, default page size → probe at pre-slice offset returns empty → truncation undetected). Spec now: `truncated = len(collected) > limit || (== limit && probe at offset limit non-empty)`.
- **AC-8 contradiction**: loaders gaining a `truncated` return breaks "17 tests unchanged" — added the explicit mechanical `_`-consumption carve-out (AC-8 Given, §7 intro, §3.1 F12 bullet).
- AC-4's Given was already corrected (signature-bytes corruption, not re-signed key); F1/F2 have AC-12/13; AC-6b exact-lock and byte-stability rules are in place.

## Pre-existing gate failures (reported separately per AGENTS.md)

`go test -run 'TestMaintainability_|TestArchitecture_' .` fails at the current worktree on two gates, both **environmental, not HEAD regressions**: `TestArchitecture_DirectorySubdirFanout` (root "." 24 > frozen 21 — untracked `examples/`, `logs/`, `.pi-batch/`, `.venv/`; HEAD's tracked root counts 20) and `TestArchitecture_DirectoryDepth` (untracked `docs/architect-analysis/` campaign artifacts at depth 4–8). Neither is touched by this design; `TestArchitecture_DirectoryFileFanout`, `FileSizeBudget`, and `auditverify` package tests pass. `go build ./... && go vet ./...` pass.
