Audit complete. I verified every claim in the five-point brief against HEAD code. All five hold, with three findings stronger than the design states and one constraint (F11) the design implies but doesn't name.

## 1. Return-code paths, no `os.Exit`, no `--limit` truncation — CONFIRMED

- The module's non-test code has exactly two `os.Exit` sites: `usageErr` (main.go:492, exit 2) and `errorf` (main.go:498, exit 1). Both are reachable only via `loadEvents` errors and misuse paths. The design's legs: `writeEventsFile` guarantees the file exists; `checkMisuse` (main.go:243-266) can't fire (`fromFile != ""`, no `--checkpoint`, non-empty anchor); `loadCheckpointIfRequested` short-circuits on empty checkpoint. `segment.go` has zero `os.Exit`.
- `flag.ExitOnError` (main.go:373) fires only on unknown/malformed flags. Fixed args are `--from-file <absolute path>` and `--anchor-hash <64-hex>`; hex cannot begin with `-`, so no flag misparse is possible.
- `--limit` is never passed; default is 10,000 (main.go:395). `readFromFile` (main.go:455-458): 3 events < 10,000 → `truncated=false`, so `verifyAnchoredSegment` takes the `segment verified:` branch (segment.go:43-47). Bonus: the AC-1 exact-match stdout assertion makes any future truncation drift fail loudly, not flake.
- Message strings verified in `verifyChainFrom` (chainer.go:209-217): `chain break at index 0` (AC-3 leg goes to the legacy `VerifyChain` tail, main.go:300 — `batch[0].PrevHash = evt-2.Hash ≠ GenesisHash ""`) and `hash mismatch at index 1` (AC-2: index 0 passes anchor+hash, index 1's `Reason` tamper breaks `eventHash`).

## 2. `usageFlags` vs `t.Parallel` under `-race` — CONFIRMED SAFE, and sequential is required for two reasons

- `parseFlags` writes package-global `usageFlags` (main.go:378); `usage()` reads it (main.go:351). The only direct test reader is `TestUsage_PrintsBanner` (coverage_test.go:188-193) — sequential.
- All six `t.Parallel()` tests (main_test.go:20/44/68/95/134/160) touch only `readFromFile`/`readFromURL`/`chainedEvents`; none call `Run`/`parseFlags`/`usage`. So no race exists today even in principle, and Go's runner completes sequential tests before parallel ones resume — a sequential new test never overlaps them.
- The sequential rule is nevertheless load-bearing for two concrete reasons the design implies but doesn't name: (a) `usageFlags` write-vs-read is a live race if the new test were ever parallelized alongside any future `Run`/`usage()` caller (or if `TestUsage_PrintsBanner` were marked parallel); (b) `captureStdout`/`captureStderr` swap package-global `os.Stdout`/`os.Stderr` (coverage_test.go:156-200) and are not goroutine-safe — two concurrent `runVerify`s would interleave pipes. Keep the new tests sequential; this is necessary, and sufficient.

## 3. `RunOnce` synchronous, no timing dependence — CONFIRMED

- `RunOnce` (relay.go:137-151) = `ClaimOutbox` → per-event `deliver` → `Publish` (nil error) → `CompleteOutbox` (relay.go:158-161). `PollInterval` is used only by `Run`'s `waitForPoll` (relay.go:113-127); `Lease` (30s default) is only *stamped* as `LeaseUntil` at claim, never waited on; backoff/jitter (relay.go:196-227) live only in retry/dead-letter error paths, unreachable with a nil-error capture client. `RunOnce` takes the exact path `managed_relay.go:200` invokes.
- Second `RunOnce`: evt-0..2 are `OutboxDelivered` → ineligible; batch 2 is evt-3..5 without any lease expiry. `RelayConfig{Owner, BatchSize:3}` passes `validRelayConfig` after `defaultRelayConfig` fills the rest.
- One note: the capture client's returned `Receipt` is ignored by the relay (only `err` matters, client.go:53-56) — field accuracy is cosmetic, but the design's values match the struct (client.go:38-45).

## 4. Deterministic batch split — CONFIRMED, stronger than designed

- `eligibleLocked` comparator is at exactly memory.go:107-112: `CreatedAt.Equal` → `ID` tiebreak, else `CreatedAt.Before`.
- Stronger than "in practice strictly increasing": `chainer.stamp` *enforces* strictly monotonic timestamps, bumping non-increasing ones to `lastTS+1ns` (chainer.go:95-98). Single-goroutine record loop → `CreatedAt` (= `e.Timestamp`, fact.go:90, stamped at recorder.go:148) strictly increases in record order. Batch split evt-0..2 / evt-3..5 is guaranteed; the ID tiebreak and `Query`'s `sort.SliceStable` are redundant second guards.

## 5. Query read-back authority, no pointer leak — CONFIRMED, hazard precisely identified

- `base.Query` returns the sink's internal pointers (memory_sink.go:66-91), newest-first by monotonic Timestamp; reversing yields chain order. Since `Recorder.Record` stamps the caller's event in place (recorder.go:148, 174) **and** `MemorySink` stores that same pointer (memory_sink.go:44), the caller-side pointer *is* the stored object — divergence is possible only if a test mutates an aliased pointer after recording.
- The tamper leg handles this correctly: `tampered := append([]*audit.Event(nil), batch...)` then `copyEv := *tampered[1]; tampered[1] = &copyEv` — value-copy plus slot replacement; the clean `batch` slice and sink-held events stay untouched, so AC-1/AC-3 can reuse them after the tamper leg.
- `readFromFile` auto-reversal (main.go:441-448) can't misfire: `batch[0].PrevHash = anchor ≠ ""` and `batch[2].PrevHash ≠ ""`. `eventHash` UTC-normalizes Timestamp (chainer.go:124-129), so the JSON file round-trip recomputes identically regardless of recorder zone.

## F1-F10 verdict + additional failure modes

F1-F10 are all **confirmed sufficient as stated** (each verified above: F1 §1, F2 runtime-built strings, F3 §4, F4/F5/F6 §5, F7 `fact_test.go:25` pins `token_issued` → `ErrClassNotPermitted` as designed, F8 §2/§3 mutex, F9 `NewMemorySink(0)` → `DefaultMemoryCapacity` 10,000 at memory_sink.go:23-26, F10 §3). I add four:

| # | Failure mode | Consequence if ignored | Mitigation |
|---|---|---|---|
| F11 | `TestUsage_PrintsBanner` (coverage_test.go:188) is a direct reader of the `usageFlags` global the new test's `Run` writes | race if either is ever parallelized | Keep new tests sequential (already designed); name this peer in the file comment as the reason — no `t.Parallel` ever |
| F12 | `captureStdout`/`captureStderr` swap global `os.Stdout`/`os.Stderr` and are not goroutine-safe | concurrent captures corrupt each other's output | Sequential discipline is the only protection; no parallel test today captures, but document the invariant on the new test |
| F13 | `MemorySink.Query` returns internal pointers (not clones) — a future simplification mutating `stored[i]` directly (instead of copy-then-swap) would corrupt the sink and the clean batch | AC-1 silently verifies tampered data | The design's `copyEv` pattern is mandatory; add a "do not simplify" comment |
| F14 | AC-5's "no duplicates / 6 total" could pass with wrong capture if `snapshot()` returned the store's mutable clones | weak AC-5 | Capture holds the `ClaimOutbox` clones (already detached from store state after claim); mutex is belt-and-braces since `RunOnce` runs on the test goroutine — fine |

**Overall verdict: the design's F1-F10 analysis is sufficient**; every leg of the five-point audit is confirmed against HEAD, and the only additions needed are documentation-grade (F11-F14 are invariant comments, not design changes). The design's sequential-test rule is not just prudent — it is required by the `usageFlags`/`os.Stdout` global state, and the relay/ordering/pointer claims are all stronger than the design states (enforced monotonic timestamps; clone detachment; single relay path). No design changes required before implementation.
