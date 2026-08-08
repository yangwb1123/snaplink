All five checks verified — statically against source and empirically by running the design's exact test code (as a scratch file, deleted afterwards; `-race -count=3` green, package tests green, no tree residue). No blocking findings. Report:

## 1. `normalizeSegmentOrder` case selection (both-ends-non-genesis mid-chain segment)

**CONFIRMED — case (a), chain order kept, never case (c).** The function is `segment.go:52-62` (the cited 43-70 range spans the doc comment at 43-51 plus the function; non-blocking citation drift). For `evt-3..evt-5` with `anchor = evt-2.Hash`:

- `segment.go:56-58`: `if events[0].PrevHash == anchor { return }` — `evt-3.PrevHash == evt-2.Hash == anchor`, so the early return fires **before** the case-(b) reversal check (`segment.go:59`) and case (c) (fall-through, `segment.go:60-61` unreached). Order untouched → `VerifyChainSegment(events, anchor)` verifies.
- Empirical: scratch run AC-1 exit 0 with exact stdout, 5/5 runs.

## 2. Exact format strings and exit codes

| Claim | Source | Verdict |
|---|---|---|
| `segment verified: %d event(s), anchored=%s, head=%s` | `segment.go:38-40` — exact `fmt.Printf("segment verified: %d event(s), anchored=%s, head=%s\n", len(events), anchor, events[len(events)-1].Hash)`, `return 0` | ✓ exact |
| `chain BROKEN: %v` | `segment.go:27-29` — `fmt.Fprintf(os.Stderr, "chain BROKEN: %v\n", err)`, `return 1` | ✓ |
| empty segment exit 1 | `segment.go:22-24` — `cannot verify an empty segment against anchor %q\n`, `return 1` | ✓ |

**Precision note (non-blocking):** the design's AC-3 leg (no `--anchor-hash` flag) does **not** route through `segment.go:27-29`. With `anchorHashSet == false`, `Run` falls to the legacy unanchored tail at `main.go:267-268` (`audit.VerifyChain(events)` → `chain BROKEN: %v` → exit 1), which is byte-identical output/exit. The design's §2.4 comment already frames AC-3 as the no-anchor leg; assertion holds at the actual call site.

## 3. Tamper arithmetic (chainer.go `verifyChainFrom`)

**CONFIRMED.** `verifyChainFrom` (`chainer.go:200-213`) checks PrevHash first (`chainer.go:205-207` → `chain break at index %d`), then recomputes `eventHash(e)` (`chainer.go:209-212` → `hash mismatch at index %d`).

- **AC-2:** mutating only `Reason` on a copy of `events[1]` leaves `PrevHash`/`Hash` fields intact. Index 0: PrevHash == anchor ✓, hash ✓. Index 1: `PrevHash == evt-3.Hash == prev` ✓ (prev check passes), but `eventHash(tampered copy) ≠ stored Hash` (stored Hash was computed over the original `Reason`) → `hash mismatch at index 1 (id=evt-4): ...`. Empirical: exit 1, `chain BROKEN: audit: hash mismatch at index 1`, 5/5 runs.
- **AC-3:** `VerifyChain` seeds `prev = GenesisHash = ""` (`chainer.go:141`, `chainer.go:200`) → index 0: `e.PrevHash = evt-2.Hash ≠ ""` → `chain break at index 0 (id=evt-3): prev_hash="<evt-2.Hash>", expected ""`. Empirical: exit 1, 5/5 runs.

## 4. `runVerify` TrimSpace + `readFromFile` heuristic

**CONFIRMED.**

- `runVerify` (`checkpoint_test.go:133-139`) returns `strings.TrimSpace(errOut)` — trims only leading/trailing whitespace. The failure line begins with `chain BROKEN: `, so `strings.HasPrefix(errOut, "chain BROKEN: ")` and `strings.Contains(errOut, "hash mismatch at index 1")` are unaffected. (Contains is trim-invariant by definition; only a leading-trim could break HasPrefix, and there is none.)
- `readFromFile` heuristic (`main.go:368`): `if len(events) > 1 && events[0].PrevHash != "" && events[len(events)-1].PrevHash == "" { reverseEvents(events) }`. For `evt-3..evt-5`: `events[0].PrevHash = evt-2.Hash ≠ ""` **and** `events[last].PrevHash = evt-4.Hash ≠ ""` → condition false → **unreversed**; the chain-order file stays chain order (confirmed empirically — AC-1 would fail if reversed). The heuristic only fires when genesis sits at the last position (newest-first file).

## 5. Tamper-leg deep copy

**CONFIRMED.** `tampered := append([]*audit.Event(nil), batch...)` allocates a fresh backing array (pointers still shared); `copyEv := *tampered[1]` is a struct copy (strings by value); `tampered[1] = &copyEv` replaces the element pointer, so the shared event at `batch[1]` is never mutated and `batch` stays pristine for the AC-3 leg. The written JSON carries the original stored `Hash`/`PrevHash` with the mutated `Reason` — exactly what produces the index-1 mismatch. Empirical: scratch assertion `batch[1].Reason` remained `"rate_limited"` after the tamper (no aliasing).

## Additional assertions re-derived (design §2.4/§2.5, all confirmed)

- **Chain construction:** recorder stamps Timestamp→redact→`chain.stamp`→sink.Record in place (`recorder.go:144-156`); `WithHashChain` seeds genesis when sink lacks `ChainTip` (`recorder.go:76-90`); `auditoutbox.MemorySink` implements no `ChainTip`. Read-back `base.Query` is newest-first (`memory_sink.go:80-82`), reversed per `chainedEvents` (`main_test.go:174-198`).
- **AC-5 deterministic split:** `FactFromAudit` sets `CreatedAt = e.Timestamp` (`fact.go:76`); chainer `stamp` enforces strict monotonicity (`chainer.go:87-93`); `eligibleLocked` sorts CreatedAt then ID (`memory.go:117-126`). Empirical (5/5 runs): `Claimed=3/Delivered=3` per `RunOnce`, captured IDs exactly `[evt-0..evt-5]` in order.
- **AC-4:** `fact.go:31-32` nil/non-`login_failure` → `ErrClassNotPermitted`; `audit.EventTokenIssued` alias at `aliases_spi.go:194`; upstream pin `fact_test.go:25`/`:32`. Empirical: `errors.Is(err, ErrClassNotPermitted)`, nil fact.
- **APIs compile as designed:** `auditoutbox.NewMemorySink(base, store, nil)` (`sink.go:29`), `auditgovernance.NewRelay(store, client, cfg, ...)` (`relay.go:88`), `RelayConfig{Owner, BatchSize}` (`relay.go:35-42`), `RunOnce → RunResult{Claimed, Delivered}` (`relay.go:140-157`), `Receipt{EventID, TenantID, Status, AcceptedAt}` (`client.go:38-44`), `OutboxEvent` has no PrevHash/Hash (`commerce/store.go:74-93`), `audit.Query{Limit}` (`auditspi/query.go:25`), `NewMemorySink(0)` → capacity 10,000 (`memory_sink.go:11,27`).
- **Gates:** layer gate skips `_test.go` (`architecture_layer_test.go:147`); `go 1.26.1` supports `for i := range 6`; imports all downward; `-race` clean.

**Blocking findings: none.** Two non-blocking precision notes only: (a) `normalizeSegmentOrder` body is `segment.go:52-62`, not 43-70 (comment+function superset); (b) AC-3's `chain BROKEN:` originates at `main.go:268` (legacy unanchored tail), not `segment.go:28` — byte-identical output and exit 1 either way.
