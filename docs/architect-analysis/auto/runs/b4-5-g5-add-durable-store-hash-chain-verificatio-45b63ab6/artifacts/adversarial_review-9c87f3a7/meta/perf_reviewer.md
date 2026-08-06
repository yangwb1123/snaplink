My footprint is exactly the two new artifact files; the design-doc modification predates my write (15:19, parallel design-gate agent). Analysis complete.

## Summary

**Artifact**: `docs/architect-analysis/auto/runs/b4-5-g5-add-durable-store-hash-chain-verificatio-45b63ab6/artifacts/adversarial_review-9c87f3a7/meta/scaling_reviewer.md` — all findings measured against the real packages + pinned `modernc.org/sqlite v1.50.1` on a 2M-row chain in `/tmp/auditbench` (no repo edits, no gates).

**1. OFFSET vs keyset** — OFFSET skip overhead scales ~n^1.8: 3.3s@250k → 84.5s@2M (23.7k rows/s) vs keyset 16.9s / streaming 16.0s (118–125k rows/s, linear). Extrapolated: **10M ≈ 22 min, 100M ≈ 22 h** for OFFSET; ~85s/14min for keyset/stream. Bonus: the export shape (`WHERE type=? ORDER BY ts OFFSET`) plans `USE TEMP B-TREE FOR ORDER BY` — a full re-sort of all matching rows *per page* (2.7s/page at offset 800k).

**2. Read txn on live WAL store** — measured: 200k appends pinned exactly 41.5 MB of WAL while the snapshot was open; `wal_checkpoint(TRUNCATE)` returns `busy=1` and no-ops; released instantly on commit. Bound: `pinned ≈ append_rate × T_verify × ~1.5KB/row` — so OFFSET's quadratic time directly multiplies WAL footprint (~20 GB @10M/10k/s vs ~1.2 GB streaming). Critical: on **delete-journal** stores (the default — `_journal=WAL` is a silent no-op) a whole-loop read txn **freezes writers** (SQLITE_BUSY, measured).

**3. Memory** — one 1000-row page = +2.6 MB (bounded, fine); the design's collect-then-`VerifyChain` shape = +2.6 GB @2M, ~13.6 GB @10M (unbounded). Also found an API trap: `VerifyChainSegment` anchors at the older side, so newest-first pages can't be verified per-page with existing APIs — requires oldest-first ordering or a backward walk.

**4. Facets L1 cost** — real `Facets(Query{Type: token_issued}).Total` = **2.74s @2M** (four grouped scans) vs **59.8ms** direct indexed `COUNT(*) WHERE type=?` (covering index) — 45× waste; use the direct count in the verify snapshot.

**5. Recommendation** — streaming chain walk (`ORDER BY ts ASC, rowid ASC`) inside **one read-only txn owned by a new sink seam** (`ChainScanner`-style SPI — mandatory, since `Sink.Query` goes through the pool and would silently read outside a caller-side txn), **counts first in the same txn** (total + token_issued, ~70ms), chunked `VerifyChainSegment` with anchor carry (O(page) memory, existing verifier API), then assert `walkTotal == countTotal && walkL1 == countL1` — same snapshot ⇒ equality exact ⇒ every truncation path (clamp, swallowed errors, appends, L1 drift) fails closed with zero false-fail noise. Keyset-in-one-txn is the equal-correctness fallback (6% slower); OFFSET rejected at scale; no-txn rejected (proven false pass); high-rate >10M live stores should verify a `VACUUM INTO`/backup copy (zero live WAL impact, journal-mode-independent). Five design deltas (D1–D5) are spelled out in the artifact.
