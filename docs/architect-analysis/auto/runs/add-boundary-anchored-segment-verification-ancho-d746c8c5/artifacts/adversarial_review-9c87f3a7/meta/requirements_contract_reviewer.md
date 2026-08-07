Artifact drift is closed. Both files now agree on a single contract.

## What changed

**1. `requirements-10762e10/requirements.md` — rewritten as the authoritative v2 contract (232 lines, replacing the 21-line summary)**

- **§1 Correction ledger** — explicitly records and corrects all three named drifts: the false "132 lines" claim (file was 21 lines, byte-identical to the evidence summary), the wrong "AC-1/2/3/5/6 preserved 1:1" mapping, and the undefined R-numbers (plus `verifyChainFrom` 200-215 → 200-217 and the stale main.go citations).
- **§2 Evidence verification** — re-verified against HEAD `d73b3d0e` and the worktree, with the HEAD/worktree line-number split and an explicit "do not reset, preserve unrelated dirty files" implementation-target caveat (the design's citations reference the worktree's checkpoint wiring).
- **§4 R1-R8** — now enumerated and testable: R1 flag semantics, R2 structural single-run order normalization, R3 single `VerifyChainSegment` call with no integrity fallback, R4 byte-identical legacy path, R5 misuse exit 2 (empty value; `--checkpoint` mutual exclusion) with pinned diagnostics, R6 empty+anchor fail-closed exit 1, R7 exact honest-reporting table (including the pin of "print `prefix verified`" over the direction's "or fetch checkpoint head" alternative), R8 shape/gates (`segment.go`, zero kernel changes, budgets).
- **§6 Final T-2 → AC mapping** — the single authoritative table: T-2 #1→AC-1, #2→AC-2, #3→AC-3, #4→**AC-7**, #5→**AC-6**, additions AC-4/5/8/9/10/11, each with `Run(args)` invocation, pinned exit, exact output tokens, and a wrong-reason barrier column.
- **§5 Rejected options pinned** (hex validation, dual-order, truncation fail-fast, integrity fallback, literal ManagedRelay, empty-anchor spelling) so implement does not re-litigate them; **§7** F1-F13 failure contract; **§8** migration.

**2. `design.md` §1** — the "132 lines" finding row now reads **FALSE — new finding, now RESOLVED**, pointing at the v2 contract and confirming its §8 table matches the new §6 row-for-row.

The implement stage now consumes one consistent contract: requirements.md v2 (R1-R8 + AC-1..AC-11) and design.md agree on every mapping and pinned string. No `.go` files were touched, so no Go gates were triggered (documentation-only change, consistent with the pipeline's own stage convention).
