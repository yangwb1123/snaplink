All three questions are now answered with code-level evidence. Here is the verification report.

---

# Verification: `--anchor-hash` composition with the sibling signed-notary flows

## Q1 — Does the signed checkpoint JSON embed `boundary_prev_hash`? Is `--anchor-hash` a weaker duplicate?

**No on both counts. The two primitives are structurally disjoint and anchor opposite ends of the chain.**

The signed checkpoint (`platform/audit/chainer.go:226-241`) contains exactly:

```go
type Checkpoint struct {
    Sequence  int64     `json:"sequence"`
    Timestamp time.Time `json:"timestamp"`
    HeadHash  string    `json:"head_hash"`
    PrevHash  string    `json:"prev_hash,omitempty"`   // previous CHECKPOINT's head, not the audit chain's boundary
}
```

There is no `boundary_prev_hash` key anywhere in the signed checkpoint JSON. The `Checkpoint.PrevHash` is checkpoint-chain continuity (`n.lastSigned`, chainer.go:398-405) — the doc comment at 224-225 says checkpoints are chained "so a deleted/reordered one is tamper-evident." The boundary hash lives **only** in the export bundle as a sibling field (`ExportBundle.BoundaryPrevHash`, auditexport.go:102-104), alongside — not inside — the embedded `Anchor` (worktree auditexport.go:108-109).

The non-duplication is structural, not just nominal:

- `VerifyChainAgainstCheckpoint` (chainer.go:469-491) runs `VerifyChain` first — a **full-genesis replay**. A mid-chain window fails at index 0 regardless of any checkpoint. The notary flow *cannot* verify windows.
- Export-side, the notary design fail-closes windowed/`--limit`-capped exports (notary design F11: only an export ending exactly at the attested head can be anchored) — so a windowed bundle can **never** carry a genuine checkpoint.
- Conversely, `--anchor-hash` on a full chain is pinned to exit 1 (AC-10: "genesis anchoring is flag-free"), so the two never overlap on the same input.

The current design's decision 1 states exactly this partition ("`--checkpoint` proves the chain END … `--anchor-hash` proves the segment START") and pins `--anchor-hash` + `--checkpoint` as misuse exit 2, since a combined run is never sound. The security review's finding agrees: tail rewrites and suffix recomputes are invisible to a *start* anchor — `--checkpoint` is the complementary *head* anchor.

The only sense in which "weaker" is true: `--anchor-hash` is an **unsigned** hex string. Its evidential strength depends wholly on the anchor arriving via an artifact the store tamperer doesn't control (previous batch export / relay chain of custody). The design's own migration (§7.2) says "feed the bundle's `boundary_prev_hash`" — same artifact, self-referential, which is exactly parallel to the notary design's F14 ("embedded anchor is convenience, not enforcement"). That is a documented residual-risk parallel, not a duplicate relationship.

## Q2 — Does the worktree's `--checkpoint` truncated path already emit 'prefix verified'?

**No — and no code or sibling artifact anywhere in the repo emits it.** `grep -rn 'prefix verified'` across `cmd/`, `platform/`, and both sibling run dirs returns nothing outside this campaign's design.

The worktree's `verifyAnchored` (main.go:126-158) does the opposite — fail-fast **refusal**:

```go
if truncated {
    fmt.Fprintf(os.Stderr, "event list truncated by --limit %d before the attested head; rerun with --limit 0\n", limit)
    return 1   // BEFORE any verification output
}
```

This matches the wire-checkpoint campaign's mandated F12 (its design.md:242-252: "fail-fast error BEFORE verification"). It verifies nothing and prints no prefix report.

The redundancy question inverts: the **false tip still exists** in the worktree's unanchored path. In `Run` (main.go:200-233), `truncated` is consumed only by the `cp != nil` branch; the legacy tail ignores it and prints `chain verified: %d event(s), head=<prefix head>` with exit 0 — the exact defect the direction names. The design's `prefix verified: … not the full chain` + exit 1 is genuinely new behavior, required for both the unanchored path and the anchored-segment path.

Conflict assessment: none — the design's reporting table pins the `--checkpoint` row as "unchanged (verifyAnchored)", and F13 keeps the checkpoint paths byte-identical. The two flows agree on exit 1 and the "rerun with --limit 0" guidance, and differ **deliberately and documented** (decision 6) on reporting: the checkpoint path refuses because the *head* claim is impossible under truncation; the anchor-hash path verifies because the *start-boundary* claim remains fully verifiable. Note also the wire-checkpoint flow already satisfies the direction's "rather than asserting the prefix head is the tip" clause for its own path — so the design's mandate is scoped exactly to the paths that still violate it.

## Q3 — Flag names / exit codes across the three surfaces

Inventory (all verified in the worktree):

| Surface | Flags | Exit codes |
|---|---|---|
| `auditexport` (notary flow, worktree) | `--anchor <path>` (SignedCheckpoint JSON) | 0 clean, 1 verify/load error, 2 misuse (main.go:39-44) |
| `auditverify` (checkpoint flow, worktree) | `--checkpoint <path>`, `--notary-key <path>` | 0 clean, 1 break/error, 2 misuse |
| `auditverify` (anchor-hash, design) | `--anchor-hash <hex>` | 0 verified, 1 break/truncation/empty, 2 misuse (empty value or + `--checkpoint`) |

**No literal collisions and no exit-code collisions**: the three flag names are distinct strings on distinct `flag.FlagSet`s, and all three surfaces share the uniform 0/1/2 convention with identical semantics. The design's misuse-exit-2 routing goes through the same `checkMisuse` return-code path the checkpoint flow introduced (main.go:160-178).

Three real hazards found, none of them a parser collision:

1. **Naming hazard (operator-facing)**: the *same artifact* (SignedCheckpoint JSON) is called `--anchor` on `auditexport` but `--checkpoint` on `auditverify` — an inconsistency already shipped in the worktree (the wire-checkpoint requirements even note "the same SignedCheckpoint JSON is shared between both verifiers"). Adding `--anchor-hash` (a *different* object: bare hex digest) on `auditverify` makes "anchor" mean "signed checkpoint file" on one binary and "boundary digest" on another. The `--anchor-hash` help text must explicitly say "hex PrevHash of the first event, from the bundle's `boundary_prev_hash` — not a checkpoint file" to prevent `--anchor`-style misuse.
2. **Sequencing hazard (the real collision risk)**: both the checkpoint flow and the anchor-hash flow edit `cmd/sso-ctl/auditverify/main.go`. The checkpoint implement **failed validation** (DECISIONS.md:21-22) and exists only as uncommitted worktree state — HEAD's main.go is 240 lines with no `checkMisuse`, no `Run` at 200, no `--checkpoint`. The anchor-hash design's every citation (main.go:321-323/325-327/230, `runVerify` in uncommitted `checkpoint_test.go`) and its `--checkpoint` mutual-exclusion rule reference that dirty state. If the worktree is reset before the implement stage, the design breaks at every citation and the exit-2 rule has nothing to exclude. Preserve the worktree; do not reset (the design_consistency review already flagged this).
3. **Empty-value asymmetry (minor)**: the checkpoint flow treats `--checkpoint ""` as absent (`if checkpointPath == ""`, main.go:177), while the design makes `--anchor-hash ""` misuse exit 2. Same surface, different empty-value semantics — defensible (the empty anchor is `GenesisHash` and must not be spellable), but it should be called out in the package doc so the asymmetry reads as intentional. The security review's `flag.Visit` note (for AC-8) is the implementation hook that keeps this precise.

## Bottom line

The composition is sound and non-redundant: the three surfaces partition the verification problem cleanly — `auditexport --anchor` produces and verifies head-attested full bundles; `auditverify --checkpoint` verifies full chains against the attested head; `auditverify --anchor-hash` fills the one gap the notary flow structurally cannot (mid-chain windows/relay batches, which can neither be genesis-replayed nor head-anchored). The signed checkpoint does not embed `boundary_prev_hash`, the worktree emits no `prefix verified` anywhere, and no flag/exit-code collision exists — the two actionable risks are the worktree-dependency of the design's citations (do not reset) and the `--anchor`/`--checkpoint`/`--anchor-hash` naming surface (mitigate with explicit help text at implement time).
