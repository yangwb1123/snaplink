Verification complete. Final state of `docs/architect-analysis/auto/runs/anchor-audit-export-verify-to-notary-signed-chai-5a41b845/artifacts/design-a77de8a6/task-1-design.md`: **332 lines**, every requested item present. Report:

## What I found

**A concurrent amendment landed mid-session** (file mtime 01:00 UTC, after my first read): it already fixed the §1/§5 "no test calls `runVerify` directly" falsehood, the citation drifts (`headHash` :214, `VerifyCheckpointSignature` :446, `CheckpointEqual` :493, exit-code contract :29-31), and added the call-site churn to §9. I re-based on that state, re-verified every claim against the tree, and corrected the two remaining `:126` → `:122` citations (the `runVerify` call inside `dispatch`, verified at main.go:122).

## Amendments I applied (the still-missing items)

**Six unmapped F-modes + R-6 → concrete tests** (new AC-10…AC-14 rows plus AC-1/AC-7 extensions, and an explicit coverage-check paragraph):
- **F1** → AC-10 `TestRun_AnchorFileErrors` (table: missing/unreadable × export/verify → exit 1, `read anchor <path>`)
- **F2** → AC-10 (malformed-JSON row → `parse anchor <path>`; export rows also assert no bundle file)
- **F9** → AC-11 `TestRun_EmptyBundleAnchor` (table: non-genesis cp × both modes → 1, head-mismatch message; genesis cp → 0, which also completes the F8 verify-mode positive)
- **F11** → AC-12 `TestRun_ExportLimitedTailAnchorExitsOne` (seed 5, `--limit 3` against the genuine head checkpoint → 1; no bundle written — feasible: `--limit` exists at main.go and maps into `query.Limit`)
- **F12** → AC-13 `TestRun_AnchorMisuseExitsTwo` (both corners, mirroring `TestRun_UnknownOutcomeBeatsMutuallyExclusive`: `--anchor` alone → 2 + banner; `--anchor`+`--dsn`+`--verify` → 2 + mutually-exclusive)
- **F13** → AC-14 `TestRunVerify_AnchorNullTreatedAsAbsent` (`"anchor": null` and key-deleted rows → exit 0, no `anchor_head=`, no warning)
- **R-6** → positive asserted in AC-1's control (`anchor_head=<cp.Checkpoint.HeadHash>` on stderr with exit 0); negative in `TestRunVerify_Pass` (AC-7: no `anchor_head=` substring when unanchored)

**AC-1/AC-3 stderr assertions** — AC-1 already named both hashes; now annotated as the load-bearing guard (a forgotten re-sign fails the signature check with a different message, so the test can't pass for the wrong reason). AC-3 gained the missing `bundle FAILED verification` stderr assertion (main.go:192), pinning that the *reported* failure is the chain check, not anchor enforcement.

**F6 byte-identity/re-issue** — F6 row now documents byte-level `CheckpointEqual` (full JSON incl. `Sequence`/`Timestamp`/`SignerKey`), the notary-restart re-issue mechanics (fresh `NewNotary` resets `lastSeq`/`lastSigned`, re-signs Sequence 1 with new timestamp and `PrevHash=""` — chainer.go:346-347, :398, :402-405, all verified against source), and the operator workaround, cross-referencing §4.2 step 3.

**Budget** — §9 now accounts for the three `runVerify` call-site edits (:395, :431, :440, one line each, compile-enforced) and per-test line estimates (`writeCheckpoint` ≈10 … AC-14 ≈20, 576 → ≈745), with the verified note that `maintainability_budget_test.go:71` excludes `_test.go` from the 500-line gate.

**§10 verification plan** regex updated with all five new test names plus `TestRunVerify_Pass`.

All citations in the added text were re-checked against the tree (main.go:122/192/26/29-31, chainer.go re-issue lines, main_test.go call sites). No `.go` edits were made — doc-only, per the design stage's declared output path, so the Go gates don't apply.
