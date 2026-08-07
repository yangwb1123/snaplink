Audit complete. Artifact written to `docs/architect-analysis/auto/runs/anchor-audit-export-verify-to-notary-signed-chai-5a41b845/artifacts/adversarial_review-9c87f3a7/meta/operator_workflow_reviewer.md`. All code claims re-verified against the tree.

## (a) Checkpoint acquisition — no production path exists; deployment prerequisite is unscoped

- **Zero production notary consumers**: `NewNotary`/`StartNotary`/`CheckpointStore` appear only in `chainer.go` (definitions) and `notary_test.go`. `cmd/sso-server/` has zero notary references; `cmd/sso-ctl/` has zero.
- **No durable store, no retrieval path**: the only `CheckpointStore` is `MemoryCheckpointStore` (chainer.go:284-290, in-process, restart-destroying). No CLI subcommand, endpoint, or file export reads a store. Offline self-generation (`NewEd25519CheckpointSigner`) is correctly restricted to test/pilot by the design — but that leaves nothing.
- §7 step 1 ("obtain checkpoint files from the notary's CheckpointStore…") reads as actionable when no such store exists. The requirements' non-goal makes the wiring a "separate direction," but the design never states the consequence: `--anchor` is a mechanism only, not deployable for evidence-grade use. **Fix**: rewrite §7 step 1 as an explicit deployment-prerequisite scoping statement (test/pilot until notary direction ships: server wiring + durable store + key custody + retrieval), and align the package doc/flag help so operators aren't misled.

## (b) §4.2 rules vs. restart re-issue — sound, canonical, but operator-invisible

Re-issue confirmed mechanically: `NewNotary` (chainer.go:351) never restores `lastSeq`/`lastSigned`; `CheckpointNow` (chainer.go:387-426) suppresses same-head only per-instance (:400) and re-issues `Sequence: lastSeq+1` = 1 with a new timestamp for the same head; `CheckpointEqual` (chainer.go:493-499) is full-struct byte equality. The rules hold:

- "Same checkpoint file" is canonical — `CheckpointEqual` compares re-marshaled structs, so whitespace never false-conflicts; only content (timestamp/sequence/key/signature) does.
- "Re-export after a fresh checkpoint" works while the head is unchanged; if the head moved, re-export fails closed and loops back to the (a) gap.
- With `MemoryCheckpointStore`, a restart destroys the store history — the retained export-time file is the *only* stable artifact, making the rule mandatory, not advisory.

Gaps: the rule lives only in §4.2's parenthetical, absent from §7 step 3; the F6 message names no cause; the omit-`--anchor` recovery (embedded enforcement with warning) is documented nowhere.

## (c) Migration/rollback + docs — mechanically consistent, enumeration incomplete

- Rollback symmetry holds (additive wire format, plain `json.Unmarshal` on every bundle path — old binary verifies anchored bundles unanchored; deployment order irrelevant).
- **Known citation error still shipped**: §7 step 5 (and requirements R-7) cite main.go:44-46; the exit-code contract is at **main.go:29-31** — flagged by two prior reviewers, unfixed in the amended design.
- Usage banner is fine by construction (`PrintDefaults` renders the flag automatically).
- §7 step 5's doc list omits, for the operator audience: the §3.2 warning semantics (`warning=embedded-anchor-not-enforcement-grade` — runtime-visible and tested via AC-2/AC-9, but documented nowhere an operator reads), the §4.2 operator rules, and the §2.1 freshness guidance.
- Carryover defects unchanged: "no test calls `runVerify` directly" is false (main_test.go:395, :431, :440 break on the signature change; §9 budget omits the three call-site updates); §9 arithmetic is loose (≈401 by its own breakdown, stated ≈425).

**Verdict**: FAIL on the operator-facing workflow — (a) is a blocking scoping gap, (b) needs the rules surfaced in §7/F6, (c) needs the citation fix and the doc enumeration completed.
