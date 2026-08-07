All source claims verified against the tree. Here is the audit.

## 1. AC-1…AC-8 ↔ F1…F13 coverage matrix

| F-mode | Design's AC/test | Covered? |
|---|---|---|
| F1 missing/unreadable anchor file | — | **❌ no test** (both modes; only `loadCheckpoint`'s error path would exercise it) |
| F2 malformed JSON anchor | — | **❌ no test** |
| F3 bad/forged/wrong-key signature | AC-4 `TestRun_AnchorForgedSignatureExitsOne` | ✅ (wrong-key/forged; the `SignerKey` size sub-case at chainer.go:461 is untested — minor) |
| F4 head mismatch, export | AC-5 | ✅ (+ no-bundle-file assertion) |
| F5 head mismatch, verify | AC-1 | ✅ |
| F6 conflicting anchors | AC-6 | ✅ |
| F7 tampered bundle + valid anchor | AC-3 (extension) | ✅ (see §4 for one caveat) |
| F8 empty bundle + genesis cp | AC-5 (export-mode positive only) | ✅ partial — verify-mode genesis-positive unasserted |
| F9 empty bundle + non-genesis cp | — | **❌ no test** — AC-5 asserts only the R-5 positive; the fail-closed half is the one that would catch a regression making empty bundles accept any anchor |
| F10 no anchor | AC-7 (keeps legacy `TestRun*` green) | ✅ implicit |
| F11 filtered/`--limit` tail ≠ head | — | **❌ no test** — distinct from F4: with `--limit 3` of 5 seeded events, `HeadHash` is event 3's hash and *no* genuine checkpoint can ever match; the intended fail-closed semantics (design §6) are unasserted |
| F12 `--anchor` misuse exit 2 | — | **❌ no test** — design relies on unchanged `dispatch` branches; both corners (`--anchor` alone; `--anchor`+`--dsn`+`--verify`) unasserted, unlike the existing misuse tests for `--outcome`/`--dsn` |
| F13 `"anchor": null` stripping | — | **❌ no test** — a hand-edited bundle with the key deleted or `"anchor": null` must verify exit 0 (unmarshal → nil → absent, consistent with F10); nothing pins this documented residual risk |

So: **F1, F2, F9, F11, F12, F13 confirmed unmapped** — exactly the six you named. All are cheap table-driven additions in the same `main_test.go` (F9/F11 reuse the genuine notary checkpoint; F12 mirrors `TestRun_UnknownOutcomeBeatsMutuallyExclusive`'s shape; F13 is a 5-line JSON hand-edit).

## 2. R-6 `anchor_head` stderr line — confirmed untested

Grep confirms **no test today asserts any `printVerifyOK` line content** (`"bundle verified:"` appears only in main.go:270). R-6's observable contract — "verify-OK summary line gains the anchor head hash when one was enforced" — is the design's own requirement (design §3.2) with zero mapped assertion. Recommendation: assert in AC-1's positive control (`Run(["--verify", evidence, "--anchor", cp])` → 0 **and** stderr contains `anchor_head=<cp.Checkpoint.HeadHash>`), plus a negative in `TestRunVerify_Pass` (no `anchor_head=` substring when unanchored), which also pins the "when one was enforced" qualifier and the exact field spelling.

## 3. F6: byte-level `CheckpointEqual` — intended fail-closed, not a false conflict

Confirmed mechanics: `CheckpointEqual` (chainer.go:493-499) marshals the **full** `SignedCheckpoint` (Checkpoint + Signature + SignerKey) and byte-compares. The re-issue scenario is real: `CheckpointNow` suppresses same-head checkpoints only within one `Notary` instance (`lastSigned`), while `NewNotary` resets `lastSeq`/`lastSigned` — so a restart (or a second notary replica) re-issues Sequence 1, new timestamp, `PrevHash=""` for the *same* head.

Verdict: **intended fail-closed, defensible, not a false conflict**, for three reasons:

1. R-3 explicitly mandates `!CheckpointEqual → exit 1`; F6 and design §4.2 step 3 implement it faithfully — the strictness is a requirement, not an accident.
2. It is fail-closed in the correct direction: it never accepts a difference. The alternative — head-level equality — would silently tolerate a same-head forged-key *embedded* anchor whenever the flag wins, because the design's single-enforcement-point (§4.2 step 4) signature-checks only the resolved checkpoint. Byte equality is what makes "flag wins only when it is the identical attestation" sound without dual verification.
3. Ed25519 is deterministic, so byte equality is stable for truly identical attestations — no signature-encoding false inequality.

The only cost is the benign same-head re-issue rejection (recoverable: omit `--anchor` to use the embedded attestation, or supply the byte-identical file). Two recommendations: (a) document in F6/migration that "differ" means *not byte-identical*, including re-issued checkpoints, with the workaround — the design currently says just "differ"; (b) note the notary-restart re-issue behavior that makes the case realistic.

## 4. AC-1 isolation trick and AC-3 tamper regression

**AC-1 — sound, cannot pass for the wrong reason.** The trick requires the test to construct `cpStale` itself: mutate `Checkpoint.HeadHash` to `events[0].Hash`, **re-sign the marshaled checkpoint with the same signer** (the test holds it from `NewEd25519CheckpointSigner`), set `SignerKey`. Then `VerifyCheckpointSignature` passes and the failure can only come from `enforceAnchorHead`. The load-bearing guard is the design's assertion **"stderr names both hashes"**: if the test forgot to re-sign or used a wrong key, the signature check would fail with a different message and no hashes → the test would fail, excluding the wrong-reason pass. The positive control (`cp` → 0) additionally proves the plumbing, so a broken `loadCheckpoint`/`enforceAnchorHead` can't make the negative pass trivially. The isolation is valid — *provided the stderr-hashes assertion is actually implemented*; it is written into the design's AC-1 row, so the design is correct. (~10 lines of test code; feasible.)

**AC-3 — sound for the essential property; the ordering claim is overstated.** The tamper flips `Events[2].ActorID` (a hashed field per eventHash, chainer.go:95-119) in a middle event, which breaks `VerifyChainSegment` while leaving the `HeadHash` field intact — so the flag `cp` (genuine head) passes both signature and head checks on the tampered bundle. The bundle has no embedded anchor. Therefore **non-zero ⟺ `VerifyExportBundle` failed**; if `VerifyExportBundle` were dropped from the anchored path, verify would exit 0 and the test would catch it. "The anchor cannot rescue" is genuinely asserted.

Caveat: the exit code does **not** pin the *order* (design §4.2 step 2's "VerifyExportBundle first"). If the implementation ran anchor enforcement first (which passes) and then the chain check, the test still passes. The design's claim "order pinned in AC-3" is stronger than the specified assertion proves. Recommendation: also assert stderr contains the verification wrapper (`bundle FAILED verification`) so the *reported* failure is the chain check — that pins the invariant the design actually cares about.

## 5. Additional finding — a citation error in the design's own evidence table

The design §1 claims: *"`runVerify(path)` … sole caller is dispatch (:128). No test calls it directly (tests drive Run), so a private signature change touches only main.go."* **This is contradicted by the tree**: `main_test.go` calls `runVerify` directly at **three sites** — :395 (`TestRunVerify_Pass`), :431 (`TestRunVerify_TamperFails`), :440 (`TestRunVerify_MissingFile`). The requirements.md correctly stated "update only direct `runVerify(path)` callers to `runVerify(path, "")`", and the design's AC-7 implicitly keeps those tests green — so the impact is mechanical (3 call sites gain a `""` arg) — but for a pipeline whose core discipline is evidence truthiness, this "no test calls it directly" claim is factually wrong and should be corrected in the design before it propagates to the implement stage.

**Bottom line:** the design is sound on the three judgment calls you asked about (F6 strictness = intended fail-closed; AC-1 and AC-3 exercise their intended failures), with two test-strengthening recommendations (stderr message assertions in AC-1/AC-3) and one citation fix. Six F-modes (F1, F2, F9, F11, F12, F13) and the R-6 `anchor_head` stderr contract have no mapped test — all should be added to the AC table in the design before implementation, since the implement stage will otherwise ship them untested.
