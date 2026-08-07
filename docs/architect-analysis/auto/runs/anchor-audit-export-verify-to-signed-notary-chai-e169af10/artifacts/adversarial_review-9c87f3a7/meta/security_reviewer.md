All edits landed (doc: 237 → 308 lines). Here is the review.

## Trust-boundary review — anchor verification in task-1-design.md

### 1. What "a signature the bundle cannot forge" actually guarantees

Verified in code: `VerifyCheckpointSignature` (chainer.go:444-458) marshals `c.Checkpoint` (`:453`) and verifies with the **embedded** `c.SignerKey` (`:457`) — no key registry exists, and the signature doesn't even cover the key field. `NewEd25519CheckpointSigner` (`:254-262`) generates a fresh key on demand.

The claim is true **only for the out-of-band `--anchor` file channel**, and the doc now says so (revised §2 + new §2.1). Precisely:

- **Guaranteed** — against a store tamperer who controls events/hashes/head and the exported bundle but **not** the checkpoint file and **not** the signing key: (1) bundle events are internally chain-consistent and unmodified since attestation; (2) the attested head is byte-exact the head the signer attested (any checkpoint-content edit breaks the signature); (3) no post-attestation re-chain/tail rewrite passes.
- **Not guaranteed** — signer identity (any self-generated key passes; store+notary compromise or a compromised operator/flag channel re-attests anything), freshness (old valid checkpoint + store rolled back to that head passes; `Sequence`/`PrevHash` continuity across checkpoint files isn't checked), and anything at all via the embedded anchor: **a bundle writer can forge the embedded attestation outright** (self-sign any head, embed it, `VerifyCheckpointSignature` passes). This was the doc's biggest overclaim: the old §2 invariant ("attested by a signature the bundle cannot forge") is false for the embedded path, which AC-2 blessed as a standalone verify path. Migration step 1's "or generate offline via `NewEd25519CheckpointSigner`" additionally licensed the exact forgery primitive — now restricted to test/pilot.

### 2. Flag-wins-over-embedded downgrade surfaces

- **Missing flag = the downgrade vector.** Flag absent → embedded anchor used → forgeable (F14, newly added). The warning on the verify-OK line (§3.2) makes the weaker path operator-visible. Flag present → byte-differing embedded anchor exits 1 (F6) — the flag cannot be silently overridden.
- **New sharp edge found (fail-closed, but real):** `CheckpointEqual` is byte/JSON equality including `Sequence`/`Timestamp`/`SignerKey` (chainer.go:493). A legitimately **re-checkpointed** anchor (same head, new timestamp) conflicts with the embedded copy → exit 1. Operator rule pinned in §4.2 step 3: export and verify with the same checkpoint file; re-export after a fresh checkpoint.
- **Flag substitution by an attacker with flag-channel control** = the trust root breaks — explicitly declared in §2.1, not treated as a verifier weakness.

### 3. F13 anchor-stripping equivalence

Correct that `"anchor": null` unmarshals to nil and is indistinguishable from F10 (legacy, no anchor) — but "equivalent to legacy risk" understated it: the **indistinguishability is the vulnerability** (downgrade of anchored evidence to unanchored is invisible; only the flag detects it). Sharpened in the F-table. And F13 was only half the story: substitution (F14) is worse than stripping because it exits 0 **while displaying `anchor_head=<forged head>` on the OK line** — the evidence *looks* attested. The embedded-anchor-only path is now documented as convenience + cross-checkable copy, never enforcement.

### 4. Fail-fast/fail-closed ordering

Sound, with one asymmetry now pinned: export mode is fail-fast on the anchor **before** opening the store, and head equality precedes bundle write (no partial artifact; AC-4/AC-5 assert file absence). Verify mode loads the flag **after** `VerifyExportBundle` (step 3), so a tampered bundle always reports the bundle error first — deliberate and deterministic; F1-F3 in verify mode are fail-late by design, stated in §4.2 so the implementer doesn't "optimize" the order and accidentally let a garbage anchor mask a chain-tamper report.

### 5. TOCTOU between loadCheckpoint and enforceAnchorHead

**None exists in the design as specified** — `loadCheckpoint` reads the file exactly once and returns the in-memory struct; `enforceAnchorHead` takes the struct, never the path; the bundle is likewise read once in verify mode. Both signature check and head equality run over the same bytes. Pinned in §4.1/§4.2 as a single-read discipline so the implementation keeps it. The residual time-window is out-of-band by nature: anchor-file provenance (operator fetch channel) and bundle-file custody between export and verify — both covered by the §2.1 threat model, not fixable in the CLI.

### 6. Distinct exit-1 messages — verifier oracle?

**No exploitable oracle.** All message-distinguishing inputs (file paths, both hashes) are attacker-supplied public data; the verifier is a local deterministic checker with no secret state; the attacker knows the ground truth of their own tamper. The AGENTS.md oracle doctrine targets network surfaces where the attacker lacks internal state — a CLI over files the attacker provides leaks nothing they don't already know. The doc already collapses F4/F5/F9/F11 into one message shape (head mismatch naming both hashes), which is the right instinct and is now stated as a rule in §6; exit 2 stays misuse-only (F12). The only hardening note: keep messages stable and free of server-side state — currently true.

**Also fixed while pinning:** `CheckpointEqual` citation drifted (design said chainer.go:498; actual :493) — corrected in §4.2.

**Doc changes:** §2 invariant rewritten (out-of-band flag = enforcement channel; embedded = forgeable convenience copy); new §2.1 trust boundary (guarantee, three non-guarantees); §3.2 warning on embedded-only verify; §4.1/§4.2 single-read/ordering pins; F13 sharpened + **F14 added**; oracle note in §6; migration step 1 restricted to test/pilot; AC-2 amended, **AC-9 added** (locks in F14 behavior + warning). No `.go` edits — doc-only, per the pipeline's declared output path.
