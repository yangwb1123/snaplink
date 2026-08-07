Review complete. Verdicts on all four questions, with evidence from HEAD:

## Q1 — Root of trust: **not genuinely out-of-band as designed**

Two defects, both verified:

1. **The proposed bootstrap is in-band TOFU.** Design §6 step 1 offered "a checkpoint fetched from the server before any compromise suspicion" as a pin source. That is the *attested party* delivering the attestation key — if the server is compromised at bootstrap time, the operator pins the attacker's key and verification passes forever (the one case where pinning gives false assurance, not fail-closed; "before suspicion" is unverifiable by definition). The only genuine out-of-band source is the key-provisioning record (ceremony/KMS/secret-store injection).
2. **No stable notary key exists.** `NewNotary`/`StartNotary` have **zero production call sites** — the notary is unwired library code; `NewEd25519CheckpointSigner` (chainer.go:255) generates a fresh ephemeral key per call with no persistence or config. The design's pinning presupposes server-side wiring that doesn't exist. This is a hard prerequisite Phase B must state, not assume.

## Q2 — Key rotation: **undefined; now defined as a match-any pin set**

`bytes.Equal` single-pin has no overlap window (A-key checkpoints fail pin B and vice versa) — rotation would be a coordinated fail-closed outage. Design now specifies: `--notary-key` file accepts **one or more hex keys (whitespace-separated)**; `readPinnedKeys` → set; `loadAnchor` requires `SignerKey ∈ set` (invariant preserved: signature verifies only after membership). Rotation runbook: provision new pair out-of-band → push pins (old+new) to all hosts → rotate notary (old key verify-only, mirroring the AGENTS.md signing-key principle; `PrevHash` chaining keeps attestation continuity) → retire old key.

## Q3 — `--limit` footgun: **mandatory, and stronger than a warning**

The design's "same as F8" is **wrong for URL mode**: `readFromURL` truncates to the *newest* `limit` then reverses → the set starts mid-chain → `VerifyChain` misreports as `chain break at index 0 ... expected ""` (chainer.go). Both modes produce observables indistinguishable from genuine compromise alarms, and `--limit 10000` is the *default* — truncation is the default state on long-running chains. Decision: under `--checkpoint`, detected truncation is a **fail-fast error before verification** (exit 1, `event list truncated by --limit N before the attested head; rerun with --limit 0`), exact detection (file: `len > limit`; URL: one extra probe page), gated on the new flags so R4's byte-identical guarantee holds.

## Q4 — Phase A → B: **yes, as written it's a documented weaker posture with no exit ramp**

Phase A closes the compromised-server hole only if the checkpoint file lives where the attacker can't write — but it sits next to `events.json`, and auditexport documents the identical hole itself ("a bundle writer can forge it", main.go:31–35). The design documented it in the F-table but presented Phase A as adoptable, no time-box, no runtime signal. Fixes applied: Phase A is **interim-only** (toolchain bring-up), Phase B is the **required end state** (prefer shipping both in one release — the pin derives from the same out-of-band artifact), and every `--checkpoint`-without-`--notary-key` run prints a stderr notice (AC-10) — the weaker posture becomes self-announcing, which also covers Phase-B→A rollback. Rollback procedure expanded: binary rollback is genuinely instant (CLI-only, R4), but must state the posture regression explicitly, revert operator runbooks in lockstep (the real hazard — operators believing they're anchored when they're not), and note anchored bundles stay verifiable and leftover pin files are inert.

## Deliverables

- **Review**: `docs/architect-analysis/auto/runs/wire-checkpoint-anchored-verification-into-audit-181192ed/artifacts/review-operational-trust.md` (verdicts, evidence table with line citations, amendment list)
- **Design updated** (15 edits, all applied): §3.1 flags/helpers/control flow, §3.3 usage, §4 R4 gating, §5 F8/F12 rows + notes, §6 migration (bootstrap discipline, rotation runbook, expanded rollback), §7 new AC-9/10/11, §8 budgets (~335 lines, still < 500)

Documentation-only changes; no Go gates run.
