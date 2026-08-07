Requirements spec complete and written to:

`docs/architect-analysis/auto/runs/wire-checkpoint-anchored-verification-into-audit-181192ed/artifacts/requirements-10762e10/requirements.md`

## What was verified (all direction citations checked against HEAD)

Every cited symbol exists with exact semantics — only minor line drift:
- **`cmd/sso-ctl/auditverify/main.go`** — flags at 70–76, `VerifyChain`-only tail (empty early-return 95–98, verify 100, "chain verified" print 104). No checkpoint surface anywhere.
- **`platform/audit/chainer.go`** — `eventHash` at 119 (unkeyed SHA-256 over canonical JSON, clears only ID/Hash), `Checkpoint`/`SignedCheckpoint`/`CheckpointSigner` at 226–263, `Notary` at 337, `VerifyCheckpointSignature` at 446–458, `VerifyChainAgainstCheckpoint` at 469–491 (empty-set rule 479–484, head equality 486–488 — the direction's "481–486" maps within ±5 lines).
- **`platform/audit/handlers.go:51–77`** — `HandleEvents` serves `rec.Sink().Query(...)`, the same Recorder/Sink the chainer writes; confirmed same-trust-domain blind spot. Also confirmed: **no checkpoint HTTP endpoint exists anywhere in the server**, so the checkpoint must be a local out-of-band file (made an explicit non-goal).
- **T-2 taxonomy** — `campaign-snaplink-b4.yaml` mandates testable checks mapping to T-2; the proposal (line 18) explicitly lists "T-2 断言形式" as unpinned, so flag names/assertion forms are marked proposed and made concrete.
- **Sibling precedent** — `auditexport` already implements the exact pattern (`--anchor`, `loadCheckpoint` at 270, `enforceAnchorHead` at 290); the same `SignedCheckpoint` JSON is shared between both verifiers.

## Spec highlights

- **R1/R2**: `--checkpoint <path>` (SignedCheckpoint JSON, signature enforced at load, exit 1 on load failure) and `--notary-key <path>` (hex-encoded Ed25519 pubkey pinning — closes the self-signed-checkpoint forge hole; requires byte-equal `SignerKey` and verifies against the pinned key, fail-closed; exit 2 if used without `--checkpoint`).
- **R3**: with `--checkpoint`, the tail becomes one `VerifyChainAgainstCheckpoint` call (signature → chain → empty-set → head equality); the "no events to verify" early return applies only unanchored.
- **R4**: absent flag ⇒ byte-identical legacy behavior.
- **Acceptance**: all five supplied T-2 checks preserved as testable Given/When/Then (AC-1..AC-6, with the URL check split positive/negative so the headline compromised-server scenario is exercised through the live path), plus proposed-flag pinning cases (AC-7) and regression lock (AC-8). Error assertions pin exact chainer.go substrings (`does not match checkpoint attestation`, `checkpoint signature invalid`, `empty chain head`).
- **Gates**: no new package (cmd/sso-ctl fan-out frozen at 16), main.go stays ~310 < 500 lines, no server/wire/OpenAPI changes, forged-chain tests reuse the `Recorder` + `NewEd25519CheckpointSigner` construction already precedented in `notary_test.go`/`auditexport`.

Documentation-only artifact — no `.go` edits, so no mandatory Go gates were run.
