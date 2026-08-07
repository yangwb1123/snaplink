Design written to `docs/architect-analysis/auto/runs/wire-checkpoint-anchored-verification-into-audit-181192ed/artifacts/design.md`.

## Verification results

Every evidence claim checked against HEAD — **all pass** with exact line matches: flags at 69–75 and `VerifyChain`-only tail in `auditverify/main.go`; `eventHash` 119, checkpoint types 226–263, `Notary` 337, `VerifyCheckpointSignature` 446, `VerifyChainAgainstCheckpoint` 469 (empty-set rule 480–484, head equality 486–488) in `chainer.go`; `HandleEvents` at 54 serving `Sink().Query`; no checkpoint HTTP endpoint (the three other "checkpoint" hits are unrelated prose); T-2 mandate at `campaign-snaplink-b4.yaml:79`; `auditexport` precedent (`loadCheckpoint` 270, `enforceAnchorHead` 290); fan-out cap 16 with `cmd/sso-ctl` exactly at 16 subdirs; test precedents in `notary_test.go:51` and `auditexport/main_test.go:510`.

## New constraint found (evidence missed it)

The kernel is **doubly blocked**: `chainer.go` is at exactly **500 lines** (the file gate) and `platform/audit` is at its **frozen 16-file exemption ceiling**. The evidence's "no new package" gate claim covered only `cmd/sso-ctl`. The design therefore places all pinning logic in `auditverify/main.go`, composing existing exported primitives — **zero kernel changes**, which also keeps `notary_test.go`/`auditexport` callers untouched.

## Design summary

- **API**: two additive flags — `--checkpoint <path>` (SignedCheckpoint JSON, signature enforced at load, exit 1 on failure) and `--notary-key <path>` (hex Ed25519 pin, exit 2 without `--checkpoint`). Anchored tail becomes one `VerifyChainAgainstCheckpoint` call; the empty-events early return applies only unanchored (empty + genesis-attesting checkpoint passes via the chainer's empty-set rule). `main.go` grows 240 → ~305 lines.
- **Pinning semantics**: `bytes.Equal(pinned, cp.SignerKey)` is the load-bearing precondition — after it passes, embedded-key signature verification *is* pinned-key verification. Comment pins this invariant against future "simplification".
- **Compatibility**: absent flags ⇒ byte-identical legacy behavior; flag orthogonality with both event sources; no wire/OpenAPI/config changes; no new package; kernel untouched.
- **Failure modes**: 12 enumerated, all fail-closed (F1–F12), including the `--limit`-truncation footgun (head mismatch), the self-signed checkpoint forge closed by pinning, and the compromised-live-server scenario.
- **Migration**: out-of-band key bootstrap (base64 JSON → hex), Phase A embedded-key anchoring (parity with `auditexport --anchor`), Phase B pinning, instant rollback.
- **Acceptance**: 11 Given/When/Then criteria (AC-1..AC-8, URL scenario split positive/negative) pinning exact chainer substrings (`does not match checkpoint attestation`, `checkpoint signature invalid`, `empty chain head`, `does not match pinned key`), reusing `chainedEvents`/`captureStdout`/`NewEd25519CheckpointSigner` precedents; AC-8 locks the regression.
