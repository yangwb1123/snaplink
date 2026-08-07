Requirements specification written to `docs/architect-analysis/auto/runs/anchor-audit-export-verify-to-notary-signed-chai-5a41b845/artifacts/requirements-10762e10/requirements.md` (the pipeline's declared output path).

## Verification outcome — every citation checked

**Confirmed as cited:**
- `auditexport.go:148` `VerifyExportBundle` — self-referential at :155-156 (`b.HeadHash != headHash(b.Events)`); `HeadHash` `omitempty` at :107
- `chainer.go:351` `NewNotary`, `:375` `StartNotary`, `Ed25519CheckpointSigner` (:250; cited region 241-272 actually spans the `CheckpointSigner` interface at :243)
- `main.go:167-181` `runVerify(path string)` — no anchor input
- Zero Notary/Checkpoint consumers under `cmd/sso-ctl/` — verified by grep; `VerifyChainAgainstCheckpoint` has zero consumers repo-wide
- Campaign mapping: B4-5 `hash_chain` (implementation-gate.md:15), G5 L0 (:77), T-8(a) token-claims-scoped (:11) — the "proposed, not applicable" mapping holds

**Corrections (drift, all symbols intact):**
- `TestRunVerify_TamperFails` is at `main_test.go:403`, not :213 — the analysis predates the landed `--outcome`/`--type` tests in this same package (now 576 lines)
- New evidence found: `auditsqlite.Sink` implements `ChainTip.LastHash` (maintenance.go:75) — so tests can generate *real* signed checkpoints via the notary (notary_test.go:51-59 pattern); the sqlite sink has **no** `CheckpointStore`, forcing the CLI to take anchors as files

## Key spec decisions (scope-bounded)

- **R-2/R-3:** `--anchor` flag in both modes; export fail-closed on head mismatch (a windowed export can never be anchored — checkpoints attest chain heads only — so emitting a knowingly-failing bundle would be the exact silent-bad-evidence failure this direction closes); verify enforces `VerifyCheckpointSignature` + exact head equality, exit 1 on mismatch
- **R-4:** additive inert `Anchor *audit.SignedCheckpoint` field on `ExportBundle` (FormatVersion stays 1, `omitempty` — backward/forward compatible); enforcement stays CLI-side with one check point
- **R-5:** empty-bundle rule mirrors the notary's `"" == GenesisHash` convention
- Rejected alternatives documented: sidecar file, unsigned head-hash reference, and `VerifyChainAgainstCheckpoint` reuse (full-genesis replay is incompatible with mid-chain bundles)

All 7 supplied acceptance checks preserved and made testable (AC-1…AC-7), plus the informational campaign mapping (AC-8); test matrix, budgets, contract touchpoints, and the `go build/vet + targeted tests + make ci` plan included. No `.go` edits — doc-only artifact.
