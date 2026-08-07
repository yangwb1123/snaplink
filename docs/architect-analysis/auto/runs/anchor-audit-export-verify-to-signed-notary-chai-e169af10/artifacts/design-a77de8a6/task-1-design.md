Design written to the pipeline-declared output path. Summary of what was done:

## Verification of untrusted evidence — all claims confirmed

Checked every citation against the tree:

- **`auditexport.go:148` `VerifyExportBundle`, self-referential head check at :155-156, `HeadHash` omitempty at :107** — confirmed; the check recomputes from the bundle's own events (`headHash` :195), so a store-side tail re-chain rewrites both together and passes. The blind spot the anchor closes.
- **`chainer.go` notary block** — `CheckpointSigner` interface :243, `Ed25519CheckpointSigner` :250, `NewNotary` :351, `StartNotary` :375, `VerifyChainAgainstCheckpoint` :469, `SignedCheckpoint` :235, `CheckpointEqual` :498. Confirmed.
- **`main.go:167-181` `runVerify(path)` has no anchor input** — confirmed; sole caller is `dispatch`, no test calls it directly (private signature change is safe).
- **Zero notary/checkpoint consumers under `cmd/sso-ctl/`; `VerifyChainAgainstCheckpoint` zero consumers repo-wide** — confirmed (only definition + `notary_test.go`; `soc2.go:167` consumes `VerifyExportBundle`, a different symbol).
- **Campaign mapping (:15 B4-5 hash_chain, :77 G5 L0, :11 T-8(a) token-claims)** — confirmed against `docs/campaigns/implementation-gate.md`.
- **`TestRunVerify_TamperFails` at `main_test.go:403`** — confirmed drift correction (:403-428, 576-line file).
- **`auditsqlite.Sink` implements `ChainTip.LastHash` (maintenance.go:75), no `CheckpointStore`** — confirmed (compile-time assertions at maintenance.go:105 list only `Sink`/`FacetQuerier`/`BatchSink`/`ChainTip`), so anchors must be CLI file inputs.
- **Test seam** — confirmed `seedStore` records hash-chained events into sqlite, so the real notary (`NewNotary(sink, ...).CheckpointNow`) produces a genuine checkpoint matching the exported head.

No contradicted claims.

## Design artifact

`docs/architect-analysis/auto/runs/anchor-audit-export-verify-to-notary-signed-chai-5a41b845/artifacts/design-a77de8a6/task-1-design.md` (the pipeline's declared path) contains:

- **API changes** — additive inert `Anchor *audit.SignedCheckpoint` field on `ExportBundle` (`omitempty`, FormatVersion stays 1); `--anchor` flag in both CLI modes; `runVerify(path, anchorPath)`; two small private helpers (`loadCheckpoint` ~17 lines, `enforceAnchorHead` ~7 lines)
- **Flow specifications** — exact check ordering per mode: export fails fast on signature before opening the store, fails closed on head mismatch *before* writing the bundle; verify runs `VerifyExportBundle` first, resolves flag-wins-over-embedded, single signature enforcement point, then head equality
- **Compatibility constraints** — backward/forward wire compat, byte-identical legacy output, frozen library semantics, no new `Err*`, stdout purity, scope fence around `auditverify`/`--from-url`
- **13 failure modes (F1–F13)** — each with mode, result, and message
- **Migration steps** — no data migration; operator checkpoint-file workflow, rollback symmetry, docs in the same change
- **Testable acceptance mapping** — AC-1…AC-8 tied to concrete test names and assertions, including the isolation trick (stale checkpoint validly signed so AC-1 tests head mismatch, not signature) and the forged-signer pattern from `notary_test.go:123`
- **Budgets and gates** — main.go 331→≈390 (under 500), auditexport.go 247→≈251, helpers under 50 lines, no new files; `go build/vet` + targeted tests + `make ci` plan
