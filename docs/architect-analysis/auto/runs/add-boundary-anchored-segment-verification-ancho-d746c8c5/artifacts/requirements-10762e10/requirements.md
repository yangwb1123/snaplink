The spec is complete and written to the pipeline's expected output path:

**`docs/architect-analysis/auto/runs/add-boundary-anchored-segment-verification-ancho-d746c8c5/artifacts/requirements-10762e10/requirements.md`** (132 lines)

## Evidence verification summary (all direction citations checked against HEAD)

| Citation | Verdict |
|---|---|
| `chainer.go:172-180` `VerifyChainSegment` boundary-anchor semantics | ✅ Confirmed (172-174; doc 161-170; `verifyChainFrom` 200-215) |
| `chainer.go:208` index-0 break | ✅ Confirmed (error return 205-208) |
| `main.go:138-144` auto-reverse / `146-149` truncation / `113` head print | ✅ Semantics confirmed, **line drift**: now at 321-323 / 325-327 / 230 (checkpoint wiring shifted the file) |
| `managed_relay.go` relay batches | ⚠️ **Correction found**: `Relay` drains `commerce.OutboxEvent` **facts** (no PrevHash/Hash fields, store.go:74-93); B4-5 wiring of auth.* events is `[PROPOSED]` (audit-contract-batch-snaplink.md:16). The relay-shaped acceptance is preserved at batch-shape level (AC-6), with the literal-integration limitation documented in §7 |

## Spec contents

- **R1-R8**: `--anchor-hash` flag semantics (string-equality against `events[0].PrevHash`, both sources), anchor-based order normalization (never "verify both orders" — fail-closed), byte-identical legacy path (R4), empty-value/`--checkpoint` mutual-exclusion misuse (exit 2), empty-list fail-closed (exit 1), honest reporting table with exact strings (`segment verified` / `prefix verified ... not the full chain`), and a `segment.go` split mandate to keep `main.go` (453 lines) under the 500-line gate.
- **AC-1..AC-10**: all five supplied acceptance checks preserved 1:1 (AC-1/2/3/5/6) plus order-normalization, URL-window, misuse, empty-set, and regression coverage — each a concrete in-process `Run(args)` invocation with pinned exit code and output tokens.
- **Gates**: no chainer/relay/auditexport changes, no new packages, no OpenAPI/config/error-code impact; package doc + usage banner updated in-code.
- **Rejected options** (with rationale): hex-format validation, dual-order verification, anchored truncation fail-fast.

Documentation-only artifact — no `.go` edits, so no mandatory Go gates were run.
