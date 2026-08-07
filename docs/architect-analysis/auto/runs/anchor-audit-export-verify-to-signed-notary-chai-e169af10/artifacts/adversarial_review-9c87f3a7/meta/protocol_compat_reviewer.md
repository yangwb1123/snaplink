All six claims verified against the tree. One substantive contradiction found (the design's own evidence table), plus minor citation drifts.

## Verdict per claim

**1. Field placement after `HeadHash` + `omitempty` → key order + byte-identical unanchored output — CONFIRMED.**
`ExportBundle` (`auditexport.go:105-107` HeadHash, then `EventCount`, `Events`) is marshaled by `json.MarshalIndent` in struct declaration order, so an `Anchor *audit.SignedCheckpoint` after HeadHash emits `anchor` between `head_hash` and `event_count` only when non-nil; nil + `omitempty` → key absent → byte-identical legacy output. No golden-file comparisons exist to conflict (`TestBuildExportBundle_RoundTripByteFlipFails` at `auditexport_test.go:143` round-trips a nil-anchor bundle; `strings.Replace` still matches). Type check: `auditexport` already imports `platform/audit` (`audit.Query`, `audit.Event`, `audit.GenesisHash`), so the field adds no import and no cycle.

**2. No strict unmarshal consumer breaks old-binary verification of anchored bundles — CONFIRMED.**
`rg DisallowUnknownFields -g '*.go'` hits only unrelated packages (auditgovernance, metering, commerce, ssoclient, snaplink-stripe-adapter, snaplink-billing, snapshot). `soc2.go:167` is exactly `auditexport.VerifyExportBundle(bundle)` — an in-memory struct; its JSON boundary is `soc2report/main.go:102` plain `json.Unmarshal`. `auditexport_test.go:149,158` and all `main_test.go` unmarshals are plain. Old binary: `anchor` key ignored, `format_version` still 1, head/events verify → anchored bundle verifies as unanchored evidence (the documented residual risk).

**3. `FormatVersion` stays 1 with additive data — CONFIRMED.** `VerifyExportBundle` (`:151-153`) demands exactly `FormatVersion` (1); no bump anywhere in the design; additive in both directions.

**4. F12 (`--anchor` misuse) exits 2 — CONFIRMED.** `dispatch` (`main.go:107-127`): `--anchor` alone → `verify=="" && dsn==""` → `return 2` ("…is required"); `--anchor`+`--dsn`+`--verify` → mutually-exclusive branch → `return 2`. Both route through `Run`, which prints usage on code 2. The design keeps `--anchor` out of the mode decision, so existing branches handle it.

**5. Package-doc/usage updates enumerated — CONFIRMED with citation drift.** Section 7 step 5 enumerates all three surfaces (package-doc exit-code paragraph, `usage()` banner, v1 paragraph). But the exit-code contract is at **`main.go:29-31`**, not `:44-46` (those lines are the import block). `usage()` renders flags via `PrintDefaults`, so the bound `--anchor` flag appears automatically; the banner text update is the Usage: section.

**6. Rollback symmetry + residual risk placement — CONFIRMED.** Section 7 step 4 documents both directions (old binary verifies anchored bundles unanchored; legacy bundles verify on the new binary; deployment order irrelevant) — mechanically sound per claims 2-3. Residual risk is consistently pinned to the package doc (section 2, section 5 constraint, F10, F13, section 7 step 5), which is also where section 7 step 5 puts the doc update. Right place, consistently named.

## New findings (design-internal contradictions)

**A. "No test calls `runVerify` directly" is FALSE — the one substantive issue.** `main_test.go` calls `runVerify(...)` directly at **:395** (`TestRunVerify_Pass`), **:431** (`TestRunVerify_TamperFails`), and **:440** (`TestRunVerify_MissingFile`). The design asserts twice that this is not so (section 1 evidence table: "No test calls it directly (tests drive Run), so a private signature change touches only `main.go`"; section 5 constraint: "no test calls it directly (verified)"). The signature change `runVerify(path)` → `runVerify(path, anchorPath)` breaks compilation at all three sites, and AC-7's "keep `TestRunVerify_MissingFile` (:439) green" is unachievable without editing it. Fix is mechanical (3 one-line call sites; `_test.go` files don't count against budgets), so this is a correction, not a blocker — but section 9's budget omits the test churn. Correction: "sole **production** caller is `dispatch`; three tests call it directly and must be updated in the same change."

**B. Minor citation drifts (immaterial):** exit-code contract at `:29-31` (not `:44-46`); `VerifyCheckpointSignature` at `chainer.go:446` (design said :455); `CheckpointEqual` at `:493` (said :498); `headHash` at `auditexport.go:214` (said :195).

**C. F6 nuance (not a contradiction):** `CheckpointEqual` (`:493-500`) is byte equality over the full marshal including `Sequence`/`Timestamp`, so a re-signed checkpoint with the same head but a later sequence counts as "conflicting" — consistent with the design's byte-level intent and the doc comment.

## Everything else confirmed

- `chainer.go`: `GenesisHash=""` :141; `SignedCheckpoint` :235 (tags `checkpoint/signature/signer_key`); `CheckpointSigner` :243; `Ed25519CheckpointSigner` :250; `NewNotary` :351; `StartNotary` :375; `VerifyChainAgainstCheckpoint` :469 with empty-chain rule :480-481 (`HeadHash != GenesisHash`); signature check needs no key registry.
- `notary_test.go:51-59` (`NewNotary`+`CheckpointNow` over a real sink) and :123-127 (forged signer, wrong key otherwise matching) — both as cited.
- `main_test.go`: seedStore :23, `ExportToFileRoundTrip` :45, `EmptyWindowExitsZero` :93, `TamperFails` :403, `MissingFile` :439, `Usage_PrintsBanner` :495; file is 576 lines.
- `sqlite/maintenance.go`: `LastHash` :75, `_ audit.ChainTip = (*Sink)(nil)` at :105, zero `Checkpoint` references in the package; notary/checkpoint API consumed nowhere except `notary_test.go`.
- Line counts: main.go 331, auditexport.go 247 — matching the design's budget math.
- `soc2report/main.go:102` plain `json.Unmarshal` (no strict decoding on the SOC2 path).

Net: all six compatibility claims hold as designed. Before implementation, amend the design to (a) correct the `runVerify`-test-caller claim and enumerate the three `main_test.go` call-site updates in the budget, and (b) fix the `:44-46` → `:29-31` exit-code citation.
