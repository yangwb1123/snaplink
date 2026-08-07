All three verification tasks are complete. Summary:

## (a) `runVerify` direct-caller claim — was NOT corrected; now fixed

The amended design still asserted "No test calls it directly (verified)" in §1 row 3 and §5. Ground truth confirmed: `main_test.go:395` (`TestRunVerify_Pass`), `:431` (`TestRunVerify_TamperFails`), `:440` (`TestRunVerify_MissingFile`) all call `runVerify` directly. Edits:

- **§1 row 3** now states: sole **production** caller is `dispatch` (call at main.go:126, spans :114-128); the three test call sites are enumerated, each gains a `""` argument; `_test.go` is outside the 500-line gate (`maintainability_budget_test.go:71`), so no budget crossing but the churn is mandatory.
- **§5 constraint row** rewritten to match.
- **§9 budget** gains a `main_test.go` line: 3 call-site updates + the new AC tests, with the note that without the call-site edits the signature change breaks compilation and AC-7's "keep `TestRunVerify_MissingFile` (:439) green" is unachievable.

## (b) Citation drifts — all four fixed (plus one more found)

| Design said | Tree says | Fixed |
|---|---|---|
| exit-code contract `main.go:44-46` (§7 step 5) | `main.go:29-31` (:44-46 is the import block) | ✓ (+ pinned the v1 paragraph at :26) |
| `CheckpointEqual` at chainer.go:498 (§1 row 2) | :493 | ✓ (already correct in §4.2) |
| `VerifyCheckpointSignature` at :455 (§1 row 2) | :446 (comment :444-445; marshals `Checkpoint` :453, embedded-key verify :457) | ✓ |
| `headHash` at auditexport.go:195 (§1 row 1) | :214 | ✓ |
| `runVerify` at main.go:167-181; `dispatch` (:128) (§1 row 3) | func at :182-198; call at :126 | ✓ |

A sweep confirms no stale `:498/:455/:195/44-46/167-181`/"no test calls it directly" strings remain; every remaining citation in the doc was re-verified against the tree (chainer.go :141/:157/:238/:243/:250/:351/:375/:444-458/:469/:480-481/:493; auditexport.go :107/:148/:155-156/:214; main_test.go :23/:45/:93/:403/:439/:495; notary_test.go :51-59/:123-127; maintenance.go :75/:105; `platform/audit/auditreport/soc2.go:167`; soc2report/main.go:102; line counts 331/247/576).

## (c) Security-editor edits — coherent, no regressions

- **Numbering**: F-table F1–F14 sequential, no gaps/dupes; AC-table AC-1…AC-9 sequential. F14's cross-refs (F6 conflict / F5 head mismatch when flag present; §3.2 warning when absent) resolve; AC-9's logic is sound (wrong-key matching-head forgery → no flag → exit 0 + warning; genuine flag → byte-unequal → F6 → exit 1). AC-2's embedded-path warning assertion matches §3.2/F14; §2.1's citations match code; migration step 1's test/pilot restriction is cross-referenced from §2.1; §6 oracle note is consistent with §4.2's fail-late F1-F3 ordering.
- **Six protocol-compat claims intact**: (1) key order/omitempty — §3.1 + §5 byte-identical row + AC-7; (2) no strict-unmarshal consumers — §5 backward-compat row; (3) FormatVersion stays 1 — §3.1/§5/§7; (4) F12 exit-2 branches — F12 row + §4.1 step 1 + §6 (dispatch untouched); (5) doc-surface enumeration — §7 step 5 (citations now correct); (6) rollback symmetry — §7 step 4.

**Flagged, not in scope:** the six unmapped F-modes (F1, F2, F9, F11, F12, F13) and the R-6 `anchor_head` stderr contract still have no mapped AC row — the testing reviewer's recommendations were not incorporated into this amendment; the implement stage would ship them untested. Recommend adding those table-driven cases to §8 before implementation.

Doc-only change (315 lines); no `.go` edits, so no gate runs required.
