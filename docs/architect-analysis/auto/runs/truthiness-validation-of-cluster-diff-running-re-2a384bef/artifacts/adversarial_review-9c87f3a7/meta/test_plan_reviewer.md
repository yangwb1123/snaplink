Audit complete. Report saved to `docs/architect-analysis/auto/runs/truthiness-validation-of-cluster-diff-running-re-2a384bef/artifacts/testmatrix-audit-2cd4457b/test-matrix-coverage-audit.md`. All four questions verified against HEAD code plus a machine run of the real `configaudit.Diff` emitter.

## Verdicts

**Q1 — Both rfc6901 ordering cautions pinned: YES** (at the outcome level — error-not-panic, which is the only machine-checkable projection of statement order).
- Caution A (`Path == ""` before `Path[0]`): pinned by case 4's `""` row — a `path[0]`-first implementation panics and fails the row.
- Caution B (tilde `seg[i+1]` bounds check): pinned **only** by design X2's "trailing `~`" — the spec has no such row, so X2 is a genuine sharpening. `/a~` splits to `["a~"]`; an unguarded scanner panics.

**Q2 — E5a `"/"` exercised: YES** — X1 pins both directions (resolves with key `""`; `remove "/"` errors without). Machine-run confirmed the emitter genuinely produces `replace /` and `add /` for empty-key snapshots — not a phantom shape. Optional: an explicit `add "/"` row (structurally identical to `add /new_field`, so coverage is complete anyway).

**Q3 — Never-reset: fully machine-checked** (case 8 fresh false/0 + pre-seeded true/3 via `buildReconcilerWithStatus`, cases 9/10, existing suite; mechanism `applyResult:181 !result.failed` verified). **Byte-identical: PARTIAL — one real 3-line gap.** The existing test file has *no* exact-Message assertion anywhere (grep confirmed: only non-empty checks), and case 10's pin is negative. So the no-drift success message (`summarize(0)`) could change wording and pass every named test — case 11 pins only the drift path. Fix: `TestReconcile_NoDrift_ExactMessage` asserting the exact string (same pattern as case 11, no existing test edited).

**Q4 — Fixtures match the real emit set: YES, byte-exact.** Ran real `Diff`: case 5/11 fixture → `replace /issuer` + `add /new_field` (sorted order included); spec case-5 nested fixture → `replace /clients/c1/redirect_uris` + `remove /old_key`; `a/b`→`/a~1b`, `a~b`→`/a~0b`, `-`→`/-` all grounded. Every rejection row verified mechanically unemittable (rooting, `~2`, scalar/array intermediates never traversed, op set bounded). One doc note: design case-5 row should cite "spec §5 case 5" for the nested snapshot body.

**Residual:** F1 confirmed still open — D-D/FM4's "token-free by construction" overstates, since §3.1 embeds patch-derived paths in error text; a cluster B can plant its own token string in `Status.Message`. Not a new disclosure class (cluster B already holds token B), but case 8's token-free assertion is a spot-check. Recommend scoping the claim or adding one token-in-path X-row.

Bottom line: matrix is sound; the only actionable gap is the one no-drift exact-message assertion. No repo files other than the audit report were touched.
