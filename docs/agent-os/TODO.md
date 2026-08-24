# Engineering-system debt

This is not the product backlog. Product scope lives in
`docs/feature-matrix.md`, `docs/deferred-backlog.md`, and `docs/ROADMAP.md`.

The previously tracked tooling gaps are closed:

1. Python and committed Go directory fan-out use the same 15-subdirectory
   ceiling and the same out-of-scope tree handling; the Go exemption count is
   still ratcheted.
2. Coverage propagates `go test` failures, resolves configured aliases to full
   import paths, runs each package target directly, and treats missing output
   as a failure rather than `SKIP`.
3. `accept` makes build/security/contract/coverage criteria blocking and labels
   repository root policy debt and pre-existing architecture debt as
   `DIAGNOSTIC`.
4. `layerExemptions` has a frozen count latch and stale-entry enforcement.
5. Both staged runners persist validated artifacts before exposing them to
   downstream stages; `from_outputs` accepts an ordered list, and aggregate
   joins include only those selected upstream stages. Regression tests cover
   resume and selected DAG joins.

Keep these gates fail-closed. Do not add exemptions or weaken a committed
threshold when future work touches the same tooling.
