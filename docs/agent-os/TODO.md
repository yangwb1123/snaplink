# Engineering-system debt

This is not the product backlog. Product scope lives in
`docs/feature-matrix.md`, `docs/deferred-backlog.md`, and `docs/ROADMAP.md`.

Open tooling work:

1. Reconcile the Python and committed Go immediate-subdirectory thresholds.
2. Remove the stale declarative file-size exemption inventory;
   `check-exemptions` currently names two deleted `interfaces/sso` files.
3. Make coverage propagate test failures, match full package paths, and reject
   unexpected `SKIP` results.
4. Make every reported `accept` criterion blocking or label it diagnostic.
5. Add a count latch or equivalent review enforcement for `layerExemptions`.
6. Make the AI staged runner persist output and explicitly aggregate selected
   upstream findings before supporting multi-stage execution.

Do not add exemptions, weaken a committed gate, or treat a false-green report
as release evidence while resolving these items.
