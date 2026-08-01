Design doc complete. Final state:

**`docs/design/domains-anomaly-detect-convergence.md`** — one `## Decision:` heading per spec decision, each covering API surface, storage model, and failure modes, plus the cross-cutting `## What could break the design` and `## Verification and gates` sections. Every claim was re-verified against the tree before writing (zero-importer grep, collision table, `runner.go:13` pointer, `buildAnomalyDetectors` order, sole `Append` caller).

Key design findings beyond the spec:

1. **Acceptance-grep defect (item 1 of "What could break the design")**: decision 3's `--include="*.md"` grep is unsatisfiable as written — the stale path is quoted inside the intent records the spec itself says are *not* rewritten (the spec, tenant-dimension spec, `docs/auto` analysis, `docs/proposals/requirements.md`). Executable acceptance must be `*.go`-scoped.
2. **`threataction.Threat*` constants cannot alias `SignalType*`** — `domains/anomaly` already imports `domains/threataction` (runner bridge), so aliasing would create a domain cycle. The four shared wire names stay in two namespaces; the design proposes a test-only equality guard and notes the pre-existing `brute_force_spray` vs `brute_force_shadow` naming divergence as out of scope.
3. **Sequencing with the tenant-dimension change**: landing the deletion *first* removes the tenant design's compile-break obligation to mechanically thread the dead `detect/` package — otherwise that update is throwaway work.
4. **In-sweep ordering nuance found during verification**: `impossible_travel.go:179` is the *only* production `RecentLoginStore` writer (omission truly kills the read-only consumers), and the production order (write-owner first) makes `countWindows`'s unconditional `+1` over-count the current event — a constant one-attempt threshold bias that must not be "fixed" in this zero-behavior-change spec.
5. **Storage model is genuinely empty** for all three decisions: no schema, index, migration, or `maxversions.go` change; the deletion removes the subtree's third parallel storage SPI (`signature.Store`, memory-only, `DistinctCount` zero-caller).

Budgets checked: `domains/anomaly` 7 → 8 non-test files (limit 10), `interfaces/sso` untouched (60-file ceiling), no `layerExemptions`, no new top-level package.
