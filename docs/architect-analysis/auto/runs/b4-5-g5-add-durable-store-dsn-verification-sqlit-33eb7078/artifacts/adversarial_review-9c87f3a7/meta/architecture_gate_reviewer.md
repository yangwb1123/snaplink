Verification complete. All results below are from direct re-measurement of the repo and a full-tree simulation of the design's file plan in `/tmp/snaplink-gatesim` (design files applied verbatim to a copy of the tree: `url_source.go` extraction, `auditexport/store.go`, `auditexport/agg.go`, and the `auditverify → auditexport` import edge).

## Verdict per gate claim

| Claim | Verdict | Evidence |
|---|---|---|
| cmd/sso-ctl 16/16 subdir fan-out, no exemption | ✅ TRUE (with caveats) | `directory_fanout_test.go:35` `maxSubdirsPerDir = 16`; `cmd/sso-ctl` has exactly 16 subdirs and is **not** in `dirSubdirExemptions` (only `".": 21`). 17th subdir → guaranteed violation; folding keeps 16. Caveats below. |
| ≤3 files/dir after additions | ✅ TRUE | Gate counts non-test `.go` (cap 10): `auditexport` main+store+agg = 3; `auditverify` main+segment+url_source = 3. Verified in sim (3/3). |
| `auditverify/main.go` ≤ 500 after extraction | ✅ TRUE | 499 today (C10 confirmed). The three functions + comment occupy 394–487 (94 lines). Sim after move: **402 lines** (design said ~410 — accurate); +~20 wiring ≈ 425 < 500. `url_source.go` = 107 lines. |
| Frozen-file list accuracy | ✅ TRUE | Matches the requirements doc's "Do not modify" list exactly, all 6 entries: `chainer.go`, `recorder_events.go`, `auditexport/auditexport.go`, `sqlite/sink.go`, `interfaces/sso/*` (confirmed exactly 60 non-test files = frozen ceiling `"interfaces/sso": 60`), `postgres/audit_sink.go`. |
| No new layers / no upward imports | ✅ TRUE | Zero new packages (no `layerName()` change). New edges: `auditexport → infrastructure/postgres` = composition(6)→infrastructure(4), downward, precedent exists (`cmd/sso-server/serverbuildauthn`); `auditverify → auditexport` = composition→composition, same rank. `TestArchitecture_ImportBoundaries` forbids only oauth↔oidc and `shared/core`. `LayerBoundaries` + `ImportBoundaries` PASS in the sim with both edges live. |
| Folded placement passes the gates | ✅ CONFIRMED (one design gap) | Sim: `FunctionLength`, `CyclomaticComplexity`, `DirectoryFileFanout`, all `ExemptionsDoNotGrow` PASS; **zero `cmd/sso-ctl` mentions in any gate output**; full `-race` suites pass (`auditverify`, `auditexport`, `platform/audit/...`) — T-9 byte-identical move proven. **Gap: a monolithic `RunAgg` (90 lines, cyclo 18) fails both function gates.** The design's blanket "new functions ≤ 50 lines, complexity ≤ 15" (§4.5) is at risk for `RunAgg`; its body shape is unspecified. Decomposed (`parseAggFlags` / `aggCollect` / `aggEmit`), it passes — the design should pin this decomposition. `store.go` (ReadAll 37, ReadChain 45 lines) passes as-is. |

## Pre-existing failures (present before the design, unchanged by it — report per AGENTS.md §2)

1. **`TestArchitecture_DirectorySubdirFanout` already FAILS on this tree** — `docs` (18 subdirs), `docs/architect-analysis/auto/runs` (267), and root regression (24 > frozen 21). `cmd/sso-ctl` is *not* a cause; the design's §7 "16/16" framing should note the gate is red tree-wide.
2. **`TestMaintainability_FileSizeBudget` FAILS** — `infrastructure/defaultimpl/ed25519_jwt_issuer.go` (539 lines).
3. **`TestArchitecture_DirectoryDepth` FAILS** — 536 dirs, all batch-artifact runs.
4. **Python mirror check** (`checks/directory_fanout.py`, max 15, run via `adr-compliance`, *not* `make ci`): already flags `cmd/sso-ctl` (16 > 15) plus dist/docs/runs/platform. Three-way drift: engineering.yaml = 15, AGENTS.md = 15 (with explicit "don't exploit the Go gate's `>16` drift" note), committed Go gate = 16. The design's "16/16" is correct for the committed gate only.
5. **Dirty tree**: 826 modified files; `platform/audit/auditexport/auditexport.go` (design's "frozen" list) already has an uncommitted modification from another in-flight task — the design adds no edits to it, but it is not pristine in this working tree.

## Minor citation nuance

C5's "zero `.go` hits": one `.go` **comment** (`auditexport/main_test.go:297`) contains `auth.token.issue`; no code does. The substantive claim (no code uses the mapping; L1 aggregation absent) holds.

**Bottom line**: every gate claim in the design verifies against the repo, and the folded placement provably clears the committed gates (simulation green for `cmd/sso-ctl`). Two things the design should carry forward: (1) specify `RunAgg`'s decomposition (parse/collect/emit) so the ≤50-line/≤15-cyclo claim is guaranteed, and (2) acknowledge the pre-existing red gates (subdir/depth/filesize) and the 15-vs-16 subdir drift so the §7 handoff contract doesn't imply a green baseline.
