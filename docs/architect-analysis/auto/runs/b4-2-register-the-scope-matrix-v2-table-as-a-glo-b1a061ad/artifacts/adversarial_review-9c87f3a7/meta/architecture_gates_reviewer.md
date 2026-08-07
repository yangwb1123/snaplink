I have all the evidence needed. Here is the gate check verdict.

---

# Design gate check — B4-2 scope registry

Verdict: **4 of 5 gates PASS; Gate 3 has one defect as written** (the named split-first plan targets a file that cannot exist), plus one constraint gap in Gate 5. Two pre-existing, unrelated failures exist in the worktree baseline.

## Gate 1 — `layerName()` classification, no `layerExemptions` — ✅ PASS

`architecture_layer_test.go` classifies by first path segment (`layerName()`, :41-44). Both new packages classify automatically with **zero exemptions needed**:

| Package | First segment | Rank |
|---|---|---|
| `protocols/oauth/scoperegistry` | `protocols` | 3 |
| `interfaces/scopecontract` | `interfaces` | 5 |

Neither is in `skipDirs` (maintainability_budget_test.go:80-88), so both get walked and classified. No `layerExemptions` entry may be added anyway (shrink-only ratchet, and the stale-exemption check at architecture_layer_test.go:121 would flag an unused one). All intended edges are downward: `cmd/sso-server` (composition 6) → scopecontract (5); scopecontract (5) → scoperegistry (3); `interfaces/sso` (5) → scoperegistry (3). The committed `importRules` (`architecture_gate_test.go`) additionally forbid `protocols/oauth/` → `protocols/oidc` — scoperegistry (a `Registry` interface + `Memory`) imports only `shared/core`-rank packages, compliant. The supplementary `checks/architecture.py` `get_package()` uses the first segment only (`protocols`, no forbidden list) — unaffected.

## Gate 2 — `interfaces/sso` 60-file ceiling — ✅ PASS

`directory_fanout_test.go:59` freezes `"interfaces/sso": 60`; the tree measures exactly **60 non-test files** today. Any new file → 61 > 60 → `TestArchitecture_DirectoryFileFanout` regression failure (directory_fanout_test.go:143-147). The design adds zero files: field in `sso_wiring.go`, option in `options_misc.go`, seam in `server_token.go`. Compliant.

## Gate 3 — 500-line budget + named split-first plans — ⚠️ ONE DEFECT

`fileSizeExemptions` is empty with `maxFileSizeExemptions = 0` (maintainability_budget_test.go:65, :169) — no exemption escape hatch; `n > 500` fails. Touched-file headroom:

| File | Lines | Headroom | Verdict |
|---|---|---|---|
| `sso_wiring.go` (field) | 447 | 53 | ✅ |
| `server_token.go` (seam + guard) | 460 | 40 | ⚠️ tight — fine only if `rejectUnregisteredScopes` stays small or lives in scoperegistry |
| `options_misc.go` (option) | 496 | 4 | ✅ **only if split #1 runs first** |
| `options_admin.go` (split #1 target) | 474 | 26 | ✅ exists |
| `cmd/sso-server` wiring | 491-500 across `build_app*.go` | 0-9 | ❌ see below |

- **Split #1 — valid**: `WithTokenUsageRecorder` (options_misc.go:259, a ~5-line `Option` func) → `options_admin.go` **exists** (474 lines). Real headroom created, no new files.
- **Split #2 — invalid as named**: `wireSessionTrustDecay` lives in `cmd/sso-server/build_app_security.go:310` — a file at **exactly 500 lines**. The plan "extract → `build_app_trust.go`" cannot execute: **`build_app_trust.go` does not exist anywhere in the tree**, and `cmd/sso-server` is at its **frozen 24-file ceiling** (directory_fanout_test.go:54) — creating it makes 25 > 24 → fan-out regression failure. The adjacent `serverbuildplatform/` package is also at 10/10 non-test files (the general cap), so it can't absorb a new file either. The extraction must target an **existing** file (e.g. `build_stores.go` 477, which already wires scope options — `WithMaxScopeCount` at :293 — or `main_wiring.go` 239), or the scope-registry wiring must be placed in a file with ≥15 lines of headroom without creating a file.

New package files (scoperegistry, scopecontract) are fresh — trivially under 500 for an interface + build-once Memory + constant matrix.

## Gate 4 — `interfaces/scopecontract` importable by `cmd/sso-server` — ✅ PASS

composition (6) → interfaces (5) is a downward edge, allowed with no exemption; `layerName("cmd/sso-server")` → `cmd` → composition (architecture_layer_test.go:71-72). scopecontract imports only downward/same-layer packages; any import of `cmd/` from it would be an upward edge to rank 6 and fail the layer gate — the design's constants-only intent avoids this. Also importable by `test/` (composition) and `interfaces/sso` (same layer).

## Gate 5 — config knobs per config-reference.md contract — ✅ PASS with constraints

- **Contract**: AGENTS.md §5.6 and docs/RELEASE.md:90 require every new knob → `docs/config-reference.md`; `docscheck/config_keys_test.go` mechanically cross-checks only backend-like leaves (`backend`/`store`/`*_backend`). `scope_registry.enabled`/`extra_scopes` are **not** backend-like, so the drift test won't force them — the AGENTS.md contract still does. Document them as a backticked dotted-key row; the doc's `scope_registry.{enabled,extra_scopes}` brace shorthand is supported by `scanConfigDocKeys` (config_keys_test.go:245-270). `configKeyDocExceptions` (2 entries) must not grow — not needed here.
- **Constraint not named in the design**: `config/` is at its **26-file frozen ceiling** (directory_fanout_test.go:55) — the knobs must live in an existing `config_*.go` file reachable from `config.Config` (e.g. `config_oauth2.go`); a new `config_scope_registry.go` would fail the fan-out gate. The summary doesn't name the host file — a placement constraint, not a violation.

## Pre-existing baseline failures (unrelated, per AGENTS.md §5.7)

- `TestArchitecture_DirectorySubdirFanout`: root `"."` at 24 subdirs > frozen ceiling 21 — untracked worktree dirs (`pbatch/`, `sso-*`, `docs/architect-analysis/auto/runs/...`).
- `TestArchitecture_DirectoryDepth`: 117 dirs under `docs/architect-analysis/auto/runs/` deeper than 3 — untracked campaign artifacts.

All design-relevant gates pass on the current tree: LayerBoundaries, DirectoryFileFanout, both exemption ratchets, FileSizeBudget, FunctionLength/Cyclomatic, and `docscheck`.

## Required design correction

Rewrite split-first plan #2: extracting `wireSessionTrustDecay` must target an **existing** `cmd/sso-server` file (or the wiring must go into `build_stores.go`-style headroom), never a new file — `cmd/sso-server` has zero file slots left. Everything else in the design is gate-clean.
