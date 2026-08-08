Deliverable written to `docs/architect-analysis/auto/runs/issuer-allowlist-config-surface-configcmd-valida-8715499d/artifacts/mapping/task-1-fm-acceptance-mapping.md`.

Note on provenance: the on-disk `task-1-design.md`/`requirements.md` are truncated summaries — I recovered the full 225-line design and 384-line requirements from the stage session transcripts, then re-verified every load-bearing fact against the tree (live gate runs, validate-schema probes, fixture inspection).

## Mapping summary

**G1–G15 (config unit, `config/issuer_policy_test.go`)** — every FM has ≥1 config-layer pin: FM-1→G1(+G14 inverse); FM-2→G4/G8–G12/G15; FM-3→G5+G6 (absent-key and empty-key arms, each asserting the distinct diagnostic); FM-4→G3/G7/G13; FM-6→G4/G15; FM-8→G14. **Exit-1 conditions:** (a)→G2, (b)→G4 (+G3 N2 sub-case), (c)→G1 (unconditional).

**C1–C7 (configcmd)** — C3→exit-1(a), C4→exit-1(b) (with `--print` array assertion), C5→exit-1(c) (existing `TestRun_InvalidConfig_Sentinel`, retained), C1/C2→byte-compat exit 0, C6/C7→schema A4 + validate-schema.

**W1** — binary-layer load-time membership guarantee: the "iss ∈ allowlist" half of T-8(a) by construction. T-8(a)/T-2 runtime halves map to `issuer_wiring_test.go` (`TokenIssClaimsMatchDiscoveryIssuer`, `AuthzErrorIssMatchesDiscoveryIssuer`, `DiscoveryIssuerIgnoresTamperedHost`).

## Flags (4 real gaps + 2 design fixes)

- **FM-7 (schema Required heuristic) — uncovered, documentation-only.** C6 asserts types but never reads `Required`; nothing asserts `validate-schema` exits 0 when `require_configured` is omitted (the heuristic's actual claim — verified in `generate.go:117-133` / `validate.go:39-43`). Fix: add the omission arm to C7.
- **FM-3 — config-pinned (G5/G6) but the design's "C-series" claim names no CLI fixture.** The stderr diagnostic is the mitigation, so the end-to-end arm matters. Fix: empty-allowlist arm in C4.
- **FM-9 — process-only, verified failing at HEAD right now:** `TestMaintainability_FileSizeBudget` (`ed25519_jwt_issuer.go` 539 lines), `TestArchitecture_DirectoryDepth` + `DirectorySubdirFanout` (auto/runs tree, root 24>21). The design's mapping table has no FM-9 row — add a reporting contract (pre/post diff must be empty; acceptance must cite the pre-existing set before claiming `make ci` green).
- **FM-5 — pinned only incidentally:** C4's positive arm keeps `base_url: http://localhost:8080` mismatched vs `issuer: https://sso.example.com`, so a re-added dead-key check would break it — fragile; add an explicit G16 or a fixture comment.
- **Design typos:** acceptance row (a) cites "G1" — should be **G2**; FM-2's pin list omits G11 (port folding, cross-listed under FM-4).

## Sentinel-outside-gate trap — CONFIRMED end to end

Three independent **flag-off, sentinel-must-still-fail** layers over the same `config.Load` engine: G1 (new, config unit) → C5 (existing `TestRun_InvalidConfig_Sentinel`, fixture has no flag) → `TestConfigRejectsSDKSentinel` (existing binary guard). Wrapping the sentinel block in the `RequireConfigured` gate fails all three on the first test run. The reverse direction is also pre-pinned by the existing `TestConfigAcceptsRealURLIssuer` (flag-off `"sso-server"` must still load — catches checks moved *out* of the gate). One hazard: G1 must be written flag-off as specified, or its layer of the trap pin silently vanishes.
