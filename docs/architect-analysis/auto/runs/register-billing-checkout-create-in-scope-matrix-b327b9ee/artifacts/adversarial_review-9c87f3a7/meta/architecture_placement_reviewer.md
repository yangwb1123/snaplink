All verification complete. Here is the verdict.

---

# Verification verdict: ownership, layer legality, alias pattern, budgets

## 1. `interfaces/commerce` as owner of `ScopeCheckoutCreate` — ✅ correct

- DIRECTORY_MAP.md has no per-constant table; ownership derives from the existing pattern: both `billing:payment:*` scopes live in `interfaces/commerce/consts.go:24-27` (the billing resource-scope owner). `billing:checkout:create` is a billing resource scope.
- No competing owner: `grep` shows the literal exists in exactly one production file today (`cmd/snaplink-stripe-adapter/model.go:13`). `cmd/snaplink-billing` owns only `audit:event:write` (`defaultAuditScope`, `config.go:22`), so there is no composition owner conflict.
- Ownership *cannot* stay in `cmd/`: `interfaces/scopecontract` must alias "original owner packages" and must not import composition (upward edge). Moving ownership to `interfaces/commerce` is the only legal, pattern-consistent resolution — the mirror image of the audit-row rationale (audit stayed a literal because its owner is composition; checkout's owner gets re-homed so the pin can be structural). The DIRECTORY_MAP line "the adapter owns checkout calls" describes the *capability*, not the scope constant.

## 2. `cmd/snaplink-stripe-adapter → interfaces/commerce` edge — ✅ legal

- **Not a nested module**: no `go.mod` in the adapter dir; nested modules are only `cmd/{sso-mcp,sso-operator}` + `infrastructure/*` (confirmed by listing). Root-module package.
- **Layer math**: `layerName()` maps `cmd` → composition (rank 6), `interfaces` → rank 5; `rank[to]=5 ≤ rank[from]=6` → legal downward edge, **no exemption needed**. `TestArchitecture_LayerBoundaries` and `TestArchitecture_ImportBoundaries` **PASS** on the current tree, with the adapter already importing `interfaces/{middleware, ssoclient/remote, ssoclient/rs}`, `infrastructure/postgres`, `shared/security`.
- **No cycle risk**: `interfaces/commerce` imports only rank ≤ 5 packages (`protocols/oauth`, `domains/tenant/commerce`, `domains/metering/usageledger`, `interfaces/ssoclient/rs`, `shared/{core,security}`).
- **Correction to the evidence**: "interfaces/commerce imports only net/http + shared/core" is **factually wrong** (see list above). It does not change the verdict — all edges are legal, and `consts.go` itself has zero imports, so the one-line constant pulls nothing new.

## 3. Structural alias pattern — ✅ matches exactly

- `interfaces/scopecontract/consts.go:46-52` commerce block: `ScopeX = commercehttp.ScopeX` under a "Commerce matrix rows" comment. Adding `ScopeCheckoutCreate = commercehttp.ScopeCheckoutCreate` after `ScopePaymentWrite` is form-identical.
- Row accounting: 7 aliases (4 commerce + 2 metering + 1 admin wildcard) + 1 pinned literal (audit) = 8 rows in `Matrix()`. The design's "seven rows structurally alias owners" is accurate.
- **Required same-change touches** (design already covers them, confirming): the package doc comment "Seven of the eight constants…" → "eight of nine"; `TestMatrixPinnedToSourceConstants` gains the new equality assert; `TestMatrixShape` `want` gains `billing:checkout:create` after `billing:payment:write` (keeps billing rows adjacent, consistent with current ordering).

## 4. Budgets — ✅ no crossing (three one-line production edits, zero new files)

| Budget | Touched dirs (current → after) | Verdict |
|---|---|---|
| File ≤ 500 lines | `commerce/consts.go` 80, `scopecontract/consts.go` 60, `model.go` 206 | ✅ far under; `fileSizeExemptions` empty, cap 0 |
| Non-test .go/dir ≤ 10 | `interfaces/commerce` **10** (at cap), adapter **10** (at cap), scopecontract 1 | ✅ at cap, not over; no file added |
| Subdirs/dir | `interfaces/` 14 ≤ 15/16 | ✅ no new dirs |
| Depth ≤ 3 | unchanged | ✅ |
| Function/cyclo/nesting | no function touched | ✅ |
| `interfaces/sso` 60-file ceiling | untouched | ✅ |

## Flags: layerExemptions, classification, pre-existing drift

- **layerExemptions**: 9 entries, all live (stale-check passes), none involving commerce/scopecontract/adapter. The design needs **no new exemption** — correct, since the ratchet is shrink-only and the stale-check would flag any unused entry.
- **Classification**: zero new files → no `layerName()` change needed; `cmd`/`interfaces` already classify.
- ⚠️ **Pre-existing gate failures on the untouched tree** (report separately per AGENTS.md §5.7 — `make ci` currently fails for unrelated reasons):
  1. `TestMaintainability_FileSizeBudget`: `infrastructure/defaultimpl/ed25519_jwt_issuer.go` = 539 lines > 500.
  2. `TestArchitecture_DirectorySubdirFanout`: `docs` (18 > 16), `docs/architect-analysis/auto/runs` (265 > 16), root `.` 24 > frozen ceiling 21.
  3. `TestArchitecture_DirectoryDepth`: 520 dirs under `docs/architect-analysis/` > depth 3.

  All three are tooling-tree/environmental drift, none touch this design's packages. The design-relevant gates (`LayerBoundaries`, `ImportBoundaries`, `DirectoryFileFanout`, `FunctionLength`, `CyclomaticComplexity`, all exemption latches) **PASS**. The implementer should verify the failure set is byte-identical before/after the change and report it as pre-existing.

**Bottom line**: the design is clearance-ready on all four asks. One factual correction to the evidence (commerce's real import set — harmless), one asymmetry worth noting deliberately kept (only `scopeCheckoutCreate` becomes an alias; the adapter's other three scope literals remain literals — correct per the smallest-cohesive-change rule, but the mixed pattern in `model.go` is now intentional).
