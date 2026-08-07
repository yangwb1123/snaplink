All facts verified against the tree. Here is the re-verification verdict:

## F2 correction itself — CONFIRMED (and it's stricter than stated)

- `cacheState` is defined at **`sso_protocol.go:360`** in a file of exactly **500 lines** — zero headroom. The comment at `sso_protocol.go:359` confirms the "Server-level signing-alg allowlist" lives *inside* `cacheState`, so the design artifact's line-9 rationale ("server_discovery_cache.go (343, where cacheState already holds the signing-alg allowlist)") is factually wrong.
- Consequence is mandatory, not stylistic: any field added to `cacheState` = +1 line in a 500/500 file → 501 → `TestMaintainability_FileSizeBudget` fails (gate counts *all* lines via `bytes.Count('\n')` and fails only on `n > 500` — verified in `maintainability_budget_test.go`). A **new embedded struct is genuinely required**, and the `Server` struct (`sso.go:33-52`) already embeds 10 sub-structs, so this follows the established decomposition pattern.

## Corrected placement — line arithmetic all checks out

| Claim | Verified | Result |
|---|---|---|
| Option/field/gate in `server_discovery_cache.go` | 343 lines → **157 headroom**; already hosts Options (`WithDiscoveryCacheTTL` :15, `WithServingRegionAdvertisement` :26) and the doc-cache lookup/store (`lookupDiscoveryDocCache` :261, `storeDiscoveryDocCache` :275 — the cache-key pin target) | ✓ fits comfortably |
| Sentinel → `validateIssuerGate` in `config_server.go` | Sentinel block is `config_load.go:176-185` (1 blank + 7 comment + if/return/`}`), inside `(c *Config) validate()` (:144). Extract 10 lines, replace with 3-line call → **net −7** (498 → ~491; `ServerOptions` :301 wiring adds ~+4 → still ≤ 498) | ✓ net-zero holds (strictly negative) |
| `config_server.go` hosting the gate | 195 lines, currently **zero functions** (pure data-types file); field + first function + imports ≈ +30 → ~225 | ✓ well under cap |
| `sso.go` at exactly 500 | 499 + 1 embedding line = 500; gate fails only `> 500`, so 500 passes — **but zero headroom, "flagged" is correct** | ✓ legal, at cap |

## Ceilings — CONFIRMED

- `interfaces/sso` frozen ceiling **60** (`directory_fanout_test.go:59`), currently exactly 60 non-test files; `config` frozen ceiling **26** (`:53`), exactly 26. Both at ceiling → zero new production files, confirmed.
- New files are only `issuer_allowlist_test.go` in both packages — `_test.go` is excluded from the 500-line gate and the fan-out count (verified in both gate sources). Zero new production files ✓.

## One gap the corrected placement still leaves open

**The gate invocation site is unspecified, and it cannot be in `sso.go`.** The panic must fire after the options loop (security-reviewer F4 requirement), but the loop is inside `NewServer` (`sso.go:58-111`) — a gate-call statement there is a *second* line → 501 → gate fails. Two legal resolutions, both keeping every file ≤ 500 with no new files:

1. Append the invocation to an existing post-loop helper in a headroom file: `applyConfigAuditWiring` (`server_backup.go:41`, 266 → 267) — post-loop ✓; or `seedFeatureGateLiveFlags` (`accessors_feature_gates.go:35`, 499 → 500 — legal, but lands a second file at the cap).
2. Pairwise apply-time checks in both option closures: `WithIssuerAllowlist` validates the current `s.issuer`; `WithIssuer` (`options.go:350`, 490 → ~493) validates the allowlist if set. Since `WithIssuer` is the sole issuer writer, the last-applied option always validates the final state; the panic still surfaces from `NewServer`. Nil-guarded, so off-path byte-identical.

Adjacent pin targets have headroom (spot-check): `resolveIssuer` (`server_discovery.go:251-256`, 483, +17), `buildOIDCConfiguration` (security F1 target, `server_discovery_config.go:102`, 487, +13), and `sso_protocol.go` stays untouched — which is the entire point of F2.

**Verdict:** the F2 correction is factually right and the corrected placement respects all caps and frozen ceilings — *provided* the design pins down the gate invocation site (option 1 or 2 above); as written, "gate in `server_discovery_cache.go`" + "sso.go takes exactly one line" has a missing link that would otherwise push `sso.go` to 501.
