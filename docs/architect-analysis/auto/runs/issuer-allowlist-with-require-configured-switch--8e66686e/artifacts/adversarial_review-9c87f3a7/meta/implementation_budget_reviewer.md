All measurements complete. Here is the verification report.

---

# Line-budget re-derivation: revised issuer-allowlist plan vs. actual worktree (HEAD `32596d23`)

**Method:** measured every touched file with the committed gates' own algorithms — file size (`n > 500` fails, `maintainability_budget_test.go`), function span/cyclo (`> 50` / `> 15` fails, incl. nested literals, `maintainability_complexity_test.go`), and the frozen fan-out ceilings (`directory_fanout_test.go`). All counts below are the **current worktree** (includes the in-flight sibling diffs: `config_load.go` +3 is in `validateFeatureConfig`, not `ServerOptions`; the touched-file counts match the design's table exactly: 456/499/483/495/488/487/436/195/498/340).

## Re-derived budget table (revised plan)

| File | Now | Δ | Final | File ≤500 | Function (≤50 ln / ≤15 cyclo) | Verdict |
|---|---:|---:|---:|:---:|---|---|
| `shared/core/errors.go` | 340 | +2–3 | 342–343 | ✓ | const only | ✓ |
| `shared/core/consts_oauth.go` | 188 | +8–9 | ~197 | ✓ | `NormalizeIssuer` ~5 ln, cyclo 2 | ✓ **must be an existing file** — shared/core is at its frozen 23-file ceiling |
| `config/config_server.go` | 195 | +22–26 | 217–221 | ✓ | `issuerOptions` ~10 ln, cyclo 3 | ✓ |
| `config/config_load.go` | 498 | −2 | 496 | ✓ | `ServerOptions` **50 → 48** | ⚠️ see trap #2 |
| `interfaces/sso/sso_wiring.go` | 456 | +39–47 | **495–503** | ⚠️ | `validateIssuerConfig` ~17–21 ln, cyclo ~6; 2 options 3 ln each | ⚠️ see flag #3 |
| `interfaces/sso/sso.go` | 499 | +1 | 500 | ✓ (exact) | `NewServer` **50 → 51** | ✗ **fails function gate** — flag #1 |
| `interfaces/sso/server_discovery.go` | 483 | +12 | 495 | ✓ | `denyUnconfiguredIssuer` 7 ln, cyclo 2 | ✓ |
| `interfaces/sso/server_discovery_config.go` | 487 | +1 (G1) | 488 | ✓ | `handleOIDCDiscovery` 31→32 | ✓ |
| `interfaces/sso/server_login.go` | 488 | +1 (G2) | 489 | ✓ | `handleLogin` 48→49 | ✓ (1 ln headroom) |
| `interfaces/sso/server_mfa.go` | 487 | +1 (G3) | 488 | ✓ | `handleMFAComplete` 42→43 | ✓ |
| `interfaces/sso/server_token.go` | 495 | +1 (G4) | 496 | ✓ | `handleToken` 47→48 | ✓ |
| `protocols/oauth/handle_introspect.go` | 436 | +5 (G5 + 1 interface method) | ~441 | ✓ | `HandleIntrospect` 43→44 | ✓ (compile note #4) |
| `interfaces/sso/accessors.go` | 494 | +4 (G5 accessor) | 498 | ✓ | 1-liner, cyclo 1 | ✓ (or in `server_discovery.go` → 499) |

**Ceilings:** `interfaces/sso` = 60/60 production files (only 2 new `_test.go` files — verified the gate excludes `_test.go`); `protocols/oauth` 12/12, `shared/core` 23/23, `config` 26/26 — all frozen, no new files possible anywhere, and the plan adds none. Import/layer boundaries untouched (G5 flows through the existing `IntrospectDeps` seam; `config`→`shared/core` and `interfaces/sso`→`shared/core` both legal).

## Remaining arithmetic failures (must be fixed before implementation)

**1. `sso.go` — file gate passes (499+1=500), function gate FAILS.** `NewServer` spans exactly **50 lines** (58→107; the design's cited "option loop at 82-83" is correct). `validateIssuerConfig()` +1 → **51 > 50 → `TestMaintainability_FunctionLength` fails**. The design's "500 exactly passes" was only checked against the file gate. Fix: absorb −1 line inside `NewServer` (trim the 3-line comment at 45–47 to one, or merge two adjacent statements) so the net is 500/50. Also note: 500 leaves **zero file headroom** — no second edit to `sso.go` may land in the same change.

**2. `ServerOptions` (config_load.go) is at exactly 50 lines, cyclo 10.** The relocation to a `config_server.go` method only works if it **replaces** the 3-line `opts := []sso.Option{sso.WithIssuer(...)}` literal with a 1-line call (net −2 → 48) or moves the whole method out (498−50=448). Adding `opts = append(opts, c.Server.issuerOptions()...)` as a new line → 51 → function-gate fail. (The original design's in-place +8 → 58 would have failed twice over; the revision fixes it, but only in the replace/move form — worth stating explicitly in the design.)

**3. `sso_wiring.go` is the tightest file: 456 + 39–47 → 495–503.** With `normalizeIssuer` moved out (saves ~9) and the reviewers' F4 entry-validation loop included (~+5), the arithmetic only clears 500 in the **tight form**: 2-line field docs, 3-line option bodies, F4 folded into the membership loop (~17-line body). Full codebase doc style → 503, fails. The design's "+~45" row must be re-derived as "+39–47, tight form required"; `validateIssuerConfig` is the only viable home (every other file in `interfaces/sso` with headroom would cross 500 hosting it: `server_discovery.go` 483+12+21=516, `accessors.go` 494+21=515, `sso.go` full).

## Verified-correct pieces (no change needed)

- G1–G4 insertion points match the worktree exactly: `server_discovery_config.go:61` (before `base := requestBaseURL` and the body-cache lookup — C3 ordering holds), `server_login.go:21` (after `tokenNoStoreHeaders`), `server_mfa.go:199` (after no-store, before the `mfaProvider == nil` check), `server_token.go:20` (after no-store, before `requireDeps`). Each +1 line keeps its handler ≤50 (max 49) and cyclo ≤15.
- G5 placement: `HandleIntrospect` (`handle_introspect.go:111`) after `TokenNoStoreHeaders` (:112), before client auth (:128) — correct; envelope via `core.ErrorBody` matches package style. `sso_protocol.go` confirmed at exactly 500 — issuer field must stay in `sso_wiring.go`'s `wiringState`, as revised.
- 60-file ceiling intact; new files are test-only. No name collisions (`normalizeIssuer`/`issuerOptions`/`IssuerAllowlist`/`requireConfiguredIssuer`/`denyUnconfiguredIssuer` all absent from the tree).

## Non-budget notes

**4. G5 breaks a test mock:** `protocols/oauth/handle_introspect_test.go:28` (`introspectDeps`) implements `IntrospectDeps` method-by-method — adding `DenyUnconfiguredIssuer` to the interface requires a compile fix there (test file; no budget impact, but the change won't build without it).
**5. Pre-existing gate failures, unrelated to this design (report separately):** `TestMaintainability_FileSizeBudget` — `infrastructure/defaultimpl/ed25519_jwt_issuer.go` (539 lines, grown by the in-flight key-persistence work); `TestArchitecture_DirectoryDepth` + `DirectorySubdirFanout` — the `docs/architect-analysis/auto/runs` tree (502 deep dirs; `docs` 18 subdirs; root `.` at 24 > frozen 21). `FunctionLength`/`CyclomaticComplexity`/`LayerBoundaries`/`ImportBoundaries`/`FileFanout` currently green.

**Bottom line:** of the revised plan's arithmetic, one row still fails a committed gate (`sso.go`/`NewServer` 50→51 — the only hard failure), one row passes only in an exact replace-form (`ServerOptions`), and one row passes only in the tight form (`sso_wiring.go`, ~495). All other rows (including the new G5 in `handle_introspect.go` at ~441) hold with margin; ceilings and function budgets are respected everywhere else.
