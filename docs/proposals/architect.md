Architecture review complete. Written to `docs/auto/interfaces-sso-direction3-arch-review.md`. I independently re-measured every material claim against the tree and the committed gates before writing. Summary:

## 1. Scope / verified architecture summary

Direction 3 (sink 174 thin delegates + mounts into 13 owning packages, move the admin surface, ratchet the 60-file ceiling to ≤52) evaluated without code changes. **The design's core census is exact** — I reproduced it with my own parser: 254 literal / 234 anchored sole-param / 20 body-bearing helpers; 174 delegates with the exact per-package split; every delegate registered exactly once; 234−109=125 holds; all 13 placement-table counts and caps hold, including 8 packages at ceiling and `interfaces/admin`'s **absent** exemption entry; `deps.go` 177 is the only admin file with ≥300 headroom; `TestArchitecture_*` all green today; router/gate semantics and all 7 hot-reload gates verified. The move is import-legal (downward, `shared/core` only), and the ratchet is the only gate-sanctioned way to create ceiling headroom — the direction is justified.

## 2. Key findings (full table in the file)

| Sev | Finding |
|---|---|
| **Critical** | The design's own final `Mount()` sketch passes `nil` for 10 of 13 mounts while Decision 1 declares nil a panic — a literal implementation panics at boot; the alternative reading contradicts Decision 1's fail-open rejection. |
| **Critical** | The same sketch silently **drops three live hot-reload gates** (`oidcGateOn` → /userinfo + /check_session_iframe, `cibaGateOn` → /backchannel/auth, `federationGateOn` → federation surface). `TestSetOIDCGateEnabled_…`/`TestSetCIBAGateEnabled_…`/`TestSetFederationGateEnabled_…` fail; fail-open wire change. Decision 4 even enumerates only 4 of the 7 atomics. |
| **High** | `check-routes` goes **vacuous** under the move (`ROUTE_DIR` hardcoded to `interfaces/sso`, one-directional, receiver whitelist) — the design's own regression net stops measuring exactly when the code moves; "unchanged" and "effective" cannot both hold. |
| **High** | FM4 misdescribes the router: first-match-wins append, no overwrite/panic, no duplicate detection anywhere. |
| **High** | The sketch omits `mountAdminTokenExchangeChainRoutes` → a documented route silently disappears (and can't fold into `MountAdminSurface` without a package cycle). |
| Medium | ≤52 not derived (only 1 of ≥8 deletions specified); FM6 cites a phantom middleware-order test; FM5/FM7 mitigations overclaim; `sdk-surface` never scans `aliases.go` ("419 re-exports" not reproducible); `make ci` checks nothing AGENTS.md↔exemption. |
| Low | AGENTS.md "ceilings are frozen" vs shrink-only ratchet (same-commit fix); numeric drift (14 vs 16 files, 12 vs 11 sub-mounts, adminuser bodies in `internal/adminuser/handlers.go` not `users.go`, "off by 20–29" → 20). |
| Info | Pre-existing: 3 maintainability tests fail on uncommitted pi-batch files only (`build_app_oauth.go`, `admin_snapshots.go`, `snapshot/diff.go`) — none in target packages. |

## 3. Decision options

- **A (recommended):** adopt the design with the bounded fix list (nil-gate resolution, gate-passing sketch + named-gate API, checker extension + runtime route-snapshot test, token-exchange-chain retention, enumerated deletions).
- **B:** 改进二 only + ratchet as a safe staging point — same-layer, `check-routes` stays effective with a small extension.
- **C:** reject — no alternative creates ceiling headroom without touching frozen exemption maps. Not viable.

## 4. Sequencing

**M0** design fixes (docs) → **M1** regression net first (extend `route_contract.py`, runtime 241-route snapshot test, duplicate-registration walk test) → **M2** 改进二 → **M3** 改进一 (gates passed as method values — pins the dropped-gate fix) → **M4** 改进三 (ratchet last, one commit: deletions + `SEED_DIRFANOUT=1` regeneration + both AGENTS.md sentences). Executable acceptances per milestone are in the file.

## 5. Unknowns for owner

Nil-gate semantics; the gate-union API for the oauth/CIBA mount; ≤52 target vs measured count; regression-net form (static scan vs runtime snapshot vs both); whether protocol F1/F2 wire fixes are in scope; and whether distributed route ownership across 13 packages is acceptable or should emit a machine-readable inventory.
