Independent re-verification complete. I measured every claim against the committed gates (`directory_fanout_test.go`, `maintainability_budget_test.go`, `architecture_layer_test.go`, `shared/core/router.go`) and the live tree. Verdict: **the placement table and all four headline claims hold**; three minor prose discrepancies and one attribution imprecision found; two unrelated pre-existing gate failures in the worktree.

## 1. File-ceiling exemptions — VERIFIED (incl. the missing admin entry)

Measured non-test file counts vs committed caps:

| Package | Files | Cap | Exemption entry |
|---|---|---|---|
| `protocols/oauth` | 12 | 12 | `12` in map ✓ |
| `platform/audit` | 16 | 16 | `16` ✓ |
| `domains/federation` | 24 | 24 | `24` ✓ |
| `protocols/oidc`/`caep`/`selfservice`, `domains/permissions` | 10 each | 10 (default) | none — AT cap ✓ |
| `interfaces/admin` | 10 | 10 (default) | **none — confirmed absent** ✓ |
| `platform/configaudit`/`netpolicy`, `lifecycle/rebac`/`wasmauthz`/`webhook` | 8/6/7/4/9 | 10 | new `mount.go` OK (webhook = 1 slot) ✓ |

`dirFileCountExemptions` has exactly 12 entries; `interfaces/admin` is not among them, and spec line 90's "its frozen `dirFileCountExemptions` value" for admin references a nonexistent entry — the correction is real. `TestArchitecture_DirectoryFileFanout` **passes today**, so the "a new file fails the very gate this direction protects" claim is live, not hypothetical.

## 2. 500-line headroom — VERIFIED

`interfaces/admin`: `deps.go` 177 (only file with ≥300 headroom), `middleware.go` 492, `connections.go` 498 — exactly as claimed; `fileSizeExemptions` is empty and `maxFileLines=500`, so ~150–200 lines appended to `deps.go` lands ~350–380. Feasibility also holds in the other 7 constrained append packages: each has small siblings (e.g. `protocols/oauth` 31/57, `protocols/selfservice` 36/64, `platform/audit` 9/59, `domains/permissions` 39/41).

## 3. Acceptance grep — VERIFIED

Literal `grep -c "func (s \*Server) handle"` = **254**; anchored sole-param `handle\w*\(ctx HandlerContext\)` = **234**. The 20 diffs are exactly 18 multi-arg `(ctx HandlerContext, …)` helpers + 2 non-ctx (`handleLivez(w, r)`, `handleReadyz(w, r)`). All 13 placement-table delegate counts reproduce exactly (selfservice 56, oauth 8, oidc 3, caep 6, rebac 7, netpolicy 6, federation 5+1 health, webhook 5, configaudit 5, permissions 3, audit 3, wasmauthz 1, admin 60, adminuser 5 = **174**); all 174 are registered exactly once, and 174 = 109 + 65 reproduces precisely (65 = 60 admin + 5 adminuser by delegate target package).

## 4. Gate-closure via method values — VERIFIED CORRECT

`GatedRouter` (`shared/core/router.go:402`) holds `live func() bool` consulted **per request** (`StdRoute.live` via `RegisterGated`, or `GateHandler` fallback). The seven `*GateOn` methods (`server_routes.go:220–224`) read the atomics at call time; capturing a `.Load()` result at boot would freeze the flag and break the existing byte-identical-404 hot-reload tests (`feature_gate_hotreload_test.go`, `degradation_test.go` — both present, covering admin/branding/oidc/ciba/caep). The design rule is not just stylistic: it is load-bearing.

## 5. Nil-gate panic discipline / boot wiring — VERIFIED SOUND

- Today, a nil `live` in `RegisterGated` means **always-on (gating bypassed)**; the `GateHandler` fallback would panic per-request. The design's boot-time panic-on-nil + pinned test is the correct, stricter discipline, and its stated failure-mode reasoning ("silently-always-off vs nil-default always-on") matches actual semantics.
- `if s.rebacStore != nil` (`server_routes.go:159`) and `if s.clientStore != nil` guards exist; `interfaces/admin/deps.go:28–30` documents nil-tolerant accessors ("or nil when not configured (routes unmounted)") — the branch-on-`d.X() != nil` pattern is real. `interfaces/admin` and `internal/adminuser` are both classified `interfaces` in `layerName()` with no relevant `layerExemptions`; `cli.py check-routes` / `sdk-surface` exist.

## Discrepancies found (minor; none invalidate the table)

1. "40 mount functions across **16 files**" → actually **14 files** (39 `mount*` + `Mount()`; count of 40 is right).
2. "`mountAdminSurface` + **11** sub-mounts" → it calls **12** (`…`, `mountAPIDocsUI` included).
3. "The 5 adminuser delegates' bodies live in `users.go` (464 lines)" → **wrong file**: the 5 bodies (`HandleAdminCreateUser` etc.) live in `internal/adminuser/handlers.go` (239 lines); `interfaces/admin/users.go` holds the 14 admin user-state handlers. The design's operational conclusion is unaffected (and `internal/adminuser` at 3 files is unconstrained), but the attribution should be corrected.
4. "Seeded … in NewServer (`sso.go`)" → the seeding code is `seedFeatureGateLiveFlags` in `accessors_feature_gates.go:33–43`, split out of `NewServer` for the line budget (design elsewhere cites that file correctly).

## Pre-existing gate state (reported separately, per AGENTS.md §5.7)

`TestMaintainability_FileSizeBudget` **fails in the worktree on two unrelated files**: `cmd/sso-server/build_app_oauth.go` (554 lines) and `interfaces/grpcserver/grpcadmin/admin_snapshots.go` (581 lines) — both from the uncommitted pi-batch stage work (+111/+289-line diffs vs HEAD), not from the design or its target packages. The fan-out gate itself is green.
