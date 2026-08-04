Audit complete. All claims were re-measured against the tree. Here is the report.

# Audit: `interfaces-sso-direction3-design.md` — failure modes, risk register, and gate consistency

## 1. Verified-correct claims (measurements reproduced)

| Design claim | Measured | Verdict |
|---|---|---|
| 60 prod files / 48,830 lines in `interfaces/sso` | 60 / 48,830 | ✓ |
| Literal grep counts **254**; anchored sole-param filter counts **234** | 254 / 234 | ✓ (spec correction 2 is real: spec's own `grep -c` pattern yields 254, so its "234 → ≤125" baseline is off by 20) |
| 174 single-call delegates = 109 non-admin + 65 admin (60 `admin.` + 5 `adminuser.`) | exact match, incl. per-package split (selfservice 56, oauth 8, oidc 3, caep 6, rebac 7, netpolicy 6, federation 5 + `federationhealth` 1, webhook 5, configaudit 5, permissions 3, audit 3, wasmauthz 1) | ✓ |
| 20 body-bearing multi-arg helpers stay | exactly 20, `handleDeviceTokenGrant`/`handleLivez`/`handleReadyz` among them | ✓ |
| 234 − 109 = 125 acceptance arithmetic | ✓ | ✓ |
| All 13 placement-table counts and caps, incl. **8 packages AT their cap** and `interfaces/admin` (10 files) with **no exemption entry** (map has none) | ✓ | ✓ (spec correction 1 fully confirmed, incl. spec:90's reference to a nonexistent admin `dirFileCountExemptions` value) |
| `deps.go` 177 is the only admin file with ≥300 headroom (`middleware.go` 492, `connections.go` 498, others 350–483) | ✓ | ✓ |
| Every ceiling-bound package has a viable "existing file with headroom" (oauth `grant_handler.go` 31, oidc `aliases.go` 49, caep `doc.go` 61, selfservice `loginui.go` 36, audit `doc.go` 9, federation `cache.go` 47, permissions `types.go` 39) | ✓ | ✓ |
| 42 thin delegates in `server_admin_handlers.go` (498 lines; 51 sole-param funcs there); `server_routes_admin.go` 332 | ✓ | ✓ |
| GatedRouter = per-request `live()` at route-match level (`router.go:409,427,249–285`); method-value-closure rule is the correct one; hot-reload tests exist for AdminAPI/Branding/OIDC/CIBA/CAEP/Federation | ✓ | ✓ |
| 7 atomics in `sso_wiring.go:217–223`; gates at `server_routes.go:222`; `server_me.go:320/357/434`; `server_health.go:70`; `aliases.go:110` alias; `deps.go:25` `Deps`; 24 "Relocated from" comments; `fileSizeExemptions` empty; `SEED_DIRFANOUT` + SHRINK contract in `directory_fanout_test.go:38–43`; gate-test names exist for `-run 'TestMaintainability_|TestArchitecture_'`; `check-routes`/`sdk-surface` in `make ci` | ✓ | ✓ |
| Exactly 7 failure modes / 9 risks present; spec corrections 1–3 each flagged inline | ✓ | ✓ |

## 2. Unmitigated breakages (design contradicts itself and the tree)

**FINDING 1 — CRITICAL: Decision 3's `Mount()` sketch passes `nil` for 10 of 13 mounts, but Decision 1 makes nil a panic.** `oauth.MountRoutes(s.router, s, nil)`, `oidc.MountRoutes(…, nil)`, `federation.MountRoutes(…, nil)`, … vs. "Nil gate = programmer error: `MountRoutes` panics if `gate` is nil." A naive implementation of the design's own final sketch panics at boot on every surface it lists. Either the rule must become "nil = ungated" (which Decision 1 explicitly rejected as fail-open) or the sketch must pass always-on closures. As written, this is the design's own FM1, unmitigated.

**FINDING 2 — CRITICAL: the same sketch silently drops three live hot-reload gates.** Today `oidcGateOn` gates `/userinfo` + `/check_session_iframe` (`server_userinfo.go:33`), `cibaGateOn` gates `/backchannel/auth` (`server_routes.go:239`), `federationGateOn` gates the federation surface (`server_federation.go:197`). The sketch passes nil to `oidc.MountRoutes` and `federation.MountRoutes` (oauth covers CIBA). Result: `feature_gate_hotreload_test.go` `TestSetOIDCGateEnabled_…` (:239), `TestSetCIBAGateEnabled_…` (:271), `TestSetFederationGateEnabled_…` (:378) fail, and the AGENTS.md §3 hot-reload invariant breaks. This is not in FM1–FM7 (FM3 covers wrong-gate, not dropped-gate) and not in the risk register. The same blind spot shows in Decision 4, which enumerates only 4 of the 7 atomics (omits `oidcLive`, `cibaLive`, `federationLive`).

**FINDING 3 — HIGH: the design's own regression net (`check-routes`) goes vacuous under the move, and the acceptance demands it stay "unchanged".** `checks/route_contract.py` statically scans **only** `interfaces/sso/*.go` (`ROUTE_DIR` hardcoded), filters receivers to `{s.router, api, gr, ssf, selfServiceGR}`, and its resolver accepts only `core.`/`oauth.` path expressions. The check is one-directional (discovered route must exist in OpenAPI; zero discovered = PASS with 0 errors). After the move, registrations live in 12 owning packages under receivers named `r`, `gr`, etc. — the gate finds ~5 leftover routes and passes silently. FM4, FM5, FM7 and risk 7 all cite this gate as the safety net; the acceptance says "`python cli.py check-routes` unchanged". It cannot be both unchanged and effective: the checker must be extended (scan dirs, receivers, resolver imports, `api`-prefix handling) and `CHECKS_REGISTRY.md:56` updated. Also, FM5's "check-routes runs in the default configuration" is false — it is a static source scan that runs no configuration at all.

**FINDING 4 — HIGH: FM4 misdescribes the router and its own mitigation.** `StdRouter.RegisterGated` appends; `ServeHTTP` is first-match-wins (`router.go:223–233,249–285`) — no overwrite, no panic. And `check-routes` cannot catch duplicates: it only errors on routes *absent* from OpenAPI; a doubly-registered documented path passes. "The acceptance check requires every `Path*` const to have exactly one registration" is an uncommitted aspiration, and no committed test detects double registration. Risk 7's "double-registration … fails the drift gate" is false as written.

**FINDING 5 — MEDIUM: the ≤52 target is not derived.** 60 → ≤52 requires ≥8 deletions; the design specifies exactly one (`server_routes_admin.go`). The rest are "files whose content fell below cohesion threshold" — undefined. `server_admin_handlers.go` stays (≤200), the big files shrink-but-stay. Nothing in the mechanics guarantees the acceptance `ls | wc -l ≤ 52` is reachable; this belongs in the risk register (it isn't there).

**FINDING 6 — MEDIUM: FM6 cites a phantom test.** "`TestArchitecture_` middleware-order assertions" do not exist — `architecture_layer_test.go`/`architecture_gate_test.go` contain layer/import/depth/fanout gates only, and no middleware-order test exists anywhere in `interfaces/`. The real protections are the sketch's `mountMiddleware()`-first line and AGENTS.md prose.

**FINDING 7 — MEDIUM: FM7/FM5 mitigations overclaim.** "the full `go test ./...` suite boots `*Server` in every configuration" — no test boots every config variant; a missed nil-accessor check in a mount panics at boot and is caught only if a test happens to exercise that exact wiring. "Feature-off byte-identity tests cover the unmounted variants" — the hot-reload tests cover gate-*off* (route registered but gated); no store-unwired route-set-diff test exists.

**FINDING 8 — MEDIUM: risk 5's mitigation overstates `sdk-surface check`.** `ops/scripts/sdk_surface.py` validates the operationId registry against `openapi.yaml`/`capabilities.json` — it never scans `aliases.go`. Deleting a re-export breaks nothing in-repo; the protection is review-only. (Related: "419 re-exports" is not reproducible — measured 388 `type`/`const` alias lines, 383 `= core.` lines, 425 `= pkg.` lines.)

**FINDING 9 — MEDIUM: risk 9's mitigation overstates the gates.** `make ci` (`fmt vet race build … route-contract capabilities-check sdk-surface-check …`) contains nothing that compares the AGENTS.md §2 sentence to the exemption value; that agreement is human-review-only. (The value↔count part is machine-pinned by `TestArchitecture_DirectoryFileFanout` + `TestSeedDirectoryFanout`.)

**FINDING 10 — LOW: AGENTS.md drift on the ratchet.** `directory_fanout_test.go:38–43` sanctions shrinking ("SHRINK THESE; never grow them, never raise a ceiling"), so the 60→≤52 ratchet is gate-legal — but AGENTS.md §2 says "fan-out ceilings are frozen", which the design's "shrink-only contract" claim cites without reconciling. Decision 3 updates the ceiling sentence but not the "frozen" wording; same commit should fix both or the ratchet contradicts AGENTS.md prose.

**FINDING 11 — LOW: numeric drift, "All numbers re-verified" not fully true.** (a) "40 mount functions across 16 files" → measured **39 across 14** (the spec carries the same stale number; it was copied, not re-verified). (b) "11 sub-mounts" → **12** calls in `mountAdminSurface`'s body (spec's own list omits `mountAPIDocsUI`). (c) "off by ~29 methods" → the exact delta is 20 (254−234); the 20–29 range is unexplained. (d) Federation row: 1 of the 6 delegates targets `federationhealth.HandleListPeerHealth` in `domains/federation/health`; a `MountRoutes` in `domains/federation` must import that subpackage, contradicting the acceptance line "all mount code imports shared/core only" (same-layer import, so no gate violation — but the sentence is overbroad, and the row's mount target is ambiguous).

## 3. Likelihood ordering and register completeness

- The register's own header ("likelihood × severity") contradicts the doc intro and the task framing ("ordered by likelihood") — pick one.
- Items 1–3 are marked "verified" because the design already corrected them; as *residual* risks they are lower than presented. Meanwhile the two genuine HIGH risks (Finding 2: dropped gates; Finding 3: check-routes vacuity) and the nil-gate contradiction (Finding 1) are **absent from the register entirely**. A completeness-correct ordering would put the dropped-gate and vacuous-gate items at or near #1–#2, and the ≤52 non-derivability (Finding 5) around #3–#4. Items 7 (check-routes lockstep) and 9 (docs drift) are mis-rated LOW given Findings 3 and 9.
- Failure modes: the seven are individually sensible and the placement/acceptance numbers mostly tie out, but the set misses (a) whole-surface gate loss during relocation (Finding 2), (b) duplicate-registration undetectability (Finding 4 — FM4's text is wrong, its mitigation inert), and (c) vacuous-pass of the route gate (Finding 3).

## 4. Minimal fix list (bounded, no scope creep)

1. **Resolve the nil-gate question explicitly**: either allow nil = ungated (and delete the panic rule + rework FM1) or require an always-on closure; then fix the sketch to pass `oidcGateOn`, `federationGateOn`, `cibaGateOn` (via oauth) where gated today. Add a "gate dropped for a surface" failure mode pinned by the existing hot-reload tests.
2. **Plan the `route_contract.py` extension** (scan owning packages, extend receivers/resolver, keep `api`-prefix mapping) as part of the same change; replace "unchanged" in the acceptance with "extended, plus `CHECKS_REGISTRY.md` updated"; or add a runtime route-snapshot test.
3. **Enumerate the ≥8 deletions** for the ≤52 target, or state the target as "measured count" and drop the numeric claim.
4. Correct FM4's router semantics; correct FM6/FM7/FM5 mitigations to cite what actually exists (mountMiddleware-first line, hot-reload tests, gate-off byte-identity tests).
5. Reconcile AGENTS.md "fan-out ceilings are frozen" in the same commit as the ratchet; fix the four stale numbers (39/14, 12 sub-mounts, re-export count, off-by-20).

The design's core architecture (per-package `MountRoutes`, ceiling-aware placement, corrected grep, storage-model decision, ratchet mechanics) is sound and gate-consistent; the audit's material issues are concentrated in Decision 3's `Mount()` sketch and the design's reliance on a route gate that stops measuring exactly when the code moves.
