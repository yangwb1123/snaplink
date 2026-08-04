# Architecture Review — `interfaces/sso` 方向三（薄委托下沉 + 天花板棘轮）

Source: `docs/auto/interfaces-sso-direction3-design.md` (spec:
`interfaces-sso-direction3-spec.md`, analysis: `interfaces-sso-analysis.md`).
Review role per `ai-dev/prompts/README.md`: advisory, evidence-labeled, no code
changed. Every material claim below was re-measured against the tree and the
committed gates (`directory_fanout_test.go`, `maintainability_budget_test.go`,
`architecture_layer_test.go`, `shared/core/router.go`, `checks/route_contract.py`,
`ops/scripts/sdk_surface.py`, `Makefile`) at this revision.

Checks that actually ran: `go test -run 'TestMaintainability_|TestArchitecture_' .`,
`python cli.py check-routes`, `wc`/`grep`/`awk`/Python census scripts over
`interfaces/sso/*.go`, `shared/core/router.go`, and the placement-table
packages. No build of the moved code exists (no code moved).

## 1. Scope, assumptions, and verified architecture summary

**Scope.** Evaluate direction 3 of the interfaces/sso slimming analysis: (改进一)
sink 109 non-admin thin delegates + their route registrations into 12 owning
protocol/domain/platform packages via per-package `MountRoutes(r core.Router,
d Deps, gate func() bool)`; (改进二) move the whole `/api/v1/admin/*` surface
(60 admin + 5 adminuser delegates) into `interfaces/admin` as
`MountAdminSurface`; (改进三) merge residual files and ratchet
`dirFileCountExemptions["interfaces/sso"]` from 60 down to ≤52.

**Assumptions.** (a) Committed gates are the regression contract and the
spec/design's "wire-invisible, byte-identical" invariant is the acceptance
bar. (b) The worktree contains unrelated uncommitted pi-batch work; pre-existing
gate failures there are reported separately, not attributed to the design.
(c) This review is advisory; it fixes the design's text only where the design
itself asks for decisions (it does, in Decision 3's `Mount()` sketch).

**Verified architecture summary.** The design's core census is exact:

- `interfaces/sso`: 60 production files / 48,830 lines; `grep -c "func (s
  \*Server) handle"` = **254**; anchored sole-param filter = **234**; the 20
  diff = 18 multi-arg `(ctx HandlerContext, …)` helpers + 2 non-ctx
  (`handleLivez(w, r)`, `handleReadyz(w, r)`).
- Exactly **174** single-call delegates `{ pkg.HandleX(s, ctx) }`, per-package
  split reproduced exactly (admin 60, selfservice 56, oauth 8, rebac 7,
  netpolicy 6, caep 6, configaudit 5, federation 5, webhook 5, adminuser 5,
  oidc 3, permissions 3, audit 3, federationhealth 1, wasmauthz 1); **every one
  registered exactly once** (`s.<name>` reference census); 174 = 109 + 65, so
  "234 → ≤125" arithmetic holds.
- The placement table: 8 of 13 target packages are AT a file cap (oauth 12/12,
  audit 16/16, federation 24/24 exemptions; oidc/caep/selfservice/permissions
  10/10 default; `interfaces/admin` 10/10 with **no exemption entry** — the
  spec's "frozen `dirFileCountExemptions` value" for admin references a map
  entry that does not exist). Only configaudit (8), netpolicy (6), rebac (7),
  wasmauthz (4), webhook (9) may take a new file. `TestArchitecture_
  DirectoryFileFanout` **passes today**, so "a new file fails the very gate
  this direction protects" is live, not hypothetical.
- `interfaces/admin/deps.go` = 177 lines, the only admin file with ≥300 lines
  headroom (middleware.go 492, connections.go 498, users.go 464, governance.go
  483, lifecycle.go 481, tenants.go 466, break_glass.go 436,
  break_glass_impersonate.go 350, token_portfolio.go 404); `fileSizeExemptions`
  is empty. The ceiling-bound packages' headroom examples also check out
  (oauth/grant_handler.go 31, oidc/aliases.go 49, caep/doc.go 61,
  selfservice/loginui.go 36, audit/doc.go 9, federation/cache.go 47,
  permissions/types.go 39). 42 of the 47 admin-file delegates are in
  `server_admin_handlers.go` (498 lines).
- `GatedRouter` consults `live func() bool` per request at route-match level
  (`shared/core/router.go:223,249-285`), with `GateHandler` fallback; method-
  value closures (never `.Load()` results) are the correct and load-bearing
  rule — `feature_gate_hotreload_test.go` (AdminAPI, Branding, OIDC, CIBA,
  CAEP, Federation, SelfService) and `degradation_test.go` pin it. The 7
  atomics (`adminAPILive, brandingLive, oidcLive, cibaLive, caepLive,
  federationLive, selfServiceLive`, `sso_wiring.go:217-223`) and 7 `*GateOn`
  methods (`server_routes.go:217-223`) exist as described.
- `checks/route_contract.py` scans only `ROUTE_DIR = interfaces/sso`, filters
  receivers to `{s.router, api, gr, ssf, selfServiceGR}`, resolves only
  `core.`/`oauth.`/bare-`Path*` expressions, and is one-directional
  (undocumented runtime route = error; unregistered documented route = silent).
  Today: PASS, 241 runtime routes / 322 documented ops. `sdk_surface.py`
  validates operationId registry vs `openapi.yaml`/`capabilities.json` and
  never scans `aliases.go`. `make ci` contains nothing comparing the AGENTS.md
  §2 sentence to the exemption value.
- Layer legality of the move is real: `core.Router`/`HandlerContext` live in
  `shared/core`; owning packages gain only downward/same-layer imports
  (`internal/adminuser` is classified `interfaces` at
  `architecture_layer_test.go:108`; `domains/federation/health` is same-layer
  to `domains/federation`). `interfaces/sso` keeps one import per `Mount*`
  call, so god-package fan-in entries are untouched. `MountAdminSurface` is
  same-layer (`interfaces → interfaces`).

**Architectural reading of the proposal.** The design moves route registration
(a classic inbound-delivery concern, per DIRECTORY_MAP "interfaces/ inbound
delivery") down into protocols/domains/platform. This is import-legal and
handler-ownership-coherent (the `HandleX` bodies already live there), and the
hard 60-file ceiling leaves no cheaper alternative. The price is that the wire
surface's canonical inventory becomes distributed across 13 packages, with
`docs/openapi.yaml` + `route_contract.py` as the only binding agent. That makes
the checker's continued effectiveness a load-bearing property of the design,
not a nice-to-have — which is exactly the property the design's own sketch
breaks (Findings H1/C2 below). Within that constraint the per-package
`MountRoutes` shape, ceiling-aware placement table, and ratchet mechanics are
sound, minimal, and gate-consistent.

## 2. Findings

Severity per `ai-dev/prompts/README.md`. Evidence is path + symbol/command.

| # | Sev | Finding | Evidence | Impact | Recommendation |
|---|---|---|---|---|---|
| C1 | Critical | **The design's own final `Mount()` sketch passes `nil` for 10 of 13 mounts while Decision 1 declares nil a panic.** `oauth.MountRoutes(s.router, s, nil)`, `oidc.…, nil)`, `rebac.…, nil)`, `netpolicy.…, nil)`, `federation.…, nil)`, `webhook.…, nil)`, `configaudit.…, nil)`, `permissions.…, nil)`, `audit.…, nil)`, `wasmauthz.…, nil)` vs "Nil gate = programmer error: `MountRoutes` panics if `gate` is nil" and "`Mount()` only ever passes real method values, so the panic is unreachable in production" — the sketch is its own FM1, unmitigated. | design Decision 3 sketch; Decision 1 nil rule | A literal implementation panics at boot on every ungated surface; the alternative reading (nil = ungated) contradicts Decision 1 and the fail-open rejection. Release blocker either way. | Resolve explicitly: (a) keep the panic and pass `func() bool { return true }` for ungated surfaces, or (b) allow nil = ungated and delete the panic rule + rework FM1. Fix the sketch to say which. |
| C2 | Critical | **The same sketch silently drops three live hot-reload gates.** Today `oidcGateOn` gates `/userinfo` + `/check_session_iframe` (`server_userinfo.go:33`), `cibaGateOn` gates `/backchannel/auth` (`server_routes.go:239`), `federationGateOn` gates the federation surface incl. HomeRealmDiscovery (`server_federation.go:197`). The sketch passes nil for oidc and federation (oauth covers CIBA). | sketch vs `NewGatedRouter` sites above; `feature_gate_hotreload_test.go:239,271,378` | `TestSetOIDCGateEnabled_…`, `TestSetCIBAGateEnabled_…`, `TestSetFederationGateEnabled_…` fail; gate-off reachability becomes gate-on — a fail-open wire change on three surfaces, violating AGENTS.md §3 hot-reload invariants. Not in FM1–FM7, not in the risk register; Decision 4's atomic enumeration names only 4 of 7 (omits `oidcLive`, `cibaLive`, `federationLive` — exactly the dropped ones). | Pass the three closures through the mounts (oidc/federation directly; CIBA via the oauth mount, which needs a named-gate API, not a positional `gates …func() bool`). Add a "gate dropped for a surface" failure mode pinned by the existing hot-reload tests. |
| H1 | High | **The design's own regression net (`check-routes`) goes vacuous under the move, and the acceptance demands it stay "unchanged".** `checks/route_contract.py:18` hardcodes `ROUTE_DIR = interfaces/sso`, whitelists receivers, and accepts only `core.`/`oauth.` path expressions; it is one-directional (undocumented route = error; zero discovered routes = PASS). After the move, registrations live in 12 owning packages under receivers like `r`; the gate discovers the ~5 leftover sso registrations and passes silently. FM4/FM5/FM7 and risk 7 all cite this gate as the safety net; the acceptance's "`check-routes` unchanged" cannot hold together with "effective". | `route_contract.py` full read; FM5's "runs in the default configuration" is also false — it is a static source scan, boots nothing | The core invariant (wire-invisible, byte-identical route set) becomes unverifiable by the only committed tool; a dropped or doubled route (see H3) passes CI. | Extend `route_contract.py` (multi-dir scan, receiver set, resolver imports, `api`-prefix mapping) and update `CHECKS_REGISTRY.md` scope in the SAME commit as the first mount move; OR add a runtime route-snapshot golden test (boot `Server`, walk the in-memory route table, diff against the pinned 241-route set). Prefer both: static scan is the OpenAPI lockstep, the runtime walk catches duplicates and gate drops. |
| H2 | High | **FM4 misdescribes the router and its own mitigation.** `StdRouter.ServeHTTP` is first-match-wins (append-only `RegisterGated`, `router.go:223-233,249-285`): a duplicate registration silently shadows — no overwrite, no panic. `check-routes` cannot catch duplicates (documented path registered twice = no error). "The acceptance check requires every `Path*` const to have exactly one registration" is an uncommitted aspiration; no committed test detects double registration. | `shared/core/router.go`; `route_contract.py:missing_route_errors` | A package mount + a leftover sso mount for the same path = dead route, invisible to CI, exactly when 13 packages start registering. | Correct FM4's text; add a runtime walk test asserting each (method, path) has exactly one registration after `Mount()`; keep the "leftover sso registrations must be zero" rule in the acceptance. |
| H3 | High | **The sketch's `Mount()` omits `mountAdminTokenExchangeChainRoutes`** (registers `GET /api/v1/admin/token-exchange-chain` behind `adminAPIGateOn`, `accessors_threat.go:197`), whose handler `handleAdminTokenExchangeChain` is body-bearing and stays in `interfaces/sso`. It cannot fold into `MountAdminSurface` without an upward import (`interfaces/admin → interfaces/sso` = package cycle). | sketch vs `accessors_threat.go:197` | A documented admin route silently disappears; undetectable once H1 lands. | Keep the mount call in the new `Mount()` (one line), or move handler + deps down to `interfaces/admin` (bigger change, not required). |
| M1 | Medium | **The ≤52 target is not derived.** 60 → ≤52 requires ≥8 deletions; the design specifies exactly one (`server_routes_admin.go` deleted). The rest are "files whose content fell below cohesion threshold" — undefined. `server_admin_handlers.go` shrinks-but-stays (≤200); the big files shrink-but-stay. Nothing in the mechanics guarantees the acceptance `ls \| wc -l ≤ 52`. | design Decision 3 vs acceptance | If the measured count lands at 57, the promised headroom for directions 一/二 shrinks; the ratchet itself is still correct (lower to measured), so this is a plan-vs-commitment gap, not a gate failure. | Enumerate the ≥8 deletions (name the merge targets) in the design, or state the acceptance as "≤ 52 planned, measured count ratified by `TestSeedDirectoryFanout`" and drop the numeric claim. |
| M2 | Medium | **FM6 cites a phantom test.** "`TestArchitecture_` middleware-order assertions" do not exist; the architecture gates cover layers/imports/depth/fan-out only, and no middleware-order test exists in `interfaces/`. | `architecture_layer_test.go`, `architecture_gate_test.go`, `directory_fanout_test.go`, `maintainability_budget_test.go` (test lists) | The mitigation for middleware-order regression is prose ("`mountMiddleware()` first" line + AGENTS.md §2), not a gate. | Cite what exists: the `mountMiddleware()`-first line and the documented middleware order; optionally add a middleware-order test while the surface is being relocated. |
| M3 | Medium | **FM7/FM5 mitigations overclaim.** "The full `go test ./...` suite boots `*Server` in every configuration" — no test boots every config variant; a missed nil-accessor in a mount panics at boot and is caught only if a test exercises that exact wiring. "Feature-off byte-identity tests cover the unmounted variants" — hot-reload tests cover gate-off (route registered, gated), not store-unwired route-set differences. | test inventory (`feature_gate_hotreload_test.go`, `degradation_test.go`, `rootcov_*`) | A store-unwired config registers a different route set with no committed test noticing. | Add one route-set-diff test: boot with stores absent vs present and assert the registered route sets; state the remaining gap in FM7's text. |
| M4 | Medium | **Risk-5's mitigation overstates `sdk-surface check`.** `ops/scripts/sdk_surface.py` validates the operationId registry against `openapi.yaml`/`capabilities.json`; it never scans `aliases.go`. Deleting a re-export breaks nothing in-repo. Related: "419 re-exports" is not reproducible (measured 380 `type/const/var = core.` lines, 427 lines containing `=`, of 500). | `ops/scripts/sdk_surface.py:44-109`; `aliases.go` | `aliases.go`'s protection is review-only; the design's "no-touch" rule is a process rule, not a gate. | Keep the no-touch rule; state it as review-enforced; fix the 419 figure or drop it. |
| M5 | Medium | **Risk-9's mitigation overstates `make ci`.** Nothing in `make ci` (`fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract capabilities-check sdk-surface-check profiles-evidence`) compares the AGENTS.md §2 sentence to the exemption value. | `Makefile:244` | AGENTS.md↔gate agreement is human-review-only (the count↔value half is machine-pinned by `TestArchitecture_DirectoryFileFanout` + `TestSeedDirectoryFanout`). | Say so; optionally add a root gate test reading the exemption map and asserting the AGENTS.md sentence contains the value. |
| L1 | Low | **AGENTS.md drift on the ratchet.** `directory_fanout_test.go:38-43` sanctions shrinking; AGENTS.md §2 says "fan-out ceilings are frozen". Decision 3 updates the ceiling sentence but not the "frozen" wording. | both texts | Prose contradiction on the sanctioned direction; gate-legal either way. | Fix both sentences in the same commit as the ratchet. |
| L2 | Low | **Numeric drift, "All numbers re-verified" overstates.** (a) "40 mount functions across 16 files" → measured 40 across **14**; (b) "11 sub-mounts" → **12** calls in `mountAdminSurface`'s body (`mountAPIDocsUI` omitted from the design's list); (c) "off by 20–29" → exact delta is 20 (254−234); (d) "The 5 adminuser delegates' bodies live in `users.go` (464 lines)" → wrong file: bodies are in `internal/adminuser/handlers.go` (239 lines); `interfaces/admin/users.go` holds the 14 admin user-state handlers; (e) "all mount code imports `shared/core` only" is overbroad — the federation row's `MountRoutes` must import `domains/federation/health` (same-layer, gate-legal). | measurements above | None beyond prose fidelity; none invalidate the table or the operational conclusions. | Fix in the design. |
| L3 | Low | **Pre-existing gate failures in the worktree (reported separately per AGENTS.md §5.7).** `TestMaintainability_FileSizeBudget` fails on `cmd/sso-server/build_app_oauth.go` (554) and `interfaces/grpcserver/grpcadmin/admin_snapshots.go` (581); `TestMaintainability_FunctionLength` and `TestMaintainability_CyclomaticComplexity` also fail (`interfaces/snapshot/diff.go:indexCategory` cyclo 40, `admin_snapshots.go` funcs, `serverbuildstore/build_oauth_stores.go` funcs). All are uncommitted pi-batch work (`git status`), none in the design's target packages. `TestArchitecture_*` all pass. | `go test -run 'TestMaintainability_|TestArchitecture_' .` | Not caused by the design; must be fixed or quarantined before `make ci` handoff. | Track separately; do not fold into this direction. |

Verified-correct design claims (not repeated as findings): the 254/234/174
census and 234−109=125 arithmetic; all 13 placement-table counts and caps incl.
the 8 at-ceiling packages and the missing admin exemption entry; `deps.go` 177
headroom and the 7 ceiling-bound packages' headroom examples; method-value
closure rule and the per-request `live()` semantics; 7 atomics + 7 `GateOn`
methods; `check-routes` 241/322 today; `make ci` membership; 24 "Relocated
from" comments; `seedFeatureGateLiveFlags` in `accessors_feature_gates.go:35`
(not `sso.go`); zero-runtime-storage decision and the "no hot-plugin
registries" boundary (MountRoutes is compile-time composition, touching none of
`FeatureGates`/`Server.Handle`/`AddReadyCheck`/`audit.Recorder.AddSink`).

## 3. Decision options

**Option A — adopt the design with the fix list (recommended).** The direction
itself is justified: the 60-file ceiling is the analysis's structural
bottleneck, the ceiling is hard, the handlers already live below, and the
ratchet is the only gate-sanctioned way to create headroom. The fixes are
bounded and enumerated (C1 nil-gate resolution, C2 gate-passing + named-gate
API for the oauth mount, H1 checker extension + runtime snapshot, H2
duplicate-registration test, H3 token-exchange-chain mount retention, M1
enumerated deletions, M2/M3 honest mitigations, L1 AGENTS.md wording, L2
numbers). Cost: ~200 lines of design revision + one Python checker extension +
one runtime walk test. Risk: low once C1/C2 are resolved; the placement table
and line-budget measurements are already verified.

**Option B — 改进二 only + ratchet (minimal viable slice).** Land the admin
surface move (same-layer, largest cluster: 65 delegates, 42 in one file) and
the ratchet; defer the 13 protocol mounts. `check-routes` stays effective with
a small extension (scan `interfaces/admin` too; receiver `api` is already
whitelisted; admin uses `core.Path*`). Trade-off: delivers ~1/3 of the line
savings and keeps the protocol-mount risk (C1/C2 territory) out of the first
commit; the 60-file ceiling still blocks directions 一/二 until 改进一 lands.
Build-vs-buy: not applicable — no external component can substitute for the
routing layer; the `Router` abstraction already supports gin/echo adapters, and
per-package mounts keep that compatibility (GatedRouter's `GatedRegistrar`
fallback).

**Option C — reject the direction.** No alternative creates ceiling headroom
without touching `layerExemptions` or `fileSizeExemptions` (both frozen).
Not viable given the analysis's stated goal of enabling directions 一/二.

**Preferred: Option A, sequenced so the regression net lands first** (see §4):
extend `route_contract.py` + add the runtime route-snapshot test BEFORE the
first mount moves, then 改进二, then 改进一, then 改进三. If the owner wants a
smaller first commit, Option B is a safe staging point — but the acceptance
must not claim `check-routes` "unchanged" in any commit that moves mounts.

## 4. Prioritized implementation sequence

1. **M0 — Design fixes (docs only, no code).** Resolve C1 (nil = ungated, or
   always-on closures; delete or rework the panic rule), fix the sketch to pass
   `oidcGateOn`, `federationGateOn`, `cibaGateOn` (via oauth, with a named-gate
   API), retain `mountAdminTokenExchangeChainRoutes`, add the "gate dropped for
   a surface" failure mode, fix M1 (enumerate deletions or measured-count
   wording), M2/M3 (honest mitigations), L1 (AGENTS.md wording), L2 (numbers).
   *Acceptance: design text only; no gate changes.*
2. **M1 — Regression net first (code).** Extend `checks/route_contract.py`
   (scan owning packages, extend receivers/resolver, keep `api`-prefix
   mapping) with unit tests (`checks/test_route_contract.py`); add a runtime
   route-snapshot golden test in `interfaces/sso` (boot `*Server`, walk the
   route table, pin the 241-route set; assert no (method, path) registered
   twice); update `docs/agent-os/CHECKS_REGISTRY.md` scope line.
   *Acceptance: `python cli.py check-routes` still PASS with 241/322; new
   tests green; `make ci` green apart from the known L3 pre-existing
   failures.*
3. **M2 — 改进二 (admin surface).** `MountAdminSurface(r core.Router, d Deps,
   gate func() bool)` in `interfaces/admin/deps.go` (~150–200 lines section,
   lands ~350–380); delete `server_routes_admin.go`; `server_admin_handlers.go`
   ≤ 200 (42+5 delegates removed); `interfaces/admin` file count stays 10;
   no `interfaces/admin → interfaces/sso` import (cycle). *Acceptance:
   `check-routes` (extended) PASS; `rootcov_admin*.go`, 401 `Bearer
   realm="admin"`, `admin:read`/`admin:write` tests unchanged; admin route set
   byte-identical vs pre-move snapshot; `go test -run
   'TestMaintainability_|TestArchitecture_' .` green.*
4. **M3 — 改进一 (protocol mounts).** Per the placement table; re-measure
   per-file line budgets at edit time for the 8 append-to-existing-file
   packages; new `mount.go` only for configaudit/netpolicy/rebac/wasmauthz/
   webhook; gates passed as method values for selfservice/caep/admin + the
   C2 three; all 174 delegates deleted; 109 non-admin acceptance grep ≤ 125.
   *Acceptance: anchored grep ≤ 125; hot-reload + degradation tests green
   (this is what pins C2); no new `layerExemptions` entry; no upward import in
   any owning package; route snapshot unchanged.*
5. **M4 — 改进三 (consolidation + ratchet).** Merge residuals per the
   enumerated deletion list (M1); ratchet LAST: edit the exemption, run
   `SEED_DIRFANOUT=1 go test -run TestSeedDirectoryFanout -v .`, commit the
   regenerated test + deletions + AGENTS.md §2 both sentences in ONE commit;
   re-run the seed immediately before push. *Acceptance: `ls
   interfaces/sso/*.go | grep -v _test | wc -l` ≤ 52; exemption value =
   measured count; `TestSeedDirectoryFanout` no drift; `python cli.py
   check-routes` and `sdk-surface check` PASS; `go test ./... -race`; `make
   ci`.*

**Compatibility plan.** Wire surface: byte-identical route set at every
milestone (route snapshot + checker); OpenAPI untouched; `aliases.go` untouched
(review-enforced); path constants stay in `shared/core`; no storage/config/
wire-format change; hot-reload byte-identity preserved via method-value
closures (M3 gate mapping is the critical path); SDK surface unchanged
(`sdk-surface check` + `rootcov_*`). Risk register: the C1/C2/H1/H2/H3 items
above plus the design's own nine-item register (items 1–3 verified residual,
items 4–9 as rated, with 7 and 9 re-rated per M5/H1).

## 5. Unknowns needing owner or product decisions

1. **Nil-gate semantics (owner decision, blocks M0).** Is `nil` = ungated
   acceptable (fail-open, matches today's `RegisterGated` nil behavior) or must
   ungated surfaces pass an explicit always-on closure? Decision 1's panic rule
   and the sketch cannot both stand.
2. **Gate-union API for the oauth mount.** CIBA's gate is today a single route
   (`/backchannel/auth`) inside the oauth area. Does `MountRoutes` take a named
   gate set (`gates …func() bool` is positionally ambiguous), or does oauth
   expose a second entry point for the CIBA route? Product call on how much API
   surface each package exports.
3. **≤52 target vs measured count.** Commit to an enumerated deletion list
   (M1) or accept a measured-count ratification? This sets the headroom
   promised to directions 一/二.
4. **Regression-net form.** Static multi-dir scan (extend route_contract.py),
   runtime route-snapshot golden test (maintenance burden per route change),
   or both? The snapshot catches what the scanner cannot (duplicates, gate
   drops); the scanner keeps OpenAPI lockstep. Owner decides the long-term
   burden.
5. **F1/F2 protocol findings in scope?** The protocol review flags `slow_down`
   +5 s (RFC 8628 §3.5 / CIBA §7.1) and the 429 body's misleading
   `unsupported_grant_type` — both small wire fixes touching files the refactor
   doesn't move. Landing them "with 改进一" violates AGENTS.md's smallest-
   cohesive-change rule unless explicitly scoped; owner decides.
6. **Single-owner-of-wire-surface property.** After this direction, the route
   inventory lives across 13 packages + OpenAPI. Acceptable, or should the
   mounts also emit a machine-readable route inventory (generated from the
   `Mount*` calls) that the OpenAPI gate consumes? Architectural preference,
   not a gate question.
