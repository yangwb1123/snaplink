# interfaces/sso — 方向三 设计 QA 评审（risk-based test review）

Review of `docs/auto/interfaces-sso-direction3-design.md` (+ spec
`interfaces-sso-direction3-spec.md` and the protocol review
`interfaces-sso-direction3-protocol-review.md`) at the current worktree.
The design is **Stage: design** — no implementation landed; this review
re-measures every load-bearing number, maps the six decisions and the
spec's acceptance checks to existing/required tests, and identifies what
the regression net does and does not cover AFTER the route registrations
move out of `interfaces/sso`. Every command below ran for this revision
against the worktree as-is; no result is inherited from the sibling
reviews (their numbers were re-measured independently and agree unless
noted).

## 1. Test inventory and commands actually run for this revision

| Command | Result | Evidence |
|---|---|---|
| `go build ./...` | PASS | no build errors |
| `go vet ./...` | **FAIL (pre-existing)** | `interfaces/snapshot/snapshot_test.go:367:24: method fixtureBlank.snapshotter already declared at interfaces/snapshot/restore_modes_test.go:440:24` — uncommitted stage work, not the design's packages |
| `go test -run 'TestArchitecture_' .` | PASS | layer, directory file/subdir fan-out, exemption ratchet (`TestArchitecture_DirectoryFileFanout`, `TestArchitecture_DirectoryFanoutExemptionsDoNotGrow`, `TestSeedDirectoryFanout` skipped without `SEED_DIRFANOUT`) |
| `go test -run 'TestMaintainability_' .` | **FAIL (pre-existing)** | `FileSizeBudget`: `cmd/sso-server/build_app_oauth.go` (554), `interfaces/grpcserver/grpcadmin/admin_snapshots.go` (581); `CyclomaticComplexity`: `interfaces/snapshot/diff.go:indexCategory` (40 > 15), `admin_snapshots.go:restoreTracked` (16 > 15); `FunctionLength`: `cmd/sso-server/serverbuildstore/build_oauth_stores.go:BuildRefreshTokenStore` (62 > 50). None in design target packages |
| `python3 cli.py check-routes` | PASS | 241 runtime routes / 322 documented operations (this is the design's headline regression net — see F1) |
| `python3 cli.py sdk-surface check` | PASS | registry valid (13 groups, 316 operations) — does NOT scan `aliases.go` (see F9) |
| `go test ./interfaces/sso/ -run 'TestSet.*GateEnabled\|TestServer_Degradation\|TestServer_DRMode\|TestHandleHealth' -count=1 -v` | PASS (all 16) | all 7 hot-reload gate tests, 4 degradation/DR-mode tests, 2 health tests |
| `go test ./interfaces/sso/ -race -count=1 -run 'TestSet.*GateEnabled\|TestServer_DRMode'` | PASS | atomics read per-request under race |
| `go test ./interfaces/sso/ -count=1` | **FAIL (pre-existing, 5 tests)** | `TestConnectionDispatch_EnabledConnectionRedirectsUpstream`, `TestConnectionDispatch_CallbackCrossTenantGuard`, `TestConnectionDispatch_CrossTenantGuardIsHostScoped`, `TestRcov2H_Callback`, `TestRcov2H_GetLoginFederatedRedirect` — all `invalid_callback`/`invalid_request` 400s, consistent with the uncommitted `interfaces/sso/handlers.go` diff (`authenticatedSubject` now requires `core.IsAccessTokenClaims(claims)`); not caused by the design |
| `go test ./interfaces/sso/ -race -count=1` | same 5 failures only | no race-detector failures beyond the pre-existing cluster |
| `go test ./interfaces/admin/ ./internal/adminuser/ -count=1` | PASS | admin + adminuser suites (70 + 10 test funcs) |
| `go test ./protocols/... ./platform/audit/ ./platform/configaudit/ ./platform/netpolicy/ ./domains/federation/ ./domains/permissions/ ./platform/lifecycle/... ./interfaces/admin/... -count=1` | PASS | every owning package in the placement table is green today |
| `go test ./test/ -run TestE2E -count=1` | PASS | 3 wire-level E2E tests (login→authorize→deny) |

Independent measurements reproduced for this revision:

| Measurement | Result |
|---|---|
| Sole-param `handle*(ctx HandlerContext)` count (design's corrected acceptance pattern) | **234** (exact command: `grep -hE 'func \(s \*Server\) handle[A-Za-z0-9_]*\(ctx HandlerContext\)' interfaces/sso/*.go \| wc -l`) |
| Literal `grep -c "func (s \*Server) handle"` (spec's unanchored pattern) | **254** — spec correction 2 confirmed; delta is exactly 20 (18 multi-arg `(ctx HandlerContext, …)` helpers + `handleLivez(w, r)` + `handleReadyz(w, r)`) |
| Exact `(s, ctx)` single-call delegates `{ pkg.HandleX(s, ctx) }` | **174**, per-package reproduction exact: selfservice 56, oauth 8, oidc 3, caep 6, rebac 7, netpolicy 6, federation 5, federationhealth 1, webhook 5, configaudit 5, permissions 3, audit 3, wasmauthz 1, admin 60, adminuser 5 |
| Additional single-call-but-not-`(s,ctx)` pass-throughs NOT in the 174 table | 16 (`handleAdminTokenUsage`, `handleAdminTokenPolicies`, `handleAdminTokenPortfolio`, `handleAdminTokenSubject`, `handleAdminTokenExpiring`, `handleAdminTokenSuspicious`, `handleAdminListThreatPolicies`/`Get`/`Put`/`Delete`, `handleAdminLinkedSessions`, `handleAdminEventsStream`, `handleStorageHealth`, `handleAdminTriggerRetentionSweep`, `handleAdminTokenExchangeChain`, `handleCheckSessionIframe`) — the "234 → ≤125" acceptance counts only the 109 table rows; these 16 stay or are handled separately and are not enumerated in the design |
| Mount functions | 39 `mount*` + `Mount()` = **40 across 14 files** (design says "40 across 16 files" — count right, file count stale; same stale 16 in the spec) |
| `mountAdminSurface` sub-mount calls | **12** (design/spec say 11; `mountAPIDocsUI` is omitted from the lists) |
| File ceilings | `protocols/oauth` 12 (= exemption 12), `platform/audit` 16 (=16), `domains/federation` 24 (=24), `protocols/oidc`/`caep`/`selfservice`, `domains/permissions`, `interfaces/admin` 10 each (= default cap, **admin has no exemption entry** — spec correction 1 confirmed), `configaudit` 8, `netpolicy` 6, `rebac` 7, `wasmauthz` 4, `webhook` 9 |
| `interfaces/admin` line budgets | `deps.go` 177 (only ≥300 headroom), `middleware.go` 492, `connections.go` 498 — spec correction 3 confirmed |
| adminuser delegate bodies | `internal/adminuser/handlers.go` (239 lines; 3 prod files, unconstrained) — design's "users.go (464 lines)" attribution is wrong (that file holds the 14 user-state handlers) |
| `dirFileCountExemptions` map | 12 entries; `"interfaces/sso": 60` (`directory_fanout_test.go:59`) with SHRINK-ONLY contract at `:40-43` |
| `check-routes` coverage today | 241 routes; 85 registered in `server_routes_admin.go`, 36 `sso_selfservice.go`, 33 `server_routes.go`, 24 `server_me.go`, 11 `server_health.go`, 9 `server_backup.go`, 9 `server_federation.go`, 8 `server_extensions.go`, 7 `signing_key_aggregation.go`, 6 `handlers.go`, 5 `server_admin_handlers.go`, 3 `server_userinfo.go`, 2 `server_discovery.go` + probes |
| Route test-reference coverage | 111/241 routes have no literal path string in any `interfaces/sso`, `interfaces/admin`, `cmd/sso-server`, or `test/` test file; 14/241 have no reference even to their last path segment |

## 2. Requirement-to-test matrix

| # | Requirement (source) | Test that pins it today | Status |
|---|---|---|---|
| R1 | 改进一: route set byte-identical after move (spec acceptance: `check-routes` unchanged) | `checks/route_contract.py` (static scan of `interfaces/sso/*.go` only, receivers `{s.router, api, gr, ssf, selfServiceGR}`, resolver accepts `core.`/`oauth.`/bare `Path*`) | **Partial → breaks after the move** — receiver `r` (the design's own parameter name) is invisible; `api`-prefix assumption wrong for `gr`-registered admin routes; one-directional (undocumented-route only). Zero discovered routes = PASS. See F1. |
| R2 | 改进一: `handle*(ctx HandlerContext)` count 234 → ≤125 | none — PR-time grep only; spec's literal grep counts 254, not 234 | **Missing** — no committed test pins the method count; the anchored pattern is the only usable filter (F4) |
| R3 | 改进一: gate closures read atomics per request (never `.Load()` capture) | `feature_gate_hotreload_test.go` — 7 tests (`TestSetAdminAPIGateEnabled_*` :88/:140/:163, `TestSetBrandingGateEnabled_*` :121/:195, `TestSetOIDCGateEnabled_` :239, `TestSetCIBAGateEnabled_` :271, `TestSetCAEPGateEnabled_` :310/:363, `TestSetFederationGateEnabled_` :378/:413/:429, `TestSetSelfServiceGateEnabled_` :453) + `degradation_test.go` :47/:58/:121/:145 | **Verified** — byte-identical off-path assertions (status + body + full header set) against a never-mounted baseline path |
| R4 | 改进一: nil gate = boot-time panic | none exists today; design proposes a per-entry-point unit test | **Proposed** — must be added with the mounts (F2) |
| R5 | 改进二: admin surface move; 401 `Bearer realm="admin"`, `admin:read`/`admin:write` unchanged | `interfaces/admin/middleware_test.go`, `governance_test.go` (scope tables), `rootcov_admin*.go` (9 files, HTTP-level, e.g. `rootcov_admin_password_reset_test.go` route tests), `feature_gate_hotreload_test.go` admin byte-identity | **Verified** at HTTP level; direct-call coverage in `interfaces/admin` exists for a subset (token portfolio/expiring/chains, governance, break-glass) — 50+ of the 65 admin/adminuser delegates have **no direct test call anywhere** (F3) |
| R6 | 改进二: `server_admin_handlers.go` ≤ 200, `server_routes_admin.go` deleted; admin file count stays 10 | generic `TestMaintainability_FileSizeBudget`; `TestArchitecture_DirectoryFileFanout` (cap 10, no exemption) | **Partial** — the file-count half is machine-pinned; the ≤200 half is only the generic budget test |
| R7 | 改进三: `interfaces/sso` prod files ≤ 52; exemption = measured count | `TestSeedDirectoryFanout` (regeneration) + `TestArchitecture_DirectoryFileFanout` (enforces map) + `TestArchitecture_DirectoryFanoutExemptionsDoNotGrow` (shrink-only latch) | **Partial** — the ratchet mechanics are pinned, but the ≤52 *target* is not derived (only `server_routes_admin.go` deletion is enumerated; ≥8 deletions unspecified) and after the ratchet the gate passes at whatever the measured count is (F5) |
| R8 | 改进三: `aliases.go` untouched; SDK surface unchanged | `python3 cli.py sdk-surface check` (operationId registry vs OpenAPI + capabilities) | **Partial** — does not scan `aliases.go`; deleting a re-export breaks nothing in-repo (F9) |
| R9 | No wire change: routes, errors, headers byte-identical | `check-routes` (see R1), `rootcov_*` HTTP suites (504 test funcs in `interfaces/sso`), `test/` suite (1,201 test funcs incl. 3 E2E), protocol suites in owning packages | **Partial** — strong HTTP net today; degrades exactly where the move happens (F1/F3) |
| R10 | Hot-reload gating preserved for all 7 surfaces (AGENTS.md §3) | the 7 gate tests above map: admin→adminAPI, branding, oidc (`/userinfo`, `/end_session`, `/check_session_iframe`), ciba (`/backchannel-authentication`), caep (SSF), federation, selfservice | **Verified today; at risk in the design's own `Mount()` sketch** — oidc/ciba/federation gates are dropped if mounts get `nil` (F2) |
| R11 | Discovery derived from server state; credential endpoints no-store; oracle-safe errors | `rootcov_discovery_test.go`, `rootcov2_discovery_test.go`, `max_token_bytes_test.go`, protocol suites (`protocols/oauth` 27 test files, `protocols/oidc` 10, `protocols/caep` 12) | **Verified** — none of these handler bodies move; only mount sites |
| R12 | Protocol findings F1/F2 (slow_down +5s; 429 body code) from the protocol review | `protocols/oauth/device_codes_test.go`, `client_registration_ratelimit_test.go:95` (the DCR quota side asserts `ratelimit.ErrRateLimited`; no test asserts the grant 429 body) | **Missing** — no test pins `slow_down` interval growth or the grant rate-limit body code; both are untested behaviors the protocol review flags for landing with 改进一 |

## 3. Findings (severity, evidence, impact, exact test to add)

### F1 — HIGH: `check-routes` goes vacuous or naming-dependent exactly when the routes move; "unchanged" acceptance is self-contradictory

**Evidence (Verified, empirically)**: `checks/route_contract.py:18` hardcodes
`ROUTE_DIR = Path("interfaces/sso")`; `:44` `ROUTE_RECEIVERS = {s.router, api,
gr, ssf, selfServiceGR}`; `:87-113` resolver accepts only `core.`/`oauth.`
prefixes or bare `Path*` (resolved as `sso.Path*`); `:152-165` errors only on
routes *absent* from OpenAPI. A synthetic mount file registering via receiver
`r` (the design's own signature `MountRoutes(r core.Router, …)`) yields **zero
discovered calls**; a `gr`-named local is discovered but loses the
`if receiver == "api": ADMIN_PREFIX` logic (`:156`), so admin routes
registered via `gr` mismatch OpenAPI's `/api/v1/admin/*`. After the move the
gate either passes with ~5 leftover routes or flags the admin set spuriously
— neither is "unchanged". `CHECKS_REGISTRY.md:56` describes the checker's
scope and must be updated with it.

**Impact**: the design's FM4/FM5/FM7 and risk-7 all cite `check-routes` as the
safety net; it stops measuring the moved set. A route dropped/renamed during
relocation is caught only by the HTTP tests that happen to hit it (see F3).

**Exact test to add**: (a) extend `route_contract.py` to scan the 13 owning
directories with a receiver whitelist that survives the move (accept any
receiver, resolve `core.Path*`/`oauth.Path*`), or (b) add a golden
route-inventory test that boots `sso.NewServer()` in the default
configuration, walks the `*core.StdRouter` route table, and asserts the exact
241-route set (method+path) — run before and after the move in the same PR.
Acceptance assertion: `python3 cli.py check-routes` reports the same 241
routes with the moved code AND the checker still fails if any single route
registration is deleted; `CHECKS_REGISTRY.md` updated in the same commit.

### F2 — HIGH: the design's own `Mount()` sketch passes `nil` for 10 of 13 mounts, contradicting Decision 1 and dropping three live hot-reload gates

**Evidence (Verified)**: Decision 1: "Nil gate = programmer error:
`MountRoutes` panics if `gate` is nil." Decision 3 sketch:
`oauth.MountRoutes(s.router, s, nil)`, `oidc.MountRoutes(s.router, s, nil)`,
`federation.MountRoutes(s.router, s, nil)`, … — a naive implementation of the
design's final sketch **panics at boot** on every surface listed. If the panic
rule is dropped instead, the oidc/ciba/federation surfaces silently lose
gating: today `oidcGateOn` gates `/userinfo`, `/end_session`,
`/check_session_iframe` (`server_userinfo.go:33` `mountOIDCUserEndpoints`),
`cibaGateOn` gates `/backchannel-authentication` (`server_routes.go:239`),
`federationGateOn` gates the whole federation group incl. protected-resource
metadata and entity config (`server_federation.go:197`
`mountFederationEndpoints`). All three would break
`TestSetOIDCGateEnabled_LiveToggleByteIdenticalWithTracing`
(`feature_gate_hotreload_test.go:239`), `TestSetCIBAGateEnabled_…` (:271),
`TestSetFederationGateEnabled_…` (:378/:429) — all currently green (measured).
FM1–FM7 do not include "whole-surface gate dropped during relocation", and
Decision 4 enumerates only 4 of the 7 atomics (omits `oidcLive`, `cibaLive`,
`federationLive`).

**Impact**: either boot-time panic (design's own FM1, unmitigated) or silent
hot-reload regression on three surfaces — an AGENTS.md §3 invariant break.

**Exact test to add**: none new needed — the existing 7 gate tests are the
pin; the fix is to the sketch (pass `s.oidcGateOn`, `s.cibaGateOn`,
`s.federationGateOn` where gated today, `nil` nowhere). Additionally add one
unit test per `MountRoutes` entry point asserting the nil-gate panic
(Decision 1's own requirement — no such test exists today). Acceptance
assertion: the full `TestSet.*GateEnabled` set stays green after the move,
and each mount panics on nil gate in a test.

### F3 — HIGH: 111/241 routes have no literal-path test reference; 14 have none at all; the weakest-covered surfaces are exactly the ones that move

**Evidence (Verified, measured)**: scanning all test files under
`interfaces/sso`, `interfaces/admin`, `cmd/sso-server`, and `test/`, 111 of
the 241 runtime routes never appear as a literal path; 14 never appear even
as a last path segment: `DELETE/POST/PUT /api/v1/admin/threat-policies*` (4,
threataction), `DELETE/GET/POST /api/v1/admin/webhooks/*` (4, webhook),
`GET /api/v1/admin/compliance/data-map`, `GET …/soc2-evidence`, `POST
…/retention-sweep` (3, compliance), `GET /.well-known/openid-federation-list`
and `-trust-mark-status` (2, federation — these do have direct handler tests
in `domains/federation/federation_test.go:178,202` and
`trustmark_status_test.go:59,73`), `GET /api/v1/admin/docs/openapi.json` (1 —
covered in `interfaces/apidocs/apidocs_test.go`). The rebac surface
(`/authz/tuples`, `/authz/tuples/batch`, `/authz/graph`, `/authz/check`) has
**no test at any level**: `platform/lifecycle/rebac/handlers_test.go` covers
only `HandleCheck`; no test references the tuple/graph routes. 50+ of the 65
admin/adminuser delegates have no direct test call anywhere (e.g.
`HandleAdminListUserMFA`, `HandleAdminResetUserPassword` — exercised only via
HTTP in `rootcov_admin*`, or not at all).

**Impact**: after the move, dropped or mis-mounted routes in webhook admin,
threat-policy admin, compliance admin, and the rebac tuple surface are
invisible to both `check-routes` (F1) and the HTTP suites. These are the
design's own placement-table packages (`webhook` 5, `rebac` 7 delegates).

**Exact test to add**: per-owning-package mount tests: call
`pkg.MountRoutes(r, deps, gate)` on a fresh `core.StdRouter`, then assert
`r.Match(method, path)` resolves for every route that package owns, and the
gated group honors `gate()` flips. Minimum set: rebac (4 routes), webhook
admin (4), threataction (4), compliance (3). Acceptance assertion: the route
snapshot of each owning package's mount is non-empty and matches the
pre-move `check-routes` entries for that surface.

### F4 — MEDIUM: the acceptance grep is not machine-pinned; the spec's own pattern counts 254 and the corrected pattern is a PR-time artifact

**Evidence (Verified)**: spec acceptance `grep -c "func (s \*Server) handle"`
= 254 today (measured), not 234; the design's anchored pattern = 234
(measured). Neither count is enforced by any committed test; nothing in
`make ci` or the maintainability gates counts `handle*` methods. The
"234 → ≤125" claim is evaluated by whoever runs the grep, with two competing
patterns in circulation.

**Impact**: the primary acceptance of 改进一 is unverifiable mechanically and
disputable at review time.

**Exact test to add**: a committed count gate in
`maintainability_budget_test.go`-style (or a `checks/` script wired into
`make ci`) that counts `func \(s \*Server\) handle\w*\(ctx HandlerContext\)`
in `interfaces/sso/*.go` (non-test) and asserts ≤ 125 post-move; document the
anchored pattern as the canonical one and delete the literal pattern from the
spec. Acceptance assertion: the count gate fails if ≥ 109 delegates are not
removed (i.e. today's 234 must drop to ≤ 125).

### F5 — MEDIUM: the ≤ 52 file target is not derived, and the ratchet makes the gate pass at any measured count

**Evidence (Verified)**: `TestArchitecture_DirectoryFileFanout` enforces
`dirFileCountExemptions["interfaces/sso"] = <measured>` — after the ratchet
the gate passes at 52, 53, or 60; nothing ties it to the "≤ 52" acceptance.
The design specifies exactly one deletion (`server_routes_admin.go`); the
remaining ≥ 8 deletions are "files whose content fell below cohesion
threshold" (undefined). The acceptance `ls … | wc -l ≤ 52` is a one-time
manual check.

**Impact**: 改进三 can land "green" at 59 files and the acceptance silently
not hold; or the consolidation scope is discovered only at implementation.

**Exact test to add**: state the target as a committed assertion: either
enumerate the ≥ 8 deletions in the design (file-level plan) or add the
count as a temporary hard gate in the PR (e.g. extend the fan-out test with
a one-commit `expected ≤ 52` assertion that is replaced by the ratchet).
Acceptance assertion: `TestArchitecture_DirectoryFileFanout` + a PR-time
`wc -l` check both read 52 or fewer; the exemption value equals the measured
count and the diff between them is zero.

### F6 — MEDIUM: the design's own acceptance is currently RED in the worktree for unrelated reasons

**Evidence (Verified)**: the acceptance requires `go test -run
'TestMaintainability_|TestArchitecture_' .` green — `TestMaintainability_`
fails today on 4 unrelated files (2 size, 2 complexity, 1 function length —
see §1), and `go vet ./...` fails on `interfaces/snapshot`. Five
`interfaces/sso` HTTP tests also fail on the uncommitted
`authenticatedSubject`/`IsAccessTokenClaims` hardening
(`interfaces/sso/handlers.go` diff). None of these are in the design's target
packages; they are pre-existing worktree state.

**Impact**: a PR landing this direction must either fix or baseline these
first, or the acceptance cannot be demonstrated green; worse, a red baseline
masks genuine regressions from the move in the same run.

**Exact test to add**: none — this is a sequencing requirement. Acceptance
assertion: the direction PR's CI run shows the maintainability/vet failures
fixed (or explicitly baselined with evidence) before the move lands; the
diff between pre-move and post-move `go test ./interfaces/sso/` failures is
empty.

### F7 — MEDIUM: boot-time wiring failures are only incidentally caught; FM5/FM7 mitigations overclaim

**Evidence (Verified)**: no test boots `*Server` in every configuration
(missed `d.X() != nil` branch panics only if a test wires that exact
combination); no store-unwired route-set-diff test exists; the hot-reload
tests cover gate-*off* (route registered, gated), not route-set differences
between store-wired variants (e.g. `mountFederationEndpoints` registers
4–6 routes depending on `protectedResourceMetadata`/`federationEntity`/
`HasSubordinates`/`Resolver().Enabled()` — `server_federation.go:197-215`).

**Impact**: a mount that registers a different route set for a given wiring
than today's `interfaces/sso` code passes all tests if no test exercises that
wiring.

**Exact test to add**: one configuration-matrix test per conditionally-wired
surface (federation, rebac, admin sub-mounts): boot with the store wired and
unwired, snapshot the route set, assert equality with the pre-move snapshot.
Acceptance assertion: route-set equality for both variants across the move.

### F8 — LOW: FM4's double-registration claim is wrong; no test detects duplicate registration

**Evidence (Verified)**: `shared/core/router.go` — `StdRouter.RegisterGated`
appends; `ServeHTTP` is first-match-wins (`router.go:223-233,249-285`); no
overwrite, no panic. `check-routes` errors only on routes absent from
OpenAPI — a doubly-registered documented path passes. No committed test
detects double registration.

**Impact**: the acceptance's "every `Path*` const has exactly one
registration" is an uncommitted aspiration; a leftover `interfaces/sso` mount
plus the moved mount silently shadows one of them (first-match-wins).

**Exact test to add**: in the golden route-inventory test (F1), fail on any
(method, path) registered from more than one source file; plus a
PR-time `grep -c` of each `Path*` const's registration sites. Acceptance
assertion: the inventory reports exactly one registration per route.

### F9 — LOW: `sdk-surface check` does not pin `aliases.go`; the "419 re-exports" figure is not reproducible

**Evidence (Verified)**: `ops/scripts/sdk_surface.py:27-37` validates an
operationId registry (`SURFACE_PATH`) against `docs/openapi.yaml` +
`ops/build/capabilities.json`; it never scans `aliases.go`. Measured alias
lines: 388 `type`/`const` alias lines, 383 `= core.` lines, 425 `= pkg.`
lines — "419 re-exports" is not reproducible (design risk 5 and Decision 4
cite it).

**Impact**: the no-touch rule on `aliases.go` is review-only; a deleted
re-export (breaking the SDK facade) passes every gate.

**Exact test to add**: a `checks/` script (or extension of `sdk-surface
check`) that diff-scans `interfaces/sso/aliases.go` against the pre-move
HEAD version and fails on any deletion/addition, run in the direction PR.
Acceptance assertion: `aliases.go` is byte-identical before and after the
move.

### F10 — LOW: stale numbers and one mis-attribution in the design

**Evidence (Verified)**: "40 mount functions across 16 files" → measured 40
across **14** files; "11 sub-mounts" → **12** calls in `mountAdminSurface`
(`mountAPIDocsUI` omitted); "5 adminuser delegates' bodies live in
`users.go` (464 lines)" → they live in `internal/adminuser/handlers.go` (239
lines); "off by ~29 methods" → exact delta is 20. None invalidate the
placement table or the acceptance arithmetic (109 + 65 = 174 reproduces
exactly).

**Impact**: none on correctness; these should be corrected in the design so
implementation-time verification targets the right files.

### Cross-cutting — protocol findings F1/F2 are untested behaviors adjacent to the move

**Evidence (Verified)**: `server_device.go:315` concedes "(RFC says +5s)" for
`slow_down` and no test asserts interval growth; the grant rate-limit 429
body says `unsupported_grant_type` and no test pins the body code (the DCR
side, `client_registration_ratelimit_test.go:95`, pins `ratelimit.ErrRateLimited`).
Both are wire fixes the protocol review recommends landing with 改进一; they
need tests in the same change.

## 4. Prioritized scenario list

Ordered by likelihood × impact for the refactor itself (wire behavior is
frozen; these scenarios verify the move preserves it):

1. **Happy path — full-surface boot**: `sso.NewServer()` with default gates on; every one of the 13 mounts registers; 241-route inventory matches (F1 golden test). Assert: no panic, no duplicate, `check-routes` identical.
2. **Hot-reload flip per surface (7×)**: admin, branding, oidc, ciba, caep, federation, selfservice — flip gate off → byte-identical to never-mounted baseline; flip on → reachable again. Existing `feature_gate_hotreload_test.go`; must stay green with mounts relocated (F2).
3. **Gate-wiring parity**: for each gated surface, assert the gate closure injected into the owning package is the *method value* (live atomic), never a `.Load()` capture — regression via a race-flip test per relocated mount (design D3).
4. **Nil-gate discipline**: `MountRoutes`/`MountAdminSurface` with nil gate panics at boot; test pins the panic per entry point (R4).
5. **Conditional wiring parity (boundary)**: federation (4-6 route variants), rebac (store nil/not), admin sub-mounts (audit/netpolicy/rebac/wasmauthz/webhook stores nil/not) — route set per wiring identical before/after (F7).
6. **Credential endpoints (error path)**: `/token`, `/token/revoke`, `/introspect`, `/par` still `Cache-Control: no-store` + `Pragma: no-cache` after oauth mount moves; oracle-safe 400s unchanged (`protocols/oauth` suites + `rootcov2_*`).
7. **Admin middleware invariants**: 401 `Bearer realm="admin"`; `admin:read`/`admin:write` scope enforcement on every moved admin route (`interfaces/admin/middleware_test.go`, `governance_test.go`, `rootcov_admin*`).
8. **Probe placement (boundary)**: `/livez`, `/readyz`, `/health` stay outside rate limiting and the GatedRouter; `mountMiddleware`-first ordering preserved (no committed test exists — FM6; pin with the inventory test asserting probe registration precedes gated groups).
9. **Race**: `-race` on hot-reload flip tests (atomics read per request, closure capture) — currently green, must stay green (F2).
10. **Recovery**: degradation/DR-mode tests (`degradation_test.go`) still gate admin endpoints byte-identically after the admin surface moves.
11. **Route-set drift detection**: delete one moved registration in a fixture copy → golden inventory test fails, `check-routes` fails (post-extension). This is the acceptance test for F1/F8.
12. **SDK facade**: `aliases.go` byte-identical after the move (F9 check); `sdk-surface check` green.

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**CI/manual-suite gaps** (each mapped to a finding):

- `check-routes` stops covering moved routes (F1) — highest-priority gap; the
  acceptance literally depends on it.
- No golden route inventory; no duplicate-registration detection (F1/F8).
- No committed `handle*` count gate (F4).
- No per-package mount tests in the 13 owning packages; zero coverage today
  for rebac tuple/graph routes, webhook admin, threat-policy admin,
  compliance admin at the route level (F3).
- No nil-gate panic test (F2/R4).
- No configuration-matrix route-set test (F7).
- No `aliases.go` diff pin (F9).
- No middleware-order assertion anywhere (design FM6 cites a phantom test —
  verified absent from `architecture_layer_test.go`,
  `architecture_gate_test.go`, and all `interfaces/` tests).
- `slow_down` interval and grant-rate-limit 429 body untested (protocol
  F1/F2).

**Flake risks**:

- The 5 pre-existing connection-dispatch/callback failures make every
  `interfaces/sso` run red today — any new failure is masked; the direction
  PR must establish a green baseline first (F6).
- `SEED_DIRFANOUT` regeneration with a stale tree writes a stale map and a
  concurrent shrink of another exempt dir conflicts on the sorted map
  (design risk 4) — ratchet last, re-run immediately before push.
- Hot-reload byte-identity tests compare full header sets; any middleware
  added to the gate path (e.g. tracing) changes the baseline — the tests
  already pin tracing variants; do not add middleware in the move.

**Fixtures needed**:

- A route-inventory harness (walk `*core.StdRouter` after `Mount()`, or
  extend the `route_contract.py` resolver to the owning packages) — the
  single highest-value fixture for this direction.
- A per-package mount test harness in `shared/core` style:
  `core.NewStdRouter()` + `pkg.MountRoutes(r, deps, gate)` with a minimal
  `testDeps` per owning package (the webhook/rebac `handlers_test.go`
  pattern already exists and is the model).
- A `RouteDeps`-satisfying stub for `*sso.Server`-shaped deps in each owning
  package so mount tests do not require booting the full server.

**Exit criteria** (all must hold in one CI run of the direction PR):

1. `go build ./...`, `go vet ./...`, `go test -run 'TestArchitecture_' .`
   green, and `TestMaintainability_` failures are either fixed or proven
   pre-existing with a recorded baseline diff (F6).
2. Full `feature_gate_hotreload_test.go` + `degradation_test.go` green with
   the relocated mounts (F2) — this is the AGENTS.md §3 hot-reload
   invariant, byte-identical.
3. `python3 cli.py check-routes` reports 241 runtime routes with the moved
   code AND the checker is extended (or the golden inventory test is added)
   so that deleting any one registration fails the gate (F1).
4. Golden inventory: exactly one registration per (method, path); no route
   added/removed/renamed vs the pre-move snapshot (F1/F8).
5. `grep -hE 'func \(s \*Server\) handle[A-Za-z0-9_]*\(ctx HandlerContext\)'
   interfaces/sso/*.go | wc -l` ≤ 125, and the count is enforced by a
   committed check (F4).
6. `interfaces/sso` prod file count ≤ 52 with
   `dirFileCountExemptions["interfaces/sso"]` = measured count, seeded and
   committed via `SEED_DIRFANOUT=1 go test -run TestSeedDirectoryFanout -v .`
   (F5); AGENTS.md §2 ceiling sentence matches the value in the same commit
   (reconciling "frozen" wording with the shrink-only contract).
7. `interfaces/admin` stays at 10 files; `deps.go` ≤ 500 lines; admin
   conformance suites (`rootcov_admin*`, `interfaces/admin`, middleware
   scope tables) green (R5/R6).
8. `go test ./... -race` and `make ci` green (subject to the F6 baseline);
   `python3 cli.py sdk-surface check` green and `aliases.go` byte-identical
   to HEAD (F9).
9. New tests landed with the change: nil-gate panic per mount, per-package
   mount route-set tests (minimum rebac/webhook/threataction/compliance),
   and the configuration-matrix route-set parity test (F3/F7).
10. No new `layerExemptions` entry; no upward import in any owning package;
    `CHECKS_REGISTRY.md` updated if the checker's scope changes (F1).

**Verdict**: the direction's core architecture (ceiling-aware placement,
corrected grep, method-value gate closures, shrink-only ratchet) is
sound and its headline numbers reproduce exactly. It is **not ready to
implement as written**: the `Mount()` sketch contradicts Decision 1 and
drops three live gates (F2), the acceptance's own regression net goes
vacuous at the moment of the move (F1), and the moved surfaces with the
thinnest test coverage (rebac tuples, webhook/threat-policy/compliance
admin) need per-package mount tests in the same change (F3). The review is
advisory: no files were modified.
