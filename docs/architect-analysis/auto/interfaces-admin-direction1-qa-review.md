# QA Review: interfaces/admin — Direction 1 (capability language, tenant dimension, delegation grading)

> Review of `docs/auto/interfaces-admin-direction1-design.md` at HEAD
> `5ce7b81d` ("Stage: design"). Advisory only — no code modified. All claims
> re-verified against executable code and running gates; every design citation
> was checked. Severity scale and evidence labels per
> `ai-dev/prompts/README.md` (Verified / Partial / Missing / Proposed /
> Unknown).

## 0. Revision and baseline state

- **Reviewed artifact:** `docs/auto/interfaces-admin-direction1-design.md` (the
  design, three decisions) and its companion spec.
- **Baseline:** `go build ./...`, `go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .` all **pass** in the
  current worktree.
- **Worktree caveat (Verified):** the worktree is dirty with ~200 files from a
  prior unrelated wave (e.g. `cmd/sso-server/build_app.go` gains
  `capConvergence*` fields; `interfaces/admin/governance.go` gains
  `HandleAdminConvergeAccessPolicies`, +22 lines after `methodScopeForPath`).
  The design cites line numbers that match **HEAD**; several drift in the
  worktree (see F7). The implementer must re-derive line anchors against the
  dirty worktree, not HEAD.

## 1. Commands actually run for this revision

| Command | Result | Notes |
|---|---|---|
| `go build ./...` | PASS | worktree, all packages |
| `go vet ./...` | PASS | |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS (0.148s) | budget + architecture gates green today |
| `go test -count=1 ./domains/permissions/... ./interfaces/admin/ ./platform/lifecycle/admingovernance/...` | PASS | 4 packages incl. sqlite conformance |
| `go test ./test/ -run 'TestE2E' -count=1 -v` | PASS 4/4 | `TestE2E_LoginThenAuthorizeAcrossWire`, `_DeniedWhenSubjectLacksPermission`, `_NoTokenIsUnauthorized`, `_BadCredentialsRejected` |
| `go test ./test/ -run 'TestAdminHTTP_|TestAdminGRPC_|TestAdminMiddleware_' -count=1` | PASS | 17 admin middleware integration tests |
| Static citation verification | n/a | every file/line cited in the design was re-read (see §2) |

**Not run** (explicitly out of scope for a no-code-change review; state
baseline only): `go test ./... -race`, full `./test/` suite, `make ci`.

## 2. Design-evidence verification (all Verified unless marked)

| Design claim | Code evidence | Verdict |
|---|---|---|
| `interfaces/admin` = 10 non-test files, fan-out ceiling | `ls interfaces/admin/*.go \| grep -v _test \| wc -l` = 10 | Verified |
| `middleware.go` 492 / `governance.go` 483 lines, ≤17 from 500 | `wc -l` | Verified |
| `interfaces/sso` at 60-file ceiling | `ls interfaces/sso/*.go \| grep -v _test \| wc -l` = 60 | Verified |
| `sso.AdminMiddleware = admin.Middleware` at `aliases.go:64` | `aliases.go:64` `type AdminMiddleware = admin.Middleware`; `AdminScope*` aliases at 68-70 | Verified |
| `wireAdminMW` at `build_app.go:291-304`, exactly two `admin:read`-despite-POST overrides | `build_app.go:291` (worktree; HEAD ≈289); wasmauthz + config-cluster-diff at 301-304 | Verified |
| Both transports share one `Middleware` object | `build_http.go:87` `a.adminMW.HTTPMiddleware(base)`; `main_servers.go:199` `a.adminMW.UnaryServerInterceptor()` | Verified |
| `Matches` prefix rule: `admin:*` covers `admin:<res>:<action>`; legacy codes exact-only | `matcher.go:19-36` — `domain:*` suffix rule; `p.Code == want` only for others | Verified — the D1 fallback need is real |
| `MemoryProvider.Permissions` = union of role codes, keyed `(clientID, code)`; assignments `userID→clientID→[]codes` | `memory.go:270-286`, `AddRole` 60-71, `AssignRoles` 134-145 | Verified |
| `tenantRequestMismatch` fail-open, handler-side | `tenants.go:280` (design says 273-287) | Verified (line drift) |
| `docs/error-codes.md:87` documents `tenant_mismatch` 403 | line 87 exact | Verified |
| `ApproveAndApply` at `approval.go:141-160`, sole caller `governance.go:157` | `approval.go:145`; caller `governance.go:157`; `writeChangeDecisionError` actually at 196+ (design says 169-187) | Verified (drift) |
| `TargetHoldsAdminScope` at `deps.go:106-117`; impl at `accessors_feature_gates.go:291-316` (both clients, nil provider → `(false,nil)`, provider error → err) | both exact | Verified |
| `refuseTargetPrivileged` at `break_glass_impersonate.go:77-92` | function at 77-90, generic 403 `break_glass_target_privileged` | Verified |
| `methodScopeForPath` longest-prefix at `governance.go:429-455` | at 438-455 (HEAD) | Verified (drift) |
| Sensitive-subset handlers exist | `users.go:173` password reset; `tenants.go:237` export; `lifecycle.go:290` bulk-revoke; `governance.go:144` approve; `break_glass_impersonate.go:27` impersonate; `proto/admin/v1/keys.proto:28` RotateSigningKey | Verified |
| `ResourceProvider` at `resources.go:150-160` | interface actually at **119-146** | **Citation error** (F7) |
| `ResolveResource` `:param` path patterns; tuple-keyed index `memory_resources.go:19-24` | `memory_resources.go:100-124`, `matchPath`; `resourceTupleKey` | Verified |
| **Platform-tenant-bucket-first catalog lookup** | `ResolveResource` iterates `m.resources` (map) with **exact** `TenantID` match — no bucket ordering exists | **Proposed, not current behavior** (F2) |
| `RequireMode`/`RequireAll` exist | `resources.go:29-41` | Verified |
| `tenant.FromHandlerContext` exists; admin mux wraps base (tenant middleware relationship external) | `domains/tenant/middleware.go:14`, `client_gate.go:22`; `build_http.go:84-99` | Verified — D2's explicit `SetTenantResolver` rationale holds |
| `permissionstest.ConformanceSuite` with skip-based optional sections | `conformance.go:36` `Run(t)`; MenuLister sections type-assert+skip — the optional tenant-section pattern has precedent | Verified |
| `EventAdminChangeApproved` + `auditreport` classification | `platform/audit/aliases_spi.go:47`; `auditreport/control_areas.go:134-138` | Verified — reuse keeps classification stable |
| `change_insufficient_scope` does not exist yet | absent from `shared/core/errors.go` and `docs/error-codes.md` (change_* rows at 559-563) | Verified — new wire code, doc update required |
| Seed `sso-admin` = `admin:*` | `builtin.go:150-166` `stepSeedAdminRole` uses `sso.AdminScope` | Verified |
| `provisionFirstAdmin` at `server_setup.go:198` | actually at **192** | Citation drift (F7) |
| `tenantHintFromClaims` at `governance.go:474-484` | actually at **456 (HEAD) / ~478 (worktree)** | Citation drift (F7) |
| "55 handlers unchanged" | exactly 55 `func HandleAdmin*` in `interfaces/admin`; 5 HTTP + 1 gRPC method get table entries | Verified (phrasing loose: 50 HTTP handlers keep defaults) |
| gRPC tenant CRUD service does no claim-vs-message tenant check today | `interfaces/grpcserver/grpcadmin/admin_tenants.go` — CRUD over `tenant.Store`, no bearer-tenant filtering | Verified — D2 handler-side logic is genuinely new |
| No test uses an `admin:write`-only subject | `test/admin_middleware_test.go` harness grants only `admin:*` (`adminProvider`); all integration tests use `admin:*` or read-only/scope-less subjects | Verified — F1 |
| Existing regression pin for the two legacy overrides | `governance_test.go:302-323` `TestMethodScopeForPath_SegmentBoundary` (exact-path + trailing-slash; sibling `checkpoint` NOT matched) | Verified (design said `middleware_test.go`; it is in `governance_test.go`) |
| No `tenants_test.go` in `interfaces/admin` | `ls interfaces/admin/*_test.go` | Verified — `tenantRequestMismatch` untested (F3) |

## 3. Test inventory relevant to this design (current, all passing)

**Unit — `domains/permissions`:** `matcher_test.go` (`TestMatches` 13 rows:
exact, `domain:*`, `*`, colon boundary, cross-domain), `memory_test.go`,
`memory_conformance_test.go` (runs `permissionstest.ConformanceSuite`),
`memory_resources_test.go` (+extra), `resources_test.go`, `handlers_test.go`,
`policy_bundle_test.go` (+extra), `memory_sod_test.go`.

**Unit — `interfaces/admin`:** `middleware_test.go` (gRPC method gating,
write-quota, destructive-confirm, clientID-without-audience, IP allowlist,
rate-limit ×3), `governance_test.go` (propose/approve/reject lifecycle,
self-approval, applier success/failure, 404-without-store,
`TestMethodScopeForPath_SegmentBoundary`), `break_glass_test.go` (17 tests:
lifecycle, self-approval, TTL, reason, revoke cascade, readonly, persist-before-
mint, sweep, panic recovery, impersonate: readonly/pending/non-owner/revoked/
privileged-target-refused/active-mint/expiry-sweep/audit-chain),
`break_glass_impersonate.go` has **no direct unit test file** — impersonate
coverage lives in `break_glass_test.go`.

**Unit — `platform/lifecycle/admingovernance`:** no test file in the package
directory (coverage via `interfaces/admin/governance_test.go`).

**Integration — `test/`:** `admin_middleware_test.go` (17), `admin_grpc_*`
(permissions, tenants, users, clients, tokens, snapshots, releases, base),
`admin_http_clients_test.go`, `admin_user_mgmt_test.go`, `admin_top_tenants_test.go`,
`admin_backup_test.go`, `admin_connections_test.go`, `admin_token_revoke_test.go`,
`TestE2E_*` (4).

**Key coverage gap:** every gate-level integration test grants `admin:*`; the
`admin:write`-only subject — the population the D1 fallback exists to protect —
appears in **no** test. `TestMethodScopeForPath_SegmentBoundary` is the only
test touching `SetMethodScope` override semantics.

## 4. Requirement-to-test matrix

Status: **New** = must be added by the change; **Extend** = existing test must
be updated; **Existing** = present and passing. Acceptance mapping follows the
design's own (D1 middleware matrices, D2 unit + conformance, D3 break-glass +
approval, all against seeded `sso-admin`).

| # | Requirement (design decision) | Test to add (package, name) | Status | Acceptance assertion |
|---|---|---|---|---|
| R1 | D1 `AdminRequirementFallbacks` expansion, single source of truth | `domains/permissions/fallbacks_test.go` `TestAdminRequirementFallbacks` — table-driven: `admin:<res>:read`→{…,`admin:read`}; `admin:<res>:<other>`→{…,`admin:write`}; legacy→identity; `admin:*`→covered | New | ≥15 rows; `admin:write` never satisfies a read requirement and vice versa; `admin:*` satisfies every row |
| R2 | D1 gate resolution chain order (table → catalog → method default) | `interfaces/admin/middleware_test.go` `TestScopeResolution_TableWinsOverCatalog`, `TestScopeResolution_CatalogFallthrough`, `TestScopeResolution_MethodDefault` | New | static table entry beats catalog entry; `Found=false` falls through to GET→read/POST→write; gRPC `isReadMethod` default unchanged |
| R3 | D1 catalog step: platform tenant bucket first | `TestResourceLookup_PlatformBucketWins` (+ middleware two-step test) | New | same decision 100/100 runs; platform entry wins; `Found=false` when neither (see F2) |
| R4 | D1 catalog error → fail closed; `RequireAll` rejected at registration | `TestScopeResolution_CatalogErrorIs500`, `TestRequireAllRejectedAtRegistration` | New | `ResolveResource` error → 500 `internal_error` / gRPC `Internal`; registration of `RequireAll` entry fails loudly |
| R5 | D1 sensitive-subset table (6 rows) — the #1 regression pin | `interfaces/admin/middleware_test.go` `TestSensitiveSubset_AdminWriteOnlyAllowed` (HTTP+gRPC); integration twin in `test/admin_middleware_test.go` against the real mux | New | per row: `{admin:write}`→allowed, `{admin:*}`→allowed, `{admin:read}`→403; export route: `{admin:tenants:read}`→**denied** (write, not read) |
| R6 | D1 legacy overrides keep legacy semantics | `TestMethodScopeForPath_SegmentBoundary` exists; extend with subject-level test | Extend | wasmauthz/check + config-cluster-diff accept `admin:read`-only subject on POST; sibling routes still require write |
| R7 | D1 `admin:write` ⇎ `admin:read` unchanged | matcher-level pin in `fallbacks_test.go` (or `matcher_test.go` row) | New | `Matches({admin:write}, "admin:read") == false`, `Matches({admin:read}, "admin:write") == false` |
| R8 | D2 tenant-tagged data model additive; base methods ignore tagged data | `domains/permissions/memory_tenant_test.go`: `TestTenantRoles_BaseMethodsIgnoreTagged`, `TestPermissionsForTenant_Union`, `TestPermissionsForTenant_UnknownUser` | New | `Permissions`/`Roles`/`ListAllRoles`/`ListAssignments` byte-identical with tagged data present; union = untagged ∪ tenant-tagged; `ErrUserNotFound` |
| R9 | D2 optional suite for both backends | `permissionstest` optional section (MenuLister precedent) + `memory_conformance_test.go`/`sqlite` harness | New | MemoryProvider + sqlite pass; provider without the interface skips, base suite untouched |
| R10 | D2 middleware tenant check (acme/globex) | `interfaces/admin/middleware_test.go` `TestTenantScope_OwnTenantAllowed`, `TestTenantScope_OtherTenantDeniedByteIdentical` | New | acme grant on globex route → 403 body byte-identical to `{"error":"forbidden"}`; gRPC `PermissionDenied "admin scope required"` |
| R11 | D2 global grant immune to forged/stale claim | `TestTenantScope_GlobalGrantIgnoresClaim` | New | `admin:*` subject with claim tenant X passes X-route and non-tenant routes |
| R12 | D2 single-tenant fail-open; resolver-outage fail-open-with-audit | `TestTenantScope_NoTenantResolvedAllowed`, `TestTenantScope_ResolverErrorAuditsAndSkips` | New | unresolved tenant → no check, allowed; resolver error → audit record + skip, no denial |
| R13 | D2 path param wins over claim | `TestTenantScope_PathParamBeatsClaim` | New | path tenant acme + claim globex → acme decision |
| R14 | D2 gRPC handler-side disagreement, fail closed | `test/admin_grpc_tenants_test.go` `TestAdminGRPC_TenantIDDisagreementDenied` | New | claim tenant A + message tenant B → `PermissionDenied`, same code as scope denial; equal → allowed |
| R15 | D2 host-routing backstop keeps `tenant_mismatch` | `interfaces/admin` new `tenants_test.go` `TestTenantRequestMismatch_Backstop` (no such file exists today) | New | backstop → 403 `tenant_mismatch`; middleware → 403 `forbidden` (F3) |
| R16 | D3 break-glass strict subset, both directions | `break_glass_test.go` extend `TestBreakGlassImpersonate_PrivilegedTargetRefused`; add `TestCanImpersonate_EqualLevelRefused`, `TestCanImpersonate_StrictlyLowerMinted`, `TestCanImpersonate_EmptyTargetMinted`, `TestCanImpersonate_ProviderErrorRefuses` | Extend+New | equal sets refused (incl. `admin:*`→`admin:*`); L1 `admin:users:*` mints ordinary user, refuses `admin:keys:write` target; all refusals byte-identical 403 `break_glass_target_privileged` |
| R17 | D3 approval matrix: propose stamps requirement, carried value wins | `governance_test.go` `TestProposeChange_StampsRequiredCapability`, `TestApprove_UsesCarriedRequirement` | New | registry change after propose does not alter pending bar; request body cannot inject the field |
| R18 | D3 approver capability enforcement | `governance_test.go` `TestApprove_InsufficientScope403Pending`, `TestApprove_LegacyAdminWriteSatisfies`, `TestApprove_AdminStarSatisfies`, `TestApprove_CheckerError500` | New | 403 `change_insufficient_scope`, record stays PENDING, audit `EventAdminChangeApproved`+`OutcomeFailure` with reason; checker error → 500, no transition |
| R19 | D3 legacy/empty requirement approvable | `TestApprove_EmptyRequirementNoCheck` | New | `RequiredCapability==""` → today's behavior; hot upgrade cannot strand pending changes |
| R20 | D3 matrix parity with D1 gate | `TestApprovalMatrix_AgreesWithRouteTable` | New | approval requirement rows use the same `AdminRequirementFallbacks`; no divergence |
| R21 | Cross-cutting: new wire code + oracle-row docs in same change | doc assertions + byte-identity test (R10) | New | `docs/error-codes.md` gains `change_insufficient_scope`; `tenant_mismatch` row states middleware denial is byte-identical `forbidden`; AGENTS.md §3 updated; `ChangeRequest.required_capability` in openapi |
| R22 | Seeded `sso-admin` byte-identical; budgets hold | existing `TestE2E_*` + admin integration suite; `TestMaintainability_|TestArchitecture_` after each step | Existing | full suite green with `admin:*` seed unchanged; no new file in `interfaces/admin` (10-file ceiling), `middleware.go`/`governance.go` stay ≤500 |

## 5. Findings (severity-ordered)

### F1 — High — The #1 regression risk (legacy-fallback omission) has zero existing test coverage
- **Evidence (Verified):** every gate-level integration test uses an `admin:*`
  subject (`test/admin_middleware_test.go:33-40` `adminProvider` grants
  `"admin:*"`; `TestAdminHTTP_ValidTokenWithScope_200`,
  `TestAdminGRPC_ValidTokenWithScopeReachesHandler`); no test anywhere
  exercises an `admin:write`-only subject against a POST admin route, and no
  test pins a qualified requirement on any of the 6 sensitive routes. The
  design identifies the risk correctly but its acceptance matrix is entirely
  new coverage.
- **Impact:** a merge that drops the legacy fallback from
  `AdminRequirementFallbacks` silently locks out every `admin:write`-only
  deployment on 5 HTTP routes + 1 gRPC method while the whole current suite
  stays green.
- **Recommendation (required):** implement R1 + R5 (unit + integration twin
  against the real mux, since `build_http.go` route registration drift is a
  separate silent-failure mode). R5 is the acceptance gate for D1.
- **Executable validation:** `go test ./interfaces/admin/ -run TestSensitiveSubset_ -count=1` and `go test ./test/ -run 'TestAdminMiddleware_|TestSensitiveSubset' -count=1`.

### F2 — High — "Platform tenant bucket first" is Proposed, not current behavior; as written it is nondeterministic
- **Evidence (Verified):** `domains/permissions/memory_resources.go:100-124`
  `ResolveResource` iterates the `m.resources` map with **exact** `TenantID`
  match — no bucket priority exists. A single `ResolveResource` call cannot
  express "platform first, then request tenant"; the design's D1 step-2 must
  be implemented as **two explicit lookups** by the middleware.
- **Impact:** if implemented as one call per tenant in the wrong order, or
  relying on provider ordering, platform-vs-tenant precedence (a
  security-relevant choice: which `RequiredPermissions` apply) becomes
  map-order dependent and flaky under `-race`/`-count=10`.
- **Recommendation (required):** R3 — two-step lookup with a determinism test
  (100 iterations), and a middleware test asserting the call sequence
  (empty tenant first).
- **Executable validation:** `go test ./domains/permissions/ -run TestResourceLookup_PlatformBucketWins -count=10`.

### F3 — Medium — Tenant oracle reconciliation needs a code pin, and the backstop is untested
- **Evidence (Verified):** `docs/error-codes.md:87` documents 403
  `tenant_mismatch`; AGENTS.md §3 states "Tenant mismatch is
  `403 tenant_mismatch`" (in the trust bullet — the design's phrase "AGENTS.md
  oracle-table row" is imprecise; the oracle table itself has no tenant row).
  `tenantRequestMismatch` (`tenants.go:280`) has **no direct test** — there is
  no `tenants_test.go` in `interfaces/admin`.
- **Impact:** the design's stricter-contract choice (byte-identical
  `forbidden` at the middleware, `tenant_mismatch` only at the host-routing
  backstop) will silently drift back to a probeable `tenant_mismatch` at the
  middleware without a byte-identity pin; the backstop itself can regress
  unnoticed.
- **Recommendation (required):** R10 (byte-identity assertion, both
  transports) + R15 (backstop pin) + R21 (doc rows in the same change).
- **Executable validation:** `go test ./interfaces/admin/ -run 'TestTenantScope_|TestTenantRequestMismatch_' -count=1`.

### F4 — Medium — D3's nil-provider "fail-open" branch is unreachable through the stock gate; rationale conflates two precedents
- **Evidence (Verified):** `providerAuthorizer.HasAdminScope`
  (`middleware.go:53-64`) returns `(false, nil)` when `Prov == nil`, so the
  transport gate **denies** (403) without a provider;
  `NewMiddleware`'s doc says nil args "reject every call". A no-RBAC
  deployment of the admin surface therefore cannot reach approval or
  break-glass handlers at all. The `TargetHoldsAdminScope` `(false,nil)`
  no-op floor is equally unreachable via stock HTTP/gRPC wiring.
- **Impact:** the D3 "no provider wired ⇒ checker returns true" branch is dead
  code in the stock binary. Harmless (fail-open is only reachable with a
  custom `Deps`/authorizer), but the design's justification ("preserving
  no-RBAC deployments") describes a deployment that cannot exist behind the
  stock gate.
- **Recommendation (optional):** keep the branch (custom wiring), document it
  as reachable only outside stock wiring. No test needed beyond the existing
  nil-provider 403 coverage.
- **Executable validation:** `go test ./test/ -run TestAdminGRPC_ValidTokenNoScopeIsPermissionDenied -count=1` (existing).

### F5 — Medium — gRPC tenant dimension has no coverage and no current implementation to build on
- **Evidence (Verified):** `interfaces/grpcserver/grpcadmin/admin_tenants.go`
  performs no claim-vs-message tenant comparison today;
  `test/admin_grpc_tenants_test.go` covers plain CRUD only.
- **Impact:** the design's new handler-side "deny on disagreement (fail
  closed)" is net-new logic in a service that currently trusts the interceptor
  entirely; without R14 the gRPC tenant boundary is unverified.
- **Recommendation (required):** R14 in `test/` (real service, bufconn
  harness already exists there).
- **Executable validation:** `go test ./test/ -run TestAdminGRPC_TenantIDDisagreementDenied -count=1`.

### F6 — Low — Approval capability check has a check-then-approve window (same class as today's store races)
- **Evidence (Verified):** design inserts the checker before
  `store.Approve` (`approval.go:145`); the memory store is not atomic across
  the two steps. A capability revoked between check and approve still
  transitions the record.
- **Impact:** bounded — the transport gate has the same point-in-time
  semantics today, and the applier (post-transition) is the durable control.
  Not a new bug class.
- **Recommendation (optional):** document that the capability check is
  point-in-time (mirroring the gate); do not add locking for v1. A race test
  (`-race`, concurrent approve+revoke) is a good hardening follow-up.

### F7 — Low — Citation drift across the design (and the dirty worktree shifts anchors)
- **Evidence (Verified):** `ResourceProvider` is at `resources.go:119-146`,
  not 150-160; `tenantHintFromClaims` at 456 (HEAD) / ~478 (worktree), not
  474-484; `provisionFirstAdmin` at `server_setup.go:192`, not 198;
  `authorizeGRPC` at 220, `authenticateHTTP` at 357; the legacy-override
  regression test lives in `governance_test.go:302-323`, not
  `middleware_test.go`; "AGENTS.md oracle-table row" is the §3 trust bullet.
  The +22-line `governance.go` worktree delta shifts every cited anchor below
  `methodScopeForPath`.
- **Impact:** none on the design's substance (every symbol was found); cost is
  implementer time and wrong-anchor risk.
- **Recommendation (optional):** re-anchor citations to the worktree when the
  change lands.

### F8 — Info — "55 handlers unchanged" is loose but correct
- **Evidence (Verified):** exactly 55 `func HandleAdmin*` exist; 5 HTTP + 1
  gRPC method receive table entries; the other 50 HTTP handlers keep method
  defaults. `docs/error-codes.md` rows 440/457/478/499/521/534 describing
  `admin:read`/`admin:write` gating remain accurate (the visible wire contract
  is unchanged — qualified codes are an internal granularity), so no doc edits
  beyond the design's list are needed.

## 6. Prioritized scenario list

**P0 — must pass before D1 merges**
1. Happy: `admin:*` subject on all 6 sensitive routes → allowed (seed
   byte-identical, R22).
2. Happy: `admin:write`-only subject on all 6 sensitive routes → allowed via
   fallback (R5 — the pin).
3. Boundary: `admin:read`-only subject on write/approve routes → 403; on
   export route `admin:tenants:read` → 403 (R5).
4. Boundary: static table entry beats catalog; catalog `Found=false` falls to
   method default; gRPC `isReadMethod` default unchanged (R2).
5. Error: catalog/provider error → 500/Internal, never allow (R4).
6. Regression: wasmauthz/check + config-cluster-diff accept `admin:read`-only
   POST; sibling routes still need write (R6).

**P0 — tenant dimension (D2)**
7. Happy: acme tenant grant on own tenant route → allowed; global grant
   passes regardless of claim (R10, R11).
8. Boundary: path tenant wins over claim; gRPC message/claim disagreement →
   denied, fail closed (R13, R14).
9. Error: `PermissionsForTenant` error → 500; resolver outage → audit + skip
   (fail-open-with-audit); no tenant resolved (single-tenant) → allowed (R12).
10. Oracle: wrong-tenant vs wrong-capability byte-identical bodies, both
    transports; `tenant_mismatch` only via host-routing backstop (R10, R15).

**P0 — delegation (D3)**
11. Break-glass: equal-level refused both directions (incl. `admin:*`→
    `admin:*`); strictly-lower minted; empty target minted; provider error →
    generic 403, no oracle (R16).
12. Approval: propose stamps requirement; carried value wins after registry
    change; legacy pending approvable; insufficient scope → 403, record stays
    PENDING, audit failure event; `admin:write` satisfies any; checker error →
    500 no transition (R17-R19).

**P1 — race/recovery**
13. Race: `-race` on new packages; concurrent approve+revoke; determinism of
    two-step catalog lookup (`-count=10`) (R3, F2, F6).
14. Recovery: in-memory pending records survive nothing across restart, but a
    hot binary upgrade must read old records as `""` → approvable (R19).

**P2 — cross-cutting**
15. Docs in same change: error-codes `change_insufficient_scope` +
    `tenant_mismatch` row, AGENTS.md §3, openapi `required_capability`,
    DIRECTORY_MAP (R21).
16. Gates: `TestMaintainability_|TestArchitecture_` green after every step;
    final `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.

## 7. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**Gaps (must be closed by the change):**
- No `admin:write`-only subject coverage anywhere (F1).
- No tenant-scope tests in `interfaces/admin`; no `tenants_test.go` (F3).
- No gRPC tenant-disagreement test (F5).
- No catalog platform-bucket test; the provider cannot express bucket priority
  today (F2).
- `change_insufficient_scope` has no doc row yet; `tenant_mismatch` row must be
  amended (R21).
- `admingovernance` package itself has no direct test file — acceptable (its
  behavior is exercised through `governance_test.go`), but new matrix tests
  there must keep that channel.

**Flake risks:**
- Map-iteration dependence if the two-step catalog lookup is not implemented
  exactly as specified (F2) — the only genuinely new nondeterminism source.
- `governance.go`/`middleware.go` line reshuffle (design's ~70-line move) is
  the highest-risk mechanical edit; the maintainability gates catch it, but
  the reshuffle must land in the same commit as the feature to avoid a broken
  intermediate.
- `-race` full-suite runtime is the long pole for CI; nothing new adds
  cross-replica state.

**Fixtures needed:**
- A seeded `ResourceProvider` harness in `interfaces/admin` tests: `http_api`
  entries for the 6 sensitive routes (platform bucket) + one tenant-tagged
  duplicate (F2 tests).
- A tenant-tagged `MemoryProvider` fixture (acme/globex roles+assignments).
- `CapabilityChecker` stub and a fake `TenantPermissionsProvider` for
  nil/error injection (R12, R18).
- An `admin:write`-only and an `admin:read`-only role fixture for the R5
  matrix (today only `admin:*` and "no scope" fixtures exist).

**Exit criteria for the design's implementation:**
1. R1-R22 tests exist and pass; `go test ./interfaces/admin/ ./domains/permissions/... ./platform/lifecycle/admingovernance/...` green.
2. Byte-identity assertions (R10) pass on both transports; backstop still
   `tenant_mismatch` (R15).
3. `go test ./test/ -run TestE2E -v` and the admin integration suite pass with
   the seeded `sso-admin` unchanged.
4. `go test ./... -race` and `make ci` green; maintainability/architecture
   gates green after each of the 7 sequencing steps.
5. Docs updated in the same change: `docs/error-codes.md`
   (`change_insufficient_scope`, `tenant_mismatch` row), AGENTS.md §3,
   `docs/openapi.yaml` (`required_capability`), DIRECTORY_MAP.

## 8. Input on the design's four open questions

1. **Oracle row for tenant mismatch** — agree with the design's resolution
   (byte-identical `forbidden` at the middleware). The alternative
   (`tenant_mismatch` at the middleware) reintroduces the cross-tenant
   existence oracle the spec closes. The doc edit must land in the same change
   (R21), and the byte-identity test (R10) is the enforcement.
2. **Strict vs plain subset** — strict is correct: it preserves today's
   equal-level refusal, and the spec's wording is satisfied by both. Pin both
   directions (R16) or a later "simplification" to plain subset widens the
   floor silently.
3. **`admin:changes:approve` as a transport code** — declaring it is safe
   (fallback keeps `admin:write` holders working) and buys symmetry; the
   requirement is the matrix parity test (R20). If the code is declared, it
   must be listed in the sensitive table and in `docs/error-codes.md`/openapi
   documentation of the changes workflow.
4. **Audit on capability-refused approvals** — reuse
   `EventAdminChangeApproved`+`OutcomeFailure` for v1 (classification stays
   stable, verified at `auditreport/control_areas.go:134-138`). Ensure the
   required capability + reason ride in `audit.SetMeta` so denials are
   searchable without a new event type; revisit only if operators need
   distinct filtering.
