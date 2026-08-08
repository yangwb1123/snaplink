All four points are now verified against the live tree, including a fresh run of the maintainability/architecture gates. Verdict below.

---

## Review verdict — cross-server E2E plan

### 1. `TestAdminGatewayE2E_UnauthenticatedRequestsStill401` audit-path extension — **CONFIRMED, valid by construction**

Verified end-to-end:

- **Path list gap is real**: the test's loop (admin_gateway_routing_e2e_test.go:333-338) carries 4 paths — `/api/v1/admin/clients`, `/api/v1/admin/sessions`, `/api/v1/admin/local-users`, `sso.PathAuthzPolicyBundle` — no audit path. "Append" is accurate.
- **Config derivation**: the test builds `adminGatewayE2EConfig(t)` → `fullFeatureConfig(t)`, which sets `Admin.Enabled=true` (:128), `Admin.APIRESTEnabled=true` (:129), `Audit.Enabled=true` (:131), `Audit.APIEnabled=true` (:133).
- **Route is mounted in that config**: `WithAuditAPI()` appended when `Audit.APIEnabled` (build_app_core.go:217-225); mount condition `s.auditAPI && s.auditor != nil` (server_routes_admin.go:74-76); auditor non-nil because `Audit.Enabled` builds the recorder. Precedent: the sibling `TestAdminGatewayE2E_SSORouterOnlyPathsReachRealRouter` already probes the exact path → 200 with a bearer through the same composition (:214).
- **401 is structurally guaranteed**: `wireAdminMW` returns non-nil under `Admin.Enabled` (build_app.go:291-292), outer wrap `base = a.adminMW.HTTPMiddleware(base)` (build_http.go:89-90), `IsProtectedPath` marks `/api/v1/audit/` (middleware.go:451) — the missing bearer dies in `authenticateHTTP` before any handler runs. The audit route is the *only* `/api/v1` surface that would be open if `Admin.Enabled` were false (default-open `WithAuditAPI`), but this config has it true.
- **Path arithmetic**: `sso.PathAPIPrefix + sso.PathAuditEvents` == `"/api/v1" + "/audit/events"` (shared/core/consts.go:34,36; aliases.go:285,371) — the REQ-1 path-equality pin is exact.
- Status-only 401 assertion matches the loop's existing style; byte identity is correctly delegated to the `middleware_test.go` four-case table. Sound division of labor.

One doc nit: §6's REQ-2 row says "(route is mounted in that config, **A2**/A-verified)" — the mount fact is A1 (A2 is the gate-off negative control). Non-blocking.

### 2. Device/userinfo/revoke `missing_token` pins — **GREEN BY CONSTRUCTION, confirmed**

All five pins exist at the cited lines: `handle_revoke_all_test.go:159` (`TestRevokeAll_RequiresBearer`), `userinfo_logout_test.go:156`, `me_sessions_test.go:239/466/528`. All are SSO-router surfaces emitted via `shared/core.ErrMissingToken` (errors.go:91) from `authenticatedSubject` (handlers.go:208) and `authenticateDeviceVerifyBearer` (server_device.go:274-275). Grep confirms **zero `AdminMiddleware` references** in the three harnesses. REQ-2 edits only `interfaces/admin.Middleware.authenticateHTTP`'s missing-bearer branch — different package, different middleware, different code path. The pins cannot be touched; §3.3's constraint and §8's full-`test/` gate run are the right locks.

### 3. `strict_credential_content_type` E2E leg — **decision: unit-level suffices, no full E2E leg; but one build-level wiring test is missing and should be added**

- **No full outer-mux E2E leg is warranted.** `/token` is SSO-router-owned; the outer mux/gateway composition (the only thing the admin-gate E2E exists to protect — the fdebea60 shadowing class) has zero influence on it. The gate-passed reference design's coverage for this exact knob was also SDK-level (`test/credential_strict_test.go` + `oauthwire/bind_test.go`), and the task design's ssotest suite carries the full wire contract (28-byte golden, no-store, no challenge, permissive contrast, `invalid_client` identity).
- **But the config→option seam is covered by no test in either design** — and it's the exact class the repo already guards for the mirrored block: `TestBuildApp_OAuth21StrictModeFlipsDiscovery` (oauth_stores_test.go:162) builds the app from `cfg.Server.OAuth21StrictMode=true` and asserts observable behavior. The planned `wireProfilesAndMetadata` block (build_app_oidc.go, after :303-306) has **no analogous test**; a typo'd field name, wrong condition, or forgotten append would ship green. 
- **Prescription**: one ~15-line build-level test in cmd/sso-server (same shape as the discovery precedent — `buildApp` + `a.server.Handler()`, no `buildHTTPHandler`): `cfg.Security.StrictCredentialContentType = true` → POST `/token` with `application/json` → 400 `{"error":"invalid_request"}` (or the accessor pin `a.server.StrictCredentialContentType()`). Fan-out-free (test file; cmd/sso-server 24/24 non-test untouched). Fold into implementation-plan step 8.

### 4. Before/after gate-diff acceptance bar — **PARTIALLY CAPTURED; must be strengthened**

The bar's *concept* is present (§4 row 8, §8 last bullet: "no new violations; pre-existing drift reported separately, not fixed here"), but:

- **The task design never names the baseline violations itself.** It defers to the strict-mode campaign's verification §5, which is stale (HEAD `5cd5ff74`) and names only `ed25519_jwt_issuer.go` explicitly — root-subdir drift appears there only generically ("`TestArchitecture_DirectorySubdirFanout`: also failing on dirty-tree files").
- **The live baseline is broader than the two-item summary.** My fresh run of `go test -run 'TestMaintainability_|TestArchitecture_' .` fails on **four** items: `ed25519_jwt_issuer.go` 539 lines; root `.` subdir 24 > frozen 21; **plus `docs` 18 > 16 and `docs/architect-analysis/auto/runs` 284 > 16** (non-exempt subdir violations, pipeline-generated — every analysis run adds an immediate subdir to `auto/runs`). The reviewer's two-item baseline is itself incomplete; the docs items are pre-existing relative to this edit set but must appear in the before-state for the diff to be honest.
- **No instruction to capture and diff.** §8 says "re-run the maintainability suite after steps 5-8" but doesn't say capture the baseline output verbatim and require an identical failure set.

**Prescription**: §8 gains one explicit line — capture the `TestMaintainability_|TestArchitecture_` output at baseline (naming the measured set: 539-line file; root 24>21; docs/auto-runs subdir counts), re-run after the full landing order, acceptance = *identical failure set, no new file/dir/line violations*. This is achievable: the edit set adds zero directories and no touched file crosses 500 (tightest margin options.go 490→498/499).

---

**Bottom line**: points 1 and 2 hold as designed; point 3's decision is "no E2E leg, but add the missing build-level wiring test" (the only genuine coverage gap found); point 4's acceptance bar needs one §8 strengthening line plus a corrected baseline enumeration before implementation starts.
