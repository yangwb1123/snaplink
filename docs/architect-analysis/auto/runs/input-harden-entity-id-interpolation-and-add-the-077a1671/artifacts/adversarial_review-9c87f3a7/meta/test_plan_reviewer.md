Validation complete. All checks ran against the actual fixtures with scratch patches applied and reverted — the tree is byte-identical to its pre-validation state (md5-verified) with all 13 red proofs intact and reproducible.

# Validation report: A4–A9 stub-driven + A10/A11 e2e implementability

## 1. Red baseline: reproduced, with one class-assignment correction

`go test ./cmd/sso-ctl/apiclient/` on the untouched tree: **13 failing test functions, 6 classes** — the design's headline is right, but the class split is not:

| Class | Tests | Verdict |
|---|---|---|
| B1 issuer mismatch | **8** (not 10): `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource`, `TestMint_RolesConditional`, `TestMint_ExpectNoRoles`, `TestRevoke_RoundTrip` | `WithEd25519Issuer(addr)` (ed25519_jwt_issuer.go:178 exists; `j.issuer` → `buildAccessPayload` at ed25519_issue.go:43) fixes exactly these 8 — verified green |
| B2 AddrValidation | 1 (2 subcases) | Usage banner's default `http://127.0.0.1:8443` contains "8443"/"http://" — false positive, exactly as disclosed |
| B3 AdvertisedURLRejection | 1 (4 subcases) | Root cause is **deeper than the design stated**: the stub's base-concatenation (`advertiseDoc`) is what yields "not a valid absolute URL" + secondary `invalid port` diagnostics; "relative" concatenates into a *valid* URL and exits 0. Fix = raw-advertisement fixture helper, which restores the test's original per-rule diagnostics for all 4 rows |
| **Own class** `TestSweep_TokenEndpointSuffix` | 1 | **Misclassified by the design as issuer-class** — it is still red after B1. Two bugs: `/oauth2/token` is unmounted so the T-2 404 row fires first, and `/oauth2/token` *ends with* `/token`, so the suffix assertion passes anyway. Fix = advertise a mounted absolute non-`/token` path (`/oauth2/tokenX`) via raw advertisement |
| B3 `TestMint_ResponseFail/status-400` | 1 | Confirmed mislabeled: sends HTTP 200 with an error body; sweep's status check correct (pinned by `redirect-302`) |
| Pre-existing `TestIntrospect_Non401Fails/wrong-bytes` | 1 | Disclosed; sweep correct, want-string doesn't match the sweep's `%q` rendering. Cheap test-only fix |

**With all six fixed (B1 + B2 + B3 + suffix + trace_id), the entire apiclient suite is green.** Every fix is confined to `cmd/sso-ctl/apiclient/check_test.go` — the prerequisite commit scope is **test-only**, exactly the design's §8 list. After restoring, md5 of check_test.go matches the original and the 13-failure state is back; `go build ./... && go vet` clean throughout.

## 2. A4–A9 stub-driven tests

- **A7 mint-with-tenant_id**: **proven by scratch test** (run, then deleted): stub-minted `craftJWT` carrying `tenant_id: "t1"` + `iss=stub URL` + `kid=testkid` + `typ=at+jwt` passes `verifyClaims` with `--expect-tenant-id t1` → exit 0, stdout == `goldenGreenStdout`; a mismatch yields `claims: tenant_id "t1" != "t2"`. `verifyTenantID` (token.go:227-235) asserts only when declared. Note: "locally-signed" — the sweep decodes without signature verification, so `craftJWT`'s placeholder sig suffices; the real Ed25519 issuer (newLiveServer precedent) also works. Probe (b)'s set-status path is the *claim-controlled* id (`t1`), so exact-path stub registration works, and `handleIntrospect` already splits credential-less vs `client_id`-bearing bodies (`postRevoke` serves `active:false`).
- **A5/A6/A8**: implementable, with **one fixture-shape delta the design didn't call out**: probe (a)'s id comes from crypto/rand `probeScope()` — unknowable in advance — and `stubCheck.dispatch` is exact-path-only; the default 404 body (`404 page not found`) fails the `message == "tenant not found"` assertion. The stub needs a prefix/wildcard route (test-only, ~5 lines). A6's 400 `tenant store not configured` → SKIPPED/INCOMPLETE/exit 1 and A8's `active:true` → FAIL both fit the existing `postRevoke`/skip plumbing.
- **A4 misuse row**: implementable, but **not a red proof as shaped** — an undefined `--admin-entities` flag already exits 2 + usage + zero requests today, so the TestExitCodes row passes pre-fix trivially. The genuinely red A4 pin is asserting the usage banner documents `--admin-entities` (the `TestUsage_RolesContract` pattern). The design's "Red today: no flag exists" is true but the row alone can't prove it.
- **A9/goldenGreenStdout**: confirmed blocked-until-B1 (both golden tests were red pre-fix); green after B1 with stdout byte-equal to the constant. T-8f is flag-opt-in, so no-flag runs preserve it.

## 3. A10/A11 e2e

- **A10**: `buildAdminGatewayE2EServer` + `adminAuthedRequest` exist; `{id}` gateway pattern catches the `:set-status` custom verb (pinned by `TestAdminOuterMux_CustomVerbShapesReachGateway`); `SetTenantStatus` → 404 `tenant not found` for unknown ids (grpcadmin/admin_tenants.go:318-320); memory tenant store mounted by `fullFeatureConfig`. No set-status e2e case exists today — red, as claimed.
- **A11**: fully wired. `fullFeatureConfig` does **not** set `cfg.Clients` (no conflict with connection `c1`); `seedClients` maps `TenantID` (build_app_core.go:91); cc mint stamps `Subject.TenantID = client.TenantID` (token_client_credentials.go:52); `SuspensionCheck.Enabled = true` precedent (:273) → `WithTenantSuspensionCheck` (build_app_oauth.go:100) → `checkTenantNotSuspended` (server_token_clientauth.go:400) → `{active:false}` (introspect_cache.go:130-131); the flip invalidates the suspension cache synchronously (grpcadmin + build_http.go:456). `adminGatewayE2EConfig` already sets `Server.TokenTTL = 15min` — essential, since `BuildSigningIssuer` otherwise overrides the TTL with zero (tokens expire on mint); OAuth 2.1 strict mode and content-type enforcement don't gate cc mint/introspect. Red today — no introspect-wire suspension test anywhere, as claimed.

## Bottom line

All six classes are test-only, reproducible reds; the prerequisite commit scope (check_test.go only) is confirmed; A5–A9 and A10/A11 are implementable against the actual fixtures with two small deltas to record in the implementer's plan: (1) the suffix test is its own class and needs a mounted non-`/token` path plus raw advertisement; (2) probe (a)'s stub test needs a prefix route, and the A4 row is a green-after pin rather than a red proof (make the usage-banner assertion the red pin). The design's §1.2 "10 tests" for B1 should read 8, with `TestSweep_TokenEndpointSuffix`/`TestSweep_AdvertisedURLRejection` reclassified into the stub/expectation classes.
