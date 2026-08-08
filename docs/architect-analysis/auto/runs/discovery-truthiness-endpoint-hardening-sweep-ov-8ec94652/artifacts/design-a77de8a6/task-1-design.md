Design complete. Here's the summary:

## Verification verdict — every cited claim held

I re-verified all 8 citations and 5 drift findings against the working tree. All are **exact or confirmed**, including: `fetchEventPage` hardcoding `/api/v1/audit/events` + Bearer (main.go:452,461), `--bearer` → `usageErr` exit 2 (:143-146,488-493), `WithAuditAPI` default-open (options_security.go:473-481 + mount condition server_routes_admin.go:74-76 + `IsProtectedPath` middleware.go:451), D1's `missing_token`/`invalid_token` divergence (:364-371), the B4-4 strict-mode design existing gate-PASSED but zero-implemented, the D3 sibling seam fork (`WithCredentialFormOnly` in 3d9cdd14/8a92c453), and D5's `os.Exit` load-error path. I also found 4 facts not in the requirements: the deploy-tree 200 probe precedent, `FeatureGates.AdminAPI: sso.Bool(false)` for the 404 negative control, `errorBody` emitting no description (28-byte golden), and `TestToken_BadJSON_400` being mode-proof.

## Design highlights

**API changes** (2 production edits + additive strict-mode slice):
- **REQ-2**: single-branch convergence in `authenticateHTTP` — missing bearer now returns the byte-identical `401 {"error":"invalid_token"}` + `WWW-Authenticate: Bearer realm="admin", error="invalid_token"` (oracle-safe); contract docs updated in the same change (error-codes.md:957, openapi.yaml:13056-13057; :387 stays)
- **REQ-4**: the gate-passed `0a8df02f` design's `/token` slice verbatim — `BindParamsFormOnly` + `normalizeContentType`, `WithStrictCredentialContentType()` no-arg option, combined bool field on sso_protocol.go:184 (file is exactly 500 lines), private `s.bindCredentialParams` at the `handleToken` selection site, config `security.strict_credential_content_type` (default off) wired in `wireProfilesAndMetadata()`

**Constraints**: byte-identical defaults (zero value off), no new error codes, admin-only convergence (device/userinfo/revoke `missing_token` pins stay green), no new production files (interfaces/sso 60/60, protocols/oauth 12/12), seam anti-fork (D3).

**Failure modes** covered: golden drift (permissive comparison must *fail* permissive binding), REQ-3 flake (synchronous `WithHashChain` recorder, `N >= 1`), the `os.Exit` legs (wrong-bearer asserted at `readFromURL`, missing-bearer kept as binary-level exit 2), AC-5 timing-leg flake guards, pre-existing drift reported separately.

**Acceptance mapping**: each direction acceptance → REQ → test file → concrete byte-level assertions, including the one deliberate deviation from the strict-mode design's AC-3 (handle_token_test.go JSON legs migrate to form per REQ-4 check 4, with the permissive JSON pin relocated to `credential_strict_test.go`).

**Deliverable**: `docs/architect-analysis/auto/runs/cmd-sso-ctl-auditverify-discovery-truthiness-and-endpoint-hardening-sweep-e0e1fbf0/artifacts/design-e1bc63fa/task-1-design.md` (247 lines, content-hash-named per repo convention).
