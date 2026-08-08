All checks complete. Here is the cross-check verdict against the committed contracts:

## Cross-check results — design API changes vs committed contracts

### 1. REQ-2 contract docs vs emitted 401 — **exact**

- **Emitted bytes** (post-change): the proposed missing-bearer branch is byte-identical to the existing wrong-bearer branch at `interfaces/admin/middleware.go:370-371` → `401`, body `{"error":"invalid_token"}\n` (via `http.Error`), header `WWW-Authenticate: Bearer realm="admin", error="invalid_token"`. The current missing-bearer branch (`:364-366`, `missing_token` + realm-only challenge) matches the design's "current" claim verbatim.
- **error-codes.md:957** — `missing_token` sits exactly on that line inside the SCIM admin-auth parenthetical (spans :956-958). Dropping it yields ``(`invalid_token` / `forbidden`, ...)`` — precisely the body-code set emitted on the admin surface (401 → `invalid_token` for both missing and wrong; 403 → `forbidden`). Row :387 (Tokens//userinfo table) untouched as claimed.
- **openapi.yaml:13056-13057** — :13056 is the `missing_token` parenthetical, :13057 the `WWW-Authenticate: Bearer realm="admin"` challenge line; both are the exact targets. Adding `error="invalid_token"` produces a string byte-identical to the emitted header. Confirmed `:13057` is the **only** `Bearer realm="admin"` in openapi.yaml, and `missing_token` appears **only** at :13056 in the whole file.
- *Two minor observations (non-blocking)*: (a) error-codes.md:959's challenge mention stays realm-only — a truthful prefix of the emitted header, with the exact header carried by openapi; (b) the ScimUnauthorized prose attaches the challenge to both 401 and 403, but the 403 branch (:384-386) emits no header — pre-existing looseness, not introduced.
- *One gap found*: `interfaces/admin/governance.go:235-236` comments "EXISTING admin_auth_not_configured / missing_token / forbidden / rate_limit_exceeded literals in middleware.go". REQ-2 removes the `missing_token` literal from middleware.go, so this comment goes stale **as a direct consequence** of the change (the design's docs sweep §2.3 omits it; note `rate_limit_exceeded` was already stale — it lives in governance.go:244). Recommend folding a one-line comment fix into the REQ-2 change.

### 2. `security.strict_credential_content_type` — **consistent**

- Not yet in `docs/config-reference.md` or `docs/feature-matrix.md` (zero hits) — correct for an unimplemented design; the planned row follows the Security table's confirmed convention ("Maps to `sso.WithStrictCredentialContentType`", cf. rows :74-76 which end "Maps to `sso.With…`").
- Wiring site verified: `wireProfilesAndMetadata` at `build_app_oidc.go:301`, live-called from `build_stores.go:257`; the `OAuth21StrictMode` block at :303-306 (`if cfg.Server… → b.opts = append(b.opts, sso.WithOAuth21StrictMode(true))` + `logger.Info`) — the planned strict block mirrors it exactly. Config field shape matches `SecurityConfig`'s flat bool/int fields (`max_token_bytes` :42); file is 227 lines. Budget rationale checks out: `build_app_security.go`=500, `build_stores.go`=496, `build_app_oidc.go`=482. All cited line numbers/budgets in §0 hold (`sso_protocol.go`=500 with `oauth21Strict bool` at :184; `bindOAuthParams` at server_jar.go:301-304; `BindParams` alias at aliases.go:97; `WithOAuth21StrictMode` ~:194; `OAuth21Strict()` :369; server_token.go=495).

### 3. Admin-only convergence — pins and OpenAPI **untouched**

- Pins verified present: handle_revoke_all_test.go:159 (`TestRevokeAll_RequiresBearer`), userinfo_logout_test.go:156, me_sessions_test.go:239/466/528 (the file actually carries 9 `missing_token` assertions, all on the same three SSO surfaces). All harnesses (`newRevokeAllServer`, `newMeSessionsHarness`, auth-flow) contain **zero** `AdminMiddleware` references — they cannot be affected by a change confined to `interfaces/admin.Middleware.authenticateHTTP`.
- Production `missing_token` outside admin: only `shared/core.ErrMissingToken` (errors.go:91) feeding the SSO surfaces (server_device.go:274, handlers.go:208) — untouched; `docs/examples/appcore` is unrelated. `bearerFromHTTP` (:409-419) returns `""` for absent and malformed headers, confirming both converge through the single edited branch.
- OpenAPI: no device/userinfo/revoke entries mention `missing_token` at all (only :13056, the SCIM entry being edited) — "their OpenAPI entries untouched" holds trivially and remains true after the edit.

### 4. Permissive default wire compatibility — **confirmed**

`BindParams` (bind.go:25-46) keeps its exact dual-mode dispatch (form CT → `ParseForm`+`formIntoStruct`; default → JSON for JSON/missing/unexpected CT); the design's `normalizeContentType` extraction preserves the current normalization byte-for-byte. `bindOAuthParams` is unchanged for MFA/device/admin callers; strict-off selects it via the new seam, so `/token` is byte-identical today. Zero-value option off, config default false (reflection schema unaffected). Ordering preserved: `tokenNoStoreHeaders` stamps before binding (server_token.go:25-29), so the strict 400 carries no-store/no-cache and no challenge. Both form and JSON clients keep working under default config, with JSON-acceptance coverage relocated to the permissive pin (D8), not dropped.

### 5. No new error codes — **confirmed**

REQ-2 emits the existing `invalid_token`; REQ-4's rejection flows through `handleToken`'s existing `ErrInvalidRequest` → `invalid_request` (documented at error-codes.md:81 and openapi) — `BindParamsFormOnly`'s internal `errors.New` never surfaces as a new wire code. The error-codes.md edit removes a mention, adds no rows. Golden byte check: `ctx.JSON` → `json.NewEncoder` → `{"error":"invalid_request"}\n` = exactly 28 bytes (27 chars + newline) — the design's A3/§6 golden is arithmetic-correct.

**Verdict**: all five cross-check targets hold against the committed contracts, with one actionable finding — the `governance.go:235-236` comment becomes stale under REQ-2 and should be added to the same-change docs sweep (or explicitly listed as pre-existing drift), plus two non-blocking documentation-shape observations noted above.
