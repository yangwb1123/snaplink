All verification complete. Here is the report.

# Verification: F2 amended SDK emission design

Baseline: `go build ./... && go vet ./...` clean; full `go test ./cmd/gensdk/` passes at HEAD. Regeneration check: `go run ./cmd/gensdk -lang all` → **zero diff** on both artifacts (client.ts 157596 B, client.py 133390 B; `git status` clean for `docs/sdks/`). Note: the design doc (`cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-design.md`) is **not yet amended** — it still contains the 4-op `tsUsesClientAuth` text and the `TestEmit` gate. Findings below are against the proposed amendment.

## 1. Credential-endpoint predicate — substance right, count wrong (7 → 9 ops)

The 7 named ops all check out: each targets a credential site in the ten-site switch list and currently JSON-serializes (`{ body, clientAuth: true }` for the 4; `{ body }` postDeviceCode :2848; `{ body, auth: true }` postDeviceVerify :2858; `{ body }` postMFAComplete :2823; Python twins at client.py :2216/:2236/:2244/:2260/:2280/:2284/:2288). Exclusions verified correct: `postRevokeAll` body-less bearer-only (client.ts :2918, handle_revoke.go:181 no binding); `postLogin` JSON-only (`rejectNonJSONLogin`, server_login.go:27); CIBA has **no** SDK op (surface's backchannel ops are admin failure-replay endpoints).

**Defect A — two credential ops missing from the predicate.** The SDK surface also contains:
- `adminCompromiseCredential` → `POST /api/v1/admin/credentials/{type}/compromise` (client.ts :2126, server_admin_handlers.go:292-295 — bind site :293 in the switch list)
- `adminReportCryptoKeyCompromise` → `POST /api/v1/admin/crypto/keys/{id}/compromise` (client.ts :2136, options_admin.go:413-416 — bind site :414)

Both emit JSON bodies with `auth: true` today and will 400 `invalid_request` post-change. The predicate must cover **9 ops**. (Full enumeration of all 78 body-bearing POST ops vs. the ten credential paths confirms no others.)

**Defect B — the predicate must gate form serialization, not `clientAuth` (Basic).** In the TS runtime, `clientAuth: true` only triggers `withClientAuthentication` (Basic injection, gen_ts_runtime.go:154); JSON serialization is unconditional for any body (:156-160). Blindly extending `clientAuth: true` to the new ops changes auth behavior: `postMFAComplete` (no client creds — Basic from constructor config would be wrong on `/auth/mfa`), `postDeviceVerify` (bearer `auth: true`, not a client-auth endpoint), `postDeviceCode` (server resolves client by ID from the body, resolveDeviceCodeClient server_device.go:127 — no secret verification). The amendment needs a separate form flag (e.g. `form: true`) for the 9 ops; `clientAuth` stays the 4-op set. Python has no `clientAuth` concept at all (pyClientHeader `_request`, gen_py.go:103-104 — JSON for any body) — it needs a form flag threaded through `_request` plus a shared predicate.

## 2. MFACompleteRequest.params — must be DROPPED, explicitly; flattening is impossible

Verified: `setFormField` (oauthwire/bind.go:104-127) handles string/bool/int/int-pointer/[]string only — a `map` field is silently skipped, no error. The server's `mfaCompleteRequest.Params map[string]string` (server_mfa.go:230) is therefore **unbindable on the form wire**; a flattened `params.session=...` convention cannot be decoded without a server decoder extension (out of scope). The only honest option is **drop + document**: the openapi `params` property (openapi.yaml:14496-14514, "When Params is set it wins") removed/deprecated in step 5's contract edit; flat `code`/`assertion` convenience fields (declared equivalent at :14483/:14493) remain the form path; CHANGELOG note; the generated SDK keeps the TypedDict field for type compat but the runtime omits it when form-encoding (or the type is updated — either must be stated). No in-repo test uses `params` (consistent with F3).

**Related (F1 dependency):** `postPAR` carries `authorization_details?: AuthorizationDetail[]` and `claims?: Record<string, unknown>` — also inexpressible on the form wire (server `parRequestForm` uses `json.RawMessage`; F1 HIGH). The F2 emission must define these jointly with F1's remediation: RFC 9396 §7.2 JSON-string form value if F1 option (a), else documented drop + server fail-loud — silent drop must not survive (RAR intent vanishes). `resource?: string[]`/`audience?: string[]` are fine via repeated keys (array branch already in the runtime, gen_ts_runtime.go:143-147).

## 3. Regeneration: byte-identical at HEAD ✓; post-change diff scope documented

Zero-diff regeneration verified (both languages). Post-amendment the diff is exactly: runtime template (TS `request()` form branch; Python `_request` form branch) + the 9 op call sites + **docs/sdks/typescript/README.md:69-72** ("the client always sends JSON" becomes false — the python README has no such claim, verified). All committed in the same change per step 4.

## 4. Emit test names — confirmed, and the TestEmit trap is real

- `func TestEmit` exists **nowhere** in the repo; `go test ./cmd/gensdk/ -run TestEmit -v` → `no tests to run`, **exit 0**. The design doc still uses it twice (§3.6 row 15 at line 109, §4 gate at line 119) — both must be corrected.
- Real tests, all PASS at HEAD: `TestTSClientAuthenticationOperations` (emit_test.go:159), `TestGenerateTS_BalancedBracesAndNoRawTemplateLeftovers` (:121), `TestPyFieldName_KeywordAndNonIdentifierMangling` (:180). A step-4 gate of `go test ./cmd/gensdk/... -run 'TestTSClientAuthenticationOperations|TestGenerateTS_BalancedBracesAndNoRawTemplateLeftovers|TestPyFieldName_' -v` matches real tests and cannot no-op.
- **Two further gate gaps:** (a) `TestTSClientAuthenticationOperations` pins only the 4 ops (+ postLogin/postLogout false) — it passes unchanged against a 9-op predicate, so it must be extended (9 true + postRevokeAll/postLogin/postLogout false) or the gate can't catch the new ops; (b) no existing test asserts the serialization branch — `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` (:207) only checks `clientAuth: true` presence. The amendment should add a form-emission assertion (e.g. `application/x-www-form-urlencoded` + URLSearchParams/urlencode for the 9 ops, JSON elsewhere), else a serialization regression passes the gate.

## 5. ssoclient/remote (Go SDK) — unaffected ✓

`postRevoke` already form-encoded + Basic (interfaces/ssoclient/remote/auth.go:326-342, comment :323-325 already matches the new enforcement); `postLogout` JSON to `/logout` (non-credential, :295-319); no calls to `/token`, `/par`, `/device/*`, `/auth/mfa`, `/introspect`, or the admin compromise routes anywhere in the package. Nothing to change.

## Verdict

The amendment's mechanism (credential-endpoint-based predicate, MFA params disposition, real test names, regeneration, Go-SDK isolation) verifies, with **two blocking corrections before implementation**: the predicate must be **9 ops** (add `adminCompromiseCredential`, `adminReportCryptoKeyCompromise`), and it must gate **form serialization only** — `clientAuth`/Basic stays the 4-op set (Python: new form flag, no Basic concept). Plus three mandatory precision items: MFA `params` dropped-and-documented (flattening unworkable server-side), postPAR `authorization_details`/`claims` disposition tied to F1, and extension of `TestTSClientAuthenticationOperations` + a new form-emission assertion so the step-4 gate cannot pass vacuously.
