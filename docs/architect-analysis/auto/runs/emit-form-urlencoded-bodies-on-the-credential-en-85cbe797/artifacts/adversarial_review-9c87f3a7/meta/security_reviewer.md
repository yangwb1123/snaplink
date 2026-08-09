All checks complete. Here is the audit report.

## Verification verdict: design preserves oracle-safe invariants and credential-endpoint rules — all audit items confirmed against actual code

### C1 — form `params` key: validated against the binder, claim is precise
- **Silent drop today — confirmed.** `setFormField` (bind.go:105-141) handles only String/Bool/Int/Pointer/`[]string`; `map[string]string` (Kind Map) falls through with no error. `mfaCompleteRequest.Params` (server_mfa.go:230) is silently skipped on the form wire.
- **Guaranteed 400 `mfa_invalid` post-sibling — confirmed.** `parseMFACompleteRequest` collapses *every* bind error to `400 mfa_invalid` via `authzErrorBody` (server_mfa.go:253-262), and the sibling decisions doc §3 (F12) pins `PostForm.Has("params")` → the *existing* envelope, no audit, no new `Err*` — byte-identical to a wrong code, so **no distinguisher** (oracle-safe: same envelope, details only in audit).
- **Guard cannot mask server errors — confirmed.** It fires pre-flight, before any fetch; when `params` is empty/absent it doesn't fire and the request proceeds, so server errors still surface through the existing SSOError path. `SSOError(0, "invalid_request")` follows the established local-validation convention (`clientId is required`, `requestTimeoutMs`…). Documented trade-off is real: pre-sibling, JSON `params` would have worked, but no in-repo caller sends it (decisions doc §3:18) and the sibling drops the JSON variant anyway.

### C2 — silent denial, not rejection — confirmed, with exact lines
bind.go:116-117: `case reflect.Bool:` → `f.SetBool(raw[0] == "true" || raw[0] == "1")` — no error return, so `True`/`False` (Python `urlencode`) silently coerce to false. The requirements spec's "the binder rejects" was overstated; the design's C2 correction is the accurate reading. Consequence verified at both sites: `Approve bool` (server_device.go:242-246 → silent device-approval denial) and `TrustDevice bool` (server_mfa.go:246 → trust grant never minted). The design's mandatory `_form_encode` bool→`"true"`/`"false"` coercion (F3) is the correct fix; TS `String(true)` already matches.

### Distinguisher audit across the form-capable surface
| Op | Binder | Audit result |
|---|---|---|
| `/token` | bindOAuthParams (server_token.go:30) | TS Basic-strip runs before serialization; Python body creds stay in body — both consistent with "Basic wins over body credentials". No new distinguisher |
| `/par` | BindParams (handle_par.go:69) | Repeated `resource` keys → `formStringSlice` verbatim; `claims`/`authorization_details` JSON-string key **inert until sibling F1** (C4 confirmed: no `reflect.Uint8`/RawMessage branch in `setFormField` today) — wire-correct, forward-compatible |
| `/register` | `ctx.Bind` (handle_register.go:200) — **JSON-only, not form-capable** | SDK keeps JSON; correctly excluded from the form set |
| `/auth/mfa` | bindOAuthParams → parseMFACompleteRequest | C1 guard; C7 honored (JSON → `mfa_invalid`, not `invalid_request`; AC3 control correctly pinned to `/token`) |
| `/device/verify` | bindOAuthParams (server_device.go:242) | C2 coercion eliminates the SDK-generated silent-denial path |
| `/token/revoke`, `/token/introspect` | BindParams (:75, :120) | String-only bodies; semantics identical on both wires |
| `/token/revoke-all` | **no BindParams** (handle_revoke.go:181, bearer-only) | Design keeps it body-less (F7 gate); byte-identical |

### Headers/challenges/PKCE — untouched by construction
- `tokenNoStoreHeaders` is stamped **before body parsing** in every credential handler (server_token.go:22, server_device.go:42, server_mfa.go:195, handle_register.go:186), so the JSON→form wire flip cannot influence response headers; the design modifies zero server code (§8 "Do not modify" verified — `cmd/gensdk` has no diff at HEAD).
- PKCE/refresh: the `contentSchema` flip is provably inert beyond the seven request bodies — all 8 dual ops carry byte-identical `$ref`s (YAML-parse verified, all `required: true`), `extractResult` is untouched (zero form responses in the spec — structural exclusion), and `code_verifier`/`refresh_token` remain plain string fields carried verbatim. Server grant-switch rules untouched.
- **Pre-existing observation (not a design defect):** `handleDeviceVerify` doesn't stamp no-store and its 401s don't use `setBearerChallenge` — pre-existing server state the design neither worsens nor fixes; worth flagging to the sibling sweep against AGENTS.md's "new bearer endpoints" rule.

### Other citations
`tsUsesClientAuth` covers only postToken/postIntrospect/postRevoke/postPAR (gen_ts.go:99-105) — the spec-driven `op.ContentType` mechanism correctly avoids the 3-op blind spot. `KindMap` exists (schema.go:20; schema_primitive.go:49) so `FormBlockedFields` is implementable as specified. All artifact citations exact (gen_ts_runtime.go:158-159, gen_py.go:103-104, operations.go:192-193, dist/client.js:130-131, client.test.mjs:53, client.ts:2918, client.py:2292, README:71-74; 7 non-test gensdk files). Line-number nits only: bind.go is 116-117 (not 115-116), server_mfa.go struct at 227 (not 224).

**Gates:** `go build`/`go vet` clean; `cmd/gensdk` tests pass. The `TestMaintainability_|TestArchitecture_` root gates fail at HEAD on pre-existing directory-depth/fan-out/file-size violations unrelated to this workstream (`cmd/gensdk` has zero diff) — report separately, not a design blocker.

**Verdict: PASS.** C1 and C2 validated against actual binder code; no new server-visible distinguishers; no-store/bearer-challenge behavior untouched; PKCE/refresh and response resolution provably unaffected by the preference flip.
