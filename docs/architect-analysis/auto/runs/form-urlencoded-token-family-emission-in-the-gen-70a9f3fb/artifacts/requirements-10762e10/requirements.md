Spec written to `docs/architect-analysis/cmd-gensdk-tokenfamily-form-emission-requirements.md`. Every citation from the direction was verified against the tree — all confirmed with exact line numbers, with two corrections surfaced.

## Verification results

**Confirmed as cited (12/14 claims):**
- `gen_ts_runtime.go:158` — `Content-Type: application/json` + `JSON.stringify` for any body; `requestOptions` (:35-41) has no `form` flag
- `gen_py.go:102-104` — `_request` JSON-only body path, no `form` param
- `gen_ts.go:99-109` — `tsUsesClientAuth` four-op predicate (case at :101)
- `emit_test.go:159` `TestTSClientAuthenticationOperations`, `:207` `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` (asserts `{ body, clientAuth: true }` at :231)
- `oauthwire/bind.go:28` `BindParams` — JSON default for missing/unexpected CT; `BindFormParams`: 0 matches repo-wide
- `openapi.yaml:1063-1065` stale `oauth_bind.go` text — file does not exist anywhere
- Committed clients: 0 `x-www-form-urlencoded` matches in either file (client.ts 3494 lines, client.py 2772); the four methods emit `{ body, clientAuth: true }` / `body=body`
- `sdk_surface.py:148` — generate = `go run ./cmd/gensdk --lang=all`; all four ops in `sdk-surface.json` (316 ops)
- `test/oauth_bind_test.go:272` `TestFormEncoded_JSONStillWorks` — currently asserts JSON → 200
- No-store headers set **before** binding at all four sites (server_token.go:21, handle_introspect.go:112, handle_revoke.go:68, handle_par.go:55) — the T-9(e) mechanism already exists
- Approved spec REQ-2.1-2.6 present, unimplemented (`Operation` has no `FormBody`; generator ignores content types — `contentSchema` at operations.go:192-201 is schema-only)

**Corrections:**
- **C1:** The "form-urlencoded-only ... for all four" claim is wrong for three of four — only `postToken` (:1102) is form-only; `postIntrospect` (:1280), `postRevoke` (:1347), `postPAR` (:1477) still declare both form and JSON (the B4-4 server module's R5.4 drops them). Doesn't change the SDK work; noted as such.
- **C2:** `withClientAuthentication` is at gen_ts_runtime.go:183, not :166-182 (fixed in the spec).

## Scope discipline

Requirements REQ-1..REQ-5 are strictly `cmd/gensdk` (FormBody flag → TS/Python form paths → emit tests → regeneration). Acceptance T-9(a)-(e) is preserved verbatim and made testable with exact commands; (d)/(e) are marked as dependency-gated on the B4-4 server module, with the sequencing rationale (committed clients must emit form before enforcement ships). No discovery sweep, no server binding work, no device/MFA ops.
