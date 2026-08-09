Spec written to `docs/architect-analysis/cmd-gensdk-b4-4-credential-form-requirements.md`. All six cited evidence items were re-verified against HEAD; the acceptance checks are preserved and made testable (AC1–AC4).

## Verification results

**Confirmed as cited:**
- `cmd/gensdk/gen_ts_runtime.go:158-159` — unconditional `Content-Type: application/json` + `JSON.stringify(authenticatedBody)` in `request()`
- `cmd/gensdk/gen_py.go:103-104` — `json.dumps(body)` + JSON Content-Type in `_request()` (exact lines)
- `cmd/gensdk/operations.go:188-193` — `contentSchema` prefers `application/json` (line 193)
- `docs/sdks/typescript/README.md:71-74` — "the client always sends JSON" simplification (note: the phrase is not in the Python banner — citation imprecision, flagged in the spec)
- `ops/build/sdk-surface.json` auth group (lines 211-238) — all six named ops, plus `postMFAComplete`/`postDeviceVerify`
- `docs/openapi.yaml` — all eight dual JSON+form request bodies with byte-identical `$ref`s (`/token` 988, `/token/introspect` 1280, `/token/revoke` 1347, `/par` 1477, `/device/code` 1543, `/device/verify`, `/auth/mfa` 643, `/backchannel-authentication`)

**Evidence-backed corrections (in §3):**
1. **`postRevokeAll` is not affected** — `/token/revoke-all` has no `requestBody` (openapi 1366-1395) and `HandleRevokeAll` (handle_revoke.go:181) never binds a body; the generated method sends none today. Its assertion becomes "unchanged, still 200" — sending a form body it never sent would be a regression.
2. **Rejection status is 400, not 415** — the B4-4 requirements spec pins T-8(b)(c)(e) to `400 invalid_request`; the direction's "415/400" ambiguity resolves to 400.
3. **"T-8a" is a mislabel** — the campaign gate assigns Content-Type enforcement to T-8(b)(c)(e); T-8(a) is the claims gate.
4. **Affected surface is 7 ops** — postDeviceVerify and postMFAComplete are also dual-content surface ops; the mechanism must be spec-driven (flip the `contentSchema` preference), not the incomplete `tsUsesClientAuth` hard-coded list (gen_ts.go:99, which omits them).
5. **Serialization nuances pinned from the server binder**: repeated form keys for string arrays (`resource`/`audience`/`tokens`), JSON-string single keys for objects (`claims`, `authorization_details` — `json.RawMessage` at handle_par.go:100,105), and Python bool coercion to `"true"`/`"false"` (`urlencode` emits `True` which bind.go:116 rejects — this bites `postDeviceVerify.approve`).

**Also surfaced:** committed `docs/sdks/typescript/dist/*.js` carry the JSON emission (must regenerate via tsc), `client.test.mjs:53` asserts `JSON.parse(seen.body)` and will break unless updated, and the form arm of the E2E is green today (server's form branch exists) while the JSON-rejection arm lands with the sibling B4-4 strict binder (merge-order note included). No scope expansion beyond the direction; budgets checked (cmd/gensdk is at its 10-file ceiling — tests extend the existing `emit_test.go`).
