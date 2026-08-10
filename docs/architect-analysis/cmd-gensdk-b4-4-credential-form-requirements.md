# Requirements Spec: cmd/gensdk — form-urlencoded emission for the credential-endpoint family (B4-4)

> Direction source: `docs/architect-analysis/auto/analyses/cmd-gensdk-4ffda121.json` (item 1,
> "Emit form-urlencoded bodies on the credential-endpoint family so the generated SDKs survive
> B4 Content-Type enforcement"). Every cited file/symbol was re-verified against the repository
> at HEAD before writing this spec; §2 records per-item verification and corrections.

## 1. Goal and user outcome

The B4-4 hardening direction (`docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md`,
T-8(b)(c)(e)) enforces `application/x-www-form-urlencoded` on the OAuth credential endpoints
(`/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/*`, `/auth/mfa`,
`/backchannel-authentication`). Today both generated SDK runtimes unconditionally serialize
every request body as JSON, so every SDK surface operation that calls those endpoints would
start failing (400) the moment enforcement lands.

Completion is observable as: the generated TypeScript and Python clients send
`application/x-www-form-urlencoded` bodies (with `Content-Type` set) on every operation whose
OpenAPI request body declares the form variant, and the B4-4 acceptance T-8(b)(c)(e) passes
end-to-end with these clients.

## 2. Evidence verification (per cited item, against HEAD)

| # | Cited evidence | Verification result |
|---|---|---|
| 1 | `cmd/gensdk/gen_ts_runtime.go` `request()`: unconditional `Content-Type: application/json` + `JSON.stringify(authenticatedBody)` | **Confirmed.** Lines 158-159: `headers["Content-Type"] = "application/json"; init.body = JSON.stringify(authenticatedBody);` — unconditional for every non-undefined body (line 157 `if (authenticatedBody !== undefined)`). |
| 2 | `cmd/gensdk/gen_py.go:103-104` (`json.dumps` + JSON Content-Type) | **Confirmed, exact.** Lines 103-104 inside `pyClientHeader` `_request()`: `headers["Content-Type"] = "application/json"; data = json.dumps(body).encode("utf-8")`. |
| 3 | `cmd/gensdk/operations.go:190-193` `contentSchema` prefers `application/json` | **Confirmed.** Function at line 192; selection order at line 193: `[...]string{"application/json", "application/x-www-form-urlencoded"}` — JSON wins whenever both are declared. Used for request bodies (line 210) and responses (line 232). |
| 4 | `docs/sdks/typescript/README.md` "the client always sends JSON" | **Confirmed, with citation fix.** `docs/sdks/typescript/README.md:71-74` documents the simplification. The phrase does **not** appear in `docs/sdks/python/client.py`'s banner (the direction's combined citation is imprecise); the Python runtime's JSON emission is the code at `docs/sdks/python/client.py:1437` (`_request`), `1453-1454`. |
| 5 | `ops/build/sdk-surface.json` auth group: postToken/postIntrospect/postRevoke/postRevokeAll/postPAR/postDeviceCode | **Confirmed.** Auth group at lines 211-238 contains all six, plus postMFAComplete (line 219) and postDeviceVerify (line 226). |
| 6 | `docs/openapi.yaml` dual JSON+form request bodies on /token, /token/introspect, /token/revoke, /par | **Confirmed.** All eight dual-content request bodies carry the **identical schema `$ref`** in both variants (verified by YAML parse): /token (988; form 1102, JSON 1144), /token/introspect (1280/1283), /token/revoke (1347/1350), /par (1477/1480), /device/code (1543/1546), /device/verify, /auth/mfa (643/646), /backchannel-authentication. The README's "identical schema" claim holds for every dual op. |

### 3. Corrections to the direction (evidence-backed)

1. **`postRevokeAll` is not body-bearing and cannot be affected by the enforcement.** The spec
   declares **no `requestBody`** for `/token/revoke-all` (openapi.yaml 1366-1395 — the next
   `requestBody` is /par's at 1474), and `protocols/oauth/handle_revoke.go:181` `HandleRevokeAll`
   never calls `BindParams` (bearer-only; the generated `postRevokeAll` sends no body and no
   `Content-Type` today — `docs/sdks/typescript/client.ts:2918-2920`, `client.py:2292-2294`).
   Its acceptance assertion is therefore **"sends no body, unchanged, still 200"**, not "sends a
   form body". Sending a body it has never sent would be a wire regression.
2. **The enforcement rule's status code is 400, not 415.** The B4-4 requirements spec §5 pins
   T-8(b) "JSON body → 400", T-8(c) "missing CT → 400", T-8(e) "unexpected CT → 400"
   (`invalid_request`). The direction's "415/400" resolves to **400 `invalid_request`**; there is
   no 415 in the hardening rule.
3. **The direction's "T-8a" label maps to T-8(b)(c)(e).** The campaign gate
   (`docs/campaigns/implementation-gate.md` row 4) assigns the Content-Type enforcement to
   T-8(b)(c)(e); T-8(a) is the issuance-claims gate (row 1). Acceptance text below is preserved
   but labeled per the canonical mapping.
4. **The affected surface is seven ops, not five-with-bodies.** The same mechanism that fixes
   postToken/postIntrospect/postRevoke/postPAR/postDeviceCode also covers the two further
   dual-content surface ops postDeviceVerify (`/device/verify`) and postMFAComplete (`/auth/mfa`)
   — both are in the B4-4 credential family. postBackchannelAuthentication (CIBA) is dual-content
   but **not** in the SDK surface (verified: absent from `ops/build/sdk-surface.json`), so no
   emission exists for it.
5. **The mechanism must be spec-driven, not the `tsUsesClientAuth` hard-coded list.**
   `gen_ts.go:99` restricts client-auth ops to postToken/postIntrospect/postRevoke/postPAR; the
   B4-4 R5.3 wording repeats that list. It is incomplete — postDeviceCode/postDeviceVerify/
   postMFAComplete are not client-auth ops but do hit hardened endpoints. Content-type selection
   must come from the operation's declared request-body content types.

## 4. Product boundary

- Surface: generated SDKs (`cmd/gensdk` → `docs/sdks/typescript/client.ts`, `docs/sdks/python/client.py`, TS `dist/`)
- Default: unconditional (no config knob; wire behavior of the generated clients changes)
- Explicit non-goals:
  - No server-side change: the form branch of `oauthwire.BindParams` (bind.go:38-42) already
    accepts form bodies today, and the strict binder is the sibling B4-4 workstream.
  - No OpenAPI edit: the spec already declares the form variants (B4-4 R5.4 drops the JSON
    variants in its own change; the picker stays correct either way).
  - No change to JSON-only ops (postLogin, postRegister, all admin/self-service/SCIM/SSF ops),
    response parsing, or `postRevokeAll`'s body-less wire shape.

## 5. Module classification

- [x] OAuth/OIDC/protocol flow (SDK emission for credential endpoints)
- [ ] Store implementation · [ ] Admin or self-service endpoint · [ ] Authenticator ·
  [ ] Audit/observability · [ ] Authorization/policy · [ ] Infrastructure/config/deployment ·
  [ ] Cold module / build profile / hot lifecycle · [ ] Refactoring only

Owning physical layer/package: `cmd/gensdk` (composition-side tool; imports only the standard
library and reads `docs/openapi.yaml` + `ops/build/sdk-surface.json` — no upward/downward
dependency change). Dependency direction review: unchanged.

Budget check before editing: `cmd/gensdk` has 10 non-test `.go` files (ceiling 10 — do not add a
new file; extend `emit_test.go`); no file is near 500 lines; no function near 50 lines; no new
package, so no `layerName()` classification needed.

## 6. Design

1. **Per-operation content type on `Operation`.** Add `ContentType string` to
   `cmd/gensdk/operations.go` `Operation` (empty = JSON, the status quo). In `contentSchema`,
   flip the preference to
   `[...]string{"application/x-www-form-urlencoded", "application/json"}` — safe because every
   dual-content operation's variants are byte-identical `$ref`s (§2 item 6) — and record the
   chosen content type on the `Operation` in `extractRequestBody`. Response resolution
   (`extractResult`) is unaffected (responses are JSON-only; the flipped order is a no-op there).
   This yields exactly: the seven credential-family ops → form; every other body op → JSON.
2. **TypeScript runtime** (`gen_ts_runtime.go` `tsRuntime` const): extend `requestOptions` with
   `form?: boolean` (or `contentType`). When set, build the body as `URLSearchParams`:
   - scalar values → `params.set(k, String(v))` (booleans already stringify to `true`/`false`,
     matching the server binder `bind.go:116` which accepts only `"true"`/`"1"`);
   - string-array values (`TokenRequest.audience`/`resource`, `IntrospectRequest.tokens`,
     `PARRequest.resource`, `DeviceCodeRequest.resource`) → **repeated keys**
     (`params.append(k, item)` per element) — the server's documented form contract
     (openapi.yaml:1063-1066 "Repeated form keys form the `resource`/`audience` lists";
     binder `formStringSlice` at bind.go:129-130);
   - object / array-of-object values (`PARRequest.claims`, `PARRequest.authorization_details`,
     `MFACompleteRequest.params`) → single key with `JSON.stringify(value)` — the RFC 9396 §3 /
     OIDC Core §5.5 JSON-string form value the B4-4 decoder adds for `json.RawMessage` fields
     (handle_par.go:100,105; decisions doc `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-decisions.md`).
   Set `headers["Content-Type"] = "application/x-www-form-urlencoded"`. Keep the JSON branch for
   `form` unset. `withClientAuthentication` keeps running before serialization so
   `client_id`/`client_secret` stripping (Basic auth) still applies to the form path.
3. **Python runtime** (`gen_py.go` `pyClientHeader`): extend `_request` with `form: bool = False`.
   When set, serialize with `urllib.parse.urlencode(..., doseq=True)` (repeated keys for lists)
   after coercing values: `bool` → `"true"`/`"false"` (**required** — `urlencode` would emit
   `True`/`False`, which the binder rejects: bind.go:116 accepts only `"true"`/`"1"`; this bites
   `postDeviceVerify.approve`), non-scalar objects → `json.dumps`. Set the form Content-Type.
4. **Emitters** (`gen_ts.go` `tsEmitRequestOpts`, `gen_py.go` `pyEmitMethod`): pass the
   per-operation form flag through (`form: true` / `form=True`) when `op.ContentType` is the
   form variant. Do **not** reuse the `tsUsesClientAuth` list (correction §3.5).
5. **Regenerate everything committed**: `go run ./cmd/gensdk --lang=all` →
   `docs/sdks/typescript/client.ts`, `docs/sdks/python/client.py`; then `bunx tsc -p tsconfig.json` in
   `docs/sdks/typescript/` for the committed `dist/` copies (`client.js:130-131` currently carry
   the JSON emission; the plain `bun run build` fails on a clean checkout — no committed
   typescript devDependency/lockfile, `tsc: command not found`), and `bun test` for `client.test.mjs`
   (9/9, incl. `client.test.mjs:53`).
6. **Docs**: replace the `docs/sdks/typescript/README.md:71-74` simplification ("the client
   always sends JSON") with the form-first statement (credential-family ops send
   `application/x-www-form-urlencoded`; JSON remains for JSON-only ops). Note the array/JSON-string
   value rules. Python README: add the same one-paragraph note.

## 7. Acceptance criteria

Universal gates (unchanged): `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`; `make ci` (includes `sdk-surface-check`); `bun test` + `bunx tsc -p tsconfig.json` in `docs/sdks/typescript/` — the two bun gates are explicitly out-of-band from `make ci` (Makefile:268 has no bun/tsc step; bun is not a declared repo toolchain), see design §7.

Feature-specific Given/When/Then — the direction's acceptance, restated testably (label per
correction §3.3; postRevokeAll per correction §3.1):

- **AC1 (T-8(b)(c)(e) — regeneration).** Given a clean tree, when `go run ./cmd/gensdk --lang=all`
  runs and `git diff` is inspected, then the committed `docs/sdks/typescript/client.ts` and
  `docs/sdks/python/client.py` methods `postToken`, `postIntrospect`, `postRevoke`, `postPAR`,
  `postDeviceCode` (and, by the same mechanism, `postDeviceVerify`, `postMFAComplete`) set
  `Content-Type: application/x-www-form-urlencoded` and serialize bodies via
  `URLSearchParams` (TS) / `urllib.parse.urlencode` (Python); the token-family request path no
  longer contains `JSON.stringify`/`json.dumps` for these operations; `postRevokeAll` is
  byte-identical (no body, no Content-Type); JSON-only ops (e.g. `postLogin`) are unchanged.
- **AC2 (T-8(b)(c)(e) — unit).** `cmd/gensdk/emit_test.go` gains tests asserting:
  (a) per-operation content-type selection — feeding the real `docs/openapi.yaml` through
  `Extract` yields `ContentType` form for the seven ops above and JSON/empty for `postLogin` and
  `postRegister`; (b) generated TS output contains the `URLSearchParams` branch and form header
  for `postToken` with `clientAuth: true` preserved, and Basic-credential stripping still
  precedes serialization; (c) generated Python output contains `urlencode` + form header for
  `post_token`, with `True`/`False` coerced to `"true"`/`"false"` and `doseq` repeated keys;
  (d) repeated-key emission for `resource`/`audience` and JSON-string single-key emission for
  `claims`/`authorization_details` in the generated `postPAR`.
- **AC3 (T-8(b)(c)(e) — contract/E2E).** A contract test (test/, package ssotest, in-process
  httptest harness as in `test/e2e_test.go`) runs the generated clients' wire shape against the
  server: form-encoded `POST /token` (`client_credentials` with a registered confidential
  client, body exactly as the generated SDK emits it — Basic auth header plus form body) →
  **200**; form-encoded `POST /par` with repeated `resource` keys → 201; with the strict binder
  enabled (the B4-4 harness's enforcement mode, same campaign), the JSON-variant control call
  → **400 `invalid_request`** (the hardening rule's status, correction §3.2). The TS-level arm
  lives in `docs/sdks/typescript/client.test.mjs`: the existing "confidential token calls" test
  (which currently asserts `JSON.parse(seen.body)`) is updated to assert
  `seen.headers["Content-Type"] === "application/x-www-form-urlencoded"` and a
  `URLSearchParams`-decoded body. Merge ordering: the JSON-rejection arm lands with the B4-4
  strict binder (same campaign); the form arm is green immediately because the server's form
  branch already exists (bind.go:38-42).
- **AC4 (artifacts/drift).** Regenerated artifacts are committed: `client.ts`, `client.py`,
  `dist/` (tsc output), both READMEs; `python cli.py sdk-surface check` and `make ci` stay green;
  a seeded stale copy (JSON emission reintroduced) fails the regeneration diff check once the
  T-9 drift gate (sibling direction) is in place — no new gate added here.

## 8. Files

### Create

```text
docs/architect-analysis/cmd-gensdk-b4-4-credential-form-requirements.md — this spec
```

### Modify

```text
cmd/gensdk/operations.go — Operation.ContentType; contentSchema preference flip (line 193) +
  record chosen type in extractRequestBody
cmd/gensdk/gen_ts_runtime.go — tsRuntime: form branch (URLSearchParams, repeated keys,
  JSON-string values), form Content-Type; keep withClientAuthentication ordering
cmd/gensdk/gen_py.go — pyClientHeader _request: form branch (urlencode doseq=True, bool
  coercion, JSON-string values), form Content-Type; pyEmitMethod form flag
cmd/gensdk/gen_ts.go — tsEmitRequestOpts passes the per-op form flag (spec-driven, not
  tsUsesClientAuth)
cmd/gensdk/emit_test.go — AC2 tests (extend existing file; no new file — file-count ceiling)
docs/sdks/typescript/client.ts — regenerated
docs/sdks/python/client.py — regenerated
docs/sdks/typescript/dist/*.js, *.d.ts — regenerated via bunx tsc -p tsconfig.json (committed artifacts)
docs/sdks/typescript/client.test.mjs — JSON.parse(seen.body) assertion → form assertions
docs/sdks/typescript/README.md — lines 71-74 simplification replaced
docs/sdks/python/README.md — form note
test/credential_sdk_form_test.go — AC3 contract/E2E (package ssotest)
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go — server binder; strict enforcement is the sibling B4-4 change
docs/openapi.yaml — request bodies already declare both variants; B4-4 R5.4 drops JSON in its own change
ops/build/sdk-surface.json — surface registry unchanged
cmd/gensdk/schema.go, schema_primitive.go, main.go — untouched
interfaces/sso/*, protocols/oauth/handle_*.go — server handlers untouched
```

## 9. Dependencies and compatibility

- New/changed SPI: none (generator-internal `Operation.ContentType`; generated-runtime
  signatures gain an internal form flag — no public API change).
- New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: the generated clients' wire format for the seven credential-family
  operations changes from JSON to form-urlencoded — a **client-side** change that the server
  already accepts (dual-mode binder). Consumers of the generated SDKs need no code changes;
  callers who relied on the JSON convenience get the RFC-mandated form wire.
- Rollout/rollback: single commit (generator + artifacts + tests + docs); rollback is reverting
  the commit — generator and artifacts always move together (regenerated in the same change).
- Interlock: AC3's JSON-rejection arm depends on the B4-4 strict binder landing in the same
  campaign; AC4 notes the T-9 drift gate as the future guard.
