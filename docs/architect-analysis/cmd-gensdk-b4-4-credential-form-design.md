# Design: cmd/gensdk — form-urlencoded emission for the credential-endpoint family (B4-4)

- Direction: B4-4, item 1 (source: `docs/architect-analysis/auto/analyses/cmd-gensdk-4ffda121.json`)
- Requirements baseline: `docs/architect-analysis/cmd-gensdk-b4-4-credential-form-requirements.md` (this design's acceptance criteria are that spec's AC1-AC4, restated testably in §7)
- Sibling workstream (merge interlock): `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-design.md` (+ its decisions doc) — the strict form-only binder at the eight credential sites
- Reconciliation (binding, amends this design): `docs/architect-analysis/b4-4-credential-form-sdk-binder-reconciliation.md` — SDK emission exclusively owned here (D1/D2); the two admin compromise ops excluded from the strict surface, stay JSON (D3); C1 guard presence-based (D4); merge order binder-first with a mechanical backstop (D6)
- Status: design (all citations re-verified against HEAD; `go build ./... && go vet ./...` clean at design time)

## 1. Verification verdict (untrusted claims -> measured reality)

Every citation in the evidence summary and in the requirements spec §2 was re-checked against the working tree.

| Evidence claim | Measured reality | Verdict |
|---|---|---|
| `cmd/gensdk/gen_ts_runtime.go:158-159` — unconditional `Content-Type: application/json` + `JSON.stringify(authenticatedBody)` in `request()` | `request()` at gen_ts_runtime.go:197-160 region; the branch `if (authenticatedBody !== undefined) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(authenticatedBody); }` is unconditional for every non-undefined body; `withClientAuthentication` runs before it and strips `client_id`/`client_secret` into the Basic header | **Confirmed** |
| `cmd/gensdk/gen_py.go:103-104` — `json.dumps(body)` + JSON Content-Type in `_request()` | `pyClientHeader` const: `if body is not None: headers["Content-Type"] = "application/json"; data = json.dumps(body).encode("utf-8")`; `_request` has **no client-auth path** — body credentials are sent in the body (verified in generated `client.py`: `post_token` -> `self._request("POST", "/token", body=body)`) | **Confirmed** (exact lines) |
| `cmd/gensdk/operations.go:188-193` — `contentSchema` prefers `application/json` | `contentSchema` at operations.go:192; preference list at :193 `[...]string{"application/json", "application/x-www-form-urlencoded"}`; used by `extractRequestBody` (:210) and `extractResult` (:232) | **Confirmed** |
| `docs/sdks/typescript/README.md:71-74` — "the client always sends JSON" simplification | README.md:71-74 "An operation's **form-urlencoded content type is not separately modeled** ... and the client always sends JSON." The phrase is not in the Python banner (`pyBanner`); Python's JSON emission is the runtime code at `client.py:1453-1454` | **Confirmed, with the spec's citation fix** |
| `ops/build/sdk-surface.json` auth group — postToken/postIntrospect/postRevoke/postRevokeAll/postPAR/postDeviceCode | Auth group (lines 211-238) holds all six plus postMFAComplete and postDeviceVerify; postBackchannelAuthentication is **absent** from the whole registry (verified by flattening every group) | **Confirmed** |
| `docs/openapi.yaml` — dual JSON+form request bodies, byte-identical `$ref`s | YAML-parse scan: exactly **8** dual-content operations (postToken, postIntrospect, postRevoke, postPAR, postDeviceCode, postDeviceVerify, postMFAComplete, postBackchannelAuthentication); every pair is a byte-identical `$ref`. postRevokeAll has **no requestBody**; postLogin/postRegister are **JSON-only** | **Confirmed** |
| `postRevokeAll` unaffected (spec correction 1) | openapi: `/token/revoke-all` has no `requestBody`; `HandleRevokeAll` (handle_revoke.go:181) is bearer-only, never binds a body; generated `client.ts:2918` / `client.py:2292` send `{ auth: true }` only | **Confirmed** |
| Rejection status is 400 `invalid_request` (spec correction 2) | Sibling requirements §5 T-8(b)(c)(e) pin 400; sibling design §3.1: the ten sites reject with "their canonical 400 (`invalid_request`; **`mfa_invalid` on `/auth/mfa`**)". No 415 anywhere in the hardening rule | **Confirmed** (with the MFA nuance folded in, see C7) |
| T-8(a) is the claims gate (spec correction 3) | `docs/campaigns/implementation-gate.md` row 1 (T-8(a): `/token` -> 200 + kid + claims) vs row 4 (T-8(b)(c)(e): Content-Type enforcement) | **Confirmed** |
| Affected surface is 7 ops (spec correction 4) | Exactly the 7 dual-content ops present in the surface registry; postBackchannelAuthentication is dual but out of surface. Completeness claim (reconciliation D3): the two generated admin compromise ops (`adminCompromiseCredential`, `adminReportCryptoKeyCompromise`) are JSON-only and are **excluded from the strict form surface by decision** (non-RFC-mandated bearer-admin control-plane endpoints; the sibling does not switch them to the strict binder) — the 7-op set is the complete SDK form surface, and the two admin ops stay JSON byte-identical | **Confirmed** |
| Serialization nuances: repeated string-array keys, JSON-string single keys, bool coercion | `bind.go:115-116` bool `raw[0] == "true" \|\| raw[0] == "1"`; `formStringSlice` :129-130 (multi-value + space/comma split); `handle_par.go:89-107` `Claims`/`AuthorizationDetails json.RawMessage`; openapi.yaml:1063-1066 "Repeated form keys form the `resource`/`audience` lists" | **Confirmed** |
| Committed artifacts carry the JSON emission; `client.test.mjs:53` asserts `JSON.parse(seen.body)` | `dist/client.js:130-131` JSON emission; `client.test.mjs:53` `assert.deepEqual(JSON.parse(seen.body), ...)` in the "confidential token calls" test | **Confirmed** |
| cmd/gensdk is at its 10-file ceiling — tests must extend `emit_test.go` | **Imprecise:** cmd/gensdk has **7** non-test `.go` files (main, gen_ts, gen_ts_runtime, gen_py, operations, schema, schema_primitive) against the 10-file budget. The constraint itself (extend `emit_test.go`, add no file) is still adopted — no new package, minimal churn | **Correction C3** |

### 1.1 New corrections surfaced by this review (beyond the spec's own §3)

**C1 — `MFACompleteRequest.params` must NOT be JSON-string-encoded; it must be rejected client-side.** The requirements spec §6 items 2-3 list `MFACompleteRequest.params` among "object values -> single key with `JSON.stringify(value)`". That contradicts the sibling decisions doc **F3**: a form request to `/auth/mfa` carrying the `params` key is rejected with `400 mfa_invalid` at parse time (no RFC defines a form encoding for maps; the flat `code`/`assertion`/`trust_device` fields are the documented form contract — server_mfa.go:224-247, decisions doc §3). Emitting `params` as a JSON-string key would therefore be a guaranteed 400 once the sibling lands (and a silent drop today, since the shared decoder skips `map[string]string`). The generated `postMFAComplete`/`post_mfa_complete` must fail loud client-side when `params` is **present with any non-null value — including `{}`** (presence semantics, matching the sibling's `r.PostForm.Has("params")`; reconciliation D4), mirroring the server's fail-loud posture; the failure is a client-side error, not a wire attempt. `undefined`/`null` are treated as absent (JSON-wire `null` decodes to a nil map server-side — byte-equivalent).

**C2 — the bool-coercion failure mode is silent denial, not a 400 rejection.** The evidence ("`urlencode` emits `True` which bind.go:116 rejects") overstates the server side: `setFormField`'s bool case is `f.SetBool(raw[0] == "true" || raw[0] == "1")` — any other value **silently coerces to false**. The consequence for `postDeviceVerify.approve` (required bool) and `MFACompleteRequest.trust_device` is therefore worse than a 400: a Python `True` would silently **deny** the device approval / not mint the trust grant. The runtime coercion to lowercase `"true"`/`"false"` is mandatory regardless of what the strict binder does (the sibling design leaves the bool case unchanged).

**C4 — merge-order window for PAR `claims`/`authorization_details`.** The shared decoder today has **no** `json.RawMessage` form branch, so a form PAR carrying `claims`/`authorization_details` is accepted with the values **silently dropped** (decisions doc §1: "silently dropped on the form wire today"). The SDK's JSON-string single-key emission is therefore wire-correct but functionally inert until the sibling's F1 decoder extension lands; PAR users who rely on those parameters must not be on the SDK change before F1. Not a blocker (same campaign), but the interlock is real and is enforced mechanically (see §6): a deliberately-red (never skipped) claims-positive E2E arm blocks this change's merge until F1 lands (D6).

**C5 — Python client has no client-auth mechanism; body credentials stay in the form body.** `_request` has no Basic path and no credential stripping; `post_token` sends `client_id`/`client_secret` in the body. On the form wire this remains valid (the binder accepts body credentials; the AGENTS.md invariant "HTTP Basic wins over body credentials" only concerns requests carrying both). No Python-side auth change. (TS keeps its Basic-strip-before-serialize ordering; both paths are compatible with the invariant.)

**C6 — response resolution is provably unaffected by the preference flip.** A scan of every response object in openapi.yaml finds **zero** responses declaring `application/x-www-form-urlencoded`; and even a hypothetical dual response would resolve to the same `$ref`. `extractResult` is untouched in behavior.

**C7 — the AC3 control arm's status must not be asserted for `/auth/mfa`.** Under the strict binder, JSON on `/auth/mfa` collapses to `400 mfa_invalid` (not `invalid_request`). The AC3 control uses `/token` (400 `invalid_request`) — fine — but any design text must not generalize `invalid_request` to the MFA endpoint.

## 2. API changes

### 2.1 Generator-internal Go API (additive, package `cmd/gensdk`)

| Symbol | Location | Notes |
|---|---|---|
| `Operation.ContentType string` | `operations.go` `Operation` struct | Empty = JSON (status quo for every JSON-only op). Set to `"application/x-www-form-urlencoded"` for the seven credential-family ops |
| `Operation.FormBlockedFields []string` | same struct | Map-typed body fields that have no form encoding (exactly `params` on `MFACompleteRequest` today), populated schema-driven (fields whose `TypeSpec.Kind == KindMap`). Drives the generated client-side guard (C1). Empty for every other op |
| `contentSchema` preference flip | operations.go:193 | Order becomes `[...]string{"application/x-www-form-urlencoded", "application/json"}`; the chosen content type is recorded on the `Operation` by `extractOne` (via a small `contentTypeOf(content) string` helper) — `extractRequestBody` keeps returning `(BodyType, BodyRequired, HasBody)`, and `extractOne` additionally stores `op.ContentType`. Safe because every dual op's variants are byte-identical `$ref`s (verified §1) and **no response declares the form variant** (C6) |

No new exported symbols, no new package, no `layerName()` classification, no `Err*`. Files stay within budgets (7 non-test files; largest file 361 lines).

### 2.2 Generated TypeScript runtime (hand-written `tsRuntime` const, gen_ts_runtime.go)

- `requestOptions` gains `form?: boolean`.
- New private `formSerialize(body: Record<string, unknown>): string` returning a `URLSearchParams`-encoded body with these per-value rules:
  - `undefined`/`null` -> key skipped (JSON.stringify today drops them; the form encoder must do the same);
  - `FormBlockedFields` keys are **never emitted** (skipped before any value rule — reconciliation D4; defense in depth behind the generated guard, so a blocked key can never reach the wire);
  - `boolean`/`number`/`string` -> `params.set(k, String(v))` (`String(true)` == `"true"`, matching the binder verbatim);
  - `string[]` -> **repeated keys** `params.append(k, item)` (the documented `resource`/`audience`/`tokens` contract, openapi.yaml:1063-1066; `formStringSlice` returns multi-value lists verbatim);
  - any other `Array` (only `authorization_details`: array of objects) -> single key with `JSON.stringify(array)` (RFC 9396 §3 serialized-JSON value; F1 requires exactly one value — repeated keys would 400);
  - plain object (only `claims`) -> single key with `JSON.stringify(value)` (OIDC Core §5.5).
- In `request()`: when `opts.form`, set `headers["Content-Type"] = "application/x-www-form-urlencoded"` and `init.body = formSerialize(...)`; keep the JSON branch for `form` unset. `withClientAuthentication` keeps running **before** serialization (already the case) so Basic-credential stripping still precedes the form body — a confidential `postToken` body ends up with `grant_type` (and anything else) but never `client_id`/`client_secret`.
- The empty-array case emits no key — identical server-visible result to the JSON `[]` wire (absent key -> zero value).

### 2.3 Generated Python runtime (`pyClientHeader` const, gen_py.go)

- `_request` gains `form: bool = False`.
- New module-level `_form_encode(body: Dict[str, Any]) -> str`:
  - `FormBlockedFields` keys are **never emitted** (skipped first — reconciliation D4);
  - drop `None` values (mirrors the existing query filter `if v is not None` and JSON's null-drop semantics at the binder);
  - `bool` -> `"true"`/`"false"` (**mandatory**, C2 — `urlencode` would emit `True`/`False`, which the binder silently coerces to false);
  - `List[str]` -> keep as list so `urllib.parse.urlencode(body, doseq=True)` emits **repeated keys**;
  - any other list (`authorization_details`) / `dict` (`claims`) -> single key with `json.dumps(value)` (F1-compatible JSON-string encoding);
  - scalars pass through (`urlencode` stringifies).
- `_request`: when `form`, set the form Content-Type and `data = _form_encode(body).encode("utf-8")`.

### 2.4 Emitters (gen_ts.go, gen_py.go)

- `tsEmitRequestOpts`: append `form: true` to the requestOptions literal when `op.ContentType == "application/x-www-form-urlencoded"`. **Spec-driven via `op.ContentType`, not `tsUsesClientAuth`** (spec correction 4 — that list omits postDeviceCode/postDeviceVerify/postMFAComplete and would silently drop the fix for three of the seven ops).
- `tsEmitMethod`/`pyEmitMethod`: when `op.FormBlockedFields` is non-empty, emit a guard at the top of the generated method with **presence semantics** (reconciliation D4 — mirrors the sibling's `r.PostForm.Has("params")`, which fires on key presence with any value): TS `if (body.params !== undefined && body.params !== null) { throw new SSOError(0, "invalid_request", "params has no application/x-www-form-urlencoded encoding; use code/assertion"); }` and Python `if body.get("params") is not None: raise SSOError(0, "invalid_request", "params has no application/x-www-form-urlencoded encoding; use code/assertion")`. `params: {}` therefore throws client-side (no wire attempt); `undefined`/`null` are treated as absent (JSON-wire `null` is byte-equivalent to a nil map server-side). Only `postMFAComplete`/`post_mfa_complete` get the guard today (C1); the mechanism is schema-driven so a future map field needs no emitter change. The serializers additionally skip `FormBlockedFields` keys entirely (defense in depth).
- `pyEmitMethod`: append `form=True` to the `_request(...)` call for the seven ops.

### 2.5 Wire API (the point of the change)

The generated clients' requests to `/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/code`, `/device/verify`, `/auth/mfa` switch from JSON bodies to `application/x-www-form-urlencoded` bodies (Content-Type set). `/token/revoke-all` stays body-less; all JSON-only ops (postLogin, postRegister, admin/self-service/SCIM/SSF) are byte-identical. Responses are unchanged (JSON parsing, no form response anywhere — C6). This is a **client-side** wire change the server already accepts (dual-mode `BindParams`, bind.go:38-42).

**Admin exclusion (reconciliation D3, binding):** `adminCompromiseCredential` and `adminReportCryptoKeyCompromise` are **not** part of the form surface. They are JSON-only by decision — the two admin:write control-plane endpoints are excluded from the sibling's strict binder (non-RFC-mandated bearer-admin APIs), so the generated JSON emission for them keeps working unchanged. They are not a "blind spot" of the schema-driven picker: there is no form variant to select, and by decision there must not be one (D3).

## 3. Compatibility constraints

1. **Server-side: zero changes in this workstream.** `oauthwire/bind.go`, `bindOAuthParams`, and all handlers stay untouched; the strict binder is the sibling change (§6). This workstream must not preempt it (e.g. no Content-Type enforcement here).
2. **Generated SDK public signatures are unchanged.** `postToken(body: TokenRequest): Promise<TokenIssuance>` etc. keep their exact names, parameters, and return types; the form flag is internal to the runtime/request plumbing. Consumers need no code changes. TypeScript callers pass the same `TokenRequest`/`PARRequest`/... shapes; runtime value handling differs only inside the transport.
3. **`postRevokeAll` wire-identical** (no body, no Content-Type) — sending a form body it never sent would be a regression (spec correction 1). Byte-diff pinned by the regeneration gate.
4. **JSON-only ops byte-identical** — `contentSchema`'s flipped preference only changes behavior where both variants exist (seven ops); `postLogin`/`postRegister` declare only JSON.
5. **Client-auth invariants preserved:** TS Basic-strip-before-serialize; Python body credentials remain in the (form) body — both consistent with "HTTP Basic wins over body credentials on /token, /introspect, /revoke, /par".
6. **Oracle-safety surfaces untouched** — this change emits no errors of its own except the C1 guard (client-side, no server oracle) and the SSOError transport errors that exist today.
7. **Docs contract:** `docs/sdks/typescript/README.md:71-74` ("the client always sends JSON") is replaced by the form-first statement (credential family -> `application/x-www-form-urlencoded`; JSON remains for JSON-only ops; array/JSON-string value rules; `params` not expressible); `docs/sdks/python/README.md` gains the same paragraph. `docs/openapi.yaml`, `ops/build/sdk-surface.json`, and `docs/feature-matrix.md` need no edits (the spec already declares both variants; the sibling R5.4 drops the JSON variants in its own change and the picker stays correct either way).
8. **Generated artifacts move with the generator in one commit** — `client.ts`, `client.py`, `dist/`, `client.test.mjs`, both READMEs regenerated/updated in the same change; rollback is reverting the commit (no generator/artifact skew).

## 4. Failure modes

| # | Failure mode | Detection | Mitigation |
|---|---|---|---|
| F1 | **Pre-sibling window: PAR `claims`/`authorization_details` silently dropped** (shared decoder has no RawMessage form branch yet) | **`TestSdkForm_PARClaimsThreaded` (claims-positive form-PAR E2E) is deliberately red until the sibling's F1 decoder lands — never skipped** (binder-conformance G4; reconciliation D6). A form-PAR-with-claims request would 201 with claims absent at login, failing the thread-through assertion | Same-campaign interlock (§6, D6): F1 decoder extension lands before this change merges; the SDK wire shape is correct either way, so no rework — the red-until-F1 arm mechanically enforces the merge order (CI cannot go green pre-sibling) |
| F2 | **`params` on `/auth/mfa`** — guaranteed `400 mfa_invalid` after the sibling lands; silent drop today | Caller passes `params` to `postMFAComplete` | C1 client-side fail-loud guard in the generated method with **presence semantics** (fires for `params: {}` too — D4); serializers never emit `FormBlockedFields` keys; README documents the flat `code`/`assertion` form contract |
| F3 | **Python bools emitted as `True`/`False`** — silently coerced to false server-side (device approval denied, trust grant not minted) — the worst failure mode in this change | Unit test asserting `_form_encode({"approve": True}) == "approve=true"`; E2E device-verify-approve arm | Mandatory coercion in `_form_encode` (C2); pinned in AC2(c) |
| F4 | **TS `undefined` optional fields serialized as the literal string** `"undefined"` (a naive `URLSearchParams` walk) | Unit test: form body with partial `TokenRequest` contains no `undefined=` key | Explicit skip in `formSerialize` (AC2(b)) |
| F5 | **`authorization_details` emitted as repeated keys** (array-of-objects mistaken for array-of-strings) — F1 rejects repeated keys with 400 | Unit test asserting a single `authorization_details=` key with valid JSON text (AC2(d)) | Runtime distinguishes `string[]` (repeated) from non-string arrays (single JSON-string key) |
| F6 | **Regression of JSON-only ops** if the preference flip leaked into response resolution | `go test ./...` + `bun test`; no response declares form (C6), so this is structurally excluded | Preference flip recorded only on request bodies via `extractOne`; `extractResult` unchanged in behavior (verified: zero form responses) |
| F7 | **`postRevokeAll` accidentally gaining a body/Content-Type** if the emitter keyed on endpoint path instead of `requestBody` presence | Regeneration diff gate: `postRevokeAll` byte-identical (AC1) | `op.HasBody` gates emission; revoke-all has no requestBody |
| F8 | **Generator/artifact skew** (hand-edited committed clients, stale `dist/`) | Sibling T-9 `sdk-drift check` regeneration leg (byte-compares regenerated `client.ts`/`client.py` vs committed; not in `make ci` at HEAD) + `bunx tsc -p tsconfig.json` byte-diff for `dist/` | Regenerate all artifacts in the same commit; AC4 drift assertions |
| F9 | **Intermediary charset surprises** | Server `normalizedMediaType` strips `;parameters` (sibling design §3.2) | No charset emitted by either runtime; `URLSearchParams`/`urlencode` percent-encode per the form spec |
| F10 | **Empty-string array element or empty body edge** | Unit + E2E | `resource: [""]` -> one empty key (binder yields `[""]`, same as JSON wire); body-less callers of the seven ops are impossible — **all seven request bodies are declared `required`** (verified: postToken, postPAR, postDeviceVerify, postMFAComplete all `required: true`; the remaining three declare a `requestBody` too), so the form branch always runs |

## 5. Migration steps

1. **Generator change** (`cmd/gensdk`): `Operation.ContentType` + `FormBlockedFields`; `contentSchema` preference flip + recording; TS runtime `form` branch + `formSerialize`; Python runtime `form` branch + `_form_encode`; emitter plumbing (`form: true` / `form=True`); C1 guard emission.
2. **Unit tests** in `emit_test.go` (extend the existing file — no new file): AC2(a)-(d) plus a `_form_encode`/`formSerialize` golden set covering F3/F4/F5, the D4 presence cases (`params: {}` throws client-side; `params: None`/`null` dropped), the F10 empty-element case (`{"resource": [""]}` -> `resource=`), and a TS bool golden (`formSerialize({"approve": true})` -> `approve=true`). **Golden harness (G3):** behavioral cases execute via node/python3 subprocess against the emitted serializer — string-presence assertions cannot prove coercion (`v is True` typos pass them) — with **no `t.Skip`** (skip is a silent pass); alternatively relocate the behavioral goldens into `client.test.mjs` + a Python test.
3. **Regenerate**: `go run ./cmd/gensdk --lang=all` -> `docs/sdks/typescript/client.ts`, `docs/sdks/python/client.py`.
4. **TS artifact rebuild + tests**: `bunx tsc -p tsconfig.json` in `docs/sdks/typescript/` for committed `dist/`; update `client.test.mjs:53` (form assertions) and run `bun test`. The plain `bun run build` (package.json `scripts.build` = `tsc -p tsconfig.json`) fails on a clean checkout with `tsc: command not found` (exit 127) — the SDK commits no node_modules, devDependencies, or lockfile; `bunx tsc` fetches typescript on demand and reproduces the committed `dist/` byte-identically (verified).
5. **Docs**: TS README:71-74 replacement; Python README paragraph; note the `params` exclusion and the array/JSON-string value rules.
6. **Contract/E2E** (`test/`, package ssotest): form-wire tests per AC3, **including the deliberately-red `TestSdkForm_PARClaimsThreaded` arm (F1/D6 — never skipped)** and the device-verify approve arm (F3).
7. **Mandatory gates**: `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`; `python cli.py sdk-surface check`; `make ci`; `bun test` + `bunx tsc -p tsconfig.json` in `docs/sdks/typescript/` (out-of-band from `make ci` — see §7).
8. **Merge interlock** with the sibling strict binder (§6) — the JSON-rejection control arm of AC3 lands with the sibling (its own T-8(b) tests cover the server side); the form arm is green immediately. **Merge order is enforced (reconciliation D6): this change does not merge before the sibling's design gate has PASSED and the sibling implementation has merged** — the red-until-F1 `TestSdkForm_PARClaimsThreaded` arm makes a pre-sibling merge CI-impossible.

Rollback: revert the single commit (generator + artifacts + tests + docs move together; the sibling binder change is independent and reverts separately without affecting the form wire). Revert order is **sibling-first**: once the strict binder has landed, reverting only this commit returns the SDKs to JSON emission on the seven ops and every credential SDK call 400s (`invalid_request`) against the form-only server — revert the binder commit first, or both together. The revert must come from git: `dist/*.js` cannot be rebuilt in a clean environment (no committed typescript dependency or lockfile; `bun run build` fails with `tsc: command not found` and `bunx` needs a network fetch), so there is no artifact-rebuild fallback for rollback.

## 6. Interlock with the sibling B4-4 strict binder

- The form arm of AC3 is green **today**: the dual-mode `BindParams` already accepts form bodies at all seven endpoints (bind.go:38-42).
- The JSON-rejection arm (400 `invalid_request`; `mfa_invalid` on `/auth/mfa`) is authoritative only after the sibling change (strict binder + test sweep). Until then the old JSON wire would also pass — which is fine, the SDK no longer sends it.
- F1 dependency (C4): PAR `claims`/`authorization_details` on the form wire are functional only after the sibling's `json.RawMessage` decoder extension. Order the campaign so F1 lands with or before this change; the wire shape is forward-compatible either way.
- The sibling's `TestFormEncoded_JSONStillWorks` inversion and 18-file JSON-post sweep (16-file inventory + `introspection_jwt_test.go` + `frontend_contract_test.go`, gate F5) are the sibling's scope; this workstream touches no server test.
- **Merge order is enforced, not just stated (reconciliation D6):** (1) this change carries `TestSdkForm_PARClaimsThreaded`, a claims-positive form-PAR E2E that is **deliberately red until the sibling's F1 decoder extension lands** — never skipped, so CI blocks this change's merge pre-sibling (binder-conformance G4); (2) the sibling design gate (run c399c070, currently FAIL) must pass before this workstream's implementation runs; (3) rollback is sibling-first (§5). The campaign row in `docs/campaigns/implementation-gate.md` records the order.

## 7. Testable acceptance mapping

Universal gates (unchanged): `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`; `make ci`; `python cli.py sdk-surface check`; `bun test` + `bunx tsc -p tsconfig.json` in `docs/sdks/typescript/`. The two bun gates are **explicitly out-of-band from `make ci`**: Makefile:268's `ci:` target list contains no bun/tsc step (verified by inspection and `grep`), and bun is not a declared repo toolchain — the SDK commits no lockfile, and `bunx tsc` needs a one-time registry fetch. They run manually in the SDK directory as the SDK package's own publish-side verification, not as `make ci` prerequisites. (`bun test` itself needs only bun, no dependencies; only the build needs the on-demand typescript fetch.)

| Acceptance (requirements spec) | Testable mapping | Gate |
|---|---|---|
| **AC1 — regeneration** (T-8(b)(c)(e)): committed `client.ts`/`client.py` send form bodies on the seven ops; `postRevokeAll` byte-identical; JSON-only ops unchanged | `git diff` clean after `go run ./cmd/gensdk --lang=all` + `bunx tsc -p tsconfig.json` (drift check); string assertions in `emit_test.go`: generated `postToken` contains `form: true` and no `JSON.stringify` in its path; generated `postRevokeAll` contains no `body`/`Content-Type`; generated `postLogin` unchanged | Regeneration + `make ci`; F7/F8 |
| **AC2(a) — content-type selection** | New `TestContentTypeSelection` in `emit_test.go`: run `Extract` over the real `docs/openapi.yaml` + `ops/build/sdk-surface.json`; assert `ContentType == "application/x-www-form-urlencoded"` for exactly {postToken, postIntrospect, postRevoke, postPAR, postDeviceCode, postDeviceVerify, postMFAComplete}; JSON/empty for postLogin, postRegister, postRevokeAll (no body); postBackchannelAuthentication not in surface; **the two admin compromise ops (`adminCompromiseCredential`, `adminReportCryptoKeyCompromise`) have empty `ContentType` (JSON — reconciliation D3 exclusion)** | `go test ./cmd/gensdk/` |
| **AC2(b) — TS emission** | `TestGenerateTS_FormBranch`: generated output for `postToken` has `clientAuth: true` preserved, the `URLSearchParams` branch, the form header **exactly `"application/x-www-form-urlencoded"` — no charset (F9)**, `undefined`-skip (F4), and Basic-strip-before-serialize ordering (assert `withClientAuthentication` call precedes serialization in the runtime const string) | unit |
| **AC2(c) — Python emission** | `TestGeneratePy_FormBranch` + golden `_form_encode` cases: `{"approve": True}` -> `approve=true` (F3); `{"resource": ["a","b"]}` -> `resource=a&resource=b` (doseq repeated keys); `{"claims": {...}}` -> single `claims=<json>` key (F5); `{"code": None}` -> key dropped; **`{"params": {}}` -> client-side guard throws, no wire attempt (D4); `{"params": None}` -> key dropped (JSON-wire null-equivalent); `{"resource": [""]}` -> `resource=` (F10)**; generated `post_mfa_complete` has `form=True` + the C1 `params` guard; generated `post_token` keeps `client_id`/`client_secret` in the body (C5 — Python has no Basic path) and adds `form=True`; generated `post_token` unchanged signature | unit (behavioral goldens executed, no `t.Skip` — G3) |
| **AC2(d) — PAR serialization** | `TestGeneratePARFormShape`: generated `postPAR` emits repeated keys for `resource` and a single JSON-string key for `claims`/`authorization_details` (assert on the runtime serializer output for representative bodies) | unit |
| **AC3 — contract/E2E** | New `test/credential_sdk_form_test.go` (package ssotest, in-process httptest as in `test/e2e_test.go`): (1) form-encoded `POST /token` with `client_credentials` + registered confidential client, Basic header + exactly the generated form body -> 200; (2) form-encoded `POST /par` with repeated `resource` keys -> 201; (2b) **`TestSdkForm_PARClaimsThreaded` — claims-positive form-PAR -> login -> claims present in the issued token; deliberately red until the sibling F1 decoder lands, never skipped (D6)**; (3) post-sibling control: JSON-variant `POST /token` -> 400 `invalid_request` (arm lands with the sibling binder; do **not** assert `invalid_request` on `/auth/mfa` — C7). TS-level arm: `docs/sdks/typescript/client.test.mjs` "confidential token calls" updated from `JSON.parse(seen.body)` to `seen.headers["Content-Type"] === "application/x-www-form-urlencoded"` (exact string, no charset — F9) + `URLSearchParams`-decoded body equality | `go test ./test/ -run TestE2E -v`; `bun test` |
| **AC4 — artifacts/drift** | Regenerated artifacts committed in the same change; `make ci` green; a seeded stale copy (JSON emission reintroduced in `client.ts`/`client.py`) fails the sibling T-9 gate once it lands — `sdk-drift check` (`checks/sdk_drift.py`, direction `add-a-regeneration-drift-and-deploy-tree-sweep`): its regeneration leg byte-compares regenerated `client.ts`/`client.py` against committed, which is exactly this stale-copy scenario. **No new gate added here and no drift test in `emit_test.go`** — T-9 is the single implementation, so the two workstreams do not double-implement the same gate. Sequencing: T-9 is design-gated but not yet in the tree (no `sdk-drift` target at HEAD), so until it lands, byte-identity is enforced by AC1's regeneration-diff step plus the single-commit rule. Scope note: T-9 deliberately excludes `dist/` (design non-goal P2), so `dist/*.js` staleness is covered by the commit rule, not by the drift gate | `make ci` (once T-9 is wired into it); `bunx tsc -p tsconfig.json` byte-diff |

## 8. Files

### Create

```text
docs/architect-analysis/cmd-gensdk-b4-4-credential-form-design.md  — this design
test/credential_sdk_form_test.go  — AC3 contract/E2E (package ssotest)
```

### Modify

```text
cmd/gensdk/operations.go      — Operation.ContentType + FormBlockedFields; contentSchema
                                preference flip (line 193) + record choice in extractOne
cmd/gensdk/gen_ts_runtime.go  — requestOptions.form; formSerialize; form branch in request()
cmd/gensdk/gen_py.go          — _request form param; _form_encode helper; pyEmitMethod
                                form=True + params guard
cmd/gensdk/gen_ts.go          — tsEmitRequestOpts form:true; postMFAComplete params guard
cmd/gensdk/emit_test.go       — AC2 tests (extend existing file; no new file — C3)
docs/sdks/typescript/client.ts      — regenerated
docs/sdks/python/client.py          — regenerated
docs/sdks/typescript/dist/*.js,d.ts — regenerated via bunx tsc -p tsconfig.json (committed artifacts)
docs/sdks/typescript/client.test.mjs — line 53 JSON.parse assertion -> form assertions
docs/sdks/typescript/README.md       — lines 71-74 simplification replaced
docs/sdks/python/README.md           — form note
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go  — server binder; strict enforcement is the sibling change
docs/openapi.yaml                  — request bodies already declare both variants; the sibling
                                     R5.4 drops the JSON variants in its own change
ops/build/sdk-surface.json         — surface registry unchanged
cmd/gensdk/schema.go, schema_primitive.go, main.go — untouched
interfaces/sso/*, protocols/oauth/handle_*.go      — server handlers untouched
```
