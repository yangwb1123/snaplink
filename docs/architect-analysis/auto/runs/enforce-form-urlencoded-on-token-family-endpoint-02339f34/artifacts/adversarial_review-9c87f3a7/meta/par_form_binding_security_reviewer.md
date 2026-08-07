All evidence gathered. Here is the review.

---

# Review: form-mode binding for PAR `authorization_details`/`claims` (G1/Gap A resolution)

## 1. Ruling on (a) vs (b): **(a), with one critical refinement — "RawMessage-from-JSON-string" means store-verbatim, not parse-at-bind**

Decision (a) is the only contract-consistent choice; decision (b) is disqualified on four independent grounds:

1. **The openapi already promises (a).** `PARRequest.authorization_details` (openapi.yaml:15042-15044) says "form-encoded body delivers a single JSON-string element the server parses", and the `/auth/login` query params (:448-453) document both `authorization_details` and `claims` as `type: string` "JSON-encoded RFC 9396 array" / "JSON-encoded OIDC claims object". (b) would require *deleting* documented behavior — the exact doc/code drift class AGENTS.md §1 forbids, and the mirror image of the C4 fix this change is making.
2. **RFC 9396 §3.1 and OIDC Core §5.5 mandate the JSON-string encoding** for form/query transport. Form-only `/par` that drops or rejects these parameters stops being RFC 9396 / OIDC-compliant on the very endpoints this change aligns with the RFCs.
3. **The login GET path already implements the convention**: `rawQueryJSON(q.Get("authorization_details"))` (server_login_resolve.go:35-36, 44-49) stores the URL-decoded string verbatim as `json.RawMessage` with **no parse at bind**, and `validateLoginAuthorizationParams` (server_login_gates.go:328-338) owns content validation. PAR form mode must mirror this or PAR→login merge semantics (consumePARRequest, server_login_resolve.go:167-174) diverge by transport.
4. **Both SDKs already expose object-typed fields** (`authorization_details?: AuthorizationDetail[]`, `claims?: Record<string, unknown>` — client.ts:1143-1145; client.py:927-928). (b) silently breaks those public types on the only body path after enforcement, and M4's `parThenLogin` migration would trip it immediately (see §3).

**The refinement matters more than the ruling.** "(a) server-side RawMessage-from-JSON-string binding" must be implemented as **store, don't parse** — one `RawMessage` case in `setFormField` that copies `raw[0]` bytes verbatim (`f.SetBytes`, with a copy, mirroring `rawQueryJSON` + `CloneRawJSON` discipline) and lets the existing gates validate. Do **not** run `json.Valid`/`Unmarshal` at bind time. Evidence for this:

- The JSON-mode path today *never* parses `authorization_details`/`claims` content at bind. `{"authorization_details": "notjson"}` binds (RawMessage = the string token) and the gate rejects it as `invalid_authorization_details`. Parsing at bind would create a new pre-auth `400 invalid_request` failure class with **no JSON-mode analog** — the exact transport-dependent behavior the oracle-safety requirement forbids.
- The RFC 9396 gate at handle_par.go:222-227 (`ValidateAuthorizationDetails`) produces `invalid_authorization_details` — a code documented in the openapi 400 description (:1495-1497), error-codes.md:305, and RFC 9396 §6 ("not a JSON array" is the RFC's own example of what that code covers; a non-JSON string is certainly not a JSON array). Bind-time parsing would violate this taxonomy.
- It breaks the existing pin `TestPAR_RejectsMalformedAuthorizationDetailsAtPushTime` (test/handle_par_test.go:414-425), which asserts a bare object → `invalid_authorization_details` — a test that survives the M4 form migration only under store-don't-parse.
- `rawQueryJSON` is the in-tree precedent for exactly this split: transport layer stores bytes, validation gates own content.

## 2. Oracle-safety analysis — where each code comes from

The "identical 400 invalid_request" requirement resolves cleanly into two disjoint classes, both oracle-safe:

| Cause | Code | Why identical / safe |
|---|---|---|
| Content-Type not form (JSON, missing CT, `text/plain`, `multipart/form-data`) | `400 invalid_request` (bind) | `BindFormParams` returns one uninformative error; every caller maps to `core.ErrorBody(core.ErrInvalidRequest)` — byte-identical bodies, no description |
| `r.ParseForm()` failure (malformed percent-encoding, e.g. `%zz`) | `400 invalid_request` (bind) | Same mapping; client-observable only as the universal malformed-request 400, identical across all four endpoints and all four causes |
| Form body > net/http `maxFormSize` (10 MiB hard cap inside `ParseForm`) | `400 invalid_request` (bind) | Same mapping; note `WithBodyLimit`/`WithBodyLimitForPath` (options_httpstack.go:47-83) rejects earlier with 413 *before* the handler — documented, not an oracle |
| `authorization_details` content: non-JSON string, non-array, missing `type`, disallowed type, RARLimits shape violation | `400 invalid_authorization_details` (gate, post-auth) | RFC 9396 §6 taxonomy; post-auth only (client authenticated), client owns its payload; identical to today's JSON path for the same logical payload |
| `claims` content: not a JSON object / bad member types | PAR: **201**; `/auth/login`: `400 invalid_request` | Pre-existing asymmetry — `validatePARRequestParams` has no claims gate (only `authorization_details`); claims are stored and validated at login (server_login_gates.go:328-331). Form mode must preserve this exactly, not "fix" it in this change |

The decisive property: **the error code depends only on the logical payload, never on the transport mode.** Under store-don't-parse, every payload that today yields a given code via JSON yields the same code via form, and vice versa. That is a stronger and more testable oracle guarantee than "all malformed JSON → invalid_request", which would be wrong on the RFC 9396 taxonomy and break the existing openapi/error-codes contract. `ErrInvalidAuthorizationDetails`'s `error_description` reveals only payload-class (syntax vs. shape vs. allowlist) — to a client that already knows its own payload. Not an oracle.

One ordering note: bind failure is the *only* pre-auth 400 besides `ErrMissingClientID`/`ErrInvalidClient` (401s) and the 501/500 short-circuits (handle_par.go:55-63, before bind). Store-don't-parse preserves the current order byte-for-byte: 501 → bind → Basic override → client auth → gate → store. Parse-at-bind would interject a new pre-auth 400 and shift the client-auth boundary.

## 3. Urlencoding fidelity (+, %, repeated keys)

ParseForm is the decoder on the server; both planned emitters encode compatibly, but the RawMessage case must be careful:

- **`+`**: `ParseForm` decodes `+` → space. A literal `+` inside the JSON (e.g. `"iban": "DE+44"`) **must** arrive as `%2B`. TS `URLSearchParams` and Python `urlencode`/`quote_plus` both emit `%2B` — correct. The regression risk is a future emitter that interpolates raw strings; pin it with a test.
- **Space inside JSON** (between tokens): TS encodes space → `+`; `ParseForm` decodes back to space. Round-trips.
- **`%`**: `%25` round-trips. **Multibyte UTF-8**: percent-encoded per byte; `ParseForm` decodes. Fine.
- **Repeated keys** (`authorization_details=a&authorization_details=b`): RawMessage must take `raw[0]` (first-wins), exactly like strings today (`setFormField` case `reflect.String`). Do **not** route RawMessage through `formStringSlice` — space/comma splitting would corrupt JSON. First-wins also means a later duplicate can never override an earlier one (relevant since PAR commits request authority).
- **Empty value** (`authorization_details=`): `raw = [""]` → `RawMessage("")` → `len == 0` → treated as absent by `ValidateAuthorizationDetails` (rar.go:110-112) — same as JSON `authorization_details: null`-ish behavior. Consistent.
- **JSON-mode bytes vs form-mode bytes differ cosmetically** (quotes around string-token RawMessages in JSON mode, whitespace). Harmless: `ValidateAuthorizationDetails`/`ValidateClaimsParameter` parse to semantics; `CloneRawJSON` preserves whatever bytes; claims projection re-parses. No wire contract depends on byte identity.

## 4. Size/parse limits — what the form path inherits

- **Hard parse cap**: `r.ParseForm()` internally caps the body at 10 MiB (`maxFormSize`) → bind error → `400 invalid_request`. Independent of `WithBodyLimit` config; applies to all four endpoints identically.
- **Configured body cap**: `bodyLimitMiddleware` (server_routes.go:455-456) → 413 pre-handler; `/par` already documented to need `WithBodyLimitForPath` for JAR-size payloads.
- **RARLimits.MaxBytes** (rar.go:50-53) applies to the **decoded** JSON bytes (gate-level, post-bind) — the form mode's percent-encoding overhead is counted outside it but inside the body caps. Correct composition.
- **Claims has no shape/size cap** beyond the body limits (pre-existing; `CheckAuthParamLengths` covers only state/redirect_uri/scope/nonce/resource, paramlimits.go:76-96). Form mode neither worsens nor fixes this — do not add a claims cap in this change (out of scope), but note it in the design so the PAR-store entry-size exposure (MemoryPARStore has `MaxEntries` but no per-entry cap) is a conscious, documented residual.

## 5. Ordering versus the RFC 9396 gate and the PAR store

Store-don't-parse makes ordering a non-issue: `setFormField`'s RawMessage case runs inside the existing bind at handle_par.go:66, the gate at :222-227 is untouched, `issuePARRequest`'s `CloneRawJSON` (:241, :251) stores exactly the bound bytes, and the login merge (server_login_resolve.go:167-174) and login gate (server_login_gates.go:328-338) re-validate. The two ordering properties to pin with tests:

- **Gate-after-auth**: malformed `authorization_details` + bad secret → `401 invalid_client`, never `invalid_authorization_details` (gate unreachable pre-auth). This is today's behavior; form mode must not change it.
- **501 short-circuit precedes bind**: PAR store unwired → 501 even for malformed form bodies (handle_par.go:56-59). The F5 flakiness warning already covers the test side.

## 6. Both SDK emitters' JSON.stringify behavior — concrete requirements

The emitters need a **per-field, spec-derived stringify policy**, not a runtime heuristic — because `resource: string[]` (repeated keys) and `authorization_details: AuthorizationDetail[]` (stringify) are both JS arrays, and `[]` is ambiguous to a type heuristic (see below). The generator already resolves schemas (`contentSchema`/`extractRequestBody`, operations.go); a field whose schema (or item schema) is `type: object` must be JSON-encoded in form mode. This yields exactly `{authorization_details, claims}` on `postPAR` today and is future-proof — same principle as the SDK reviewer's Gap C objection to the hardcoded four-op predicate.

**TS runtime** (slot at gen_ts_runtime.go:154, after `withClientAuthentication`):
- Form path: `headers["Content-Type"] = "application/x-www-form-urlencoded"`; encode from `authenticatedBody` (secret already stripped to Basic — F6 ordering holds).
- Per-field: nullish → skip (G3); scalar → `String(v)`; `string[]` → `append` repeated keys; object / array-of-object fields → `JSON.stringify(v)` **including empty arrays** (`[]` → `"[]"`, not skipped) — because JSON mode today stores `[]` and downstream `len(stored.AuthorizationDetails) > 0` distinguishes it from absent; skipping would silently change issued-token claims for `authorization_details: []` callers.
- `URLSearchParams` gives correct `+`→`%2B`, `%`→`%25`, space→`+` fidelity.

**Python runtime** (`_request`, gen_py.go:76-110):
- `form=True` → pre-process the body dict: `json.dumps` object-valued fields per the same spec-derived key list, drop `None` (G3, matching the query filter precedent at client.py:1441-1443), then `urllib.parse.urlencode(body, doseq=True)` — repeated keys for `resource`. Without the pre-stringify, `urlencode(doseq=True)` mangles dicts (iterates keys: `claims=id_token`) and list-of-dicts (`str(dict)` per element) — the live-verified G1 failure mode.
- No Basic stripping exists in the Python client (verified: `_request` has only `auth=True` bearer); body credentials continue to work since the server's Basic-wins rule is only engaged when Basic is present. Same exposure as today's JSON mode — not a regression, worth one sentence in the design.

## 7. Concrete regression-test requirements

**Server unit — `protocols/oauth/`** (fold into design M2):
1. `TestFormBindRawMessage` (bind_extra_test.go): form `authorization_details=%5B%7B%22type%22%3A%22a%22%7D%5D&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%7D%7D` → bound `RawMessage` equals the **decoded** bytes; fidelity matrix: literal `+` via `%2B`, `%` via `%25`, space via `+` and `%20`; repeated key → first wins; empty value → nil.
2. `TestFormBindRawMessageNoContentParse` (the taxonomy pin): `authorization_details=notjson` must reach the gate, i.e. bound as bytes without bind error.

**PAR handler — `protocols/oauth/handle_par_test.go`**:
3. Form-mode RAR matrix: valid array → 201 and `ps.Consume` returns byte-identical `AuthorizationDetails`/`Claims` (store round-trip); bare object → `invalid_authorization_details`; non-JSON string → `invalid_authorization_details`; disallowed type → `invalid_authorization_details`; `RARLimits.MaxBytes` enforced on **decoded** bytes.
4. Malformed percent-encoding (`authorization_details=%zz`) → `400 invalid_request`, body byte-identical to the Content-Type-rejection body; no-store headers present (extends F5/M3a).
5. Gate-after-auth ordering: bad secret + malformed RAR → `401 invalid_client`.
6. Transport-parity table: same logical payload via JSON (pre-change) and form (post-change) → same status + same error code.

**Integration — `test/handle_par_test.go`** (M4): migrate `parThenLogin` (:337-377) to form with the JSON-string convention; the four RAR tests (:394, :403, :420, :435) must pass unchanged — they are the end-to-end pins for the taxonomy. Add one fidelity e2e: a RAR field containing `+` and `%` survives verbatim into the access token's `authorization_details` claim. Add a claims e2e: valid form claims → 201 at PAR, merged, projected at login; invalid claims → 201 at PAR then 400 `invalid_request` at login (pins the documented asymmetry).

**Generator — `cmd/gensdk/emit_test.go`** (M5 + new):
7. TS: `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` expectation at :231 flips to `{ body, clientAuth: true, form: true }`; `usesFormBody`-style table: four ops true, `postLogin`/`postRevokeAll`/admin false.
8. **New `TestGeneratePython*` emission test (G4 gap)**: `post_par` → `_request("POST", "/par", body=body, form=True)`; the other three form ops `form=True`; `post_login`/`put_registration`/device ops carry no `form`.
9. Runtime-level unit tests for the encoders (in emit tests or committed-client review): TS `encodeForm` stringifies `authorization_details`/`claims`, repeats `resource` keys, skips nullish, `[]` → `"[]"`, `+`→`%2B`; Python form-prep `json.dumps` dict fields, drops `None`, `doseq` repeats.

**Openapi** (M7): `PARRequest.claims` needs the same one-line description as `authorization_details` ("form-encoded body delivers a JSON string"); nothing else changes — the schemas are already correct for (a).

**Scope notes**: `ops/deploy/openresty/fullstack/static/` is untracked external-pipeline output (consumer auditor Gap 2) and `docs/examples/quickstart/main.go:164` needs the M4b migration (consumer auditor Gap 1) — both stand independent of this ruling. The stale static `client.py`/`client.ts` carry the G1 JSON-only `postPAR`; they refresh at the next external generation, but the G1 silent-drop bug lives in the **server binder**, so static-tree staleness is not a release blocker for this item.

---

**VERDICT**: Adopt decision (a) — form-mode `authorization_details`/`claims` as JSON-string values — implemented as **store-verbatim binding** (`setFormField` RawMessage case copying `raw[0]`, mirroring `rawQueryJSON`), with **no JSON parse at bind time**: bind failures (Content-Type, `ParseForm` percent errors, 10 MiB form cap) yield byte-identical `400 invalid_request`; content failures keep the documented post-auth taxonomy (`invalid_authorization_details` per RFC 9396 §6 for RAR at handle_par.go:222-227, `invalid_request` at login for claims), making error codes transport-independent — the only defensible reading of the oracle-safety requirement. Decision (b) is disqualified because the openapi already documents (a), RFC 9396 §3.1 / OIDC §5.5 mandate it, and the login query path already implements it. Ship the nine server-side and three generator-side regression tests in §7 (in M2/M4/M5), keep the 501→bind→auth→gate→store ordering untouched, and treat the claims-size cap absence and the PAR-time claims-validation asymmetry as documented pre-existing residuals, not this change's problem.
