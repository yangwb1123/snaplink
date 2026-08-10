# Design: Form-urlencoded token-family emission in the generated TS/Python SDKs (cmd/gensdk slice of B4-4)

Companion to `docs/architect-analysis/cmd-gensdk-tokenfamily-form-emission-requirements.md`.
This document treats that requirements spec (and its citations) as untrusted
evidence, records what was independently re-verified against the tree, and
turns REQ-1..REQ-6 into a concrete, ordered design with API changes,
compatibility constraints, failure modes, migration steps, and testable
acceptance mapping. Scope is strictly `cmd/gensdk` plus the two committed
generated clients; server-side work (the RFC 9396 form-binding fix and the
enforcement flip, T-9(d)/(e)/(g)) is dependency-gated on the B4-4 server
module and sequenced so it cannot regress the shipped clients.

Revision note: this revision folds in the security review (F-A blocking, F-B
minor), the generator-maintainability review (citation corrections, T-9(a)
coverage gaps, `client.test.mjs` breakage), and the wire-compatibility review
(A2 `audience` correction, null/None divergence). Every corrected claim is
re-verified against the tree below.

## 1. Evidence verification verdict

All 15 evidence rows re-checked against the tree: **confirmed**. Both
corrections (C1, C2) confirmed. Four additional observations (A1-A4) surfaced
during verification; A2 is **corrected** below (reviewer-discovered). Two new
findings (F-A blocking, F-B minor) from the security review are folded in.

| Row | Claim | Verdict |
|---|---|---|
| E1 | `gen_ts_runtime.go` `requestOptions` (:35-41) has no `form`; any body → `Content-Type: application/json` + `JSON.stringify` (:157-160) | Confirmed. `authenticatedBody` computed at :154 (clientAuth stripping first); JSON branch at :157-160. |
| E2 | `gen_py.go` `_request` template (:85-94) has no `form` param; JSON-only body path (:102-105) | Confirmed. Query filter at :97-99 (`filtered = {k: v ... if v is not None}` — the None-skip precedent for F-B). |
| E3 | `tsUsesClientAuth` four-op predicate at gen_ts.go:99-109 | Confirmed, **citation corrected to :99-106** (function spans :99-106; case list at :101-104). |
| E4 | `emit_test.go:159` `TestTSClientAuthenticationOperations` | Confirmed. Table: 4 ops true, `postLogin`/`postLogout` false. |
| E5 | `emit_test.go:207` `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`; `{ body, clientAuth: true });` at :231 | Confirmed (fixture hand-built at :214-232). Also asserts `delete withoutCredentials.client_secret;` — usable for the REQ-4.2 structural pin. |
| E6 | `oauthwire/bind.go:28` `BindParams` form path body-only (`r.PostForm`); JSON default; `BindFormParams` 0 matches | Confirmed. Comment at :15-26 documents "JSON ... non-standard convenience for SPAs" and "Empty body + no Content-Type is treated as JSON" — the contract T-9(d) inverts. |
| E7/C1 | Only `postToken` (openapi.yaml:1100-1102) is form-only; introspect (:1267/1280), revoke (:1343/1347), PAR (:1473/1477) declare form+JSON | Confirmed at exact lines. |
| E8 | openapi.yaml:1063-1065 stale `oauth_bind.go` text; file absent | Confirmed (`find . -name oauth_bind.go` → 0). Wire review nuance: the "`resource` / `audience` lists" clause is partly accurate (`audience` exists in `TokenRequest`, :14735); only the "Form + JSON accepted via `oauth_bind.go`" claim is wrong post-flip — REQ-6's rewrite range is complete. |
| E9 | Approved spec REQ-2.1-2.6 (cmd-gensdk-tokenfamily-form-spec.md:82-114) unimplemented | Confirmed. `Operation` (operations.go:58-70) has `HasBody`, no `FormBody`; `contentSchema` schema-only. |
| E10 | 0 `x-www-form-urlencoded` in committed clients; four methods at client.ts:2878/2903/2908/2913, client.py:2260/2280/2284/2288 | Confirmed (`grep -c` → 0 in both files; exact method lines re-verified). Python four methods emit `body=body)` with no `auth=True`; TS emits `{ body, clientAuth: true });`. |
| E11 | `sdk_surface.py:65` `validate_registry`; `generate` at :146 = `go run ./cmd/gensdk --lang=all`; `check` validates registry vs openapi+capabilities | Confirmed. **Blind spot confirmed**: the checker validates schema header, duplicate ids, registry ⊆ openapi membership, capability refs, and language-file existence — never media types, never output diffing; membership is one-directional (the four ops are not required to be present). The blind spot is inside CI: `make ci` (Makefile:265) includes `sdk-surface-check` (target at :125-126). |
| E12 | `test/oauth_bind_test.go:272` `TestFormEncoded_JSONStillWorks` asserts JSON → 200 | Confirmed. |
| E13 | TS `withClientAuthentication` at gen_ts_runtime.go:183 strips before encoding branch; Python `_request` has no Basic path | Confirmed. Strip-then-encode is structural: `authenticatedBody` (:154) precedes the body branch (:157-160). |
| E14 | No-store before binding at all four sites | Confirmed: `tokenNoStoreHeaders` server_token.go:21-22 before `bindOAuthParams`; `middleware.TokenNoStoreHeaders` handle_introspect.go:112, handle_revoke.go:68, handle_par.go:55. |
| E15 | Four ops + device ops in sdk-surface.json (13 groups, 316 ops) | Confirmed. `postDeviceCode`/`postDeviceVerify`/`postMFAComplete` present. |
| C2 | `withClientAuthentication` at :183, not :166-182 | Confirmed. |

### Additional observations (A1-A4, A2 corrected)

- **A1 — second no-store site in revoke:** `handle_revoke.go:182` also calls
  `middleware.TokenNoStoreHeaders` (the `postRevokeAll` handler). E14's four
  sites are the bind-path sites; the mechanism claim is unaffected.
- **A2 — request-schema shapes (corrected).** `TokenRequest` (openapi :14602)
  is strings + **two** string arrays: `resource` and `audience` (RFC 8693,
  :14735, merged with `resource` into the issued `aud`); `IntrospectRequest`
  is strings + `tokens` array; `RevokeRequest` is strings only; `PARRequest`
  (:15007) is strings + `resource` string array + **`authorization_details`
  array of objects** (:15044-15047, items `$ref: AuthorizationDetail`,
  schema at :14119) + **`claims` object** (:15073-15075, OIDC Core §5.5).
  Two implications, both folded into §3.3/§3.4:
  1. The wire-compat reviewer's three-way harness (TS encoder / Python
     `urlencode(doseq=True)` / Go `url.ParseQuery`) confirmed repeated-key
     parity for all four flat string-array fields (`resource`, `audience`,
     `tokens`, `authorization_details`-as-strings) and the one real
     byte-level difference (percent-encode set: TS leaves `*` raw, Python
     leaves `~` raw; Go decodes both identically — byte-identity is not
     claimed, decode-identity is).
  2. **`authorization_details` and `claims` are NOT flat** — see F-A: a
     naive repeated-key/`String()` encode would emit `[object Object]`
     (TS) / Python reprs, and the server's form binder silently drops them.
     Both runtimes special-case objects and object-arrays as **single
     JSON-string elements** (RFC 9396 §7.1.1), matching the documented
     openapi contract at :15049-15051 ("form-encoded body delivers a single
     JSON-string element the server parses").
- **A3 — Python emit shape:** the four Python methods currently emit
  `self._request("POST", "/token", body=body)` (no `auth=True`). After the
  change they become `..., body=body, form=True)` — the `form=True` part is
  appended after the existing `auth=True` part in `pyEmitMethod`
  (gen_py.go:168-171), so part order is deterministic and assertable.
- **A4 — `URLSearchParams` is already a runtime dependency** of the TS client
  (query builder, gen_ts_runtime.go:143-151). Reusing it for form bodies adds
  no new runtime requirement (browser/Node both support it).

### Reviewer findings folded in (all re-verified)

- **F-A (BLOCKING, security review) — PAR RAR/claims silently dropped by the
  form path.** `parRequestForm` (protocols/oauth/handle_par.go:91-112) binds
  `AuthorizationDetails json.RawMessage` (:100) and `Claims json.RawMessage`
  (:105) via `BindParams`. The form path's `setFormField` (bind.go:111-137)
  has **no `json.RawMessage` case** — its Slice case handles only
  `Elem().Kind() == String`, and `json.RawMessage` is `[]byte` (Uint8), so
  the fields bind `nil`. `ValidateAuthorizationDetails(nil, ...)`
  (handle_par.go:222) passes (empty = no RAR), so a form-encoded PAR with
  `authorization_details`/`claims` **silently issues a request_uri without
  RAR/claims** — a silent wrong-grant regression vs today's working JSON
  delivery. The openapi contract at :15049-15051 already documents the
  form-encoded single-JSON-string-element semantics (drift, unimplemented
  server-side). Fixes: (a) both runtimes special-case objects/object-arrays
  as one JSON-string element (§3.3/§3.4); (b) add a `json.RawMessage` case
  to `setFormField` (server-side, §6 step 8a); (c) form-PAR RAR/claims
  server test (§6 step 8b, T-9(g)); (d) behavioral PAR pin in
  `client.test.mjs` (§3.7).
- **F-B (minor, security review) — Python `None` literals.** TS skips
  `undefined`/`null` scalars; Python `urlencode` renders `None` as the
  literal string `"None"` (verified). Fails closed (no leak) but silently
  changes `null` semantics vs the JSON branch (`json.dumps` → `null`).
  **Resolution: mirror the TS skip** — the Python form branch filters `None`
  values, matching the query path's existing `if v is not None` filter
  (gen_py.go:97-99). Residual, documented, out-of-contract divergence:
  `[None]` **array items** still render as `"None"` (Python) vs `"null"`
  (TS); all four schemas are strings + string-arrays, so this is unreachable
  in contract (§3.4).
- **Citation corrections (generator-maintainability review):**
  `extractOne` is at operations.go:**116-138** (struct literal :123-130,
  `RequiresAuth` :124-127), not :171-190; `pyEmitMethod` is at gen_py.go:
  **151-174** (`auth=True` part :168-171), not :163-178; `tsUsesClientAuth`
  is at gen_ts.go:**99-106**, not :99-109. The substantive insertion-point
  instructions were unaffected.
- **`client.test.mjs` breaks post-flip (generator-maintainability review).**
  Test #2 (:40-54) asserts `assert.deepEqual(JSON.parse(seen.body), { grant_type: "client_credentials" })` at :53. After the flip, `seen.body` is
  `"grant_type=client_credentials"` → `JSON.parse` throws. The file is
  hand-written (not generated) and runs only via local `bun test`/`npm test`
  — verified not wired into `make ci` or workflows — but it is the only
  behavioral test of the generated runtime and the strongest available
  regression net for F1/F3/F-A. Update required (§3.7), plus new F1/F3/F-A
  behavioral pins there.
- **T-9(a) coverage gaps (generator-maintainability review):** nothing
  pinned the *encode input inside the form branch* (a buggy
  `Object.entries(opts.body)` passes the old assertions) and nothing pinned
  the F3 skip predicate (an unconditional `params.append(k, String(v))`
  passes). **T-9(d)/(e) catch none of the client-side failure modes** (they
  drive the server directly). Strengthened in §3.6 and re-derived in §7.
- **T-9(e) wording correction:** the no-store assertions on rejections "do
  not exist yet" in `test/oauth_bind_test.go` (zero `Cache-Control`/
  `no-store` strings there today). T-9(e) describes **new** assertions added
  in the B4-4 phase; the header mechanism at the handler sites is verified
  (E14/A1).
- **A2 `audience` correction (wire-compat review):** the old A2 line listed
  `TokenRequest` as "strings + `resource` array" — it also carries the
  `audience` string-array (RFC 8693). Corrected above; the runtime loop is
  generic over all array values, and the corpus case `token-exchange-audience`
  passes.
- **Budget/citadel check (generator-maintainability review):** all insertion
  points are inside `cmd/gensdk` (composition layer) with headroom (gen_ts.go
  306→~309, gen_ts_runtime.go 197→~218, gen_py.go 361→~370, operations.go
  237→~252; `tsEmitRequestOpts` 20 ln/cyclo 6→23/7, `pyEmitMethod`
  24/6→27/7, new `usesFormBody` ~8 ln/cyclo 3, `extractOne` 24/3 — all within
  50 ln/cyclo 15). The TS/Python runtime edits land inside Go const strings,
  invisible to the Go gates. `interfaces/sso` 60-file ceiling untouched
  (zero files there). No new packages, imports, or `layerName()` changes.
  Pre-existing unrelated gate failures exist today (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`
  539>500 lines; docs fanout 18>16; root subdir count 24>21) — step 7's gate
  run inherits them; reported separately per AGENTS.md §5.

## 2. Design overview

The generator's `Operation` model gains a `FormBody bool`, populated at
extraction time by a shared four-op predicate `usesFormBody`. Both emitters
read the flag and emit a per-op form marker (`form: true` in the TS
request-options literal, `form=True` in the Python `_request(...)` call).
Both runtime templates gain a form-encoding branch:

- TS: `URLSearchParams` encoding of the **Basic-stripped** body
  (`authenticatedBody`), `Content-Type: application/x-www-form-urlencoded`.
  String arrays → repeated keys; **objects and object-arrays → one
  JSON-string element** (RFC 9396 §7.1.1 — this is the `authorization_details`/
  `claims` special-case, F-A); `undefined`/`null` scalars skipped (F3).
- Python: `urllib.parse.urlencode(form_data, doseq=True)` (repeated keys via
  `doseq=True`; `None` scalars filtered to mirror the TS skip, F-B; objects
  and object-arrays JSON-stringified, F-A), same Content-Type.

The JSON branch is preserved byte-for-byte for the other 312 surface ops.
Committed clients are regenerated with `python cli.py sdk-surface generate`.

Data flow:

```text
docs/openapi.yaml ──Extract──▶ Operation{ID, HasBody, FormBody, ...}
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
   gen_ts.go tsEmitRequestOpts  gen_py.go pyEmitMethod  emit_test.go
   "form: true" part            ", form=True" part      predicate + output tests
              │                      │
              ▼                      ▼
   gen_ts_runtime.go request()  pyClientHeader _request()
   URLSearchParams(form branch) urlencode(doseq=True)
              │                      │
              ▼                      ▼
   docs/sdks/typescript/client.ts  docs/sdks/python/client.py   (committed)
              │                      │
              └──────────┬───────────┘
                         ▼
   docs/sdks/typescript/client.test.mjs  (hand-written behavioral harness,
                                          updated + extended: F1/F3/F-A pins)

   Server-side (dependency-gated, B4-4 module): setFormField json.RawMessage
   case (bind.go:111-137) + form-PAR RAR/claims test (§6 steps 8a-8b), then
   the enforcement flip (§6 steps 8c-8f).
```

## 3. API changes

All changes are internal to `cmd/gensdk` (package `main`) plus the two
committed generated clients and the hand-written `client.test.mjs`. No public
Go API, no SDK consumer API, no server API changes in this module.

### 3.1 Model: `Operation.FormBody` + `usesFormBody` (`operations.go`)

- Add `FormBody bool` to `Operation` (operations.go:58-70), after the
  body-related cluster (`HasBody`/`BodyRequired`/`BodyType`).
- Add the shared predicate next to the `Operation` struct (model file — both
  emitters and the tests already import it; `tsUsesClientAuth` stays in
  gen_ts.go as the TS-only precedent):

```go
// usesFormBody marks the four RFC-mandated form-urlencoded OAuth credential
// endpoints. Hardcoded deliberately: the model is content-type-blind
// (contentSchema is schema-only), and spec-driven derivation would sweep in
// postDeviceCode/postDeviceVerify/postMFAComplete, whose handlers still
// accept JSON.
func usesFormBody(operationID string) bool {
	switch operationID {
	case "postToken", "postIntrospect", "postRevoke", "postPAR":
		return true
	default:
		return false
	}
}
```

- Populate at extraction: in `extractOne` (operations.go:116-138), after
  `op.RequiresAuth` is set in the struct literal (:124-127, literal :123-130),
  add `FormBody: usesFormBody(id)`.
  Consequence: emit tests that build `Operation` literals by hand (e.g.
  `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`, fixture at
  emit_test.go:214-232) must set `FormBody: true` on the `postToken`
  fixture — the flag is not re-derived at emission time (F5).

### 3.2 TS emitter (`gen_ts.go`)

In `tsEmitRequestOpts` (gen_ts.go:68-88), after the existing `clientAuth: true`
part (so the emitted literal is `{ body, clientAuth: true, form: true }`):

```go
if op.FormBody {
    parts = append(parts, "form: true")
}
```

### 3.3 TS runtime (`gen_ts_runtime.go`)

- `requestOptions` interface (:35-41): add `form?: boolean;` after
  `clientAuth?: boolean;`.
- `request()`: replace the body branch (:157-160) with a form/JSON split that
  encodes `authenticatedBody` (already Basic-stripped at :154 when
  `clientAuth` is set; `isRecord` at :42-44):

```ts
if (authenticatedBody !== undefined) {
  if (opts.form && isRecord(authenticatedBody)) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(authenticatedBody)) {
      if (v === undefined || v === null) continue;             // F3: no "undefined"/"null" literals
      if (Array.isArray(v)) {
        if (v.length > 0 && isRecord(v[0])) {
          params.append(k, JSON.stringify(v));                 // F-A: object array -> single JSON-string element (RFC 9396 §7.1.1)
        } else {
          for (const item of v) params.append(k, String(item)); // string array -> repeated keys
        }
      } else if (typeof v === "object") {
        params.append(k, JSON.stringify(v));                   // F-A: claims object -> single JSON-string element
      } else {
        params.append(k, String(v));
      }
    }
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    init.body = params.toString();
  } else {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(authenticatedBody);
  }
}
```

Design points, mapped to the four schemas (A2):

| Body value | Encoding | Ops |
|---|---|---|
| string / number / boolean scalar | single `k=v` | all four ops |
| string array (`resource`, `audience`, `tokens`) | repeated keys `k=a&k=b` (server `formIntoStruct` on `r.PostForm`, bind.go:42; `formStringSlice`) | postToken, postIntrospect, postPAR |
| object array (`authorization_details`) | **one** element `JSON.stringify(arr)` (RFC 9396 §7.1.1) | postPAR |
| object (`claims`) | **one** element `JSON.stringify(obj)` | postPAR |
| `undefined`/`null` scalar | skipped (JSON.stringify would drop them; sending the literal `"undefined"` would be a new bug) | all |
| empty array | zero appends → key absent (matches JSON-branch `[]`; `formIntoStruct` skips absent keys, bind.go:49-51) | all |
| `[null]` items | `k=null` (out of contract; documented) | — |

The `isRecord` guard keeps the JSON fallback for non-object bodies (F4).
Scalar values use `params.append` (a single append == the query builder's
`qs.set` output for one value).

### 3.4 Python runtime (`gen_py.go` `pyClientHeader`)

- `_request` signature (:85-94): add `form: bool = False` after `auth: bool =
  False`.
- Body path (:102-105):

```python
if body is not None:
    if form:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        form_data = {}
        for k, v in body.items():
            if v is None:
                continue  # F-B: mirror the TS undefined/null scalar skip
            if isinstance(v, dict) or (isinstance(v, list) and v and isinstance(v[0], dict)):
                form_data[k] = json.dumps(v)  # F-A: single JSON-string element (RFC 9396 §7.1.1)
            else:
                form_data[k] = v
        data = urllib.parse.urlencode(form_data, doseq=True).encode("utf-8")
    else:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
```

Design points:

- `doseq=True` is load-bearing: without it a list value is rendered as its
  Python repr (`%5B%27a%27%2C...`) instead of repeated keys (F2).
- `if v is None: continue` mirrors the TS skip (F-B): `None` scalars are
  dropped exactly like the query path's existing `filtered` filter
  (gen_py.go:97-99), preserving `null` semantics vs the JSON branch.
- `json.dumps(v)` for dicts and dict-arrays produces the single JSON-string
  element the server's (fixed) `setFormField` parses (F-A). String arrays
  stay lists so `doseq=True` emits repeated keys.
- Residual documented divergence (out of contract): `[None]` **array items**
  render as `"None"` (Python) vs `"null"` (TS); mixed arrays
  `["a", {...}]` render the object via repr in Python and `[object Object]`
  in TS. All four schemas are strings + string-arrays only (verified:
  TokenRequest 22 fields, IntrospectRequest 5, RevokeRequest 4, PARRequest
  18 — zero booleans, zero numbers), so this is unreachable in contract.

### 3.5 Python emitter (`gen_py.go` `pyEmitMethod`)

`pyEmitMethod` is at gen_py.go:151-174. After the `auth=True` part
(:168-171):

```go
if op.FormBody {
    b.WriteString(", form=True")
}
```

Emitted shape for the four ops: `self._request("POST", "/token", body=body,
form=True)`.

### 3.6 Tests (`emit_test.go`)

- **`TestTSFormBodyOperations`** (new, sibling of `TestTSClientAuthenticationOperations`):
  table over `usesFormBody` — `postToken`, `postIntrospect`, `postRevoke`,
  `postPAR` true; `postLogin`, `postLogout`, `postRevokeAll` false; one admin
  op (`listAccessPolicies`) and one SCIM op (`scimListGroups`) false
  (negative pins: F5, F7).
- **`TestPyEmitFormBodyOperations`** (new): build `Operation` fixtures for the
  four ops (`FormBody: true`) plus `postLogin`/`postLogout` (bodies, no flag)
  and `postRevokeAll` (no body); run `GeneratePy`; assert `body=body,
  form=True)` appears exactly in the four methods and nowhere else; assert
  `form=True` appears **exactly four times** in the whole output; assert the
  JSON branch string `json.dumps(body).encode("utf-8")` is still present.
- **`TestTSRuntimeFormEncoding`** (new): run the full TS generation and
  assert the emitted runtime contains, in the form branch region:
  - `if (opts.form && isRecord(authenticatedBody)) {` — branch condition (F1),
  - `Object.entries(authenticatedBody)` — **encode input inside the form
    branch** (F1: a buggy `Object.entries(opts.body)` fails this pin),
  - `if (v === undefined || v === null) continue;` — **skip predicate** (F3:
    an unconditional `params.append(k, String(v))` fails this pin),
  - `params.append(k, JSON.stringify(v));` — JSON-string special-case (F-A),
  - `headers["Content-Type"] = "application/x-www-form-urlencoded";`,
  - and the existing strip assertions (`delete withoutCredentials.client_secret;`)
    remain present (F1 structural).
- **`TestPyRuntimeFormEncoding`** (new): assert the emitted Python runtime
  contains:
  - `urllib.parse.urlencode(form_data, doseq=True)` — F2 (a missing
    `doseq=True` fails this pin),
  - `if v is None:` — F-B (an unfiltered `urlencode(body, doseq=True)` fails
    this pin),
  - `form_data[k] = json.dumps(v)` — F-A (a plain repeated-key encoder fails
    this pin),
  - `json.dumps(body).encode("utf-8")` still present (JSON branch untouched).
- **`TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`** (:207):
  add `FormBody: true` to the `postToken` fixture (:214-232); change the
  :231 assertion to `{ body, clientAuth: true, form: true });` — the
  exact-string assertion fails loudly if the fixture lacks the flag (F5).
- **Whole-output count:** in the TS full-generation test, assert `form: true`
  appears **exactly four times** in `client.ts` output (the four method
  literals; the runtime template's `form?: boolean;`/`opts.form` do not
  match). Together with the Python count, this pins the four-op boundary
  across the whole emitted file, closing the residual "predicate change
  affecting an op outside the fixed table" gap (F7).

### 3.7 `client.test.mjs` (hand-written behavioral harness — update + new pins)

`docs/sdks/typescript/client.test.mjs` (54 lines) is NOT generated and NOT
wired into `make ci`; it runs via `cd docs/sdks/typescript && bun test`
(or `npm test`). It is the only behavioral test of the generated runtime —
mandatory update (it breaks post-flip) and the strongest F1/F3/F-A regression
net.

1. **Required update — test #2 (:40-54).** The :53 assertion
   `assert.deepEqual(JSON.parse(seen.body), { grant_type: "client_credentials" })`
   throws after the flip (`seen.body` becomes `"grant_type=client_credentials"`).
   Replace with a form-body assertion:

   ```js
   assert.equal(seen.headers["Content-Type"], "application/x-www-form-urlencoded");
   assert.deepEqual(
     Object.fromEntries(new URLSearchParams(seen.body)),
     { grant_type: "client_credentials" },
   );
   ```

2. **F1 behavioral pin (same test, clientSecret configured).** The sent body
   must contain no credentials — they moved to the Basic header:

   ```js
   assert.equal(seen.body, "grant_type=client_credentials");
   assert.ok(!seen.body.includes("client_id") && !seen.body.includes("client_secret"));
   ```

   This closes the strip-ordering hole the string-containment pins leave
   open: a buggy `Object.entries(opts.body)` encode emits
   `client_id=body-id&client_secret=body-secret` and fails both assertions.

3. **F3 behavioral pin (new test).** A body carrying `undefined`-valued keys
   must not serialize the literal `"undefined"`:

   ```js
   test("form bodies never serialize undefined values", async () => {
     // public client (no clientSecret), fetch-capturing mock as in test #2
     await client.postToken({ grant_type: "client_credentials", scope: undefined, extra: undefined });
     assert.equal(seen.body, "grant_type=client_credentials");
     assert.ok(!seen.body.includes("undefined"));
   });
   ```

4. **F-A behavioral pin (new test).** A `postPAR` call carrying
   `authorization_details` (array of objects) and `claims` (object) sends
   each as a single URL-encoded JSON string:

   ```js
   // confidential client (clientSecret: "secret"), fetch-capturing mock
   await client.postPAR({
     response_type: "code",
     redirect_uri: "https://app.example.test/cb",
     scope: "openid",
     authorization_details: [{ type: "bank_account_access", actions: ["read", "list"] }],
     claims: { id_token: { email: null } },
   });
   const params = new URLSearchParams(seen.body);
   assert.equal(params.get("authorization_details"),
     JSON.stringify([{ type: "bank_account_access", actions: ["read", "list"] }]));
   assert.equal(params.get("claims"), JSON.stringify({ id_token: { email: null } }));
   assert.equal(params.getAll("authorization_details").length, 1); // single element, not repeated keys
   assert.ok(!seen.body.includes("client_secret")); // F1 applies to postPAR too
   ```

### 3.8 Regeneration

`python cli.py sdk-surface generate` (`go run ./cmd/gensdk --lang=all`),
commit `docs/sdks/typescript/client.ts` + `docs/sdks/python/client.py`, then
`python cli.py sdk-surface check` (validate_registry at ops/scripts/sdk_surface.py:65).

## 4. Compatibility constraints

| Constraint | Detail |
|---|---|
| SDK consumer API | No signature/type changes: the four methods keep `TokenRequest`/`IntrospectRequest`/`RevokeRequest`/`PARRequest` bodies. Only the wire encoding of those four calls changes. |
| Server today | `BindParams` accepts both form and JSON (bind.go:28-53) — committed clients stay valid before and after this change; no server edit in this module. **Exception (F-A):** form-encoded `authorization_details`/`claims` currently bind `nil` server-side — the regenerated `postPAR` form emission must not ship before the `setFormField` `json.RawMessage` case lands (§6 step 8a, same campaign; additive fix with zero JSON-path change). |
| Ordering vs B4-4 | This module MUST land before the server form-only flip (T-9(d)). Committed clients must emit form before enforcement ships, or they break with `400 invalid_request`. |
| Non-form ops | JSON branch byte-for-byte untouched (REQ-2.4): regeneration diff for the other 312 ops must be zero per-op hunks. Baseline verified byte-stable today: `go run ./cmd/gensdk --lang=all` regenerates both clients with zero diff. |
| Wire semantics | `resource`/`audience`/`tokens` string arrays → repeated keys (A2), which the server's `formIntoStruct` already parses; `authorization_details`/`claims` → single JSON-string element (RFC 9396 §7.1.1, F-A); `scope` stays a single space-delimited string. Cross-language decode parity verified by the three-way harness; percent-encode sets differ (`*` vs `~`) and decode identically. |
| Python confidential clients | Python has no Basic-auth path today; `form=True` ships with the body unchanged (client_id/client_secret remain in the body — matching today's behavior for public clients). A future Python Basic path must strip before encoding, mirroring TS; out of scope here. |
| Runtime deps | `URLSearchParams` already used for queries (A4); `urllib.parse` already imported by the Python client. No new dependencies. |
| Part order determinism | `tsEmitRequestOpts` joins parts in fixed order (query, body, auth, clientAuth, form); `pyEmitMethod` appends in fixed order — emitted strings are stable and assertable. |
| `sdk-surface check` blind spot | The checker validates registry membership only (never media types, never output diffing) and is inside `make ci` (Makefile:265). It cannot catch a missing form emission. The emit/output tests (T-9(a)) and the committed-diff review (T-9(c)) are the real gates (see §7). |
| Behavioral harness | `client.test.mjs` is not wired into CI; it is updated and extended anyway because it is the only behavioral test of the generated runtime (F1/F3/F-A pins). |

## 5. Failure modes and mitigations

| # | Failure mode | Mitigation |
|---|---|---|
| F1 | **Credential leak via encoding order.** If the form branch encoded `opts.body` instead of `authenticatedBody`, `client_id`/`client_secret` would survive into the urlencoded body after Basic extraction (double transmission, secrets in bodies/logs). | Structural: form branch keys on `authenticatedBody` (gen_ts_runtime.go:154); T-9(a) pins the branch condition **and the encode input** `Object.entries(authenticatedBody)`; behavioral: `client.test.mjs` #2 pin asserts the sent body contains no `client_id`/`client_secret` and equals `grant_type=client_credentials` exactly. |
| F2 | **Python list mangling.** `urlencode` without `doseq=True` turns `["a","b"]` into `%5B%27a%27%2C+%27b%27%5D`; the server then binds `resource` as one garbled string — silent wrong-grant behavior. | Pin `urllib.parse.urlencode(form_data, doseq=True)` in `TestPyRuntimeFormEncoding`. |
| F3 | **`"undefined"` literals in TS form bodies.** `JSON.stringify` drops `undefined` keys; `URLSearchParams.append(k, String(undefined))` sends `"undefined"`. | Skip predicate `if (v === undefined || v === null) continue;` pinned in `TestTSRuntimeFormEncoding`; behavioral pin in `client.test.mjs` (no `"undefined"` substring). |
| F4 | **Non-record body with `form` flag.** A string/number body would crash `Object.entries`. | `isRecord` guard falls back to the JSON branch (defensive; the four ops' bodies are always objects and required). Branch condition pinned in T-9(a). |
| F5 | **Fixture drift.** If the `postToken` fixture in `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` lacks `FormBody: true`, the `form: true` assertion fails loudly — extraction-time population means fixtures must set the flag. | Exact-string assertion `{ body, clientAuth: true, form: true });` (emit_test.go:231); documented in §3.1. |
| F6 | **Regeneration diff sprawl.** Runtime template edits touch the shared runtime section of both clients, so the committed diff contains runtime hunks beyond the four methods. | Diff review rule (T-9(c)): runtime template hunks expected (one per client region); per-op hunks limited to the four methods; zero unrelated per-op hunks. |
| F7 | **Future spec-driven scope creep.** Adding a fifth form op to openapi.yaml would not be picked up (hardcoded predicate) and `sdk-surface check` won't flag it. | Negative predicate tests pin the boundary; whole-output count (`form: true` / `form=True` exactly four) pins it across the entire emitted file; predicate comment documents deliberate extension. |
| F8 | **Server enforcement landing first.** Committed clients still JSON → `400 invalid_request` on all four endpoints. | Sequencing gate (§6): this module is the prerequisite of the B4-4 flip. |
| F9 | **REQ-6 doc drift.** Rewriting openapi.yaml:1063-1065 to "form only" while the server still accepts JSON creates the opposite drift (AGENTS.md §1). | REQ-6 gated on the server flip, same as T-9(d). |
| F10 | **Missing-CT body on the four ops.** Python `body=None` + `form=True` leaves `data=None` (no Content-Type); today the server defaults missing-CT to JSON. Under B4-4 enforcement this becomes `400 invalid_request` — but the four generated methods always pass a required body, and this exact case is what T-9(d) pins server-side. | Documented; no code needed (bodies are required on all four ops). |
| F-A | **PAR RAR/claims silent drop.** Form-encoded `authorization_details`/`claims` bind `nil` in `setFormField` (no `json.RawMessage` case) → PAR issues without RAR/claims (silent wrong-grant vs today's JSON delivery); a naive client encoder additionally sends `[object Object]`/reprs. | Client side: objects/object-arrays encoded as single JSON-string elements (§3.3/§3.4), pinned in `TestTSRuntimeFormEncoding`/`TestPyRuntimeFormEncoding` and behaviorally in `client.test.mjs` #4. Server side: `setFormField` `json.RawMessage` case (§6 step 8a) + form-PAR RAR/claims test (§6 step 8b, T-9(g)) — fails today, passes after the fix. |
| F-B | **Python `None` literals.** `urlencode` renders `None` as `"None"`; JSON branch renders `null`. Fails closed but silently changes semantics. | Form branch filters `None` scalars (`if v is None: continue`), mirroring the TS skip and the query path's existing filter; pinned in `TestPyRuntimeFormEncoding`. `[None]` array items remain a documented out-of-contract divergence (`"None"` vs TS `"null"`). |

## 6. Migration steps (ordered)

Generator module steps 1-7 are self-contained and land together. Step 8
(server prerequisite) must land **before the regenerated clients are
released** — it is additive and safe on its own (form PAR today silently
drops RAR/claims; the fix only makes the form path honor the documented
contract). Steps 9-12 are the B4-4 enforcement phase.

1. **Model** (3.1): `FormBody` field, `usesFormBody`, populate in `extractOne`
   (operations.go:123-130).
2. **Emitters** (3.2, 3.5): TS `form: true` part (gen_ts.go:68-88); Python
   `, form=True` (gen_py.go:168-171).
3. **Runtimes** (3.3, 3.4): TS `requestOptions.form` + form branch
   (gen_ts_runtime.go:35-41, :157-160); Python `form` param + `doseq=True`
   branch with `None` filter and JSON-string special-case (gen_py.go:85-94,
   :102-105).
4. **Tests** (3.6): new predicate/emit/runtime-encoding tests; update the
   confidential-auth fixture and assertions (emit_test.go:207-231).
5. **Behavioral harness** (3.7): update `client.test.mjs` #2; add F1/F3/F-A
   pins.
6. **Regenerate** (3.8): `python cli.py sdk-surface generate`; review the
   diff against the T-9(c) rule; commit the two clients.
7. **Check + gates**: `python cli.py sdk-surface check`;
   `go build ./... && go vet ./...`;
   `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `go test ./cmd/gensdk/... -count=1`; `go test ./... -race`;
   `go test ./test/ -run TestE2E -v`; `make ci`.
   (Pre-existing unrelated failures: `infrastructure/defaultimpl/ed25519_jwt_issuer.go`
   539 lines, docs fanout 18>16, root subdirs 24>21 — reported separately,
   not introduced by this change.)
8. **Server prerequisite (B4-4 server module — MUST land before step 6's
   clients are released):**
   a. `setFormField` gains a `json.RawMessage` case (bind.go:111-137;
      `encoding/json` already imported). `json.RawMessage` is `[]byte`; the
      Slice case must handle it before the `Elem().Kind() == String` check:

      ```go
      case reflect.Slice:
          if f.Type() == reflect.TypeOf(json.RawMessage(nil)) {
              // RFC 9396 §7.1.1 / OIDC Core §5.5: the form value is a single
              // JSON-string element; store the raw text so downstream
              // ValidateAuthorizationDetails / claims parsing unmarshal it.
              f.SetBytes([]byte(raw[0]))
          } else if f.Type().Elem().Kind() == reflect.String {
              f.Set(reflect.ValueOf(formStringSlice(raw)))
          }
      ```

      Additive: JSON path and every existing string/[]string field are
      untouched; the four form ops' other fields bind exactly as today.
   b. **Form-PAR RAR/claims test** (T-9(g)): extend `TestHandlePAR`
      (protocols/oauth/handle_par_test.go:50) with a form-encoded subtest —
      `ctFormURLEncoded` body
      `client_id=rp&client_secret=s&authorization_details=%5B%7B%22type%22%3A%22bank_account_access%22%7D%5D&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%7D%7D`
      → expect 201 and the stored `parRequestForm.AuthorizationDetails` /
      `Claims` non-empty with the exact JSON bytes; plus a ssotest-level
      round-trip in `test/handle_par_test.go`: form PAR → consume the
      `request_uri` at `/auth/login` → the final token carries the RAR
      `authorization_details` claim and the requested claims. **Fails today**
      (nil binding → no RAR), passes after 8a — this is the F-A regression
      gate.
9. **Enforcement flip (B4-4 server module):** server form-only binding flip
   (R1/R5 of the B4-4 server requirements).
10. **Invert `TestFormEncoded_JSONStillWorks`** (test/oauth_bind_test.go:272):
    JSON body and missing-CT body → byte-identical `400 invalid_request`
    (same status, same body bytes); form → 200.
11. **Add no-store assertions on the rejections** (new assertions, mechanism
    already in place — E14/A1: `tokenNoStoreHeaders` server_token.go:21-22,
    `TokenNoStoreHeaders` handle_introspect.go:112, handle_revoke.go:68/:182,
    handle_par.go:55 all run before binding, so the 400s inherit them).
12. **Rewrite openapi.yaml:1063-1065** (REQ-6): drop the "Form + JSON ...
    `oauth_bind.go`" sentence and the "JSON shape uses arrays" clause (the
    `audience` part of that clause is accurate — keep `audience`/`resource`
    as accepted lists — only the acceptance claim is wrong post-flip); state
    form-urlencoded per RFC 6749. No schema changes (the four request bodies
    already declare form; E7/C1).

No SDK-consumer migration is required at any step: method names, parameters,
and result types are unchanged.

## 7. Testable acceptance mapping

### T-9(a) — emit/output tests (the media-type gate; closes the `sdk-surface check` blind spot)

Command:

```bash
go test ./cmd/gensdk/ -run 'TestTSFormBodyOperations|TestPyEmitFormBodyOperations|TestTSRuntimeFormEncoding|TestPyRuntimeFormEncoding|TestTSClientAuthenticationOperations|TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport' -v -count=1
```

Pass criteria (each bullet pins a specific failure mode; the pin fails on the
buggy implementation):

- Predicate truth table: the four ops true; `postLogin`, `postLogout`,
  `postRevokeAll`, one admin op, one SCIM op false (F5, F7).
- Whole-output counts: `form: true` appears **exactly four times** in the TS
  output; `form=True` appears **exactly four times** in the Python output
  (F7 boundary; a fifth op or a missing op breaks the count).
- `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`: exact-string
  `{ body, clientAuth: true, form: true });` (F5); fixture sets
  `FormBody: true`.
- TS runtime contains `if (opts.form && isRecord(authenticatedBody)) {`
  (F1 branch condition + F4 guard) and `Object.entries(authenticatedBody)`
  (F1 **encode input** — a buggy `Object.entries(opts.body)` fails),
  `if (v === undefined || v === null) continue;` (F3 skip predicate — an
  unconditional append fails), `params.append(k, JSON.stringify(v));` (F-A
  JSON-string special-case), the form Content-Type line, and still contains
  `delete withoutCredentials.client_secret;` (F1 structural).
- Python runtime contains `urllib.parse.urlencode(form_data, doseq=True)`
  (F2), `if v is None:` (F-B), `form_data[k] = json.dumps(v)` (F-A), and
  still contains `json.dumps(body).encode("utf-8")` (JSON branch untouched).
- Negative: `form: true`/`form=True` absent from every other generated
  method in the same outputs.

### T-9(b) — regeneration green

Command: `python cli.py sdk-surface generate && python cli.py sdk-surface check`

Pass criterion: both exit 0; `check` prints "OK: sdk-surface registry valid
(13 groups, 316 operations, ...)". Note: `check` validates membership only —
this row alone would NOT catch a missing form emission; T-9(a) and T-9(c)
are the real gates.

### T-9(c) — committed diffs

Command: `git diff` review of `docs/sdks/typescript/client.ts`,
`docs/sdks/python/client.py`; `grep -c "x-www-form-urlencoded"` both files.

Pass criteria: four methods per client emit form markers (0 today → 4 each);
TS runtime encodes the stripped body (`authenticatedBody`); per-op hunks
limited to the four methods (baseline regeneration is byte-stable today);
runtime hunks limited to the template regions (F6); zero unrelated per-op
hunks.

### T-9(d) — server inversion (B4-4-gated, step 10)

Command: `go test ./test/ -run TestFormEncoded_ -v -count=1`

Pass criterion: `TestFormEncoded_JSONStillWorks` inverted — JSON and
missing-CT → byte-identical `400 invalid_request`; form → 200. Fails fast
until the server flip lands (F8, F10).

### T-9(e) — no-store on rejections (B4-4-gated, step 11; assertions are NEW, added in the B4-4 phase)

Command: `go test ./test/ -run 'TestFormEncoded_|TestTokenNoStore' -v`

Pass criterion: the rejection tests assert `Cache-Control: no-store` +
`Pragma: no-cache` on the 400s (headers set before binding at the four
handler sites; E14/A1).

### T-9(f) — behavioral harness (local, not in CI)

Command: `cd docs/sdks/typescript && bun test` (or `npm test`)

Pass criteria: updated test #2 asserts the form Content-Type + a
`URLSearchParams`-parsed body equals `{ grant_type: "client_credentials" }`;
the F1 pin asserts the sent body contains no `client_id`/`client_secret`
when `clientSecret` is configured; the F3 pin asserts no `"undefined"`
substring for `undefined`-valued keys; the F-A pin asserts
`authorization_details` and `claims` arrive as single URL-encoded JSON
strings (one element each) on `postPAR`.

### T-9(g) — form-PAR RAR/claims server test (B4-4-gated, step 8b)

Command: `go test ./protocols/oauth/ -run TestHandlePAR -v -count=1 && go test ./test/ -run TestPAR -v -count=1`

Pass criterion: the new form subtest binds `authorization_details` and
`claims` as raw JSON and the E2E round-trip carries RAR + claims through
`request_uri` consumption to the issued token. **Fails today** (setFormField
has no `json.RawMessage` case; fields bind nil) — this is the F-A regression
gate.

### Failure-mode → test coverage matrix

| FM | Failing test (on the buggy implementation) | Command |
|---|---|---|
| F1 | `TestTSRuntimeFormEncoding` (`Object.entries(authenticatedBody)` pin) + `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` (branch-condition pin) + `client.test.mjs` #2 F1 pin (no credentials in body) | `go test ./cmd/gensdk/` / `bun test` |
| F2 | `TestPyRuntimeFormEncoding` (`urlencode(form_data, doseq=True)` pin) | `go test ./cmd/gensdk/` |
| F3 | `TestTSRuntimeFormEncoding` (skip-predicate pin) + `client.test.mjs` #3 (no `"undefined"` substring) | `go test ./cmd/gensdk/` / `bun test` |
| F4 | `TestTSRuntimeFormEncoding` (`isRecord(authenticatedBody)` guard pin) | `go test ./cmd/gensdk/` |
| F5 | `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` (exact `{ body, clientAuth: true, form: true });` string; fixture `FormBody`) | `go test ./cmd/gensdk/` |
| F6 | T-9(c) diff review (per-op hunk rule; baseline byte-stable) | `git diff` |
| F7 | `TestTSFormBodyOperations` truth table + whole-output `form: true`/`form=True` count == 4 | `go test ./cmd/gensdk/` |
| F8 | T-9(d) inversion (fails fast until flip; sequencing gate) | `go test ./test/` |
| F9 | REQ-6 openapi prose review after the flip (no pre-flip rewrite) | `grep`/review openapi.yaml:1063-1065 |
| F10 | T-9(d) missing-CT → `400 invalid_request` (new assertion) | `go test ./test/` |
| F-A | `TestTSRuntimeFormEncoding`/`TestPyRuntimeFormEncoding` (`JSON.stringify(v)`/`json.dumps(v)` pins) + `client.test.mjs` #4 (single JSON-string elements on the wire) + T-9(g) server test (fails today: nil binding) | `go test ./cmd/gensdk/` / `bun test` / `go test ./protocols/oauth/ ./test/` |
| F-B | `TestPyRuntimeFormEncoding` (`if v is None:` pin) | `go test ./cmd/gensdk/` |

REQ-to-test map: REQ-1 → `TestTSFormBodyOperations` + `TestPyEmitFormBodyOperations`
(predicate truth table); REQ-2 → updated `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`
+ `TestTSRuntimeFormEncoding` containment; REQ-3 → `TestPyEmitFormBodyOperations`
+ `TestPyRuntimeFormEncoding` (`doseq=True`, `form=True` containment); REQ-4 →
the same four tests plus `client.test.mjs` #2/#3; REQ-5 → T-9(b)/(c); REQ-6 →
review of the openapi edit after the B4-4 server flip (step 12).

## 8. Out of scope (unchanged from the requirements spec)

- Server-side binding changes (`BindFormParams`, bind-site switches, the
  test/ JSON call-site migrations, the enforcement flip) — B4-4 server
  module (except the `setFormField` `json.RawMessage` case and form-PAR
  test, which this design sequences as the prerequisite of the client flip,
  §6 step 8).
- `postDeviceCode`/`postDeviceVerify`/`postMFAComplete` and `postRevokeAll`
  emission.
- Python confidential-client Basic auth (the future Basic path must strip
  before encoding, mirroring TS).
- `[None]`-array-item literal divergence (`"None"` vs `"null"`) — out of
  contract for all four schemas; documented, not fixed.
- Discovery truthiness sweep (B4-3) and the other directions in
  `cmd-gensdk-4ffda121.json`.
