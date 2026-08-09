# Cross-check verdict

I re-derived the server semantics from the code (not the design's citations) and compared them against the proposed TS/Python serialization rules, the flip mechanics, and the design's test plan. All 7 ops route through the same path: `bindOAuthParams` → `oauthwire.BindParams` (bind.go:38-42) → `formIntoStruct`/`setFormField`, with `r.PostForm` only (query ignored) and `;charset` stripped. Everything the design claims about the binder is confirmed; I found **6 actionable gaps** (G1-G6), one of which is a real correctness bug in the C1 guard predicate.

## 1. Per-value rules vs. actual binder semantics — confirmed, one server quirk to document

| Proposed rule | bind.go reality | Verdict |
|---|---|---|
| scalars → single key | `setFormField` String: `raw[0]` verbatim (bind.go:114) | ✓ |
| bool → lowercase `"true"`/`"false"` | `f.SetBool(raw[0] == "true" \|\| raw[0] == "1")` (bind.go:115-116); anything else **silently → false** | ✓ C2 confirmed; coercion is mandatory (Python `urlencode` emits `True` → silent denial of `approve`/`trust_device`) |
| `string[]` → repeated keys | Slice-of-string case → `formStringSlice(raw)` (bind.go:129-130): `len>1` returned verbatim; repeated keys decode to `["a","b"]` | ✓ matches `resource`/`audience`/`tokens` (openapi.yaml:1063-1066, verified) |
| object / array-of-object → single JSON-string key | `json.RawMessage` (`[]byte` = slice-of-uint8) and maps **fall through `setFormField` silently today** (C4/C1 confirmed); sibling F1 adds the Uint8 sub-branch (single value, `json.Valid`, repeated keys → 400, decisions §2) | ✓ the single-key JSON-string emission is exactly the F1 wire shape; today it is inert (silent drop) |
| `undefined`/`None` skip | absent key → field skipped (`!ok \|\| len(raw)==0`) → zero value = same as JSON null/undefined drop | ✓ |
| empty-string element `[""]` | `key=` → `raw=[""]`, len 1, **not** skipped → `[""]` verbatim (F10 verified) | ✓ |

**Server quirk worth documenting (not an SDK defect):** `formStringSlice` splits a *single* value containing a literal space or comma (bind.go:133-141). An array element containing a space (incl. `%20`, which `ParseForm` decodes back to a space) is split server-side on the form wire, unlike the JSON wire. Any form client is subject to this — the SDK cannot avoid it without corrupting the value — but the design should note it in the value-rules doc so `resource` elements with encoded spaces are known to differ from the JSON wire.

**Per-op inventory** (verified field-by-field against the schemas and bound structs):

| Op | Handler/bind | Array fields | JSON-string fields | Bool | Map (blocked) |
|---|---|---|---|---|---|
| postToken | server_token.go:30 `TokenRequest` | `resource`, `audience` | — | — | — |
| postIntrospect | handle_introspect.go `introspectRequest` | `tokens` | — | — | — |
| postRevoke | handle_revoke.go:75 `revokeRequest` | — | — | — | — |
| postPAR | handle_par.go `parRequestForm` | `resource` | `authorization_details` (array-of-obj), `claims` (bare object) | — | — |
| postDeviceCode | server_device.go:53 | `resource` | — | — | — |
| postDeviceVerify | server_device.go:242 | — | — | `approve` (required) | — |
| postMFAComplete | server_mfa.go:255 `mfaCompleteRequest` | — | — | `trust_device` | `params` |

No int fields anywhere in the 7 ops, so the int bind-error path (bind.go:119-126) is irrelevant. The `json:"-"` presence-flag fields (`ClientSecretPresent` etc., token_request.go:70-88) are skipped by `formFieldKey` on the form wire — a pre-existing form-wire asymmetry with no handler dependency. Client-auth: TS `withClientAuthentication` provably runs before serialization (gen_ts_runtime.go `request()`), Python has no Basic path and body creds stay in the body (verified in generated `client.py` `post_token`) — C5 confirmed.

**Schema-driven `FormBlockedFields` works** — this was the subtle one: `params` is declared `additionalProperties: {type: string}` → `KindMap` (schema_primitive.go `resolveObjectLike`), while `claims` is a bare `type: object` → `KindObject`, so a `Kind == KindMap` check catches exactly `params` and nothing else. Empty `authorization_details` → key skipped → `len(raw)==0` → `ValidateAuthorizationDetails` returns nil (rar.go:154-156) — same as JSON `[]`.

## 2. contentSchema flip can never select form for a JSON-only op — proven

- `contentSchema` (operations.go:192-203) selects only from the **declared** content map; `postLogin`/`postRegister` declare only `application/json`; `postRevokeAll` has no `requestBody` → `HasBody=false`, `ContentType` stays empty. Structurally excluded, not just unlikely.
- All 8 dual pairs verified **byte-identical `$ref`** (form vs JSON), so the flipped pick changes only the recorded ContentType, never the resolved `BodyType`.
- **Zero** responses in the whole spec declare form (scan of every response object) → `extractResult` behavior identical under the flip (C6 proven at code level, not just asserted).
- `postBackchannelAuthentication` is dual but **not in sdk-surface.json** (verified) → not extracted, no concern.
- Surface membership of the 7 ops verified; `tsUsesClientAuth` covers only 4 of 7 (gen_ts.go:99-106) — the design's spec-correction-4 point (keying form emission on it would drop 3 ops) is confirmed.

## 3. Test-coverage matrix (C1-C7, F1-F10) — 6 gaps

**Covered, fails loudly:** C2 (golden bool case), C3 (process; `_test.go` is exempt from the 500-line gate in engineering.yaml, and 7 non-test files vs 10 ceiling — the extend-`emit_test.go` constraint is safe), C6 (AC2(a) exact 7-op set + structural proof), C7 (AC3 control arm correctly on `/token`, design explicitly forbids the `/auth/mfa` generalization), F4 (AC2(b) undefined-skip), F6 (AC2(a)), F7/F10-required (string assertion + all 8 dual bodies verified `required: true`; `body` params are non-optional in both generated signatures).

**Gaps — the design must be tightened before implementation:**

- **G1 (real bug): the C1/F2 guard predicate must be presence-based, not non-empty-based.** The sibling rejects on `r.PostForm.Has("params")` — **key presence, any value** (decisions §3.2, pinned). The design's `Object.keys(body.params).length > 0` (TS) / truthy (Python) lets `params: {}` through; `formSerialize` would then emit `params={}` → silent drop today, **guaranteed `400 mfa_invalid` after the sibling lands** — while `params: {}` + flat `code` works on the JSON wire today (collectMFAParams folds flat fields into an empty map). The guard must be `body.params !== undefined` / `body.get("params") is not None`, and the golden set must include the `params: {}` case.
- **G2: C5 has no emission-level test.** Nothing asserts the generated `post_token` keeps `client_id`/`client_secret` in the body and adds `form=True` (and that TS strips them before serialize — AC2(b) covers TS ordering, Python does not). Add one string assertion; the Go E2E can't cover the Python runtime.
- **G3: the "golden `_form_encode`/`formSerialize` cases" have no specified execution harness.** AC2(c) claims `{"approve": True}` → `approve=true`, but emit_test.go is pure-Go string assertions today; string-presence assertions cannot prove coercion behavior (a `v is True` typo passes them). python3/node/bun are all present in this environment; specify exec-based tests (no `t.Skip` — skip is a silent pass) or relocate the behavioral goldens into `client.test.mjs` + a Python test. Also note: **`bun test`/`bun run build` are not in `make ci`** (verified Makefile:268 target list; no gensdk/bun step anywhere in ci) — the design lists them as "universal gates" but they are currently out-of-band unless wired in.
- **G4: the F1 window has no failing test in this workstream.** AC2(d) pins the wire shape (correct — that's the emission-level property), but nothing fails when the sibling's F1 decoder lands late; the design's own detection is "code review of merge order", and AC3's PAR arm covers only repeated-`resource`, not the claims/authorization_details path. Make the interlock mechanical: a campaign-gate check or a deliberately-blocked (not skipped) E2E arm that is enabled only when F1 is present.
- **G5: F8's detection is misstated.** The design's F8 row says "make ci regeneration check", but no regeneration/drift gate exists in `make ci` or `cli.py` today (verified), and AC4 defers to the sibling's T-9 gate ("no new gate added here"). Until then, generator/artifact skew is undetected. Cheap fix within the C3 constraint: a full-file drift test in emit_test.go — `GenerateTS`/`GeneratePython` over the real openapi.yaml + sdk-surface.json, diffed against the committed `client.ts`/`client.py`. This also automates AC1's `postRevokeAll` byte-identical pin (F7).
- **G6 (minor):** AC2(c)'s golden list omits the F10 empty-element case (`{"resource": [""]}` → `resource=`) and there is no TS-side bool golden (`formSerialize({"approve": true})` → `approve=true`); AC2(b) should pin the exact form header string (`"application/x-www-form-urlencoded"`, no charset — F9), and the `request()` form branch should mirror the JSON branch's `body !== undefined` guard for robustness (unreachable today — all 7 bodies required).

**Verdict:** The per-value serialization rules are a faithful, verified match to the Go binder for every operation in the 7-op surface (including repeated-key, empty-value, bool-coercion, and the F1/F3 JSON-string/map semantics as they will exist after the sibling change); the preference flip is provably inert for JSON-only ops, `postRevokeAll`, and all responses. The C1-C7/F1-F10 test plan covers most items with loud-failing emission tests, but it is **not yet complete**: G1 (presence-based `params` guard), G2 (C5 pin), G3 (golden-case harness + bun-out-of-ci), G4 (F1 interlock enforcement), and G5 (no automated drift gate until T-9) must be resolved in the design before implementation; G6 is a one-line addition to the golden set. No code was modified; `go test ./cmd/gensdk/` baseline is green.
