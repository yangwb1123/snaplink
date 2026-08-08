Pre-existing worktree dirt under `ops/deploy/` only — my runs left `docs/sdks/`, `cmd/gensdk/`, `docs/openapi.yaml`, `ops/build/` untouched. Verification complete.

---

# Verification verdict: all four parity claims hold, with two small corrections

## 1. Cross-language wire parity — CONFIRMED (empirically, 14/14 in-contract cases)

I built a three-way harness (TS encoder = the design's exact §3.3 branch, Python `urlencode(body, doseq=True)`, Go `url.ParseQuery` — the exact decoder `r.ParseForm()` feeds `r.PostForm` → `formIntoStruct`, bind.go:38-42) over a corpus covering all four flat schemas.

- **All four array fields exercised**: `resource` (TokenRequest/PARRequest), `tokens` (IntrospectRequest), `authorization_details` (PARRequest), plus scalars (`grant_type`, `scope`, `client_id`, `redirect_uri`, PKCE values), URI values with query strings, JSON-string `authorization_details` values, unicode, and the special-char gauntlet.
- **Repeated keys**: both clients emit `resource=a&resource=b` in insertion order; Go binds `["a","b"]` in order. Identical.
- **Empty array**: TS emits zero appends; Python `doseq=True` expands `[]` to zero pairs (verified: `urlencode({'r': []}, doseq=True) == ''`) — **key absent on the wire**; `formIntoStruct` skips absent keys (bind.go:49-51), matching JSON-branch `[]` semantics.
- **`[""]`** → `resource=` (present-but-empty) and **`["", "b"]`** → `resource=&resource=b` — byte-identical in both languages.
- **The one real byte-level difference** is the percent-encode set: TS leaves `*` raw but encodes `~! ' ( )`; Python leaves `~` raw but encodes `*! ' ( )`. Complementary exceptions — Go decodes both to identical strings. This is precisely the "decode identically" requirement; byte-identity is not required and does not hold (nor is it claimed).

**Correction to design A2**: it says TokenRequest is "strings + `resource` array" — TokenRequest **also carries an `audience` string-array** (RFC 8693, merged with `resource`; openapi TokenRequest.audience). Not a design flaw — the runtime loop is generic over all array values and §4's wire-semantics row already names `audience` — but the A2 summary line is incomplete. The corpus case `token-exchange-audience` passes.

**Out-of-contract divergence (documented, not a parity break)**: `null`/`None` — TS skips null scalars but emits `resource=null` for `[null]` items; Python emits `client_id=None`/`resource=None` literals. Booleans — TS `String(true)` = `"true"`, Python = `"True"`, and Go's bool binding only accepts `"true"`/`"1"` (bind.go:76). All four schemas are strings + string-arrays only (verified: 22/5/4/18 fields, zero booleans, zero numbers), so this is out of contract; worth a one-line note (optionally None-filter the Python branch like the query path already does at gen_py.go `filtered = {... if v is not None}`).

## 2. JSON branch byte-for-byte for the other 312 ops — CONFIRMED

- sdk-surface.json: 13 groups / 316 ops; the four form ops are all in the `auth` group → exactly 312 others.
- Emitters branch only on `op.FormBody` for the new parts (`tsEmitRequestOpts` gen_ts.go:67-88; `pyEmitMethod` gen_py.go:163-178); `FormBody` is populated only by the hardcoded four-op `usesFormBody` in `extractOne`. No other path touches the body branch. The design's runtime snippets preserve the JSON branch lines verbatim (`headers["Content-Type"] = "application/json"; init.body = JSON.stringify(...)` / `json.dumps(body).encode("utf-8")`).
- **Baseline empirically byte-stable**: `go run ./cmd/gensdk --lang=all` regenerates both committed clients with **zero diff** today — so after the change, per-op hunks are provably limited to the four methods (T-9(c) rule); the two runtime-template hunks are the only shared churn (F6, correctly scoped).

## 3. openapi.yaml /token form-only vs B4-4 flip — CONSISTENT

- `postToken` requestBody (openapi.yaml:1100-1102) declares only `application/x-www-form-urlencoded`; introspect (:1267/1280), revoke (:1343/1347), PAR (:1473/1477) declare both — E7/C1 re-confirmed at exact lines.
- The stale prose at :1063-1065 is the **only** JSON-acceptance claim in the /token description (other `application/json` hits in range are response content types); REQ-6's rewrite range is complete. Nuance: the stale "`resource` / `audience` lists" clause is partly accurate — `audience` does exist (see above); only the "Form + JSON accepted via `oauth_bind.go`" claim is wrong post-flip.
- Direction check: today openapi (form-only) is *stricter* than the server (both); the flip makes the server match openapi. The design changes neither the /token declaration nor the server and gates the prose fix on the flip — no new drift in either direction. `oauth_bind.go` absent, `BindFormParams` 0 matches repo-wide.

## 4. sdk-surface blind spot — REAL, and closed only by the emit tests

- `sdk_surface.py` `validate_registry` checks schema header, duplicate ids, registry ⊆ openapi membership, capability refs, language-file existence — **never media types, never output diffing**, and membership is one-directional (the four ops aren't required to be *present*). An unintended media-type change passes `check` with exit 0, and `make ci` (Makefile:265) includes `sdk-surface-check` — the blind spot is inside CI.
- Closure is exactly as the design says: `make ci` also runs `race` → `go test -race -count=1 ./...`, which includes cmd/gensdk — the proposed predicate/emit tests with negative pins are the real media-type gate; T-9(c) diff review is the second; and the check output prints "316 operations", so membership regressions are at least visible. The design's §4/§7 attribution is correct.
- Residual: the negative pins cover a fixed op table — a predicate change affecting an op outside the table would be caught by diff review, not tests. Acceptable for a hardcoded predicate; a "form: true appears exactly four times" whole-output assertion would strengthen it (cheap to add).

## Gate status

No `.go` edits were made (verification only). All cited line anchors re-checked: gen_ts_runtime.go:35/142-151/154/157-160/183; gen_py.go:87/103-104/163; emit_test.go:159/207/231; bind.go:28-53/76; operations.go:58-70/171-190/192-201. `sdk-surface check` green ("13 groups, 316 operations, 2 languages"); regeneration byte-stable. One correction (A2 missing `audience`) and one documented out-of-contract divergence (null/None/boolean literals) to fold into the design; everything else holds as written.
