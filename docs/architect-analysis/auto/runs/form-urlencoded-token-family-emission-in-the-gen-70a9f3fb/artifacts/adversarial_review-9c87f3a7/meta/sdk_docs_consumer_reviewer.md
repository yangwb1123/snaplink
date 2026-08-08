All surfaces audited. Here is the complete report.

# Consumer-surface audit: B4-4 form-only flip impact

## A. Stale consumer-facing items — exact locations

### Committed files that **break or become wrong** post-flip (JSON body → `400 invalid_request`)

| # | File:lines | What | Becomes |
|---|---|---|---|
| 1 | `README.md:219-223` | Root README "Call over the wire" curl: `POST /token -H 'Content-Type: application/json' -d '{...authorization_code...}'` | Breaks. First doc a consumer reads; also the only /token example in the root README |
| 2 | `ops/deploy/k8s-distributed/README.md:98-99` | HA verification step: `POST /token/introspect -H 'Content-Type: application/json' -d '{"token":...}'` | Breaks (introspect goes form-only under B4-4 R5.4) |
| 3 | `docs/examples/quickstart/main.go:163-173` + `:214-222` | Runnable example: `exchangeCode` posts JSON to `/token` via `postJSON` (`http.Post(url, "application/json", ...)` at :216) | Breaks at runtime ("token exchange failed"). Referenced as canonical by `README.md:76,91` — this is executable consumer code, the strongest stale item |
| 4 | `docs/sdks/typescript/client.test.mjs:47-53` | Behavioral test #2: `postToken` then `assert.deepEqual(JSON.parse(seen.body), {grant_type:...})` at :53 | `JSON.parse` throws on `grant_type=client_credentials`. Not wired into `make ci`, but it is the only behavioral net for the generated TS runtime — the natural home for the F1/F3 pins (see §C) |
| 5 | `docs/sdks/typescript/dist/client.js` (+ `.d.ts`, committed) | **The npm package's actual consumable artifact** — `package.json` `main: ./dist/index.js`, `files: ["dist", ...]`; `request()` at :118-136 is JSON-only | A `file:`-dependency consumer imports `dist`, not `client.ts` — the packaged client keeps sending JSON and breaks post-flip. Design step 7 commits only `client.ts`/`client.py`; **rebuild + commit `dist/` is a missing migration step**. Note: dist (Aug 7 00:03) already lags client.ts (Aug 7 16:41) — pre-existing staleness to fix in the same step |

### Committed files with **already-stale claims** (wrong today, fully wrong post-flip)

| # | File:lines | Claim |
|---|---|---|
| 6 | `docs/sdks/typescript/README.md:71-74` | "Known simplifications": *"form-urlencoded content type is not separately modeled — every curated operation that accepts `application/x-www-form-urlencoded` also accepts `application/json` with an identical schema, and the client always sends JSON."* Already false today (openapi declares postToken form-only at `:1100-1102`); the design's `FormBody` makes "not separately modeled" obsolete and post-flip the sentence is fully wrong for all four ops |
| 7 | `docs/openapi.yaml:1063-1065` | "/token description: "Form + JSON — both … accepted via the dispatcher in `oauth_bind.go`" (file does not exist). Already in the design's REQ-6 rewrite range, gated on the flip (F9) — confirmed, no new action |
| 8 | `docs/openapi.yaml:1283, 1350, 1480` | `application/json` requestBody declarations for postIntrospect/postRevoke/postPAR — to be dropped by the B4-4 server module's REQ-6 openapi update; already scheduled in the design |

### Untracked deployment artifact (not committed, but served)

| # | Location | Content |
|---|---|---|
| 9 | `ops/deploy/openresty/fullstack/static/` (git status `??`) | Published docs snapshot served by the OpenResty static mount: `sdks/typescript.html` + `assets/sdks_typescript.md.B7NILrxH.js` (baked "client always sends JSON" bullet), `sdks/client.ts` (:735), `sdks/client.py` (:502-530), `openapi.yaml` copy, `typescript-package.json`. The baked TS page is already an older revision ("coreSurface ~200 ops" vs current 316-op set). The docs step must rebuild/republish the site before the flip — no commit needed, but the deployed snapshot otherwise keeps showing the old contract |

### Verified non-issues (so the docs step doesn't over-reach)

- `docs/examples/playground/index.html:90,130-149` — already form-encoded for all token-family calls ✓
- `docs/examples/embed-gin/main_test.go:62`, `embed-echo/main_test.go:59` — already form ✓
- `interfaces/ssoclient/remote/auth.go:327-337` (Go consumer SDK) — already form for revoke; no token/introspect/PAR calls ✓
- `cmd/sso-mcp` (JWKS-local introspection), `cmd/sso-operator/controller/http.go:93` (admin cluster-diff) — not token family ✓
- `docs/config-reference.md:95`, `docs/error-codes.md:318` — `Accept: application/token-introspection+jwt` is a response-format opt-in, unaffected ✓
- `docs/sdks/typescript/README.md:48,:106,:154`, `docs/sdks/python/README.md:103` — method-call examples, media-agnostic; stay valid ✓

## B. sdk_surface.py / registry / capability files: no media-type or content assertions

Verified by reading all five relevant files:

- **`ops/scripts/sdk_surface.py`** — validates only: schema header/version, language status + output-file *existence* (`(ROOT / lang["file"]).exists()`), duplicate group ids, registry ⊆ openapi membership (**one-directional** — the four ops aren't required to be present), capability refs. Never inspects media types, request bodies, or emitted client content. `make ci` (Makefile:265) runs the same checker — the blind spot is inside CI.
- **`ops/build/sdk-surface.schema.json`** — `additionalProperties: false`; group properties are `id/name/capability/operations` only; no media-type field is even representable.
- **`ops/build/sdk-surface.json`** — `auth` group (25 ops) contains all four form ops; `compatibility.policy` speaks only of operationId add/rename. Nothing about content.
- **`ops/build/capabilities.json`** (`oauth.sso`: surfaces `/auth/login`, `/token`) + **`capability.schema.json`** + **`ops/scripts/capability_registry.py`** (shape/vocabulary/feature-gate drift/module refs) — no media-type or content checks.
- Confirmed: the design's emit tests + T-9(c) diff review are the *only* gates for the form emission; the wire reviewer's "blind spot" finding stands. Cheap strengthening (already suggested): a whole-output "`form: true` appears exactly four times" assertion.

## C. "No SDK-consumer API change" claim — holds for the revised design (incl. F-A fix)

- **Types**: `TokenRequest`/`IntrospectRequest`/`RevokeRequest`/`PARRequest` unchanged — type emission is untouched by the `FormBody` work; confirmed in committed clients (client.ts:2903-2915, client.py:2260-2290, signatures take `body`).
- **Method signatures**: unchanged in both languages. F-A's JSON-string encoding of `authorization_details`/`claims` changes only the wire encoding of two fields — consumers pass the same objects, and the `setFormField` `json.RawMessage` case restores today's JSON-delivery semantics (no silent null).
- **Other 312 ops**: emitters branch only on `op.FormBody` (`tsEmitRequestOpts` gen_ts.go, `pyEmitMethod` gen_py.go); `FormBody` is populated only for the hardcoded four. TS runtime gains optional `requestOptions.form?: boolean` (additive) and a branch keyed on `opts.form && isRecord(authenticatedBody)` — JSON branch preserved verbatim; Python `_request(form: bool = False)` default keeps the JSON path byte-for-byte. Baseline regeneration is zero-diff today (wire reviewer), so per-op hunks are provably limited to the four methods. 316 − 4 = 312.
- **Scoped caveat (already correct in the design)**: the four ops' default request Content-Type intentionally changes; the claim is correctly scoped to the other 312. The one gap in the claim's *delivery* is item A5 — the committed `dist/` must be rebuilt or consumers of the packaged entry get the old JSON behavior.

## D. Recommended docs step for the migration plan (all items land **before** the flip; all work under both server states)

1. Rewrite `docs/sdks/typescript/README.md:71-74` (four ops emit form; JSON no longer accepted post-flip; replace the "not separately modeled" claim with the new `FormBody` reality).
2. Rewrite `README.md:219-223` and `ops/deploy/k8s-distributed/README.md:98-99` curls to form-encoded (`--data-urlencode` / `url.Values`).
3. Fix `docs/examples/quickstart/main.go` `exchangeCode` (:163-173) to form encoding (new `postForm` helper or `url.Values`; `postJSON` stays for `/auth/login` which remains JSON).
4. Update `docs/sdks/typescript/client.test.mjs:47-53` to form assertions (`URLSearchParams` parse + `Content-Type: application/x-www-form-urlencoded`), and add the F1 pin (stripped body: no `client_id`/`client_secret` substring) and F3 pin (no `"undefined"` literal) there — the only behavioral harness for the runtime.
5. Add "rebuild + commit `docs/sdks/typescript/dist/`" to the generator's regeneration step (design step 7 currently omits it).
6. Rebuild/republish the OpenResty static docs snapshot (`ops/deploy/openresty/fullstack/static/`).
7. Keep openapi.yaml:1063-1065 + :1283/:1350/:1480 in the flip-gated REQ-6 step (already scheduled; no change).
8. Optional: a CHANGELOG note on the four ops' wire-encoding change (registry policy demands CHANGELOG only for opId removal/rename, but the wire behavior change warrants a line).

The design's 7-step plan has no docs step; items 1-6 are the additions, with item 3 (executable example) the highest-priority one — it is the only stale item that actively breaks when a consumer runs it.
