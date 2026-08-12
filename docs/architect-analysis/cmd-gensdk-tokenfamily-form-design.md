# Design: Form-urlencoded enforcement on token-family endpoints, SDK regeneration, discovery truthiness sweep

Companion to `docs/architect-analysis/cmd-gensdk-tokenfamily-form-spec.md`. This
document treats that spec (and the direction it cites) as untrusted evidence,
records what was independently verified, corrects the drift found, and turns the
requirements into a concrete, ordered design with API changes, compatibility
constraints, failure modes, migration steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation in the spec was re-checked against the tree. The spec's own two
corrections (C1, C2) are confirmed correct. Four further drifts were found and
are incorporated below (C3–C6); none invalidates the scope, one reverses a
"no schema change" claim (C4) and one shrinks the discovery sweep (C5).

| # | Claim | Verdict |
|---|---|---|
| E1 | `BindParams` (oauthwire/bind.go): form path only for `application/x-www-form-urlencoded`; JSON/missing-CT/other default to JSON; `r.PostForm` body-only | Confirmed (`bind.go:28-53`) |
| E2 | `bind_extra_test.go:148-150` pins missing-CT→JSON default | Confirmed (`TestBindParamsJSONDefault`) |
| E3 | `gen_py.go:100-103` emits JSON for every body op | Confirmed |
| E4/C1 | `gen_ts.go:101-109` `tsUsesClientAuth` is the client-auth marker (four ops); JSON emission lives in `gen_ts_runtime.go:154-159` | Confirmed |
| E5 | `client.ts:2903` `{ body, clientAuth: true }`; `client.ts:1848-1850` and `client.py:1453-1454` JSON emission | Confirmed |
| E6 | Form-only openapi declarations at `openapi.yaml:1102/1280/1347/1477` | **Corrected (C4): only 1102 (postToken) is form-only; postIntrospect (1280), postRevoke (1347), postPAR (1477) declare form + JSON both.** |
| E7 | `openapi.yaml:55` `localhost:8080`; nothing in `docs/docscheck/` asserts on servers | Confirmed (docscheck is route/keys-only; no content-type or servers assertions) |
| E8 | Discovery metadata `base + Path*` at `server_discovery_config.go:146-149`; `PathToken`/`PathIntrospect`/`PathRevoke`/`PathPAR` in `shared/core/consts.go:21-23,32` | Confirmed |
| E9 | `oidc_discovery_test.go:85-101, 200-216` absolute-URL / XFP tests; no suffix assertion exists | Confirmed |
| E10 | Constant-time compare precedents `mesh_authz.go:443`, `server_native_sso.go:102`; untouched seam `CompareClientSecret` (`shared/security/client_secret.go:19`) | Confirmed |
| E11 | Legacy defect tests `TestOIDCDiscovery` / `TestOIDCDiscoveryEndpoint` absent | Confirmed (0 matches) |
| E12 | `cmd/sso-minimal/edition_test.go` has `editionServer` helper; no `"/authenticate"` literal tree-wide | Confirmed |
| E13 | gensdk extension points: `emit_test.go:159/207/231`, `Operation` (`operations.go:58`), `cli.py sdk-surface` → `ops/scripts/sdk_surface.py:119-149` (`go run ./cmd/gensdk --lang=all`) | Confirmed |
| E14 | Four bind sites `server_token.go:29` (via `bindOAuthParams` delegate `server_jar.go:301-304`), `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`; all → `400 invalid_request`; no-store set before binding | Confirmed (`TokenNoStoreHeaders` at introspect:112 / revoke:68 / par:55; `tokenNoStoreHeaders` at server_token.go:21) |
| E15 | 34 JSON call sites across 14 test files | **Corrected (C3): 33 direct `http.Post` sites (enumeration matches exactly) plus 2 `http.NewRequest`+`Header.Set("Content-Type","application/json")` sites on `/token/introspect` omitted from the enumeration (`handle_introspect_test.go:202` `TestIntrospect_AcceptsBasicAuth`; `introspect_batch_signed_test.go:248` `TestIntrospectSigned_UnwiredSignerStaysPlainJSON`). True surface: 35 sites in the same 14 files.** |
| C2 | `PathJWKS = "/.well-known/jwks.json"` (`shared/core/jwks.go:9`); acceptance must assert `base + PathJWKS` | Confirmed |

### New corrections

- **C3 — migration surface is 35, not 34** (see E15). The two missed sites are
  exactly the REQ-4.4c introspect caller-auth regressions; they must migrate
  too or they fail under enforcement.
- **C4 — openapi content types: the contract edit is required, not "no schema
  change".** Only `postToken` is declared form-only today; `postIntrospect`,
  `postRevoke`, `postPAR` each advertise `application/json` alongside the form
  media type (openapi.yaml:1280-1283, 1347-1350, 1477-1480). The openapi is
  currently the document that legitimizes JSON on three of the four endpoints.
  Making the handlers reject JSON while the openapi still advertises it would
  create doc/code drift in the opposite direction (AGENTS.md §1: satisfy the
  stricter contract, report). This change must therefore remove the JSON
  siblings for those three ops in the same change. The spec's out-of-scope
  note ("openapi declares form-only for device endpoints") is also wrong in
  the other direction: `postDeviceCode` (:1543), `postDeviceVerify` (:1845),
  `postMFAComplete` (:643), `postBackchannelAuthentication` (:1604) declare
  **both** media types, matching their handlers' JSON acceptance — there is no
  drift in the out-of-scope set, and nothing to fix there.
- **C5 — the discovery sweep iterates two editions, not three.**
  `cmd/sso-minimal` has exactly two runtime editions (`editionPrototype`,
  `editionMinimal`; `edition.go:8-9`). "standard" is a build profile
  (`platform/buildinfo/modules.go:15`, default `BuildProfile`) that resolves
  to `editionMinimal` (`edition_test.go:26` already pins
  `{"standard", editionMinimal, ...}`). REQ-3.1's "(prototype, minimal,
  standard)" becomes: iterate the two runtime editions; the standard→minimal
  alias is already covered by `TestEditionCapabilities`.
- **C6 — `PathOIDCDiscovery` lives in `interfaces/sso/server_discovery.go:18`**
  (`"/.well-known/openid-configuration"`), not `shared/core/consts.go`; the
  sweep imports it from there (or uses the literal, which is already
  tree-consistent).
- **C7 — device polls are in scope and are form-after-migration.** Confirmed:
  `handle_device_test.go:130/312/342` poll `/token` (RFC 8628 §3.1 mandates
  form there) and are part of the 35-site surface.

## 2. API changes

### 2.1 Server wire contract (four endpoints)

| Endpoint | Today | After |
|---|---|---|
| `POST /token` | form or JSON (form-only in openapi) | form only |
| `POST /token/introspect` | form or JSON (both in openapi) | form only |
| `POST /token/revoke` | form or JSON (both in openapi) | form only |
| `POST /par` | form or JSON (both in openapi) | form only |

- **New internal API:** `func BindFormParams(ctx core.HandlerContext, v any) error`
  in `protocols/oauth/oauthwire/bind.go`, next to `BindParams`. Behavior:
  - Content-Type normalized exactly like `BindParams` (case-insensitive,
    `;`-parameter suffix stripped).
  - Only `application/x-www-form-urlencoded` proceeds: `r.ParseForm()` +
    `formIntoStruct(r.PostForm, v)` — identical to today's form path, body-only,
    never query params.
  - `application/json`, missing Content-Type, and any other Content-Type
    return an error. The error text is intentionally uninformative
    (`oauth: request Content-Type must be application/x-www-form-urlencoded`);
    every caller maps it to the existing `400 invalid_request`
    (`ErrInvalidRequest`), so bodies stay byte-identical across all rejection
    causes — no new `Err*`, no `docs/error-codes.md` change, no oracle
    differentiation.
  - `BindParams` is untouched: CIBA (`handle_ciba.go:87`), MFA
    (`server_mfa.go:255`), device (`server_device.go:53,242`), admin
    (`options_admin.go:413`, `server_admin_handlers.go:293`) keep JSON.
- **Four call-site switches:**
  - `interfaces/sso/server_token.go:29` — via new delegate
    `bindOAuthFormParams` next to `bindOAuthParams` (`server_jar.go:301-304`),
    preserving the `interfaces`-package alias pattern.
  - `protocols/oauth/handle_introspect.go:120`, `handle_revoke.go:75`,
    `handle_par.go:66` — direct `BindFormParams` calls (these packages import
    oauthwire directly via `aliases.go`).
- **No handler logic changes beyond the bind call.** Basic-wins precedence,
  `CompareClientSecret`, revoke-always-200, introspect inactive `{"active":false}`,
  PAR 501-when-store-missing (checked before binding, `handle_par.go:56`) all
  stay as-is. No-store headers are already set before binding on all four
  paths, so the 400 rejection automatically carries
  `Cache-Control: no-store` + `Pragma: no-cache`.

### 2.2 SDK generator and committed clients

- `cmd/gensdk/operations.go:58` `Operation` gains `FormBody bool`.
- New shared predicate (next to `tsUsesClientAuth`, same switch shape, used by
  both emitters):
  `func usesFormBody(operationID string) bool` returning true for exactly
  `postToken`, `postIntrospect`, `postRevoke`, `postPAR`. It is hardcoded to
  the four ops on purpose — generalizing to spec-driven media types would
  pull in device/MFA/CIBA ops whose handlers still accept JSON (out of scope).
- **TS runtime** (`gen_ts_runtime.go`): `requestOptions` gains
  `form?: boolean` (line 35-39). In `request()` the form path slots where
  `authenticatedBody` is already computed (line 154), so
  `withClientAuthentication` still strips `client_id`/`client_secret` into
  HTTP Basic before encoding:
  - `form` set: `headers["Content-Type"] = "application/x-www-form-urlencoded"`;
    body built with URLSearchParams-style repeated-key encoding (arrays such as
    `resource`/`audience` — `TokenRequest`/`PARRequest` `[]string` fields —
    become repeated keys), matching the server's multi-value form parsing.
  - `form` unset: today's JSON path unchanged.
- **TS emitter** (`gen_ts.go:66-90` `tsEmitRequestOpts`): `op.FormBody` appends
  `form: true` to the request-options literal.
- **Python runtime** (`gen_py.go` `pyClientHeader`, lines 76-110): `_request`
  gains `form: bool = False`; when `form` and `body is not None`:
  `headers["Content-Type"] = "application/x-www-form-urlencoded"` and
  `data = urllib.parse.urlencode(body, doseq=True).encode("utf-8")`
  (dict-of-lists → repeated keys). Non-form ops keep
  `json.dumps(body).encode("utf-8")`.
- **Python emitter** (`gen_py.go:163-176`): `op.FormBody` appends
  `, form=True` to the emitted `_request(...)` call. Method signatures
  (`post_token(body)`, …) are unchanged — only the wire format of the body.
- **Committed clients:** regenerate via `python cli.py sdk-surface generate`
  (runs `go run ./cmd/gensdk --lang=all`); commit
  `docs/sdks/typescript/client.ts` + `docs/sdks/python/client.py`. The four
  methods lose the JSON body path; `postLogin`, `postRevokeAll`, admin, SCIM,
  SSF ops keep it. `python cli.py sdk-surface check` must stay green (the
  registry is an operationId allowlist; content types are not recorded).

### 2.3 OpenAPI contract edits (required by C4 — same change)

- Remove the `application/json` sibling block for `postIntrospect`
  (openapi.yaml:1282-1283), `postRevoke` (1349-1350), `postPAR` (1479-1480).
  `postToken` already form-only — no edit.
- Rewrite the `/token` description at openapi.yaml:1063-1065: drop the stale
  "Form + JSON … dispatcher in `oauth_bind.go`" text (no such file exists
  anywhere in the tree) and state form-urlencoded only.
- `servers:` list (openapi.yaml:54-57): remove the hardcoded
  `http://localhost:8080` entry; keep `https://{host}`. Verified: no
  `docs/docscheck/` test asserts on the list.

### 2.4 Discovery truthiness sweep (REQ-3, corrected per C5/C6)

New sweep in `cmd/sso-minimal/edition_test.go`, iterating exactly
`editionPrototype` and `editionMinimal` via the existing `editionServer`
helper (boots with `cfg.Issuer = "https://issuer.example"`):

- Fetch `interfaces/sso.PathOIDCDiscovery` (`server_discovery.go:18`).
- `token_endpoint == issuer + PathToken` (`/token`), `jwks_uri == issuer +
  PathJWKS` (`/.well-known/jwks.json`) — the C2-corrected acceptance — and
  `introspection_endpoint`/`revocation_endpoint` suffix checks.
- No `/authenticate` substring in the raw document body.
- No port pinning: endpoint URLs carry the actual `httptest` server port; raw
  body contains neither `:8080` nor `:0`.
- Deploy-tree guard (same file): no `"/authenticate"` path literal in `cmd/`
  Go sources (0 matches today; pure regression lock).
- `TestEditionCapabilities` already pins the `standard`→`minimal` alias; the
  sweep need not and must not iterate a third edition.

## 3. Compatibility constraints

1. **Breaking wire change, bounded to four routes.** Any external client that
   POSTs JSON (or omits Content-Type) to `/token`, `/token/introspect`,
   `/token/revoke`, `/par` gets `400 invalid_request` after this lands. That is
   the acceptance outcome, not a defect. The shipped SDKs are regenerated in
   the same change so the default client surfaces never break; every other
   endpoint (login, device/code + device/verify, MFA, admin, JAR, CIBA,
   revoke-all, registration, SCIM, SSF) keeps its JSON convenience.
2. **Oracle safety is preserved.** All rejection causes (JSON, missing CT,
   other CT, parse failures) yield the same byte-identical `400
   invalid_request` body with no-store headers. No new error code, no
   `docs/error-codes.md` change, no audit detail added.
3. **Credential handling unchanged.** HTTP Basic still wins over body
   credentials; `CompareClientSecret` (`shared/security/client_secret.go:19`)
   untouched; query-param credentials never bound (`r.PostForm` body-only);
   missing-CT-with-empty-body still fails, now with the same 400 shape.
4. **SDK public API stability.** `postToken(body)`, `postIntrospect(body)`,
   `postRevoke(body)`, `postPAR(body)` signatures and return types are
   unchanged; only the emitted wire format of the body changes. TS
   `requestOptions` gains an additive `form?` flag; Python `_request` gains an
   additive keyword parameter with a default.
5. **Discovery contract unchanged.** Endpoint URLs and suffix shapes are
   already correct (`buildBaseMetadata`); the sweep only locks them. OpenAPI
   servers-list edit is doc-only.
6. **Budget gates.** No new files: `bind.go` grows by ~20 lines (well under
   500), `gen_ts.go`/`gen_py.go`/`gen_ts_runtime.go` by a few lines each,
   `operations.go` by one field; `cmd/gensdk` stays at 9 non-test files
   (≤10). `interfaces/sso` is at its 60-file ceiling — the new delegate lives
   in the existing `server_jar.go`, no new file.

## 4. Failure modes

| # | Failure mode | Detection | Mitigation |
|---|---|---|---|
| F1 | External JSON-speaking clients on the four endpoints break (including RFC 8628 device polls — they must switch to form per the RFC anyway) | 400 `invalid_request` in client logs; `parse_error`-class errors surface in audit only as today | Intentional. Release note + regenerated SDKs land in the same commit; migration step M4 converts all in-repo callers |
| F2 | Doc/code drift if the openapi JSON siblings are not removed (C4) | `docs/openapi.yaml` advertises JSON the server rejects | M7 removes them in the same change; openapi review gate |
| F3 | Missed JSON call sites in `test/` → suite red | `go test ./test/...` failures under enforcement | M4 enumerates all 35 sites (C3 list), including the two `NewRequest`+`Header.Set` sites the spec missed |
| F4 | SDK regen diffs surprise (`form: true`/`form=True` in wrong ops) | `cmd/gensdk/emit_test.go` tables + `sdk-surface check` | M5/M6 pin the four ops positive and the JSON ops negative |
| F5 | PAR rejection test flaky if PAR store unconfigured | 501 short-circuits before binding (`handle_par.go:56`) | Acceptance tests for `/par` must boot with `WithPARStore` (the existing `newPARHarness`-style helpers do) |
| F6 | Basic-auth stripping + form encoding ordering bug in TS client (strip after encode would leak `client_secret` into the body) | emit test + committed client review | Form encoding happens strictly after `withClientAuthentication` (slot at `gen_ts_runtime.go:154`); add a runtime-level unit assertion in emit tests if feasible |
| F7 | Sweep flakiness from port-dependent assertions | `httptest` port embedded in metadata | Assert `url.Port() == server port` rather than a fixed value; assert `:8080`/`:0` absence in the raw body |
| F8 | `postToken` JSON path removal in openapi is already form-only; nothing else to remove there — regressing by touching it | n/a | Explicitly no-op for postToken |

## 5. Migration steps (ordered; each step keeps the tree green)

- **M1 — Server bind API.** Add `BindFormParams` to `oauthwire/bind.go`;
  add `bindOAuthFormParams` delegate next to `bindOAuthParams`
  (`server_jar.go`); switch the four sites (`server_token.go:29`,
  `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`).
  Mandatory gates: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`
- **M2 — Unit tests.** New `BindFormParams` tests in `protocols/oauth/`
  next to `bind_extra_test.go`: form CT with and without charset accepted;
  `application/json`, missing CT, `text/plain`, `multipart/form-data`
  rejected; body-only (query credentials never bound). Invert
  `TestFormEncoded_JSONStillWorks` (`test/oauth_bind_test.go:272`) into the
  three-way rejection test (JSON → 400; no CT → 400 byte-identical;
  form → success).
- **M3 — Regression additions.** (a) `400 invalid_request` rejection on all
  four endpoints carries `Cache-Control: no-store` + `Pragma: no-cache`
  (extend `test/token_no_store_test.go` which today covers `/token`,
  `/token/revoke`, `/token/introspect` but not `/par`); (b) Basic-over-body
  precedence on a form request; (c) introspect caller auth — migrate
  `TestIntrospect_AcceptsBasicAuth` (the C3-missed site at
  handle_introspect_test.go:202) and assert unauthenticated form introspect
  still returns `401 invalid_client`; (d) `/token?client_id=…&client_secret=…`
  with empty form body never authenticates (query ignored).
- **M4 — Migrate the 35 JSON call sites** (C3 list, 14 files) to
  form-urlencoded bodies. Direct posts become `http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(url.Values{…}.Encode()))`;
  the two `NewRequest` sites set the form Content-Type. Device polls
  (`handle_device_test.go:130/312/342`) migrate too.
- **M5 — Generator.** `Operation.FormBody` + `usesFormBody` predicate +
  TS/Python runtime form modes + emitter changes; extend
  `TestTSClientAuthenticationOperations`-style tables and update
  `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`
  (emit_test.go:207, expected `{ body, clientAuth: true }` at :231 →
  `{ body, clientAuth: true, form: true }`).
- **M6 — Regenerate and commit clients.** `python cli.py sdk-surface generate`
  then `check`; commit `docs/sdks/typescript/client.ts` +
  `docs/sdks/python/client.py`.
- **M7 — OpenAPI.** Remove the three JSON siblings (C4), rewrite the `/token`
  description (:1063-1065), drop the `localhost:8080` server entry (:54-57).
- **M8 — Discovery sweep.** Add the two-edition sweep + deploy-tree guard to
  `cmd/sso-minimal/edition_test.go` (C5/C6).
- **M9 — Full gates.** `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  `make ci`.

## 6. Testable acceptance mapping

| Acceptance | Testable form | Location |
|---|---|---|
| AC-1 (server CT matrix) | Table test: 4 endpoints × (JSON → 400 `invalid_request`; no CT → 400, body byte-identical to JSON case; form ± charset → success path; `text/plain`/`multipart/form-data` → 400) | `test/oauth_bind_test.go` (inverted `TestFormEncoded_JSONStillWorks`), `protocols/oauth/bind_extra_test.go`, per-endpoint tests in `test/handle_token_test.go`, `handle_introspect_test.go`, `handle_revoke`-adjacent, `handle_par_test.go` (PAR harness must configure the PAR store — F5) |
| AC-2 (SDK emission) | `emit_test.go`: `usesFormBody` table (four ops true; `postLogin`, `postRevokeAll`, admin/SCIM ops false); generated TS contains `form: true`, Python `form=True` only for the four; `python cli.py sdk-surface generate && check` green; committed `client.ts`/`client.py` diffs show form-urlencoded + urlencoded bodies and no JSON path for the four methods | `cmd/gensdk/emit_test.go`, `ops/scripts/sdk_surface.py` |
| AC-3 (regressions) | (a) no-store + Pragma on all four endpoints including 400 rejection — extend `test/token_no_store_test.go` with a `/par` rejection case; (b) Basic-over-body precedence — existing + migrated `TestIntrospect_AcceptsBasicAuth`, `handle_par_test.go` Basic cases; (c) unauthenticated form introspect → `401 invalid_client` — existing introspect tests stay green post-migration; (d) query-credential rejection — new test in M3d; `CompareClientSecret` untouched — existing secret-validation tests green | `test/`, `protocols/oauth/` |
| AC-4 (discovery truthiness) | Sweep: for `prototype` and `minimal`: `token_endpoint == issuer+PathToken`, `jwks_uri == issuer+PathJWKS` (C2), no `/authenticate` substring, no `:8080`/`:0`, endpoint ports equal the `httptest` port; deploy-tree guard: no `"/authenticate"` literal in `cmd/`; openapi has no `localhost:8080` (docscheck + grep in the sweep file); legacy `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` remain absent | `cmd/sso-minimal/edition_test.go` |
| AC-5 (contract alignment, from C4) | openapi requests for `postIntrospect`/`postRevoke`/`postPAR` declare form only; `/token` description no longer references `oauth_bind.go` | grep/awk assertions in `docs/docscheck/` or the sweep file |

## 7. Out of scope (unchanged, corrected justification)

- `postDeviceCode`/`postDeviceVerify`/`postMFAComplete`/`postBackchannelAuthentication`:
  handlers keep JSON and the openapi honestly declares both media types — no
  drift, no action (C4).
- `postRevokeAll` (bearer, no request body — openapi.yaml:1395).
- All JSON-declared ops (`postLogin`, admin, SCIM, SSF, federation).
- Any other B4 item.

## 8. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./protocols/oauth/... ./interfaces/sso/... ./cmd/gensdk/... ./cmd/sso-minimal/... -count=1
go test ./test/ -run 'TestFormEncoded|TestToken|TestIntrospect|TestRevoke|TestPAR|TestDevice|TestDiscovery|TestNoStore' -v
go test ./... -race
go test ./test/ -run TestE2E -v
python cli.py sdk-surface check
python cli.py sdk-surface generate   # then re-check; commit client.ts/client.py
make ci
```
