# Requirements Specification: Form-urlencoded enforcement on token-family endpoints, SDK regeneration, discovery truthiness sweep

Module: `cmd/gensdk` (wire-contract and discovery surfaces it generates against)
Source direction: `docs/architect-analysis/auto/analyses/cmd-gensdk-4ffda121.json` (entry 3)
Related requirement: B4(4) credential-endpoint Content-Type enforcement; B4(3) discovery truthiness.

## 1. Scope

1. Enforce `application/x-www-form-urlencoded` on exactly four endpoints: `/token`,
   `/token/introspect`, `/token/revoke`, `/par`.
2. Regenerate the committed TS/Python SDKs so the token family sends form-encoded
   bodies (the server change is a behavior break for the shipped clients otherwise).
3. Discovery truthiness sweep: assert `token_endpoint == base+PathToken`,
   `jwks_uri == base+PathJWKS`, no `/authenticate` anywhere in the deploy tree, no
   port-pinned discovery assertions; fix the `localhost:8080` server entry drift in
   `docs/openapi.yaml`.

Not in scope: any other endpoint (device, MFA, admin, JAR, login, CIBA-push keep
the JSON convenience), `postRevokeAll` (bearer JSON op), and any other B4 item.

## 2. Evidence verification

Every citation in the direction was checked against the tree. All verified except
two claims corrected below (C1, C2).

| # | Cited evidence | Verification result |
|---|---|---|
| E1 | `protocols/oauth/oauthwire/bind.go` — JSON accepted as non-standard convenience; missing Content-Type defaults to JSON | Confirmed. `BindParams` (bind.go:28) dispatches on Content-Type; only `application/x-www-form-urlencoded` takes the form path; `default:` (bind.go:51-53) decodes single JSON for `application/json`, missing CT, or anything unexpected. Body-only: `r.PostForm` (bind.go:42), so query-param credentials are never bound. |
| E2 | `protocols/oauth/bind_extra_test.go:150` pins the missing-CT→JSON default | Confirmed. `TestBindParamsJSONDefault` (bind_extra_test.go:148), comment at :150: "Missing Content-Type defaults to JSON (the original SDK contract)". |
| E3 | `cmd/gensdk/gen_py.go:100-103` — every body op emits `application/json` | Confirmed. `_request` in `pyClientHeader` (gen_py.go:100-103): `headers["Content-Type"] = "application/json"; data = json.dumps(body).encode("utf-8")` for any non-nil body. |
| E4 | `cmd/gensdk/gen_ts.go:101` `tsUsesClientAuth` | Confirmed at gen_ts.go:101; lists exactly `postToken`, `postIntrospect`, `postRevoke`, `postPAR` (gen_ts.go:102-109). **C1 (correction):** `tsUsesClientAuth` only adds the `clientAuth: true` request option (Basic-auth injection + `client_id`/`client_secret` stripping via `withClientAuthentication`). The JSON emission lives in the shared runtime `tsRuntime` in `cmd/gensdk/gen_ts_runtime.go` (`headers["Content-Type"] = "application/json"; init.body = JSON.stringify(authenticatedBody)`). The fix point is the shared runtime + a per-operation form flag, not this function. |
| E5 | `docs/sdks/typescript/client.ts:2903` — postToken with `{ body, clientAuth: true }` | Confirmed (client.ts:2903); `request()` sets JSON Content-Type at client.ts:1848-1850. `withClientAuthentication` strips `client_id`/`client_secret` from the body and uses HTTP Basic. |
| E6 | `docs/openapi.yaml:1102` declares form-urlencoded for postToken | Confirmed. postToken requestBody has only `application/x-www-form-urlencoded` (openapi.yaml:1102); likewise postIntrospect :1280, postRevoke :1347, postPAR :1477. Additional drift found: the `/token` description at openapi.yaml:1063-1065 says "**Form + JSON** — both ... are accepted via the dispatcher in `oauth_bind.go`" — no `oauth_bind.go` file exists anywhere (stale reference); this text must be rewritten by this change. |
| E7 | `docs/openapi.yaml:55` — `localhost:8080` server URL | Confirmed. `servers:` list at openapi.yaml:54-57 has `http://localhost:8080` ("Local dev (cmd/sso-server default listen)."). Nothing in `docs/docscheck/` asserts on the servers list, so removal is safe for gates. |
| E8 | `interfaces/sso/server_discovery_config.go:146` — `token_endpoint = base + PathToken` | Confirmed (:146-149: TokenEndpoint/JWKSURI/RevocationEndpoint/IntrospectionEndpoint all `base + Path*`). Path constants: `PathToken="/token"` (shared/core/consts.go:21), `PathIntrospect` :22, `PathRevoke` :23, `PathPAR="/par"` :32. |
| E9 | `test/oidc_discovery_test.go:214-216` — absolute https token_endpoint | Confirmed (`TestDiscovery_RespectsXForwardedProto`). Also `TestDiscovery_EndpointsAreAbsoluteURLs` (:85-101) asserts absolute http(s) for all endpoint fields. No suffix/truthiness assertion (`== /token`) exists yet — that is genuinely remaining work. |
| E10 | `interfaces/sso/mesh_authz.go:443`, `interfaces/sso/server_native_sso.go:102` — constant-time compare precedent | Confirmed: `subtle.ConstantTimeCompare` at both. The credential-compare seam this change must not touch is `shared/security/client_secret.go:19` `CompareClientSecret` (bcrypt or `ConstantTimeStringEq`), used by the `/token` client-auth path via `ClientStore.ValidateSecret`. |
| E11 | Legacy defect tests `TestOIDCDiscovery` (asserting `/authenticate`) and `TestOIDCDiscoveryEndpoint` (asserting the `8080:0` port) absent | Confirmed: 0 matches for both across all `*.go`. |
| E12 | `cmd/sso-minimal/edition_test.go` as sweep home | Confirmed: file exists with `editionServer` helper (boots each edition with `cfg.Issuer = "https://issuer.example"`); no discovery sweep exists yet. Deploy tree contains no `"/authenticate"` literal (0 matches tree-wide) — the sweep is a regression guard, not a fix. |
| E13 | `cmd/gensdk` regeneration workflow | Confirmed: `cmd/gensdk/main.go` (`--lang=ts|py|all`), reads embedded spec + `ops/build/sdk-surface.json`; `ops/scripts/sdk_surface.py:119-149` (`python cli.py sdk-surface generate|check`); existing emit tests `cmd/gensdk/emit_test.go:159` (`TestTSClientAuthenticationOperations`) and :207 (`TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`, asserts `{ body, clientAuth: true }` at :231) are the extension points. |
| E14 | Handler bind sites and error mapping | Confirmed: `/token` → `interfaces/sso/server_token.go:29` via `bindOAuthParams` (delegate at `interfaces/sso/server_jar.go:301-304` → `oauth.BindParams`); `/token/introspect` → `protocols/oauth/handle_introspect.go:120`; `/token/revoke` → `handle_revoke.go:75`; `/par` → `handle_par.go:66`. All four map bind failure to `400 invalid_request` (`ErrInvalidRequest`) and all four set no-store headers *before* binding (`server_token.go:21`; `middleware.TokenNoStoreHeaders` at `handle_introspect.go:112`, `handle_revoke.go:68`, `handle_par.go:55`) — so the 400 rejection automatically carries `Cache-Control: no-store` / `Pragma: no-cache`. |
| E15 | JSON-posting tests that break under enforcement | Confirmed: 34 call sites across 14 files post `application/json` to the four endpoints: `test/{handle_introspect_test.go:89,237, oidc_test.go:228, introspection_cache_invalidation_test.go:105,122, oauth_bind_test.go:276, rar_test.go:265,429,480,527, refresh_rotation_claims_test.go:55, introspect_batch_signed_test.go:101,139,163,223, refresh_token_test.go:118,342,375,496, auth_code_test.go:124,484, pkce_test.go:130,421,441, claims_param_test.go:352, handle_token_test.go:59,87,284, handle_par_test.go:112,352, handle_device_test.go:130,312,342}`. Note the device-code grant polls `/token` (RFC 8628 §3.1 also mandates form there) — these migrate, they do not stay JSON. |

**C2 (correction to the acceptance wording):** the direction's acceptance says
`jwks_uri==/jwks`, but `PathJWKS = "/.well-known/jwks.json"` (shared/core/jwks.go:9)
and `server_discovery_config.go:147` emits `base + PathJWKS`. The truthful
assertion is `jwks_uri == base + PathJWKS` (suffix `/.well-known/jwks.json`), not
`/jwks`. The spec below preserves the acceptance's intent (jwks_uri equals the
server's own advertised JWKS route) with the corrected constant.

## 3. Requirements

### REQ-1 — Server: form-only binding for the token family

- REQ-1.1 Add `BindFormParams(ctx core.HandlerContext, v any) error` in
  `protocols/oauth/oauthwire/bind.go` that accepts **only**
  `application/x-www-form-urlencoded` (case-insensitive; `;`-parameters such as
  charset stripped, mirroring `BindParams` CT handling). `application/json`,
  missing Content-Type, and any other Content-Type all return an error.
  Behavior on the accepted path is identical to today's form path
  (`r.ParseForm` + `formIntoStruct(r.PostForm, v)` — body-only, never query
  params). `BindParams` itself is **unchanged** and keeps its JSON convenience
  for every other caller (login, device, MFA, admin, JAR, CIBA) — no scope
  expansion.
- REQ-1.2 Switch the four bind sites to the form-only entry point:
  `interfaces/sso/server_token.go:29` (via a new `bindOAuthFormParams` delegate
  next to `bindOAuthParams` in `interfaces/sso/server_jar.go:301-304`),
  `protocols/oauth/handle_introspect.go:120`, `handle_revoke.go:75`,
  `handle_par.go:66`.
- REQ-1.3 Error contract: all rejection causes (JSON, missing CT, other CT, and
  existing parse failures) return the existing `400 invalid_request`
  (`ErrInvalidRequest`) with byte-identical bodies — no new `Err*`, no
  `docs/error-codes.md` change, no oracle differentiation. Rejections carry
  `Cache-Control: no-store` / `Pragma: no-cache` (headers set before binding).
- REQ-1.4 Unchanged invariants (regression-guarded, not reimplemented): HTTP
  Basic wins over body credentials; `CompareClientSecret` (shared/security/
  client_secret.go:19, bcrypt/constant-time) is untouched; no query-param
  credentials are ever honored.

### REQ-2 — SDKs: form-encoded token family, regenerated

- REQ-2.1 `cmd/gensdk`: add `FormBody bool` to `Operation` (`operations.go`),
  populated by a predicate covering exactly `postToken`, `postIntrospect`,
  `postRevoke`, `postPAR` (mirroring the `tsUsesClientAuth` precedent at
  gen_ts.go:101-109, shared by both emitters). Do not generalize to all
  form-declared operations: `postDeviceCode`, `postDeviceVerify`,
  `postMFAComplete` are in the surface but out of scope (their handlers still
  accept JSON).
- REQ-2.2 TS runtime (`gen_ts_runtime.go`): `request()` gains a `form` request
  option. When set: `Content-Type: application/x-www-form-urlencoded` and body
  built with the URLSearchParams-style repeated-key encoding already used for
  queries (arrays like `resource`/`audience` become repeated keys). When set
  together with `clientAuth`, `withClientAuthentication` still strips
  `client_id`/`client_secret` into HTTP Basic before encoding. Non-form ops
  keep JSON.
- REQ-2.3 Python runtime (`gen_py.go` `pyClientHeader`): `_request` gains a
  `form` parameter. When set: `Content-Type: application/x-www-form-urlencoded`
  and `urllib.parse.urlencode(body).encode("utf-8")` (dict-of-lists yields
  repeated keys, matching the server's multi-value form parsing). `post_token`/
  `post_introspect`/`post_revoke`/`post_par` pass `form=True`; all other
  methods unchanged (JSON).
- REQ-2.4 Emit tests (`cmd/gensdk/emit_test.go`): extend
  `TestTSClientAuthenticationOperations`-style coverage to assert the four ops
  emit the form marker and `postLogin`/`postRevokeAll`/admin/SCIM ops do not
  (TS: `form: true` in the emitted request options; Python: `form=True` in the
  emitted `_request(...)` call). Update
  `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` (:207, asserts
  `{ body, clientAuth: true }` at :231) to the new option set.
- REQ-2.5 Regenerate and commit: `python cli.py sdk-surface generate` (runs
  `go run ./cmd/gensdk --lang=all`); commit `docs/sdks/typescript/client.ts`
  and `docs/sdks/python/client.py` diffs showing the four methods emit
  form-urlencoded with urlencoded bodies and the JSON body path is gone for
  them; `python cli.py sdk-surface check` stays green.
- REQ-2.6 Doc drift in the same change: rewrite the `/token` description at
  `docs/openapi.yaml:1063-1065` (drop "Form + JSON — both ... accepted via the
  dispatcher in `oauth_bind.go`"; the referenced file does not exist) to state
  form-urlencoded only. The four operations' request bodies already declare
  form-urlencoded only — no schema change.

### REQ-3 — Discovery truthiness sweep

- REQ-3.1 New sweep test in `cmd/sso-minimal/edition_test.go` iterating every
  edition (`prototype`, `minimal`, `standard`): boot via `editionServer`, fetch
  `PathOIDCDiscovery`, and assert:
  - `token_endpoint` ends with `sso.PathToken` (`/token`) and equals
    `issuer + PathToken` shape (no `/authenticate`),
  - `jwks_uri` ends with `PathJWKS` (`/.well-known/jwks.json`) — see C2,
  - no `/authenticate` substring anywhere in the raw document body,
  - no port bug: each endpoint URL's port equals the actual `httptest` server
    port, and the raw body contains neither `:8080` nor `:0`.
- REQ-3.2 Deploy-tree guard: a test (in the same file) asserting no
  `"/authenticate"` path literal exists in `cmd/` Go sources (excluding
  `_test.go` comments is unnecessary — the tree currently has 0 matches; the
  guard is a regression lock for the legacy defect).
- REQ-3.3 `docs/openapi.yaml` `servers:` list (openapi.yaml:54-57): remove the
  hardcoded `http://localhost:8080` entry; keep `https://{host}`. No gate
  asserts on the list (verified), no SDK regeneration impact.
- REQ-3.4 Existing discovery guarantees stay green:
  `TestDiscovery_EndpointsAreAbsoluteURLs`, `TestDiscovery_RespectsXForwardedProto`
  (test/oidc_discovery_test.go:85-101, 200-216), `buildBaseMetadata`
  (server_discovery_config.go:146-149), and the absence of
  `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint`.

### REQ-4 — Test migration and regressions

- REQ-4.1 Invert `TestFormEncoded_JSONStillWorks` (test/oauth_bind_test.go:272)
  into a rejection test: `application/json` body → `400 invalid_request`;
  same body with no Content-Type → `400 invalid_request` with a byte-identical
  body; form-urlencoded succeeds.
- REQ-4.2 Migrate the 34 JSON posts enumerated in E15 to form-urlencoded
  bodies (they exercise grants/auth flows, not content negotiation). The
  device-code polls in handle_device_test.go migrate too.
- REQ-4.3 Unit tests for `BindFormParams` next to `bind_extra_test.go`: accepts
  form CT with and without charset parameter; rejects `application/json`,
  missing CT, `text/plain`, `multipart/form-data`; body-only (query-param
  credentials never bound).
- REQ-4.4 New integration assertions for the acceptance's T-9 regression list:
  (a) the `400 invalid_request` rejection on all four endpoints carries
  `Cache-Control: no-store` + `Pragma: no-cache`; (b) Basic auth still
  overrides body credentials on form requests; (c) introspect with valid form
  credentials succeeds and unauthenticated form introspect still returns
  `401 invalid_client` (existing assertions in test/handle_introspect_test.go
  and protocols/oauth/handle_introspect_test.go stay, migrated to form);
  (d) `/token?client_id=...&client_secret=...` with an empty form body never
  authenticates (query credentials ignored).
- REQ-4.5 `test/token_no_store_test.go` stays green (it covers `/token`, `/token/revoke`, `/token/introspect`, login, userinfo, register — not `/par`; `/par` no-store on the rejection path is covered by REQ-4.4a).

## 4. Acceptance criteria (preserved from the direction, made testable)

- **AC-1 (T-9, server):** For each of `/token`, `/token/introspect`,
  `/token/revoke`, `/par` with a valid-parameter payload: Content-Type
  `application/json` → `400` with `error=invalid_request`; no Content-Type →
  `400` with `error=invalid_request`, body byte-identical to the JSON case;
  `application/x-www-form-urlencoded` (with or without charset) → success
  path; any other Content-Type (`text/plain`, `multipart/form-data`) → `400
  invalid_request`.
- **AC-2 (T-9, SDKs):** `python cli.py sdk-surface generate` then `check`
  succeed; the committed `docs/sdks/typescript/client.ts` and
  `docs/sdks/python/client.py` diffs show `postToken`/`postIntrospect`/
  `postRevoke`/`postPAR` emitting `application/x-www-form-urlencoded` with
  urlencoded bodies (TS: URLSearchParams-style; Python: `urlencode`), and
  `cmd/gensdk/emit_test.go` asserts the four ops carry the form marker while
  every other surfaced op retains JSON.
- **AC-3 (T-9, regressions):** no-store/Pragma on all four endpoints including
  the 400 rejection (REQ-4.4a); constant-time credential compare
  (`CompareClientSecret`) untouched; body-only parsing proven (REQ-4.4d);
  introspect caller auth still enforced (REQ-4.4c); Basic-over-body precedence
  still holds (REQ-4.4b).
- **AC-4 (T-2, discovery):** the `cmd/sso-minimal/edition_test.go` sweep
  asserts `token_endpoint` suffix `/token`, `jwks_uri` suffix
  `/.well-known/jwks.json`, no `/authenticate` in the served documents for
  every edition, no port-pinned/`:0`/`:8080` content; the deploy-tree guard
  finds no `"/authenticate"` literal in `cmd/`; `docs/openapi.yaml` no longer
  advertises `localhost:8080`; the legacy defect tests remain absent.

## 5. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./protocols/oauth/... ./interfaces/sso/... ./cmd/gensdk/... -count=1
go test ./test/ -run 'TestFormEncoded|TestToken|TestIntrospect|TestRevoke|TestPAR|TestDevice|TestDiscovery|TestNoStore' -v
go test ./... -race
go test ./test/ -run TestE2E -v
python cli.py sdk-surface check
python cli.py sdk-surface generate   # then re-check; commit client.ts/client.py
make ci
```

## 6. Out of scope (explicit)

- `postDeviceCode`/`postDeviceVerify`/`postMFAComplete` SDK emission and their
  handlers' JSON acceptance (same drift class: openapi declares form-only for
  device endpoints, handlers still accept JSON via `BindParams`) — flagged,
  separate change.
- `postRevokeAll` (`/token/revoke-all`, bearer JSON) and all JSON-declared ops
  (`postLogin`, admin, SCIM, SSF, federation).
- Any other B4 item (scope registry, tenant_id/roles claims, iss allowlist).

## 7. Risks and notes

- Behavior change is intentional and is the point of B4(4); the blast radius is
  bounded to four routes but includes the device-code poll path (migrated in
  REQ-4.2). External clients that relied on the documented-JSON convenience on
  these four endpoints will break — that is the acceptance outcome.
- Oracle safety: REQ-1.3 keeps all rejection causes byte-identical
  `400 invalid_request`; no audit detail beyond what exists today.
- The generator change is hardcoded to the four ops (REQ-2.1) to match the
  existing `tsUsesClientAuth` precedent; generalizing to spec-driven content
  types is deferred and would also touch device/MFA ops (out of scope).
