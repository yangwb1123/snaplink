# Requirements Spec: discovery truthiness sweep + purge the localhost:8080 port drift from the generator's spec input

- Direction: "Discovery truthiness sweep + purge the localhost:8080 port drift from the generator's spec input (B4-3)" (source: `docs/architect-analysis/auto/analyses/cmd-gensdk-4ffda121.json`, entry 2)
- Analysis module: `cmd/gensdk`; change surface: `docs/openapi.yaml` (spec input purge) + `cmd/sso-minimal/edition_test.go` (edition discovery sweep) + one new deploy-tree guard test in `cmd/sso-minimal` + one new spec-input regression test in `cmd/gensdk`. No production Go changes anywhere.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `docs/openapi.yaml:54-57` — `servers:` list with `http://localhost:8080` "Local dev" entry | `servers:` at line 54; entry `url: http://localhost:8080` + `description: Local dev (cmd/sso-server default listen).` at 55-56; production entry `url: https://{host}` (variables `host` default `sso.example.com`) at 57-61. Drift present exactly as cited | Confirmed |
| "docscheck gates do not assert on it" | No `servers`/`localhost`/`8080` reference in `checks/`, `docs/agent-os/CHECKS_REGISTRY.md`, or `ops/scripts/` (doc gates are `route_contract.py` — routes vs OpenAPI operations — and `sdk_surface.py` — operationId registry; neither reads `servers:`). No Go test parses the `servers:` list (repo-wide grep, 0 relevant hits) | Confirmed |
| `cmd/sso-minimal/edition_test.go` — `editionServer` helper exists; no discovery sweep | Helper at line 112 (`editionServer(t, edition runtimeEdition) (*httptest.Server, runtimeConfig)`; `httptest.NewServer(app)`, `cfg.Issuer = "https://issuer.example"`, `t.Cleanup(server.Close)`). Five tests only: `TestEditionCapabilities` (17), `TestPrototypeExposesOAuthWithoutOIDC` (39), `TestMinimalAddsOIDCAndTracing` (56), `TestDefaultTenantIsStableMigrationAnchor` (82), `TestJSONLoggerCarriesTraceID` (99). No `token_endpoint`/`jwks_uri`/`/authenticate`/port sweep | Confirmed |
| `interfaces/sso/server_discovery_config.go:146-149` — `buildBaseMetadata` emits `base + PathToken` / `base + PathJWKS` | `buildBaseMetadata(s, base)` at 142; `AuthorizationEndpoint: base + PathLogin`, `TokenEndpoint: base + PathToken`, `JWKSURI: base + PathJWKS`, `RevocationEndpoint: base + PathRevoke`, `IntrospectionEndpoint: base + PathIntrospect` at 145-149 | Confirmed (exact lines 145-149) |
| `shared/core/consts.go:21-23` — `PathToken=/token`, `PathIntrospect`, `PathRevoke` | `PathToken = "/token"` (21), `PathIntrospect = "/token/introspect"` (22), `PathRevoke = "/token/revoke"` (23); `PathLogin = "/auth/login"` (9) | Confirmed |
| `shared/core/jwks.go:9` — `PathJWKS=/.well-known/jwks.json` (corrected constant, not `/jwks`) | `const PathJWKS = "/.well-known/jwks.json"` at line 9 | Confirmed |
| `test/oidc_discovery_test.go:85-101,200-216` — `TestDiscovery_EndpointsAreAbsoluteURLs`, `TestDiscovery_RespectsXForwardedProto`; absolute-URL coverage only, no suffix/truthiness assertion | `TestDiscovery_EndpointsAreAbsoluteURLs` at 88 (spans 88-101; asserts `http(s)://` prefix on 7 endpoint fields — empty/absolute only, no suffix check); `TestDiscovery_RespectsXForwardedProto` at 200 (spans 200-216; `https://public.example.com` prefix only). `newDiscoveryServer` at 21 | Confirmed (line drift 3; no suffix assertion) |
| Legacy defect tests absent | `rg 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' --include='*.go'` → 0 hits repo-wide; `rg '"/authenticate"' --include='*.go' cmd/` → exactly 1 hit: `cmd/sso-ctl/generate/scaffold_contract_test.go:136` (`bytes.Contains(content, []byte("/authenticate"))` — an anti-pattern **guard** over generated scaffolds, the pattern this spec extends). Non-test cmd/ Go sources: 0 hits | Confirmed, with one scoping correction (see R2) |
| "there is no deploy-tree guard against an `/authenticate` literal" | No test sweeps the cmd/ tree itself. The only adjacent guard is `assertNoLegacyPathPort` (`cmd/sso-ctl/generate/scaffold_contract_test.go:128-146`, R3.1/R3.2 of the verify-gate requirements) which asserts generated **scaffold output** is free of `/authenticate`, `8080`, `https?://...:[0-9]+`, and `host:port:port` shapes — it never scans the deploy tree's Go sources | Confirmed |
| `ops/build/sdk-surface.json` discovery group — 10 ops incl. `getOpenIDConfiguration`/`getOAuthAuthorizationServerMetadata`/`getJWKS` | Group `discovery` (`capability: oidc.core`) has exactly 10 operations: `getJWKS`, `getOAuthAuthorizationServerMetadata`, `protectedResourceMetadata`, `getOpenIDConfiguration`, `resolveMeNetPolicy`, `postSetup`, `getSetupStatus`, `getAPIVersionPreview`, `getCheckSessionIframe`, `getHealth` (lines 253-265) | Confirmed |
| `python cli.py sdk-surface generate && check` | `cli.py:39` routes `sdk-surface` to `ops/scripts/sdk_surface.py`; `generate` = `go run ./cmd/gensdk --lang=all` (line 146-151), `check` validates registry vs `docs/openapi.yaml` operationIds + `ops/build/capabilities.json` + language output files (lines 112-124). The generator's spec input is `docs.OpenAPISpec` (embedded from `docs/openapi.yaml` via `go:embed`, `docs/openapi_embed.go:28`; `cmd/gensdk/main.go:63-70`) | Confirmed |
| Campaign context B4-3/T-2 | `docs/campaigns/implementation-gate.md` row 3: legacy defect regression tests (`TestOIDCDiscovery` asserting `/authenticate`; `TestOIDCDiscoveryEndpoint` asserting the `8080:0` port bug) "不得带入部署仓"; T-2 = sweep all green, `token_endpoint == "/token"` | Confirmed |

Additional facts verified to make the acceptance testable (not in the direction, required to pin its assertions):

| New fact | Measured reality |
|---|---|
| Discovery base is request-derived | `handleOIDCDiscovery` computes `base := requestBaseURL(ctx.Request())` (`server_discovery_config.go:62`) — the served endpoints carry the live request host:port, so the httptest ephemeral port appears in `token_endpoint`/`jwks_uri` and the port assertion is testable. Both `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` are served by the same handler → byte-identical docs (`server_discovery.go:18-30`; alias const `PathOAuthAuthorizationServerMetadata = "/.well-known/oauth-authorization-server"`, `shared/core/consts.go:68`) |
| Prototype edition gates OIDC discovery off | `TestPrototypeExposesOAuthWithoutOIDC` asserts 404 on `PathOIDCDiscovery`; `featureGatesForEdition` sets `OIDC: sso.Bool(edition.oidcEnabled())` (`app.go:184`). The RFC 8414 alias stays served. The five `buildBaseMetadata` endpoint fields are unconditional (only UserInfo/EndSession are `oidcGateOn`-gated, `server_discovery_config.go:159`) |
| "standard" profile resolves to `editionMinimal` | `edition.go:18-22` (`editionForProfile` returns `editionMinimal` for "standard"); locked by `TestEditionCapabilities`. No third runtime edition exists — the sweep iterates the three build profiles through `editionForProfile` |
| The generator does not consume the `servers:` list | `base_url` is a runtime constructor parameter (`gen_py.go:83-84` `def __init__(self, base_url: str, ...)`; TS equivalent); no `servers` handling in `cmd/gensdk`. Removing the localhost entry therefore leaves generated output byte-identical — the "wire shape unchanged" acceptance is a regeneration-stability assertion |
| Committed discovery surface | `docs/sdks/typescript/client.ts:2957-2976` (`getJWKS` → `/.well-known/jwks.json`, `getOAuthAuthorizationServerMetadata` → `/.well-known/oauth-authorization-server`, `getOpenIDConfiguration` → `/.well-known/openid-configuration`, all `Promise<OpenIDConfiguration>`/`Promise<JWKS>`); `docs/sdks/python/client.py:2324` (`get_jwks`). Zero `8080` content in either client today |

## 2. Goal and user outcome

Server-side discovery is already truthful: every advertised endpoint is `requestBaseURL + core.Path*` (`buildBaseMetadata`), the legacy `/authenticate` defect is gone, and the legacy defect tests were deleted rather than carried forward. What the contract demands as regression guards does not exist yet:

1. No test sweeps the served discovery document across the sso-minimal editions for suffix truthiness (`/token`, `/.well-known/jwks.json`), for the `/authenticate` substring, or for the port-bug shapes (`:8080`, `8080:0`).
2. No guard prevents an `/authenticate` literal from re-entering the deploy tree's Go sources.
3. The generator's single spec input still advertises a hardcoded `http://localhost:8080` server entry — the exact port-drift class B4-3 says must never be carried into the deploy tree — and it is what the 10-op `discovery` surface group generates against. No gate asserts on it today.

Completion marker: the served discovery document for every sso-minimal edition is byte-truthful against `core.Path*` constants (suffix + port assertions), the cmd/ deploy tree is regression-locked against the `/authenticate` literal, the spec input no longer advertises a hardcoded dev port, and regeneration of both SDKs stays byte-identical.

## 3. Product boundary

- Surface: test-only truthiness/regression coverage plus one informational edit to the OpenAPI spec's `servers:` list. No server behavior, no generator production code, no route or wire changes.
- Defaults: discovery endpoints derive from the request base (`requestBaseURL`); the sweep fetches through the live httptest server, so the ephemeral port is what must appear in every advertised endpoint URL.
- Explicit non-goals (do not implement):
  - No changes to `interfaces/sso/*`, `shared/core/*`, `protocols/*`, `test/oidc_discovery_test.go`, `ops/build/sdk-surface.json`, `ops/scripts/sdk_surface.py`, or any `cmd/gensdk` production file.
  - No port/`8080` sweep added to the deploy-tree guard (R2) — the direction scopes that guard to the `/authenticate` literal only; ports are covered by the served-document sweep (R1) and the spec-input lock (R3). The `assertNoLegacyPathPort` scaffold guard already covers generated-scaffold ports and stays untouched.
  - No new `TestOIDCDiscovery`/`TestOIDCDiscoveryEndpoint` tests anywhere (legacy defect tests are not recreated).
  - No issuer/allowlist work (that is the separate B4-1 direction), no `server_discovery.go` changes, no new `Err*`, config keys, routes, or audit events.
  - No change to `cmd/sso-server/config.yaml` (its `base_url: http://localhost:8080` is a sample-config value, not the generator's input; the direction's drift is the spec entry).
  - No change to the `https://{host}` production server entry — it is retained.

## 4. Module classification

- [x] Infrastructure/config/deployment (spec-input purge + deploy-tree regression lock)
- [x] OAuth/OIDC protocol flow (test-only discovery truthiness sweep)
- [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layers: `cmd/sso-minimal` (root-module `package main`, deploy tree) and `cmd/gensdk` (root module, generator). Dependency direction: tests only, stdlib plus existing in-package helpers; `cmd/sso-minimal` tests already import `interfaces/sso` + `shared/core` (edition_test.go imports both). No package imports `cmd/`; no nested-module go.mod changes.

## 5. Requirements

### R1 — Edition discovery-truthiness sweep (T-2a)

Extend `cmd/sso-minimal/edition_test.go` with `TestEditionDiscoveryTruthiness`:

- Table over the three build profiles `{prototype, minimal, standard}`, resolved through `editionForProfile` (standard → `editionMinimal`, already locked by `TestEditionCapabilities`). Reuse the existing `editionServer` helper (line 112).
- Document endpoint per row: prototype → `server.URL + sso.PathOAuthAuthorizationServerMetadata` (OIDC discovery is 404-gated for prototype); minimal/standard → `server.URL + sso.PathOIDCDiscovery`.
- Assertions on the served document (raw body + parsed fields):
  1. The raw body contains no `/authenticate` substring.
  2. `token_endpoint` is byte-equal to `server.URL + core.PathToken` (ends with `/token`; never `/authenticate`).
  3. `jwks_uri` is byte-equal to `server.URL + core.PathJWKS` (ends with `/.well-known/jwks.json`).
  4. The remaining unconditional endpoint fields match their constants: `authorization_endpoint == server.URL + core.PathLogin`, `revocation_endpoint == server.URL + core.PathRevoke`, `introspection_endpoint == server.URL + core.PathIntrospect`.
  5. Port truthiness: for each of the five endpoint URLs above, parse with `net/url` and assert scheme `http`, non-empty numeric port, port equal to the live httptest port (parsed from `server.URL`), and port neither `8080` nor `0`. This makes "no `:8080`/`:0` port content" exact: the only port that may appear is the live server's.
- The five fields are the unconditional `buildBaseMetadata` endpoints, present in both editions (OIDC-only fields are gated and are not asserted).

### R2 — Deploy-tree guard against the `/authenticate` literal (T-2b)

Add `cmd/sso-minimal/deploy_tree_test.go` (`package main`) with `TestDeployTreeNoAuthenticateLiteral`:

- Resolve the repo root from the test file location (same `repoRoot(t)` pattern as `cmd/sso-ctl/generate/scaffold_build_test.go:16`), walk `cmd/` recursively, and for every `*.go` file whose name does not end in `_test.go` assert the source contains no `"/authenticate"` literal.
- Scoping is mandatory: today the string `"/authenticate"` appears in exactly one cmd/ file — `cmd/sso-ctl/generate/scaffold_contract_test.go:136` (`[]byte("/authenticate")`, the scaffold anti-pattern guard) — which is a `_test.go` file and is excluded. Non-test cmd/ Go sources have 0 matches (verified). Without the `_test.go` exclusion the guard would fail on day one against a legitimate guard; with it, this is a pure regression lock, not a fix.
- The guard must not assert on ports or on `docs/openapi.yaml` (those are R1/R3's jobs).

### R3 — Purge the localhost:8080 server entry and lock the spec input (T-2c)

- Edit `docs/openapi.yaml`: delete the `- url: http://localhost:8080` entry (lines 55-56, including its description). Keep the `https://{host}` production entry unchanged.
- Add `cmd/gensdk/spec_input_test.go` (`package main`) with `TestSpecInputServersAreDeployTruthful`, using the existing in-package `parseSpec` over the embedded `docs.OpenAPISpec` (so the test automatically tracks `docs/openapi.yaml`):
  1. `servers` is a non-empty list.
  2. No entry's `url` contains `localhost`, `127.0.0.1`, or a numeric-port literal (regex `:\d+`).
  3. Exactly one entry has `url == "https://{host}"` (the production entry is retained).
- This converts the direction's prose acceptance into a machine-checked regression lock on the generator's single spec input.

### R4 — SDK regeneration stays green and wire-shape-identical (T-2d)

- Run `python cli.py sdk-surface generate` (which runs `go run ./cmd/gensdk --lang=all`) then `python cli.py sdk-surface check`.
- Assert regeneration stability: `git diff --exit-code docs/sdks/` is empty after `generate` — the generator does not consume the `servers:` list (`base_url` is a runtime constructor parameter), so the spec edit must not change a single emitted byte, in particular `getOpenIDConfiguration`/`getOAuthAuthorizationServerMetadata`/`getJWKS` and the `OpenIDConfiguration`/`JWKS` types in `docs/sdks/typescript/client.ts:2957-2976` and `docs/sdks/python/client.py:2324`.
- The existing `cmd/gensdk` emit tests (`emit_test.go`, `schema_test.go`) keep passing unchanged.

### R5 — Existing discovery coverage stays green; legacy defect tests stay absent (T-2e)

- `TestDiscovery_EndpointsAreAbsoluteURLs` (test/oidc_discovery_test.go:88) and `TestDiscovery_RespectsXForwardedProto` (:200) — and the rest of `go test ./test/ -run TestDiscovery` — keep passing unchanged; no edits to `test/oidc_discovery_test.go`.
- `rg 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' --include='*.go'` stays 0 hits repo-wide (currently 0, verified); no new test recreates either legacy defect test.

### Testable acceptance (Given/When/Then)

R1 sweep — extended `cmd/sso-minimal/edition_test.go`:

1. Given `editionServer(t, editionForProfile("prototype"))`, when GET `server.URL + sso.PathOAuthAuthorizationServerMetadata` returns the served document, then `token_endpoint == server.URL + core.PathToken`, `jwks_uri == server.URL + core.PathJWKS`, the other three unconditional endpoints match their `core.Path*` constants, no `/authenticate` substring exists in the raw body, and every endpoint URL's parsed port equals the httptest port (never `8080`/`0`).
2. Same assertions for `editionForProfile("minimal")` and `editionForProfile("standard")` (both resolve to `editionMinimal`), fetched at `server.URL + sso.PathOIDCDiscovery`.
3. Given a future regression that re-advertises `/authenticate` or a hardcoded port in `buildBaseMetadata`, when the sweep runs, then it fails with a message naming the offending field and the expected constant.

R2 guard — new `cmd/sso-minimal/deploy_tree_test.go`:

4. Given the cmd/ deploy tree at HEAD, when the guard scans non-test `*.go` sources under `cmd/`, then 0 files contain the `"/authenticate"` literal (pure regression lock; passes today, verified).
5. Given a future commit that reintroduces an `/authenticate` path literal in any non-test cmd/ Go file, when the guard runs, then it fails naming the file. (Compile-time corollary: a reintroduction via a `core.Path*` constant is inherently safe — `core.PathLogin` is `/auth/login`.)
6. Review invariant: the guard's own `_test.go` exclusion is what keeps case 4 true despite the legitimate `[]byte("/authenticate")` assertion in `cmd/sso-ctl/generate/scaffold_contract_test.go:136`; a future edit that rewrites the guard to scan test files fails loudly on day one (by design, and would then need the scaffold guard excluded explicitly — prefer keeping the `_test.go` exclusion).

R3 spec input — edited `docs/openapi.yaml` + new `cmd/gensdk/spec_input_test.go`:

7. Given the edited spec, when `parseSpec(docs.OpenAPISpec)` runs and the `servers:` list is inspected, then no URL contains `localhost`, `127.0.0.1`, or a numeric port, and exactly one entry `https://{host}` remains.
8. Given a future commit that re-adds a localhost/numeric-port server entry, when the test runs, then it fails naming the offending URL.

R4 regeneration:

9. Given the spec edit, when `python cli.py sdk-surface generate && python cli.py sdk-surface check` runs, then both exit 0.
10. Given the same edit, when `git diff --exit-code docs/sdks/` runs after generation, then it is empty — `getOpenIDConfiguration`/`getOAuthAuthorizationServerMetadata`/`getJWKS` and the `OpenIDConfiguration`/`JWKS` types are byte-identical in wire shape.

R5 regression:

11. Given the change, when `go test ./test/ -run 'TestDiscovery_' -v` runs, then `TestDiscovery_EndpointsAreAbsoluteURLs` and `TestDiscovery_RespectsXForwardedProto` (and the rest of the discovery suite) pass unchanged.
12. Review-time check: `rg 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' --include='*.go'` → 0 hits (currently 0; the new tests add no legacy-shaped names).

### Acceptance mapping grade: 12/12 machine-checked except cases 6 and 12

Cases 1-5 and 7-11 fail on regression under a named gate (`go test ./cmd/sso-minimal/`, `go test ./cmd/gensdk/`, `python cli.py sdk-surface generate && check`, `go test ./test/ -run TestDiscovery_`). Case 6 is a design invariant (vacuous as a failing test). Case 12 is review-time (absence, no gate can fail on a non-test) — both are stated explicitly so the implementer cannot silently drop them.

## 6. Engineering-gate constraints (verified)

- **Budgets**: no production Go changes, so filesize/complexity/nesting/directory-fanout gates are untouched. `cmd/gensdk` gains one `_test.go` (non-test count stays 7 of 10); `cmd/sso-minimal` gains one `_test.go` and one extended test file (test files exempt from the non-test file budget). `edition_test.go` grows from 141 lines to ~200 — under 500.
- **`interfaces/sso` 60-file ceiling**: untouched (no edits there; `_test.go` files are exempt anyway).
- **Architecture**: tests import `interfaces/sso` + `shared/core` (downward) from `cmd/sso-minimal` — the same direction `edition_test.go` already exercises. No new package, no `layerExemptions` entry, no `cmd/` import.
- **Wire/contract invariants**: no routes, no `Err*`, no config keys, no credential endpoints, no SSRF surface (tests use httptest; the guard and spec-input tests read local files only). Oracle-safe response tables unaffected.
- **Root policy**: no new root-level files; `docs/openapi.yaml` is a docs edit, `docs/architect-analysis/` is analysis output.
- **Nested modules**: untouched by this change; R2's scan does cover nested-module sources under `cmd/` (they are part of the deploy tree) and their non-test Go sources currently contain no `"/authenticate"` literal (verified: `cmd/sso-mcp`, `cmd/sso-operator`, `cmd/snaplink-billing`, `cmd/sso-ctl`, `cmd/sso-server`, `cmd/sso-minimal` all clean).

## 7. Files

### Create

```text
cmd/sso-minimal/deploy_tree_test.go — R2 deploy-tree guard
    (package main; repoRoot(t) via runtime.Caller; walks cmd/ recursively,
    skips *_test.go, asserts no `"/authenticate"` literal; pure regression lock).
cmd/gensdk/spec_input_test.go — R3 spec-input servers lock
    (package main; parseSpec(docs.OpenAPISpec); asserts no localhost/127.0.0.1/
    numeric-port server URL and exactly one https://{host} entry).
```

### Modify

```text
cmd/sso-minimal/edition_test.go — R1: add TestEditionDiscoveryTruthiness
    (profile table {prototype, minimal, standard} via editionForProfile;
    prototype fetches sso.PathOAuthAuthorizationServerMetadata, minimal/standard
    fetch sso.PathOIDCDiscovery; suffix + /authenticate + port assertions
    against server.URL + core.Path* constants; reuses editionServer helper).
docs/openapi.yaml — R3: delete the `- url: http://localhost:8080` entry
    (lines 55-56 incl. description); keep `https://{host}` unchanged.
```

### Do not modify

```text
interfaces/sso/*            — no server changes (discovery is already truthful)
shared/core/*               — constants already correct
test/oidc_discovery_test.go — existing TestDiscovery_* coverage stays as-is
ops/build/sdk-surface.json, ops/scripts/sdk_surface.py — registry and CLI unchanged
cmd/gensdk/*.go (production) — generator unchanged; regeneration must be byte-identical
docs/sdks/typescript/client.ts, docs/sdks/python/client.py — must show zero diff
cmd/sso-ctl/generate/scaffold_contract_test.go — existing scaffold guard untouched
```

## 8. Dependencies and compatibility

- Test-only additions; stdlib only (`net/url`, `net/http`, `strings`, `testing`, `path/filepath`, `runtime`). No new module dependencies; root `go.mod`/`go.sum` unchanged; no `go.work`.
- The `docs.OpenAPISpec` embed (`docs/openapi_embed.go:28`) picks up the spec edit automatically — no regeneration step for the embed itself.
- Wire compatibility: nothing on the wire changes. `sdk-surface check` validates operationId registry vs the edited spec — the edit touches only `servers:`, which the registry never references, so `check` stays green.
- Behavioral compatibility: `TestPrototypeExposesOAuthWithoutOIDC` (RFC 8414 alias served, OIDC discovery 404 for prototype) is the pattern R1 relies on and is not altered.

## 9. Documentation

- `docs/openapi.yaml` is itself the public contract; the `servers:` edit is the documentation change. No `docs/config-reference.md`, `docs/error-codes.md`, or `docs/feature-matrix.md` impact (no new config, errors, or features).
- No new README/comment content beyond the test doc comments required by the repo discipline ("comments explain hidden constraints and reasons").

## 10. Verification plan

1. Edit `docs/openapi.yaml` (remove the localhost:8080 entry; verify `grep -n 'localhost:8080' docs/openapi.yaml` → 0 hits, the `https://{host}` entry remains, and line 30's unrelated swagger-ui comment `http://localhost:8088` — a different port, docs-serve tooling — is untouched).
2. Add R3 test → `go test ./cmd/gensdk/ -run TestSpecInputServersAreDeployTruthful -v`.
3. Add R1 sweep → `go test ./cmd/sso-minimal/ -run TestEditionDiscoveryTruthiness -v`.
4. Add R2 guard → `go test ./cmd/sso-minimal/ -run TestDeployTreeNoAuthenticateLiteral -v`.
5. `python cli.py sdk-surface generate && python cli.py sdk-surface check`; then `git diff --exit-code docs/sdks/` (must be empty).
6. `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`
7. `go test ./test/ -run 'TestDiscovery_' -v` (R5: `TestDiscovery_EndpointsAreAbsoluteURLs`, `TestDiscovery_RespectsXForwardedProto` green).
8. `rg -n 'TestOIDCDiscovery|TestOIDCDiscoveryEndpoint' --include='*.go'` → 0 hits (R5 absence, review-time).
9. `go test ./... -race`; `make ci` (full handoff gate, including nested modules and the sdk-surface checks).
