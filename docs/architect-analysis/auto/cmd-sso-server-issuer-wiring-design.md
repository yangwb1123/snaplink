# Design: cmd/sso-server issuer-wiring end-to-end pinning (B4-1 iss allowlist)

Design for the direction "Wire `sso.WithIssuer(cfg.Server.Issuer)` into
cmd/sso-server so resolveIssuer is never Host-derived", per
[cmd-snaplink-audit-provisioner-issuer-wiring-spec.md](cmd-snaplink-audit-provisioner-issuer-wiring-spec.md).
Every claim in the supplied evidence was re-verified against this tree
(§1). One attribution claim is **wrong** (commit origin); no semantic
claim failed. The spec's verdict — the wiring already exists end to end,
so the change set is tests only — is confirmed, and this document makes it
an implementation contract.

Module: `cmd/sso-server` (package `main`, test file only). Doc-only
artifact: this file triggers no gates; the implementation is the test file
specified in §2.

## 0. Summary

| Question | Answer |
|---|---|
| Does cmd/sso-server already wire `sso.WithIssuer(cfg.Server.Issuer)`? | **Yes.** `config.Config.ServerOptions()` emits it (`config/config_load.go:308`); `wireSigningIssuer` appends `ServerOptions()` (`build_app_core.go:154`); `sso.NewServer(b.opts...)` consumes `b.opts` (`build_app.go:257`). |
| Are the JWT `iss` claim and discovery issuer pinned to the same value? | **Yes.** JWT: `WithEd25519Issuer(srv.Issuer)` (`serverbuildsign/build_signing_issuers.go:43`); discovery: `applyMFAIssuerSigning` override (`server_discovery_config.go:264-265`, called unconditionally at `:112`); authorization responses: `resolveIssuer` (`server_discovery.go:251-257`). All three read `cfg.Server.Issuer` via `s.issuer` or the signing-issuer constructor. |
| Is the direction's production change a no-op? | **Yes.** Implementing it again would be speculative churn. The only real remainder is the direction's own acceptance: no test pins the cross-path issuer equalities at the binary level. |
| What is the change set? | One new test file, `cmd/sso-server/issuer_wiring_test.go`, with three end-to-end tests (T-2a/T-2b/T-2c). T-2d stays green unchanged. Zero production code, zero config, zero docs-contract changes. |
| Evidence correction | "The wiring landed in commit `305dc6c0` (2026-06-19)" is **wrong**. `git log -S 'sso.WithIssuer(c.Server.Issuer)' -- config/` shows the origin at `eb7b6212` (2026-05-12, "feat(sso): core SDK with 7 pluggable authenticators + per-APP config"). `305dc6c0` (2026-06-19) is the maintainability refactor that split `config.go` → `config_load.go`, moving the code **verbatim** (`git show 305dc6c0 -- config/config_load.go` is a new-file diff of moved code; parent `config/config.go:852` already had `sso.WithIssuer(c.Server.Issuer)`). The "analysis is stale" conclusion survives; the commit citation does not. |

## 1. Evidence verification — untrusted claims re-checked against the tree

All 6 evidence claims verify TRUE in substance. One citation is wrong
(commit attribution, §0). The spec's 20+ table rows were each re-checked;
line numbers below are the current tree.

| # | Claim | Verdict | Evidence (this tree) |
|---|---|---|---|
| E1 | `ServerOptions()` (config/config_load.go:301-308) always emits `sso.WithIssuer(c.Server.Issuer)` | ✅ | Function at `config/config_load.go:301`; `sso.WithIssuer(c.Server.Issuer)` at `:308`, first element of `opts`. Baseline composition pinned by `config/security_test.go:72-124`: 4 opts (issuer + 3 security) / 2 opts (issuer + body-limit default) / 1 opt (issuer only). |
| E2 | `build_app_core.go:154` appends `ServerOptions()`; `build_app.go:257` feeds `b.opts` to `sso.NewServer` | ✅ | `b.opts = append(cfg.ServerOptions(), ...)` at `cmd/sso-server/build_app_core.go:154` inside `wireSigningIssuer` (`:133`); `srv = sso.NewServer(b.opts...)` at `cmd/sso-server/build_app.go:257`. |
| E3 | JWT `iss` comes from the same `cfg.Server.Issuer` via `serverbuildsign/build_signing_issuers.go:43` | ✅ | `defaultimpl.WithEd25519Issuer(srv.Issuer)` at `:43` in `buildEd25519SigningIssuer`. Third consumer named by `issuer_test.go:15` confirmed: `tracing.WithServiceName(cfg.Server.Issuer)` at `cmd/sso-server/main_wiring.go:203`. |
| E4 | `issuer_test.go:15` comment is accurate, not drift | ✅ | Comment names exactly `WithIssuer via ServerOptions`, `WithEd25519Issuer for the JWT iss claim`, `tracing.WithServiceName`; all three exist (E1-E3). |
| E5 | Wiring is tested: `config/security_test.go:72-124`, `rootcov_accessors_test.go:246-248`, `TestConfigRejectsSDKSentinel` | ✅ | Three ServerOptions-composition tests at `:72-124`; `rootcov_accessors_test.go:246-248` ("explicit WithIssuer wins over the request base URL", server wired at `:68`); `cmd/sso-server/issuer_test.go:37-53` + rejection at `config/config_load.go:184` ("must not equal"). |
| E6 | Wiring landed in commit `305dc6c0` (2026-06-19) | ❌ attribution | Origin is `eb7b6212` (2026-05-12). `305dc6c0` moved the code verbatim during the `config.go` split. Substance unaffected. |

Load-bearing findings re-verified for the test design:

| Finding | Evidence |
|---|---|
| Discovery honors `WithIssuer` unconditionally | `applyMFAIssuerSigning` (`server_discovery_config.go:264-265`, override when `s.issuer != "" && != DefaultIssuer`) is called from `buildOIDCConfiguration` at `:112` on every discovery render. |
| `resolveIssuer` fallback reachable only when issuer empty/sentinel | `server_discovery.go:251-257`: returns `s.issuer` unless empty/`DefaultIssuer`, else `requestBaseURL`. |
| Tampered `X-Forwarded-Host` changes the request base URL | `interfaces/middleware/request_url.go:18-40` (`BaseURL` honors X-Forwarded-Proto/Host); `ForwardedHeadersTrusted` default-true with no TrustedProxies verdict (`interfaces/middleware/trusted_proxy.go:176-180`; `forwarded_trust_test.go:70` "no middleware: true (legacy)"). So an httptest request with `X-Forwarded-Host: attacker.example` + `X-Forwarded-Proto: http` yields base `http://attacker.example` — the exact divergence the direction feared, and the exact discriminator T-2a needs. |
| `/auth/login` errors carry RFC 9207 `iss` + no-store | `handleLogin` stamps `tokenNoStoreHeaders` before any response (`server_login.go:19-24`); every error path uses `authzErrorBody` (`rejectNonJSONLogin` `:165-178`, `rejectDisallowedLoginOrigin` `:180-200`, `server_login_client.go:27-65` — unknown client → 401 `ErrInvalidClient` at `:37`). |
| Code-flow success envelope carries `iss` | `finishLoginCodeFlow` returns `{code, iss}` (`server_finish_login.go:466-470`), `iss = s.resolveIssuer(ctx)`. |
| form_post hidden `iss` input | `protocols/oidc/oidcsupport/form_post.go:38`: `<input type="hidden" name="iss" value="{{.Iss}}">`; `renderFormPostResponse` passes `resolveIssuer` (`server_discovery.go:343`). |
| No authorization-code flow test exists in cmd/sso-server | `grep -rn "authorization_code" cmd/sso-server/*_test.go`: zero hits. Net-new coverage confirmed. |
| Discovery tests assert presence only | `rootcov_discovery_test.go:49,268`, `cache_ttl_test.go:90` (`if _, ok := doc["issuer"]`). T-2a/T-2b add equality assertions, not duplicates. |
| Test infrastructure exists | `buildApp(cfg, quietLogger())` works with a near-empty `&config.Config{}` (`cache_ttl_test.go`); `shutdownApp` (`build_app_coverage_test.go:28`); `writeBcryptHashFile` (`password_test.go:362`); `fetchDoc` (`cache_ttl_test.go:15`); `fetchDiscovery` (`operator_metadata_test.go:15`); `a.clientStore` / `a.userProvider` reachable post-build (`client_config_test.go:65`, `userlifecycle_wiring_test.go:150`); clients seeded via `cfg.Clients`; password users seeded via `cfg.Authenticators.Password.Users` (`PasswordUserConfig{Username,BcryptHashFile,SubjectID}`, `config/config_authn.go:208-212`; `appendPasswordAuthenticator` at `serverbuildauthn/build_authenticators_helpers.go:129-151`, enabled iff `Enabled: true`). |
| `interfaces/sso` at its file ceiling | 60 non-test files (`ls interfaces/sso/*.go | grep -v _test | wc -l` = 60). The spec's "no new files there" constraint is binding; all new code lives in `cmd/sso-server` (test file — excluded from the 10 non-test files/dir budget). |

## 2. Design

Single change: create `cmd/sso-server/issuer_wiring_test.go` (package
`main`, target ≤ 500 lines, reusing existing helpers). No production file
is touched; no contract doc is touched; no SDK file is touched.

### 2.1 Shared fixture

```go
const issWireIssuer  = "https://sso.example.com"
const issWireClient  = "iss-wire-client"
const issWireSecret  = "iss-wire-secret"
const issWireUser    = "iss-wire-user"
const issWirePass    = "iss-wire-pass"
const issWireRedirect = "https://rp.example/cb"

// newIssuerWiringServer builds the real binary composition with
// server.issuer pinned, plus one seeded JWT client and one seeded
// password user, and returns the live httptest server.
func newIssuerWiringServer(t *testing.T) *httptest.Server {
    t.Helper()
    cfg := &config.Config{}
    cfg.Server.Issuer = issWireIssuer
    cfg.Clients = []config.ClientConfig{{
        ID: issWireClient, Secret: issWireSecret,
        RedirectURIs: []string{issWireRedirect},
        AllowedScopes: []string{"openid", "profile"},
        AllowedAuthenticators: []string{authenticators.MethodPassword},
        TokenStrategy: "jwt", Active: true, SkipConsent: true,
    }}
    cfg.Authenticators.Password = &config.PasswordConfig{
        Enabled: true,
        Users: []config.PasswordUserConfig{{
            Username: issWireUser,
            BcryptHashFile: writeBcryptHashFile(t, issWirePass),
            SubjectID: issWireUser,
        }},
    }
    a, err := buildApp(cfg, quietLogger())
    if err != nil { t.Fatalf("buildApp: %v", err) }
    t.Cleanup(func() { shutdownApp(t, a) })
    srv := httptest.NewServer(a.server.Handler())
    t.Cleanup(srv.Close)
    return srv
}
```

Rationale, all verified in §1: `buildApp` with a minimal `*config.Config`
is the established pattern (`cache_ttl_test.go`); `cfg.Server.Issuer`
flows `ServerOptions` → `s.issuer` and `serverbuildsign` → JWT `iss`;
`TokenStrategy: "jwt"` guarantees a JWT (not session) access token;
`SkipConsent: true` keeps the code flow single-round-trip; the bcrypt
hash file is generated at runtime (no committed secrets, no YAML fixtures).

### 2.2 T-2a — discovery issuer is never Host-derived

```
Given  server.issuer = https://sso.example.com
When   GET /.well-known/openid-configuration with
       X-Forwarded-Host: attacker.example, X-Forwarded-Proto: http
Then   doc["issuer"] == "https://sso.example.com"
```

Implementation: build the server, issue the request with the two tampered
headers (plain `http.NewRequest` + `http.Client.Do`; `fetchDoc` takes a
URL, so the request is constructed inline), unmarshal, assert equality.
`ForwardedHeadersTrusted` is default-true with no TrustedProxies config
(§1), so without the `s.issuer` override the doc issuer would be
`http://attacker.example` — the assertion discriminates the direction's
exact concern. This is the only test that needs the custom headers;
T-2b/T-2c reuse the plain `fetchDoc`/client helpers.

### 2.3 T-2b — authorization error body `iss` == discovery issuer

```
Given  the same server
When   POST /auth/login {"client_id": "no-such-client"}   (unknown client)
Then   status 401, body["iss"] == "https://sso.example.com"
       == discovery doc["issuer"] from T-2a's value
       and Cache-Control: no-store, Pragma: no-cache (guard)
When   POST /auth/login (valid password login, response_mode=form_post)
Then   HTML body contains
       name="iss" value="https://sso.example.com"          (hidden input)
When   POST /auth/login (valid password login, response_type=code)
Then   200 body["iss"] == "https://sso.example.com"        (success envelope)
```

Three surfaces, one value. The unknown-client path is
`server_login_client.go:37` → 401 `ErrInvalidClient` via
`authzErrorBodyWithState` (RFC 9207 `iss`); the no-store headers are
stamped in `handleLogin` before any response (`server_login.go:19-24`) —
asserted as a guard so a future refactor cannot silently drop them; the
form_post path renders `oidcsupport/form_post.go:38`'s hidden `iss` input
via `renderFormPostResponse` (`server_discovery.go:343`); the code-flow
success envelope is `finishLoginCodeFlow`'s `{code, iss}`
(`server_finish_login.go:466-470`).

### 2.4 T-2c — access-token and id-token `iss` claims == discovery issuer

```
Given  the same server
When   POST /token, Basic iss-wire-client:iss-wire-secret,
       grant_type=client_credentials, scope=profile
Then   decode access_token payload; payload["iss"] == "https://sso.example.com"

When   POST /auth/login (password, response_type=code, scope="openid profile")
       → 200 {"code": C, "iss": ...}
       POST /token, Basic auth, grant_type=authorization_code,
       code=C, redirect_uri=https://rp.example/cb
Then   decode access_token + id_token payloads; both
       payload["iss"] == "https://sso.example.com"
```

Implementation: a local `decodeJWTPayload(t, token)` helper —
`strings.Split(token, ".")`, require 3 parts, `base64.RawURLEncoding`
decode of part 2, `json.Unmarshal` into `map[string]any`. No signature
verification (the token is the server's own response; the assertion is
the `iss` payload value). Client-credentials exercises the JWT issuer's
default token strategy; the code flow additionally exercises
`WithIDTokenIssuer(jwtIssuer)` (`build_app_core.go:169`) — the id token's
`iss` comes from the same `Ed25519JWTIssuer` (`WithEd25519Issuer(srv.Issuer)`),
so the two issuance paths cross-check each other. Token requests are
`application/x-www-form-urlencoded`; HTTP Basic wins over body creds per
`bindOAuthParams` (AGENTS.md invariant) — credentials go in the Basic
header only. This is the first authorization-code-flow test in
`cmd/sso-server` (§1: zero existing hits).

### 2.5 T-2d — sentinel rejection stays green

No new test. `TestConfigRejectsSDKSentinel` (`issuer_test.go:37-53`) and
`config_load.go:184` are regression pins; the spec requires them unchanged.
The mandatory gates (§5) run them; any relaxation of the sentinel check
fails the suite.

## 3. API changes

**None.** This is the design's core compatibility property:

- No production Go changes: `config.Config.ServerOptions`, `sso.WithIssuer`,
  `resolveIssuer`, `applyMFAIssuerSigning`, `WithEd25519Issuer`, the
  login/token/discovery handlers, and `tracing.WithServiceName` wiring are
  all untouched.
- No new `Err*`, no new endpoint, no new config knob → no
  `docs/error-codes.md`, `docs/openapi.yaml`, `docs/config-reference.md`,
  or `docs/observability.md` changes (AGENTS.md §5.6 triggers none).
- No SDK surface change: `interfaces/sso` remains at its 60-file ceiling.

The *frozen contract surface under test* (regression pins, not API):
`ServerOptions()` output composition; `WithIssuer` semantics (non-empty,
non-sentinel wins over request base URL); discovery issuer override;
RFC 9207 `iss` in authorization error/success/form_post responses;
`no-store`/`no-cache` on `/auth/login`; JWT `iss` from `server.issuer`.

## 4. Compatibility constraints

| Constraint | Enforcement |
|---|---|
| Wire bytes unchanged | Tests only; no handler touched. T-2b's no-store assertion is a guard against future drift, not a behavior change today. |
| Config schema/semantics unchanged | `server.issuer` behavior, `DefaultServerIssuer = "sso-server"` (`config_load.go:51`), and sentinel rejection (`:184`) untouched. |
| `interfaces/sso` ceiling (60 files) | All new code in `cmd/sso-server/issuer_wiring_test.go` (test file; excluded from the 10 non-test files/dir budget). |
| Budgets | New file ≤ 500 lines, ≤ 15 cyclomatic per function, ≤ 3 `if` nesting, no new non-test files, no new top-level packages (no `layerName()` classification needed). |
| Discovery-cache key | Untouched — T-2a/T-2b read the doc over HTTP exactly as clients do. |
| No parallel/`-race` hazards | Each test builds its own server; `shutdownApp` + `srv.Close` via `t.Cleanup` (kitchen-sink pattern); `writeBcryptHashFile` is already race-safe and parallel-friendly (`password_test.go:362`, `t.TempDir()`). |
| Determinism | The tampered `X-Forwarded-Host` is independent of httptest's random port, so the base-URL divergence is stable; the issuer literal is unique to this fixture. |
| No committed secrets | Bcrypt hash generated per-test in `t.TempDir()`. |

## 5. Failure modes

### 5.1 Production drift the tests guard (each maps to a direction concern)

| Failure | Test that catches it | Mechanism |
|---|---|---|
| `ServerOptions` stops emitting `WithIssuer` | T-2a, T-2b, T-2c | `s.issuer` empty → discovery/error/form_post issuers fall back to request base URL; JWT `iss` still pinned → cross-surface mismatch. |
| Discovery override (`applyMFAIssuerSigning`) removed | T-2a | Doc issuer becomes `http://attacker.example` under the tampered headers. |
| `resolveIssuer` sentinel/fallback order changed | T-2b | Error-body `iss` diverges from discovery. |
| `WithEd25519Issuer` (JWT `iss`) dropped or re-pointed | T-2c | Token payload `iss` diverges; RFC 9068 validators break. |
| no-store headers dropped on `/auth/login` | T-2b (guard) | Header assertion fails. |
| form_post hidden `iss` dropped | T-2b | HTML assertion fails. |
| Sentinel rejection relaxed | T-2d | `TestConfigRejectsSDKSentinel` fails (existing). |

### 5.2 Test-construction failure modes (bounded at implementation time)

| Hazard | Mitigation |
|---|---|
| `buildApp` with minimal config fails in a wire phase | Proven working by `cache_ttl_test.go` (discovery + JWKS + full build on near-empty config). |
| Password authenticator not wired | `cfg.Authenticators.Password.Enabled = true` is required (`build_authenticators_helpers.go:130`); fixture sets it. |
| Client rejected at login | Fixture client is `Active: true` with `AllowedAuthenticators: ["password"]` and matching `RedirectURIs`; otherwise login returns 403/400 before minting. |
| Code flow demands PKCE | Fixture client does not set `RequirePKCE`; no verifier needed. If a future default flips, the test fails loudly — the correct outcome (contract drift). |
| `id_token` absent | Only emitted when `WithIDTokenIssuer` wired; full `buildApp` wires it (`build_app_core.go:169`). Test asserts `id_token != ""` before decoding. |
| Session-token strategy | Fixture client pins `TokenStrategy: "jwt"`; access tokens are JWTs. |
| Goroutine leaks under `-race` | `shutdownApp` (all lifecycle cancellers + closers) registered via `t.Cleanup`, mirroring the kitchen-sink test. |
| Flaky decode | `base64.RawURLEncoding` matches the issuer's no-padding output; 3-part split is asserted before decode. |

## 6. Migration steps

**Operators: none.** This change alters no wire behavior, no config
parsing, and no defaults. There is nothing to migrate; the pinning tests
only make the shipped default observable.

**Repository steps:**

1. Create `cmd/sso-server/issuer_wiring_test.go` per §2 (fixture + T-2a +
   T-2b + T-2c + `decodeJWTPayload` helper). Target ≤ 500 lines; if it
   grows past ~450 lines during review, split the fixture into
   `issuer_wiring_fixture_test.go` (test files are not budget-counted) —
   do not touch production files.
2. Run the mandatory gates (§7). Fix only the new file; report any
   pre-existing failure separately per AGENTS.md.
3. Optional record fix: correct the spec/evidence commit attribution
   (`305dc6c0` → `eb7b6212`, §0). This design does not depend on the
   commit claim; the correction is for archive accuracy only.
4. Commit as a conventional, imperative message (e.g. `test(sso-server):
   pin issuer equality across discovery, authz errors, and JWT claims`),
   with the AI co-author trailer when applicable. No binaries.

## 7. Testable acceptance mapping

| Direction acceptance | Test (name) | Concrete assertions | Gate |
|---|---|---|---|
| (a) Discovery issuer is never Host-derived | `TestBuildApp_DiscoveryIssuerIgnoresTamperedHost` | `GET /.well-known/openid-configuration` with `X-Forwarded-Host: attacker.example` + `X-Forwarded-Proto: http` → `doc["issuer"] == "https://sso.example.com"` | §7 gates; fails if base-URL fallback ever wins |
| (b) Authz error `iss` == discovery issuer | `TestBuildApp_AuthzErrorIssMatchesDiscoveryIssuer` | unknown-client POST `/auth/login` → 401, `body["iss"] == "https://sso.example.com"`, `Cache-Control: no-store`, `Pragma: no-cache`; form_post HTML contains `name="iss" value="https://sso.example.com"`; code-flow success body `iss` equals same value | §7 gates |
| (c) Token `iss` claims == discovery issuer | `TestBuildApp_TokenIssClaimsMatchDiscoveryIssuer` | client-credentials access_token payload `iss`; auth-code access_token + id_token payloads `iss` — all `== "https://sso.example.com"` | §7 gates |
| (d) Sentinel `snaplink-sso` rejected at load | `TestConfigRejectsSDKSentinel` (existing) | unchanged; must stay green | `go test ./cmd/sso-server/` |

## 8. Verification plan

1. Targeted: `go test ./cmd/sso-server/ -run 'TestBuildApp_(DiscoveryIssuerIgnoresTamperedHost|AuthzErrorIssMatchesDiscoveryIssuer|TokenIssClaimsMatchDiscoveryIssuer)' -v -count=1`
2. After every edit (AGENTS.md mandatory):
   `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .`
3. Pre-handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
   `make ci`.
4. The new tests must not be skipped, relaxed, or annotated; pre-existing
   failures, if any, are reported separately.
